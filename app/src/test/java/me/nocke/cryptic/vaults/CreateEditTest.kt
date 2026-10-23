package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.ChannelBlockDevice
import me.nocke.cryptic.vaults.block.Gpt
import me.nocke.cryptic.vaults.block.Partitions
import me.nocke.cryptic.vaults.block.SliceBlockDevice
import me.nocke.cryptic.vaults.fs.Create
import me.nocke.cryptic.vaults.luks.Luks2
import me.nocke.cryptic.vaults.luks.LuksEdit
import me.nocke.cryptic.vaults.luks.LuksFormat
import me.nocke.cryptic.vaults.luks.WrongPassphraseException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile

/** Create (GPT + LUKS2 + exFAT/ext4 + labels), change passphrase, relabel — judged by Linux tools. */
class CreateEditTest {
    private val kdf = LuksFormat.Kdf(8192, 4, 2)

    private fun blank(name: String, mib: Int) = File(Vectors.dir, name).also { f -> f.delete(); RandomAccessFile(f, "rw").use { it.setLength(mib * 1024L * 1024) } }

    private fun linux(img: String, pass: String): Pair<Int, List<String>> {
        val p = ProcessBuilder(File(Vectors.dir, "../vectors.sh").canonicalPath, "check", img, pass).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readLines()
        return p.waitFor() to out
    }

    private fun value(out: List<String>, key: String) = out.firstOrNull { it.startsWith("$key=") }?.substringAfter("=")

    private fun partition(f: File) = ChannelBlockDevice.open(f).let { dev -> Partitions.findLuks(dev).single().let { SliceBlockDevice(dev, it.start, it.size) } }

    @Test fun createOnDriveForBothFilesystems() {
        assumeTrue(FsChecks.docker())
        for (fs in Create.Fs.values()) {
            val name = "c-drive-${fs.name.lowercase()}.img"
            val f = blank(name, 128)
            ChannelBlockDevice.open(f).use { dev ->
                Create.encrypted(dev, true, Vectors.PASS.toByteArray(), fs, "STICK", kdf, 1000).flush()
            }
            val (rc, out) = linux(name, Vectors.PASS)
            assertEquals(out.joinToString("\n"), 0, rc)
            assertEquals("gpt", value(out, "PTABLE")); assertEquals("STICK", value(out, "PARTLABEL"))
            assertEquals("STICK", value(out, "LUKSLABEL")); assertEquals("STICK", value(out, "FSLABEL"))
            // and our own reader finds the partition, unlocks it and sees the label
            val crypt = Luks2.open(partition(f), Vectors.PASS.toByteArray())
            val fsys = if (fs == Create.Fs.EXT4) me.nocke.cryptic.vaults.ext4.Ext4.mount(crypt) else me.nocke.cryptic.vaults.exfat.ExFat.mount(crypt)
            fsys.use { assertEquals("STICK", it.label) }
        }
    }

    @Test fun changePassphraseAndLabels() {
        assumeTrue(FsChecks.docker())
        val name = "c-edit.img"
        val f = blank(name, 128)
        ChannelBlockDevice.open(f).use { dev -> Create.encrypted(dev, true, Vectors.PASS.toByteArray(), Create.Fs.EXT4, "OLD", kdf, 1000).flush() }

        partition(f).use { LuksEdit.changePassphrase(it, Vectors.PASS.toByteArray(), "new-pass".toByteArray(), kdf) }
        partition(f).use { part ->
            LuksEdit.setLabel(part, "renamed vault")
            me.nocke.cryptic.vaults.ext4.Ext4.mount(Luks2.open(part, "new-pass".toByteArray())).use { it.setLabel("NEWFS") }
        }
        ChannelBlockDevice.open(f).use { Gpt.rename(it, 0, "new part") }

        var threw = false
        try { partition(f).use { Luks2.open(it, Vectors.PASS.toByteArray()) } } catch (e: WrongPassphraseException) { threw = true }
        assertTrue("old passphrase must stop working", threw)

        val (rcOld, _) = linux(name, Vectors.PASS)
        assertEquals("cryptsetup must refuse the old passphrase", 2, rcOld)
        val (rc, out) = linux(name, "new-pass")
        assertEquals(out.joinToString("\n"), 0, rc)
        assertEquals("renamed vault", value(out, "LUKSLABEL")); assertEquals("NEWFS", value(out, "FSLABEL")); assertEquals("new part", value(out, "PARTLABEL"))
    }

    @Test fun exfatLabelChangeOnExistingVolume() {
        assumeTrue(FsChecks.docker())
        val name = "c-exlabel.img"
        val f = blank(name, 64)
        ChannelBlockDevice.open(f).use { dev ->
            val crypt = Create.encrypted(dev, false, Vectors.PASS.toByteArray(), Create.Fs.EXFAT, "", kdf, 1000)
            me.nocke.cryptic.vaults.exfat.ExFat.mount(crypt).use { it.setLabel("Holiday") }
        }
        val (rc, out) = linux(name, Vectors.PASS)
        assertEquals(out.joinToString("\n"), 0, rc)
        assertEquals("Holiday", value(out, "FSLABEL"))
        assertEquals(null, value(out, "PTABLE"))
    }
}
