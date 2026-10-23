package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.ChannelBlockDevice
import me.nocke.cryptic.vaults.exfat.ExFat
import me.nocke.cryptic.vaults.exfat.ExFatFormat
import me.nocke.cryptic.vaults.ext4.ExtFormat
import me.nocke.cryptic.vaults.luks.Luks2
import me.nocke.cryptic.vaults.luks.LuksFormat
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile

class FormatTest {
    private fun blank(name: String, mib: Int): File = File(Vectors.dir, name).also { f ->
        f.delete(); RandomAccessFile(f, "rw").use { it.setLength(mib * 1024L * 1024) }
    }

    private fun fill(fs: me.nocke.cryptic.vaults.fs.FileSystem) {
        val d = fs.create(fs.root, "made on the phone", true)
        fs.write(fs.create(d, "notes.txt", false), 0, "hello from cryptic\n".toByteArray())
        fs.write(fs.create(fs.root, "big.bin", false), 0, ByteArray(3_000_000) { (it * 31).toByte() })
    }

    private fun linux(img: String, pass: String?): Pair<Int, List<String>> {
        val cmd = mutableListOf(File(Vectors.dir, "../vectors.sh").canonicalPath, "check", img).apply { if (pass != null) add(pass) }
        val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readLines()
        return p.waitFor() to out
    }

    @Test fun luksFormatAndMkfsAreAcceptedByCryptsetupAndFsck() {
        val f = blank("f-luks.img", 64)
        ChannelBlockDevice.open(f).use { dev ->
            val crypt = LuksFormat.format(dev, Vectors.PASS.toByteArray(), LuksFormat.Kdf(8192, 4, 2), digestIterations = 1000)
            ExFatFormat.format(crypt, "PHONE")
            ExFat.mount(crypt).use { fs -> assertEquals("PHONE", fs.label); fill(fs) }
        }
        // our own reader, from scratch
        ExFat.mount(Luks2.open(ChannelBlockDevice.open(f), Vectors.PASS.toByteArray())).use { fs ->
            assertEquals(19L, fs.lookup("/made on the phone/notes.txt")!!.length)
        }
        val (rc, out) = linux("f-luks.img", Vectors.PASS)
        assertEquals(out.joinToString("\n"), 0, rc)
        assert(out.any { it.endsWith("./made on the phone/notes.txt") && it.startsWith("f 19 ") }) { out.joinToString("\n") }
    }

    @Test fun mkfsExt4IsAcceptedByE2fsckAndWritable() {
        for ((name, mib) in listOf("f-ext4.img" to 64, "f-ext4-small.img" to 20, "f-ext4-multi.img" to 400)) {
            val f = blank(name, mib)
            ChannelBlockDevice.open(f).use { dev -> ExtFormat.format(dev, "PHONE") }
            me.nocke.cryptic.vaults.ext4.Ext4.mount(ChannelBlockDevice.open(f)).use { fs ->
                assertEquals("PHONE", fs.label); org.junit.Assert.assertNull(fs.readOnlyReason); fill(fs)
            }
            val (rc, out) = linux(name, null)
            assertEquals(name + "\n" + out.joinToString("\n"), 0, rc)
            assert(out.any { it.endsWith("./big.bin") && it.startsWith("f 3000000 ") }) { out.joinToString("\n") }
        }
    }

    @Test fun luksFormatWithExt4IsAcceptedByCryptsetupAndE2fsck() {
        val f = blank("f-luks-ext4.img", 96)
        ChannelBlockDevice.open(f).use { dev ->
            val crypt = LuksFormat.format(dev, Vectors.PASS.toByteArray(), LuksFormat.Kdf(8192, 4, 2), digestIterations = 1000)
            ExtFormat.format(crypt, "VAULT")
            me.nocke.cryptic.vaults.ext4.Ext4.mount(crypt).use { fill(it) }
        }
        val (rc, out) = linux("f-luks-ext4.img", Vectors.PASS)
        assertEquals(out.joinToString("\n"), 0, rc)
    }

    @Test fun mkfsOn512ByteSectorsIsAcceptedByFsck() {
        val f = blank("f-plain.img", 40)
        ChannelBlockDevice.open(f).use { dev -> ExFatFormat.format(dev); ExFat.mount(dev).use { fill(it) } }
        val (rc, out) = linux("f-plain.img", null)
        assertEquals(out.joinToString("\n"), 0, rc)
        assert(out.any { it.endsWith("./big.bin") && it.startsWith("f 3000000 ") }) { out.joinToString("\n") }
    }
}
