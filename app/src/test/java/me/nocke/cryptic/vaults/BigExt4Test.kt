package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.ChannelBlockDevice
import me.nocke.cryptic.vaults.ext4.Ext4
import me.nocke.cryptic.vaults.luks.Luks2
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** A 2 TB drive (~15000 block groups): writes must stay fast. Needs `vectors.sh big`; skipped without it. */
class BigExt4Test {
    @Test fun formatTwoTerabyteIsFastAndClean() {
        assumeTrue(FsChecks.docker())
        val f = File(Vectors.dir, "f-big-ext4.img"); f.delete()
        java.io.RandomAccessFile(f, "rw").use { it.setLength(2000L shl 30) }   // sparse
        val t0 = System.nanoTime()
        ChannelBlockDevice.open(f).use { dev ->
            val crypt = me.nocke.cryptic.vaults.luks.LuksFormat.format(dev, Vectors.PASS.toByteArray(), me.nocke.cryptic.vaults.luks.LuksFormat.Kdf(8192, 4, 2), digestIterations = 1000)
            me.nocke.cryptic.vaults.ext4.ExtFormat.format(crypt, "BIG")
            Ext4.mount(crypt).use { fs -> fs.write(fs.create(fs.root, "a.bin", false), 0, ByteArray(5_000_000) { 1 }) }
        }
        val s = (System.nanoTime() - t0) / 1e9
        println("format+write 2TB: %.1fs".format(s))
        assertTrue("format took ${s}s", s < 20)
        val p = ProcessBuilder(File(Vectors.dir, "../vectors.sh").canonicalPath, "check", f.name, Vectors.PASS).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        org.junit.Assert.assertEquals(out, 0, p.waitFor())
        f.delete()
    }

    @Test fun writeOnTwoTerabyteVolumeIsFast() {
        val src = File(Vectors.dir, "big-ext4.img")
        assumeTrue(src.isFile)
        val f = File(Vectors.dir, "w-big-ext4.img")
        ProcessBuilder("cp", "-c", src.path, f.path).start().waitFor()   // APFS clone keeps it sparse
        val t0 = System.nanoTime()
        Ext4.mount(Luks2.open(ChannelBlockDevice.open(f), Vectors.PASS.toByteArray())).use { fs ->
            assertNull(fs.readOnlyReason)
            val t1 = System.nanoTime()
            val n = fs.create(fs.root, "copied.bin", false)
            val t2 = System.nanoTime()
            val chunk = ByteArray(128 * 1024) { it.toByte() }
            var pos = 0L
            repeat(80) { fs.write(n, pos, chunk); pos += chunk.size }   // 10 MB in Files-app-sized writes
            val t3 = System.nanoTime()
            fs.flush()
            val t4 = System.nanoTime()
            println("mount %.2fs create %.2fs write10MB %.2fs flush %.2fs".format((t1 - t0) / 1e9, (t2 - t1) / 1e9, (t3 - t2) / 1e9, (t4 - t3) / 1e9))
            assertTrue("create took ${(t2 - t1) / 1e9}s", t2 - t1 < 2e9)
            assertTrue("writes took ${(t3 - t2) / 1e9}s", t3 - t2 < 5e9)
        }
    }
}
