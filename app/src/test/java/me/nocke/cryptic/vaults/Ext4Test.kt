package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.FsChecks.content
import me.nocke.cryptic.vaults.FsChecks.exercise
import me.nocke.cryptic.vaults.FsChecks.manifest
import me.nocke.cryptic.vaults.FsChecks.writeAndVerify
import me.nocke.cryptic.vaults.ext4.Ext4
import me.nocke.cryptic.vaults.fs.FileSystem
import me.nocke.cryptic.vaults.luks.Luks2
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test

class Ext4Test {
    private val plain = listOf("ext4.img", "ext4-1k-nocsum.img", "ext3.img")

    @Test fun readsEveryImageLikeLinux() {
        for (name in plain) Ext4.mount(Vectors.open(name)).use { fs ->
            assertEquals(name, Vectors.manifest(name).toSet(), manifest(fs))
        }
        Ext4.mount(Luks2.open(Vectors.open("luks2-ext4.img"), Vectors.PASS.toByteArray())).use { fs ->
            assertEquals(Vectors.manifest("luks2-ext4.img").toSet(), manifest(fs))
        }
    }

    @Test fun ext3IsReadOnlyAndExt4IsNot() {
        Ext4.mount(Vectors.open("ext3.img")).use { assertNotNull(it.readOnlyReason) }
        Ext4.mount(Vectors.open("ext4.img")).use { assertNull(it.readOnlyReason) }
        Ext4.mount(Vectors.open("ext4-1k-nocsum.img")).use { assertNull(it.readOnlyReason) }
    }

    /** The shared workload plus what only ext4 has: htree, hard links, uninit extents, sparse files, big extent trees. */
    private fun extExercise(fs: FileSystem) {
        exercise(fs)
        fs.write(fs.create(fs.lookup("/bigdir")!!, "added-to-an-htree-directory", false), 0, "x".toByteArray())
        fs.delete(fs.lookup("/bigdir/entry-with-a-longish-name-17")!!)
        fs.delete(fs.lookup("/dir/hard")!!)                                       // one of two links
        val pre = fs.lookup("/prealloc.bin")!!
        fs.write(pre, 100_001, "inside the preallocated range".toByteArray())      // uninit -> init split
        fs.write(fs.lookup("/sparse-ext.bin")!!, 900_000, "late".toByteArray())  // fill a hole
        fs.rename(fs.lookup("/newdir")!!, fs.lookup("/dir/sub")!!, "moved dir")    // ".." changes
        // many small extents: forces an extent tree deeper than the inode's four slots
        val frag = fs.create(fs.root, "fragmented.bin", false); val pad = fs.create(fs.root, "pad.bin", false)
        repeat(40) { fs.write(frag, frag.length, ByteArray(5000) { 7 }); fs.write(pad, pad.length, ByteArray(5000) { 9 }) }
        fs.delete(pad)
        val deep = fs.create(fs.root, "deep-tree.bin", false); val pad2 = fs.create(fs.root, "pad2.bin", false)
        repeat(60) { fs.write(deep, deep.length, ByteArray(4096) { 3 }); fs.write(pad2, pad2.length, ByteArray(4096) { 4 }) }  // stays > 4 extents
        fs.truncate(frag, 33_333)

        val p = content(fs, "/prealloc.bin")
        assertEquals("head", String(p, 0, 4))
        assertEquals(0, p.slice(4 until 100_001).count { it != 0.toByte() })
        assertEquals("inside the preallocated range", String(p, 100_001, 29))
        assertArrayEquals("hello exfat\n".toByteArray(), content(fs, "/dir/sub/moved hello with a much longer name.txt"))
        assertEquals(33_333, content(fs, "/fragmented.bin").count { it == 7.toByte() })
    }

    @Test fun writes4kImageThatE2fsckAccepts() = writeAndVerify("ext4.img", "w-ext4.img", { Ext4.mount(it) }, null, ::extExercise)

    @Test fun writes1kNoChecksumImageThatE2fsckAccepts() = writeAndVerify("ext4-1k-nocsum.img", "w-ext4-1k.img", { Ext4.mount(it) }, null, ::extExercise)

    @Test fun writesLuksExt4ThatE2fsckAccepts() = writeAndVerify("luks2-ext4.img", "w-luks-ext4.img",
        { Ext4.mount(Luks2.open(it, Vectors.PASS.toByteArray())) }, Vectors.PASS, ::extExercise)

    @Test fun randomWorkloadOn4kImage() = writeAndVerify("ext4.img", "w-ext4-fuzz.img", { Ext4.mount(it) }, null) { FsChecks.randomWorkload(it, 1) }

    @Test fun randomWorkloadOn1kImage() = writeAndVerify("ext4-1k-nocsum.img", "w-ext4-fuzz1k.img", { Ext4.mount(it) }, null) { FsChecks.randomWorkload(it, 2) }

    /** Linux left these mounted: the files exist only in the journal until it is replayed. */
    @Test fun replaysTheJournalOfAnUnpluggedDrive() {
        for (name in listOf("dirty-ext4.img", "dirty-ext4-1k.img"))
            writeAndVerify(name, "w-$name", { Ext4.mount(it) }, null) { fs ->
                assertNull(name, fs.readOnlyReason)
                assertEquals(name, Vectors.manifest(name).toSet(), manifest(fs))
                FsChecks.randomWorkload(fs, 3)
            }
    }

    init { assumeTrue(Vectors.dir.isDirectory) }
}
