package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.block.ChannelBlockDevice
import me.nocke.cryptic.vaults.fs.FileSystem
import me.nocke.cryptic.vaults.fs.FsNode
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import java.io.File
import java.security.MessageDigest
import java.util.Random

/** Shared checks for every FileSystem: manifests like inside.sh, a write workload, and Linux's verdict. */
object FsChecks {
    /** Same lines as inside.sh's manifest(), as a set. */
    fun manifest(fs: FileSystem): Set<String> {
        val out = HashSet<String>()
        fun walk(dir: FsNode) {
            for (n in fs.list(dir)) {
                val p = "." + n.path
                if (n.isDir) { out.add("d 0 - $p"); walk(n) } else out.add("f ${n.length} ${sha(fs, n)} $p")
            }
        }
        walk(fs.root)
        return out
    }

    fun sha(fs: FileSystem, n: FsNode): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(65536); var pos = 0L
        while (true) { val k = fs.read(n, pos, buf); if (k <= 0) break; md.update(buf, 0, k); pos += k }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun content(fs: FileSystem, path: String): ByteArray {
        val n = fs.lookup(path)!!
        val b = ByteArray(n.length.toInt()); fs.read(n, 0, b); return b
    }

    /** Works on the populate() tree from inside.sh. */
    fun exercise(fs: FileSystem) {
        val r = Random(42)
        fun bytes(n: Int) = ByteArray(n).also { r.nextBytes(it) }
        val root = fs.root
        // new file, new nested dirs, a multi-cluster file
        fs.write(fs.create(root, "new.txt", false), 0, "written by cryptic\n".toByteArray())
        val nd = fs.create(fs.create(root, "newdir", true), "inner", true)
        val big = bytes(1_000_000)
        fs.write(fs.create(nd, "big.bin", false), 0, big)
        // interleaved growth fragments both files
        val a = fs.create(root, "a.bin", false); val b = fs.create(root, "b.bin", false)
        repeat(5) { fs.write(a, a.length, bytes(9000)); fs.write(b, b.length, bytes(9000)) }
        // unaligned overwrite in the middle of an existing file, write past the end leaving a hole
        val rnd = fs.lookup("/dir/sub/random-300k.bin")!!
        fs.write(rnd, 12345, bytes(70001))
        val sparse = fs.create(root, "sparse.bin", false)
        fs.write(sparse, 50000, "tail".toByteArray())
        // truncate down and up
        fs.truncate(fs.lookup("/frag.bin")!!, 100000)
        fs.truncate(fs.lookup("/empty.bin")!!, 10000)
        // delete, rename across dirs, rename in place
        for (i in 1..20) fs.delete(fs.lookup("/dir/many-$i.txt")!!)
        fs.rename(fs.lookup("/hello.txt")!!, fs.lookup("/dir/sub")!!, "moved hello with a much longer name.txt")
        fs.rename(fs.lookup("/new.txt")!!, root, "NEW.txt")
        // enough entries to grow a directory past one cluster/block
        val many = fs.create(root, "many", true)
        for (i in 0 until 100) fs.write(fs.create(many, "f$i", false), 0, "$i".toByteArray())
        fs.delete(fs.lookup("/many/f7")!!)
        fs.delete(fs.create(root, "gone", true))

        assertArrayEquals(big, content(fs, "/newdir/inner/big.bin"))
        val sp = content(fs, "/sparse.bin")
        assertEquals(50004, sp.size); assertEquals(0, sp.take(50000).count { it != 0.toByte() }); assertEquals("tail", String(sp, 50000, 4))
        assertEquals(10000, content(fs, "/empty.bin").count { it == 0.toByte() })
    }

    /** [ops] random operations checked against an in-memory model of every file's bytes. */
    fun randomWorkload(fs: FileSystem, seed: Long, ops: Int = 400) {
        val r = Random(seed)
        val model = HashMap<String, ByteArray>()
        val dirs = arrayListOf("/")
        fs.create(fs.root, "fuzz", true); dirs.clear(); dirs.add("/fuzz")
        fun path(d: String, n: String) = (if (d == "/") "" else d) + "/" + n
        repeat(ops) { step ->
            when (r.nextInt(10)) {
                0 -> { val d = dirs[r.nextInt(dirs.size)]; val p = path(d, "d$step"); fs.create(fs.lookup(d)!!, "d$step", true); dirs.add(p) }
                1, 2 -> { val d = dirs[r.nextInt(dirs.size)]; val p = path(d, "f$step"); fs.create(fs.lookup(d)!!, "f$step", false); model[p] = ByteArray(0) }
                3, 4, 5 -> if (model.isNotEmpty()) {
                    val p = model.keys.elementAt(r.nextInt(model.size)); val old = model.getValue(p)
                    val pos = if (r.nextBoolean() || old.isEmpty()) r.nextInt(old.size + 20000) else r.nextInt(old.size)
                    val data = ByteArray(1 + r.nextInt(if (r.nextInt(8) == 0) 300_000 else 9000)).also { r.nextBytes(it) }
                    fs.write(fs.lookup(p)!!, pos.toLong(), data)
                    val nw = old.copyOf(maxOf(old.size, pos + data.size)); data.copyInto(nw, pos); model[p] = nw
                }
                6 -> if (model.isNotEmpty()) {
                    val p = model.keys.elementAt(r.nextInt(model.size)); val old = model.getValue(p)
                    val size = r.nextInt(old.size + 50000); fs.truncate(fs.lookup(p)!!, size.toLong()); model[p] = old.copyOf(size)
                }
                7 -> if (model.isNotEmpty()) { val p = model.keys.elementAt(r.nextInt(model.size)); fs.delete(fs.lookup(p)!!); model.remove(p) }
                8 -> if (model.isNotEmpty()) {
                    val p = model.keys.elementAt(r.nextInt(model.size)); val d = dirs[r.nextInt(dirs.size)]
                    val np = path(d, "r$step"); fs.rename(fs.lookup(p)!!, fs.lookup(d)!!, "r$step"); model[np] = model.remove(p)!!
                }
                9 -> fs.flush()
            }
        }
        for ((p, want) in model) assertArrayEquals(p, want, content(fs, p))
    }

    fun docker() = runCatching { ProcessBuilder("docker", "info").redirectErrorStream(true).start().waitFor() == 0 }.getOrDefault(false)

    /** Runs vectors.sh check: the Linux fsck must be clean and Linux must read what we read. */
    fun linuxCheck(img: String, pass: String?, ours: Set<String>) {
        val cmd = mutableListOf(File(Vectors.dir, "../vectors.sh").canonicalPath, "check", img)
        if (pass != null) cmd.add(pass)
        val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readLines()
        val rc = p.waitFor()
        val lines = out.filter { it.startsWith("f ") || it.startsWith("d ") }.toSet()
        assertEquals("fsck failed:\n" + out.joinToString("\n"), 0, rc)
        assertEquals(ours, lines)
    }

    /** Copies [src] to [dst], runs [work] on it, checks a remount reads the same and Linux agrees. */
    fun writeAndVerify(src: String, dst: String, mount: (BlockDevice) -> FileSystem, pass: String?, work: (FileSystem) -> Unit = ::exercise) {
        val f = File(Vectors.dir, dst); Vectors.file(src).copyTo(f, overwrite = true)
        val ours = mount(ChannelBlockDevice.open(f)).use { fs -> work(fs); manifest(fs) }
        mount(ChannelBlockDevice.open(f)).use { assertEquals("after remount", ours, manifest(it)) }
        if (docker()) linuxCheck(dst, pass, ours) else println("docker unavailable: skipped the Linux check of $dst")
    }
}
