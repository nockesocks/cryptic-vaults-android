package me.nocke.cryptic.vaults.exfat

import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.fs.FileSystem
import me.nocke.cryptic.vaults.fs.FsNode
import java.io.IOException
import java.lang.ref.WeakReference
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

class ExFatException(msg: String) : IOException(msg)

/**
 * exFAT driver (Microsoft exFAT specification) over a BlockDevice: read, write, create, delete, rename.
 * Metadata goes through a write-back [SectorCache]; [flush] makes the volume consistent and clears VolumeDirty.
 * One lock for the whole volume; finer locking only if parallel transfers need it.
 */
class ExFat private constructor(private val dev: BlockDevice) : FileSystem {
    private val c = SectorCache(dev)
    val bytesPerSector: Int
    val clusterSize: Int
    val clusterCount: Int
    private val fatOffset: Long
    private val heapOffset: Long
    private val rootCluster: Int
    private val upcase = CharArray(65536) { it.toChar() }
    private var bitmapCluster = 0
    private lateinit var bitmap: ByteArray
    private var nextFree = 0
    var freeClusters = 0L; private set
    override var label = ""; private set
    override val type = "exFAT"
    override val readOnlyReason: String? = null
    private var dirty = false
    private val chains = HashMap<Int, IntArray>()
    private val nodes = HashMap<Long, WeakReference<Node>>()
    override val root: Node

    class Node internal constructor(
        name: String, override val isDir: Boolean, attrs: Int,
        internal var firstCluster: Int, length: Long, internal var validLength: Long, internal var noFatChain: Boolean,
        mtime: Long, internal var parent: Node?, internal var entryPos: Long, internal var secondaryCount: Int,
    ) : FsNode {
        override var name = name; internal set
        var attrs = attrs; internal set
        override var length = length; internal set
        override var mtime = mtime; internal set
        internal var ctime = mtime
        internal var deleted = false
        override val isRoot get() = parent == null
        override val path: String get() = parent?.let { p -> (if (p.isRoot) "" else p.path) + "/" + name } ?: "/"
    }

    init {
        val boot = ByteArray(512); c.read(0, boot)
        if (String(boot, 3, 8, Charsets.US_ASCII) != "EXFAT   ") throw ExFatException("Not an exFAT volume")
        if (le16(boot, 510) != 0xAA55) throw ExFatException("Bad boot signature")
        val bpsShift = boot[108].toInt(); val spcShift = boot[109].toInt()
        if (bpsShift !in 9..12 || spcShift !in 0..(25 - bpsShift)) throw ExFatException("Bad geometry")
        if (boot[110].toInt() != 1) throw ExFatException("TexFAT (2 FATs) is not supported")
        bytesPerSector = 1 shl bpsShift
        clusterSize = 1 shl (bpsShift + spcShift)
        fatOffset = le32(boot, 80) shl bpsShift
        heapOffset = le32(boot, 88) shl bpsShift
        val cc = le32(boot, 92)
        if (cc > Int.MAX_VALUE - 16) throw ExFatException("Too many clusters")
        clusterCount = cc.toInt()
        rootCluster = le32(boot, 96).toInt()
        if (clusterSize % dev.sectorSize != 0) throw ExFatException("Cluster smaller than device sector")
        root = Node("", true, 0x10, rootCluster, 0, 0, false, 0, null, -1, 0)
        root.length = chain(root).size.toLong() * clusterSize
        root.validLength = root.length
        readRootMetadata()
    }

    private fun readRootMetadata() {
        val e = ByteArray(32)
        var p = 0L
        while (p < root.length) {
            readDir(root, p, e)
            when (e[0].toInt() and 0xff) {
                0x00 -> break
                0x81 -> {
                    bitmapCluster = le32(e, 20).toInt()
                    val len = le64(e, 24)
                    if (len < (clusterCount + 7) / 8) throw ExFatException("Bitmap too short")
                    bitmap = ByteArray(len.toInt())
                    readClusters(chainFrom(bitmapCluster, false, len), bitmap)
                }
                0x82 -> {
                    val len = le64(e, 24)
                    val raw = ByteArray(len.toInt())
                    readClusters(chainFrom(le32(e, 20).toInt(), false, len), raw)
                    var i = 0; var ch = 0
                    while (i + 1 < raw.size && ch < 65536) {
                        val v = le16(raw, i); i += 2
                        if (v == 0xFFFF && i + 1 < raw.size) { ch += le16(raw, i); i += 2 } else upcase[ch++] = v.toChar()
                    }
                }
                0x83 -> label = String(CharArray(e[1].toInt().coerceIn(0, 11)) { le16(e, 2 + 2 * it).toChar() })
            }
            p += 32
        }
        if (!::bitmap.isInitialized) throw ExFatException("No allocation bitmap")
        freeClusters = (0 until clusterCount).count { !used(it + 2) }.toLong()
    }

    // ---- clusters, FAT, bitmap ----

    private fun clusterPos(cl: Int) = heapOffset + (cl - 2).toLong() * clusterSize
    private fun used(cl: Int) = (bitmap[(cl - 2) ushr 3].toInt() shr ((cl - 2) and 7)) and 1 == 1

    private fun setUsed(cl: Int, v: Boolean) {
        val i = (cl - 2) ushr 3; val bit = 1 shl ((cl - 2) and 7)
        val old = bitmap[i].toInt()
        bitmap[i] = (if (v) old or bit else old and bit.inv()).toByte()
        if ((old and bit != 0) != v) freeClusters += if (v) -1 else 1
        c.write(clusterPos(bitmapCluster) + i, bitmap, i, 1)  // bitmap is contiguous (mkfs and we never move it)
    }

    private fun fat(cl: Int) = c.u32(fatOffset + 4L * cl)
    private fun setFat(cl: Int, v: Long) = c.putU32(fatOffset + 4L * cl, v)

    private fun valid(cl: Int) = cl >= 2 && cl < clusterCount + 2

    private fun chainFrom(first: Int, noFatChain: Boolean, length: Long): IntArray {
        if (first == 0) return IntArray(0)
        val n = ((length + clusterSize - 1) / clusterSize).toInt()
        if (noFatChain) return IntArray(n) { first + it }
        val out = ArrayList<Int>()
        var cl = first
        while (valid(cl)) {
            out.add(cl)
            if (out.size > clusterCount) throw ExFatException("FAT chain from $first loops")
            cl = fat(cl).toInt()
        }
        if (out.size < n) throw ExFatException("FAT chain from $first is shorter than the file")
        return out.toIntArray()
    }

    /** Allocated clusters: the FAT chain to its end, or ceil(length / clusterSize) for a NoFatChain run. */
    private fun chain(n: Node): IntArray = chains.getOrPut(n.firstCluster) {
        chainFrom(n.firstCluster, n.noFatChain, if (n.isRoot) 0 else n.length)
    }

    /** n clusters, preferring the run right after [after]; marked used. */
    private fun allocate(n: Int, after: Int): IntArray {
        if (n > freeClusters) throw ExFatException("No space left on the volume")
        val out = IntArray(n)
        var k = 0
        var cl = if (after != 0) after + 1 else nextFree + 2
        var scanned = 0L
        while (k < n) {
            if (!valid(cl)) cl = 2
            if (!used(cl)) { out[k++] = cl; setUsed(cl, true) }
            cl++
            if (++scanned > clusterCount.toLong() + 1) throw ExFatException("Bitmap and free count disagree")
        }
        nextFree = cl - 2
        return out
    }

    private fun free(cls: IntArray, from: Int, chained: Boolean) {
        for (i in from until cls.size) {
            setUsed(cls[i], false)
            if (chained) setFat(cls[i], 0)
            c.invalidate(clusterPos(cls[i]), clusterSize.toLong())
        }
        chains.clear()
    }

    /** Grows n's allocation to [need] clusters, keeping it contiguous (NoFatChain) while it can. */
    private fun ensureClusters(n: Node, need: Int, zero: Boolean) {
        val have = chain(n)
        if (have.size >= need) return
        val last = if (have.isEmpty()) 0 else have.last()
        val add = allocate(need - have.size, last)
        markDirty()
        val contiguous = add.indices.all { add[it] == (if (it == 0) (if (last == 0) add[0] else last + 1) else add[it - 1] + 1) }
        if (have.isEmpty()) {
            n.firstCluster = add[0]; n.noFatChain = contiguous && !n.isRoot
        } else if (n.noFatChain && !contiguous) {
            for (i in 0 until have.size - 1) setFat(have[i], have[i + 1].toLong())
            n.noFatChain = false
        }
        if (!n.noFatChain) {
            if (last != 0) setFat(last, add[0].toLong())
            for (i in add.indices) setFat(add[i], if (i + 1 < add.size) add[i + 1].toLong() else 0xFFFFFFFFL)
        }
        chains[n.firstCluster] = have + add
        if (zero) for (cl in add) c.zero(clusterPos(cl), clusterSize.toLong())
    }

    // ---- data I/O (bypasses the metadata cache) ----

    private fun readClusters(cls: IntArray, dst: ByteArray) {
        var o = 0
        for (cl in cls) { val n = minOf(clusterSize, dst.size - o); if (n <= 0) break; c.read(clusterPos(cl), dst, o, n); o += n }
    }

    private fun dataIo(n: Node, pos: Long, buf: ByteArray, off: Int, len: Int, write: Boolean) {
        val cls = chain(n)
        var p = pos; var o = off; var left = len
        while (left > 0) {
            val ci = (p / clusterSize).toInt()
            val inC = (p % clusterSize).toInt()
            // merge a run of consecutive clusters into one device call
            var run = 1
            while (ci + run < cls.size && cls[ci + run] == cls[ci] + run && run.toLong() * clusterSize - inC < left) run++
            val cnt = minOf(left.toLong(), run.toLong() * clusterSize - inC).toInt()
            rawIo(clusterPos(cls[ci]) + inC, buf, o, cnt, write)
            p += cnt; o += cnt; left -= cnt
        }
    }

    private fun rawIo(at: Long, buf: ByteArray, off: Int, len: Int, write: Boolean) {
        val u = dev.sectorSize
        val head = (at % u).toInt()
        if (head == 0 && len % u == 0) {
            if (write) dev.write(at, buf, off, len) else dev.read(at, buf, off, len)
            return
        }
        val start = at - head
        val span = ((head + len + u - 1) / u) * u
        // Bounce buffer for unaligned I/O; aligned middle pass-through if large unaligned writes get slow
        val b = ByteArray(span)
        if (!write || head != 0 || len % u != 0) dev.read(start, b, 0, span)
        if (write) { buf.copyInto(b, head, off, off + len); dev.write(start, b, 0, span) }
        else b.copyInto(buf, off, head, head + len)
    }

    // ---- directories ----

    private fun dirPos(dir: Node, p: Long): Long {
        val cls = chain(dir)
        val i = (p / clusterSize).toInt()
        if (i >= cls.size) throw ExFatException("Directory position $p past its end")
        return clusterPos(cls[i]) + p % clusterSize
    }

    private fun readDir(dir: Node, p: Long, dst: ByteArray, len: Int = dst.size) {
        var o = 0
        while (o < len) { val n = minOf(len - o, clusterSize - ((p + o) % clusterSize).toInt()); c.read(dirPos(dir, p + o), dst, o, n); o += n }
    }

    private fun writeDir(dir: Node, p: Long, src: ByteArray, len: Int = src.size) {
        var o = 0
        while (o < len) { val n = minOf(len - o, clusterSize - ((p + o) % clusterSize).toInt()); c.write(dirPos(dir, p + o), src, o, n); o += n }
    }

    private fun key(dir: Node, pos: Long) = (dir.firstCluster.toLong() shl 32) or pos

    @Synchronized
    override fun list(dir: FsNode): List<Node> {
        dir as Node
        check(dir.isDir && !dir.deleted)
        val out = ArrayList<Node>()
        val e = ByteArray(32)
        var p = 0L
        while (p < dir.length) {
            readDir(dir, p, e)
            val t = e[0].toInt() and 0xff
            if (t == 0) break
            if (t == 0x85) {
                val sc = e[1].toInt() and 0xff
                if (sc >= 2 && p + 32L * (sc + 1) <= dir.length) parseSet(dir, p, sc)?.let { out.add(it) }
                p += 32L * (sc + 1); continue
            }
            p += 32
        }
        return out
    }

    private fun parseSet(dir: Node, p: Long, sc: Int): Node? {
        nodes[key(dir, p)]?.get()?.let { if (!it.deleted) return it }
        val s = ByteArray(32 * (sc + 1)); readDir(dir, p, s)
        if (s[32].toInt() and 0xff != 0xC0) return null
        val nameLen = s[32 + 3].toInt() and 0xff
        val name = CharArray(nameLen)
        for (i in 0 until nameLen) {
            val e = 2 + i / 15; if (e > sc || s[32 * e].toInt() and 0xff != 0xC1) return null
            name[i] = le16(s, 32 * e + 2 + 2 * (i % 15)).toChar()
        }
        val attrs = le16(s, 4)
        val flags = s[33].toInt()
        val node = Node(String(name), attrs and 0x10 != 0, attrs, le32(s, 52).toInt(), le64(s, 56), le64(s, 40),
            flags and 2 != 0, decodeTime(le32(s, 12), s[21].toInt() and 0xff, s[23].toInt() and 0xff), dir, p, sc)
        node.ctime = decodeTime(le32(s, 8), s[20].toInt() and 0xff, s[22].toInt() and 0xff)
        nodes[key(dir, p)] = WeakReference(node)
        return node
    }

    @Synchronized
    override fun lookup(path: String): Node? {
        var n = root
        for (part in path.split('/').filter { it.isNotEmpty() }) {
            if (!n.isDir) return null
            n = find(n, part) ?: return null
        }
        return n
    }

    private fun up(s: String) = String(CharArray(s.length) { upcase[s[it].code] })

    private fun find(dir: Node, name: String): Node? { val u = up(name); return list(dir).firstOrNull { up(it.name) == u } }

    // ---- reading and writing files ----

    override fun parentOf(n: FsNode) = (n as Node).parent

    @Synchronized
    override fun read(n: FsNode, pos: Long, buf: ByteArray, off: Int, len: Int): Int {
        n as Node
        check(!n.isDir && !n.deleted)
        if (pos >= n.length) return if (len == 0) 0 else -1
        val cnt = minOf(len.toLong(), n.length - pos).toInt()
        val real = (minOf(pos + cnt, n.validLength) - pos).coerceAtLeast(0).toInt()
        if (real > 0) dataIo(n, pos, buf, off, real, false)
        java.util.Arrays.fill(buf, off + real, off + cnt, 0)
        return cnt
    }

    @Synchronized
    override fun write(n: FsNode, pos: Long, buf: ByteArray, off: Int, len: Int) {
        n as Node
        check(!n.isDir && !n.deleted)
        if (len == 0) return
        markDirty()
        val end = pos + len
        ensureClusters(n, ((end + clusterSize - 1) / clusterSize).toInt(), false)
        if (pos > n.validLength) zeroData(n, n.validLength, pos)
        dataIo(n, pos, buf, off, len, true)
        n.length = maxOf(n.length, end)
        n.validLength = maxOf(n.validLength, end)
        n.mtime = System.currentTimeMillis()
        writeEntry(n)
    }

    private fun zeroData(n: Node, from: Long, to: Long) {
        val z = ByteArray(minOf(to - from, 1L shl 20).toInt())
        var p = from
        while (p < to) { val k = minOf(to - p, z.size.toLong()).toInt(); dataIo(n, p, z, 0, k, true); p += k }
    }

    @Synchronized
    override fun truncate(n: FsNode, size: Long) {
        n as Node
        check(!n.isDir && !n.deleted && size >= 0)
        if (size == n.length) return
        markDirty()
        if (size > n.length) {
            ensureClusters(n, ((size + clusterSize - 1) / clusterSize).toInt(), false)
        } else {
            val keep = ((size + clusterSize - 1) / clusterSize).toInt()
            val cls = chain(n)
            free(cls, keep, !n.noFatChain)
            if (keep == 0) { n.firstCluster = 0; n.noFatChain = false }
            else if (!n.noFatChain) setFat(cls[keep - 1], 0xFFFFFFFFL)
            n.validLength = minOf(n.validLength, size)
        }
        n.length = size
        n.mtime = System.currentTimeMillis()
        writeEntry(n)
    }

    // ---- entry sets ----

    private fun buildSet(n: Node): ByteArray {
        val nameEntries = (n.name.length + 14) / 15
        val sc = 1 + nameEntries
        val s = ByteArray(32 * (sc + 1))
        s[0] = 0x85.toByte(); s[1] = sc.toByte()
        putLe16(s, 4, n.attrs)
        putTime(s, 8, 20, 22, n.ctime); putTime(s, 12, 21, 23, n.mtime); putTime(s, 16, -1, 24, n.mtime)
        s[32] = 0xC0.toByte()
        s[33] = (if (n.firstCluster != 0 || n.isDir) 1 or (if (n.noFatChain) 2 else 0) else 1).toByte()
        s[35] = n.name.length.toByte()
        putLe16(s, 36, nameHash(n.name))
        putLe64(s, 40, n.validLength)
        putLe32(s, 52, n.firstCluster.toLong())
        putLe64(s, 56, n.length)
        for (i in n.name.indices) {
            val e = 2 + i / 15
            s[32 * e] = 0xC1.toByte()
            putLe16(s, 32 * e + 2 + 2 * (i % 15), n.name[i].code)
        }
        for (e in 2..sc) s[32 * e] = 0xC1.toByte()
        putLe16(s, 2, setChecksum(s))
        return s
    }

    private fun writeEntry(n: Node) {
        if (n.isRoot) return
        val s = buildSet(n)
        check(s.size == 32 * (n.secondaryCount + 1))
        writeDir(n.parent!!, n.entryPos, s)
    }

    private fun nameHash(name: String): Int {
        var h = 0
        for (ch in up(name)) {
            h = (((h and 1) shl 15) or (h ushr 1)) + (ch.code and 0xff) and 0xffff
            h = (((h and 1) shl 15) or (h ushr 1)) + (ch.code ushr 8) and 0xffff
        }
        return h
    }

    private fun setChecksum(s: ByteArray): Int {
        var h = 0
        for (i in s.indices) { if (i == 2 || i == 3) continue; h = (((h and 1) shl 15) or (h ushr 1)) + (s[i].toInt() and 0xff) and 0xffff }
        return h
    }

    /** Position of a run of [count] unused entries in dir, growing the directory if needed. */
    private fun freeSlot(dir: Node, count: Int): Long {
        val e = ByteArray(32)
        var p = 0L; var runStart = -1L
        while (p < dir.length) {
            readDir(dir, p, e)
            val t = e[0].toInt() and 0xff
            if (t == 0) { if (runStart < 0) runStart = p; break }
            if (t and 0x80 == 0) { if (runStart < 0) runStart = p; if ((p + 32 - runStart) / 32 >= count) return runStart }
            else runStart = -1
            p += 32
        }
        if (runStart < 0) runStart = dir.length
        val needLen = runStart + 32L * count
        if (needLen > dir.length) {
            val need = ((needLen + clusterSize - 1) / clusterSize).toInt()
            if (need.toLong() * clusterSize > 256L * 1024 * 1024) throw ExFatException("Directory full")
            ensureClusters(dir, need, true)
            dir.length = need.toLong() * clusterSize; dir.validLength = dir.length
            writeEntry(dir)
        }
        return runStart
    }

    private fun checkName(name: String) {
        if (name.isEmpty() || name.length > 255 || name == "." || name == "..") throw ExFatException("Invalid name")
        if (name.any { it.code < 0x20 || it in "\"*/:<>?\\|" }) throw ExFatException("Name contains a character exFAT forbids")
    }

    @Synchronized
    override fun create(dir: FsNode, name: String, isDir: Boolean): Node {
        dir as Node
        check(dir.isDir && !dir.deleted)
        checkName(name)
        if (find(dir, name) != null) throw ExFatException("$name already exists")
        markDirty()
        val now = System.currentTimeMillis()
        val n = Node(name, isDir, if (isDir) 0x10 else 0x20, 0, 0, 0, false, now, dir, 0, 1 + (name.length + 14) / 15)
        if (isDir) {
            ensureClusters(n, 1, true)
            n.length = clusterSize.toLong(); n.validLength = n.length
        }
        n.entryPos = freeSlot(dir, n.secondaryCount + 1)
        writeDir(dir, n.entryPos, buildSet(n))
        nodes[key(dir, n.entryPos)] = WeakReference(n)
        dir.mtime = now; writeEntry(dir)
        return n
    }

    private fun removeSet(n: Node) {
        val dir = n.parent!!
        val s = ByteArray(32 * (n.secondaryCount + 1)); readDir(dir, n.entryPos, s)
        for (e in 0..n.secondaryCount) s[32 * e] = (s[32 * e].toInt() and 0x7f).toByte()
        writeDir(dir, n.entryPos, s)
        nodes.remove(key(dir, n.entryPos))
    }

    @Synchronized
    override fun delete(n: FsNode) {
        n as Node
        check(!n.isRoot && !n.deleted)
        if (n.isDir && list(n).isNotEmpty()) throw ExFatException("Directory not empty")
        markDirty()
        removeSet(n)
        free(chain(n), 0, !n.noFatChain)
        n.deleted = true
        n.parent!!.mtime = System.currentTimeMillis(); writeEntry(n.parent!!)
    }

    /** Moves and/or renames; the node keeps its data and identity. */
    @Synchronized
    override fun rename(n: FsNode, newDir: FsNode, newName: String) {
        n as Node; newDir as Node
        check(!n.isRoot && !n.deleted && newDir.isDir && !newDir.deleted)
        checkName(newName)
        var a: Node? = newDir
        while (a != null) { if (a === n) throw ExFatException("Can't move a directory into itself"); a = a.parent }
        val clash = find(newDir, newName)
        if (clash != null && clash !== n) throw ExFatException("$newName already exists")
        markDirty()
        removeSet(n)
        n.name = newName; n.parent = newDir
        n.secondaryCount = 1 + (newName.length + 14) / 15
        n.entryPos = freeSlot(newDir, n.secondaryCount + 1)
        writeDir(newDir, n.entryPos, buildSet(n))
        nodes[key(newDir, n.entryPos)] = WeakReference(n)
    }

    override fun info(): List<Pair<String, String>> {
        val boot = ByteArray(512); c.read(0, boot)
        return listOf(
            "Version" to "exFAT %d.%02d".format(boot[105].toInt(), boot[104].toInt()),
            "Serial" to "%04X-%04X".format(le16(boot, 102), le16(boot, 100)),
            "Cluster size" to "$clusterSize bytes",
            "Sector size" to "$bytesPerSector bytes",
        )
    }

    @Synchronized
    override fun setLabel(label: String) {
        require(label.length <= 11 && label.none { it.code < 0x20 }) { "exFAT labels are at most 11 characters" }
        markDirty()
        val e = ByteArray(32); e[0] = 0x83.toByte(); e[1] = label.length.toByte()
        for (i in label.indices) putLe16(e, 2 + 2 * i, label[i].code)
        // replace the existing label entry, else take a free slot in the root directory
        val cur = ByteArray(32)
        var p = 0L; var at = -1L
        while (p < root.length) {
            readDir(root, p, cur)
            val t = cur[0].toInt() and 0xff
            if (t == 0x83 || t == 0x03) { at = p; break }
            if (t == 0) break
            p += 32
        }
        if (at < 0) at = freeSlot(root, 1)
        writeDir(root, at, e)
        this.label = label
        flush()
    }

    // ---- volume state ----

    private fun markDirty() {
        if (dirty) return
        dirty = true
        setVolumeDirty(true)
        c.flush()
    }

    private fun setVolumeDirty(v: Boolean) {
        val b = ByteArray(2); c.read(106, b)
        putLe16(b, 0, if (v) le16(b, 0) or 2 else le16(b, 0) and 2.inv())
        c.write(106, b)
    }

    @Synchronized
    override fun flush() {
        if (!dirty) return
        c.flush()
        setVolumeDirty(false)
        c.flush()
        dirty = false
    }

    override val totalBytes get() = clusterCount.toLong() * clusterSize
    override val freeBytes get() = freeClusters * clusterSize

    override fun close() { flush(); dev.close() }

    companion object {
        fun mount(dev: BlockDevice) = ExFat(dev)

        private fun decodeTime(ts: Long, ms10: Int, utcOff: Int): Long {
            if (ts == 0L) return 0
            val dt = runCatching {
                LocalDateTime.of(((ts ushr 25) and 0x7f).toInt() + 1980, ((ts ushr 21) and 0xf).toInt(), ((ts ushr 16) and 0x1f).toInt(),
                    ((ts ushr 11) and 0x1f).toInt(), ((ts ushr 5) and 0x3f).toInt(), ((ts and 0x1f) * 2).toInt())
            }.getOrNull() ?: return 0
            val offMin = if (utcOff and 0x80 != 0) ((utcOff shl 25) shr 25) * 15 else 0
            return dt.toInstant(ZoneOffset.ofTotalSeconds(offMin * 60)).toEpochMilli() + ms10 * 10L
        }

        /** Stores UTC with the offset field marked valid (+00:00). */
        private fun putTime(s: ByteArray, at: Int, ms10At: Int, offAt: Int, ms: Long) {
            val t = LocalDateTime.ofInstant(Instant.ofEpochMilli(maxOf(ms, 315532800000L)), ZoneOffset.UTC)
            val v = ((t.year - 1980).toLong() shl 25) or (t.monthValue.toLong() shl 21) or (t.dayOfMonth.toLong() shl 16) or
                (t.hour.toLong() shl 11) or (t.minute.toLong() shl 5) or (t.second / 2).toLong()
            putLe32(s, at, v)
            if (ms10At >= 0) s[ms10At] = ((t.second % 2) * 100 + t.nano / 10_000_000).toByte()
            s[offAt] = 0x80.toByte()
        }
    }
}
