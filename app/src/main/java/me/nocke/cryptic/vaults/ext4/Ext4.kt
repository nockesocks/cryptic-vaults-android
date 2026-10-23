package me.nocke.cryptic.vaults.ext4

import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.exfat.SectorCache
import me.nocke.cryptic.vaults.fs.FileSystem
import me.nocke.cryptic.vaults.fs.FsNode
import me.nocke.cryptic.vaults.fs.readBytes
import me.nocke.cryptic.vaults.fs.writeBytes
import java.io.IOException
import java.security.SecureRandom

class Ext4Exception(msg: String) : IOException(msg)

/**
 * ext4 driver (kernel.org ext4 disk layout) over a BlockDevice. Reads ext2/3/4 (extents and block maps);
 * writes ext4 with extents, keeping metadata_csum checksums, bitmaps and counters exact for e2fsck.
 * Writes bypass the journal: the volume is marked not-clean while dirty, so an unplug mid-write is
 * repaired by e2fsck rather than replayed. A journal Linux left behind is replayed at mount ([Jbd2]). Indexed (htree) directories are flattened to linear ones
 * when changed; the kernel and e2fsck accept both.
 * One lock for the volume; extent trees are rebuilt whole when a file's mapping changes.
 */
class Ext4 private constructor(private val dev: BlockDevice, private val replayError: String? = null) : FileSystem {
    private val c = SectorCache(dev)
    private val sb = ByteArray(1024)
    val blockSize: Int
    private val blocksCount: Long
    private val firstDataBlock: Long
    private val blocksPerGroup: Int
    private val inodesPerGroup: Int
    private val inodeSize: Int
    private val groupCount: Int
    private val descSize: Int
    private val compat: Int
    private val incompat: Int
    private val roCompat: Int
    private val csum: Boolean
    private val csumSeed: Int
    private val firstIno: Int
    private val inodeTableBlocks: Int
    private val gdtBlocks: Int
    private val reservedGdt: Int
    override val readOnlyReason: String?
    override val type = "ext4"
    private var currentLabel = ""
    override val label: String get() = currentLabel
    override val root: Node
    private var dirtyState = false
    private val dirtyGroups = HashSet<Int>()
    private val rnd = SecureRandom()

    inner class Node internal constructor(internal val ino: Int, override val name: String, internal val parent: Node?) : FsNode {
        override val isDir get() = isDirMode(inode(ino).mode)
        override val length get() = inode(ino).size
        override val mtime get() = inode(ino).mtime
        override val isRoot get() = parent == null
        override val path: String get() = parent?.let { p -> (if (p.isRoot) "" else p.path) + "/" + name } ?: "/"
    }

    init {
        c.read(1024, sb)
        if (u16(sb, 0x38) != 0xEF53) throw Ext4Exception("Not an ext2/3/4 volume")
        blockSize = 1024 shl u32(sb, 0x18).toInt()
        if (blockSize !in listOf(1024, 2048, 4096, 8192, 16384, 32768, 65536)) throw Ext4Exception("Bad block size")
        compat = u32(sb, 0x5C).toInt(); incompat = u32(sb, 0x60).toInt(); roCompat = u32(sb, 0x64).toInt()
        val unknownIncompat = incompat and (INCOMPAT_FILETYPE or INCOMPAT_RECOVER or INCOMPAT_META_BG or INCOMPAT_EXTENTS or
            INCOMPAT_64BIT or INCOMPAT_FLEX_BG or INCOMPAT_CSUM_SEED or INCOMPAT_LARGEDIR or INCOMPAT_INLINE_DATA or INCOMPAT_MMP).inv()
        if (unknownIncompat != 0) throw Ext4Exception("Unsupported ext4 features (0x%x: encryption, casefold or similar)".format(unknownIncompat))
        blocksCount = u32(sb, 0x04) or (if (incompat and INCOMPAT_64BIT != 0) u32(sb, 0x150) shl 32 else 0)
        firstDataBlock = u32(sb, 0x14)
        blocksPerGroup = u32(sb, 0x20).toInt()
        inodesPerGroup = u32(sb, 0x28).toInt()
        inodeSize = if (u32(sb, 0x4C) == 0L) 128 else u16(sb, 0x58)
        firstIno = if (u32(sb, 0x4C) == 0L) 11 else u32(sb, 0x54).toInt()
        descSize = if (incompat and INCOMPAT_64BIT != 0) u16(sb, 0xFE) else 32
        groupCount = ((blocksCount - firstDataBlock + blocksPerGroup - 1) / blocksPerGroup).toInt()
        csum = roCompat and RO_METADATA_CSUM != 0
        csumSeed = if (incompat and INCOMPAT_CSUM_SEED != 0) u32(sb, 0x270).toInt() else Crc32c.update(-1, sb, 0x68, 16)
        inodeTableBlocks = (inodesPerGroup * inodeSize + blockSize - 1) / blockSize
        gdtBlocks = ((groupCount.toLong() * descSize + blockSize - 1) / blockSize).toInt()
        reservedGdt = if (compat and COMPAT_RESIZE_INODE != 0) u16(sb, 0xCE) else 0
        currentLabel = String(sb, 0x78, 16, Charsets.UTF_8).trimEnd('\u0000')
        if (blockSize % dev.sectorSize != 0 && dev.sectorSize % blockSize != 0) throw Ext4Exception("Block size doesn't fit the device")
        if (blocksCount * blockSize > dev.size + blockSize) throw Ext4Exception("ext4 is larger than its device")
        readOnlyReason = writeBlocker()
        root = Node(2, "", null)
    }

    private fun writeBlocker(): String? {
        val state = u16(sb, 0x3A)
        return when {
            replayError != null -> "its journal could not be replayed ($replayError): mount it once on Linux"
            incompat and INCOMPAT_RECOVER != 0 -> "its journal needs recovery: mount it once on Linux"
            state and 2 != 0 -> "it has errors: run e2fsck on Linux"
            roCompat and RO_ORPHAN_PRESENT != 0 || u32(sb, 0xE8) != 0L -> "it has orphan inodes: mount it once on Linux"
            incompat and INCOMPAT_EXTENTS == 0 -> "it is ext2/ext3 (no extents)"
            incompat and (INCOMPAT_META_BG or INCOMPAT_INLINE_DATA or INCOMPAT_MMP) != 0 -> "it uses meta_bg, inline data or MMP"
            roCompat and (RO_GDT_CSUM.inv() and RO_KNOWN).inv() != 0 -> "it uses read-only-compatible features this app doesn't write"
            roCompat and RO_GDT_CSUM != 0 && !csum -> "it uses the old uninit_bg checksums"
            compat and COMPAT_SPARSE_SUPER2 != 0 -> "it uses sparse_super2"
            u32(sb, 0x1C) != u32(sb, 0x18) -> "it uses bigalloc"
            else -> null
        }
    }

    // ---- low level ----

    private fun descPos(g: Int) = (firstDataBlock + 1) * blockSize + g.toLong() * descSize
    private fun desc(g: Int) = ByteArray(descSize).also { c.read(descPos(g), it) }
    private fun lohi(d: ByteArray, lo: Int, hi: Int, wide: Int) =
        (if (wide == 4) u32(d, lo) else u16(d, lo).toLong()) or (if (descSize >= 64) (if (wide == 4) u32(d, hi) else u16(d, hi).toLong()) shl (8 * wide) else 0)
    private fun putLohi(d: ByteArray, lo: Int, hi: Int, wide: Int, v: Long) {
        if (wide == 4) put32(d, lo, v) else put16(d, lo, v.toInt())
        if (descSize >= 64) { if (wide == 4) put32(d, hi, v ushr 32) else put16(d, hi, (v ushr 16).toInt()) }
    }
    private fun blockBitmap(d: ByteArray) = lohi(d, 0x00, 0x20, 4)
    private fun inodeBitmap(d: ByteArray) = lohi(d, 0x04, 0x24, 4)
    private fun inodeTable(d: ByteArray) = lohi(d, 0x08, 0x28, 4)
    private fun groupStart(g: Int) = firstDataBlock + g.toLong() * blocksPerGroup
    private fun groupBlocks(g: Int) = minOf(blocksPerGroup.toLong(), blocksCount - groupStart(g)).toInt()

    private fun hasSuper(g: Int): Boolean {
        if (g == 0 || roCompat and RO_SPARSE_SUPER == 0) return true
        if (g == 1) return true
        for (p in intArrayOf(3, 5, 7)) { var x = p; while (x < g) x *= p; if (x == g) return true }
        return false
    }

    // ---- inodes ----

    internal inner class Inode(val ino: Int, val raw: ByteArray) {
        val mode get() = u16(raw, 0x00)
        var size: Long
            get() = u32(raw, 0x04) or (u32(raw, 0x6C) shl 32)
            set(v) { put32(raw, 0x04, v); put32(raw, 0x6C, v ushr 32) }
        val flags get() = u32(raw, 0x20).toInt()
        var links: Int
            get() = u16(raw, 0x1A)
            set(v) = put16(raw, 0x1A, v)
        val mtime get() = u32(raw, 0x10) * 1000 + (if (inodeSize > 128 && extra >= 0x0C) (u32(raw, 0x88) ushr 2) / 1_000_000 else 0)
        val extra get() = if (inodeSize > 128) u16(raw, 0x80) else 0
        val generation get() = u32(raw, 0x64).toInt()
        val fileAcl get() = u32(raw, 0x68) or (u32(raw, 0x76).and(0xffff) shl 32)
        val extents get() = flags and FL_EXTENTS != 0
        fun seed() = Crc32c.le32(Crc32c.le32(csumSeed, ino), generation)
    }

    private fun inodePos(ino: Int): Long {
        val g = (ino - 1) / inodesPerGroup; val i = (ino - 1) % inodesPerGroup
        return inodeTable(desc(g)) * blockSize + i.toLong() * inodeSize
    }

    internal fun inode(ino: Int): Inode {
        if (ino < 1 || ino > inodesPerGroup.toLong() * groupCount) throw Ext4Exception("Bad inode number $ino")
        return Inode(ino, ByteArray(inodeSize).also { c.read(inodePos(ino), it) })
    }

    private fun writeInode(n: Inode) {
        if (csum) {
            put16(n.raw, 0x7C, 0)
            val hasHi = inodeSize > 128 && n.extra >= 4
            if (hasHi) put16(n.raw, 0x82, 0)
            var crc = Crc32c.update(n.seed(), n.raw)
            put16(n.raw, 0x7C, crc and 0xffff)
            if (hasHi) put16(n.raw, 0x82, crc ushr 16)
        }
        c.write(inodePos(n.ino), n.raw)
    }

    private fun setTimes(n: Inode, m: Boolean = true, ct: Boolean = true) {
        val now = System.currentTimeMillis()
        val s = now / 1000; val ns = (now % 1000) * 1_000_000
        val ext = (ns shl 2) or ((s ushr 32) and 3)
        if (m) { put32(n.raw, 0x10, s); if (n.extra >= 0x0C) put32(n.raw, 0x88, ext) }
        if (ct) { put32(n.raw, 0x0C, s); if (n.extra >= 0x08) put32(n.raw, 0x84, ext) }
    }

    // ---- block mapping ----

    internal class Ext(val lblk: Long, val pblk: Long, val len: Int, val uninit: Boolean)

    /** The file's extents (sorted) and the tree's index/leaf blocks. */
    private fun extentMap(n: Inode): Pair<List<Ext>, List<Long>> {
        val out = ArrayList<Ext>(); val tree = ArrayList<Long>()
        fun node(b: ByteArray, off: Int, depthLeft: Int) {
            if (u16(b, off) != 0xF30A) throw Ext4Exception("Bad extent header in inode ${n.ino}")
            val entries = u16(b, off + 2); val depth = u16(b, off + 6)
            if (depth != depthLeft && depthLeft >= 0) throw Ext4Exception("Bad extent tree depth in inode ${n.ino}")
            for (i in 0 until entries) {
                val e = off + 12 + 12 * i
                if (depth == 0) {
                    val raw = u16(b, e + 4)
                    out.add(Ext(u32(b, e), (u16(b, e + 6).toLong() shl 32) or u32(b, e + 8), if (raw > 32768) raw - 32768 else raw, raw > 32768))
                } else {
                    val child = (u16(b, e + 8).toLong() shl 32) or u32(b, e + 4)
                    tree.add(child)
                    val blk = ByteArray(blockSize); c.read(child * blockSize, blk)
                    node(blk, 0, depth - 1)
                }
            }
        }
        node(n.raw, 0x28, -1)
        return out to tree
    }

    /** Old block-mapped file: physical block of logical [l] (0 = hole), and every indirect block. */
    private fun blockMap(n: Inode): Pair<LongArray, List<Long>> {
        val nBlocks = ((n.size + blockSize - 1) / blockSize).toInt()
        val map = LongArray(nBlocks); val ind = ArrayList<Long>()
        val per = blockSize / 4
        var l = 0
        fun walk(blk: Long, level: Int) {
            if (l >= nBlocks) return
            if (blk == 0L) { l += Math.pow(per.toDouble(), level.toDouble()).toInt().coerceAtMost(nBlocks - l); return }
            if (level == 0) { map[l++] = blk; return }
            ind.add(blk)
            val b = ByteArray(blockSize); c.read(blk * blockSize, b)
            for (i in 0 until per) { if (l >= nBlocks) break; walk(u32(b, 4 * i), level - 1) }
        }
        for (i in 0 until 12) { if (l >= nBlocks) break; walk(u32(n.raw, 0x28 + 4 * i), 0) }
        for (lv in 1..3) walk(u32(n.raw, 0x28 + 4 * (11 + lv)), lv)
        return map to ind
    }

    // ---- reading ----

    @Synchronized
    override fun list(dir: FsNode): List<FsNode> {
        val d = dir as Node
        val out = ArrayList<FsNode>()
        forEachEntry(inode(d.ino)) { _, _, ino, name, type ->
            if (name != "." && name != ".." && (type == FT_REG || type == FT_DIR || (type == FT_UNKNOWN && regOrDir(ino)))) out.add(Node(ino, name, d))
            false
        }
        return out
    }

    private fun regOrDir(ino: Int) = inode(ino).mode.let { isDirMode(it) || it and 0xF000 == 0x8000 }

    /** Calls f(blockIndex, offsetInBlock, inode, name, fileType) for each live entry; stops when f returns true. */
    private fun forEachEntry(dir: Inode, f: (Long, Int, Int, String, Int) -> Boolean) {
        val nb = dir.size / blockSize
        val b = ByteArray(blockSize)
        for (l in 0 until nb) {
            readLogical(dir, l, b)
            var o = 0
            while (o + 8 <= blockSize) {
                val ino = u32(b, o).toInt(); val rec = u16(b, o + 4); val nl = b[o + 6].toInt() and 0xff
                if (rec < 8 || o + rec > blockSize) break
                if (ino != 0 && nl > 0) {
                    val type = if (incompat and INCOMPAT_FILETYPE != 0) b[o + 7].toInt() and 0xff else FT_UNKNOWN
                    if (f(l, o, ino, String(b, o + 8, nl, Charsets.UTF_8), type)) return
                }
                o += rec
            }
        }
    }

    private fun physOf(n: Inode, l: Long): Long {
        if (n.extents) {
            for (e in extentMap(n).first) if (l >= e.lblk && l < e.lblk + e.len) return if (e.uninit) 0 else e.pblk + (l - e.lblk)
            return 0
        }
        val m = blockMap(n).first
        return if (l < m.size) m[l.toInt()] else 0
    }

    /** One logical block through the metadata cache (directories); zeros for holes. */
    private fun readLogical(n: Inode, l: Long, b: ByteArray) {
        val p = physOf(n, l)
        if (p == 0L) java.util.Arrays.fill(b, 0) else c.read(p * blockSize, b)
    }

    @Synchronized
    override fun lookup(path: String): FsNode? {
        var n = root
        for (part in path.split('/').filter { it.isNotEmpty() }) {
            if (!n.isDir) return null
            n = find(n, part) ?: return null
        }
        return n
    }

    private fun find(dir: Node, name: String): Node? {
        var hit: Node? = null
        forEachEntry(inode(dir.ino)) { _, _, ino, nm, _ -> if (nm == name) { hit = Node(ino, nm, dir); true } else false }
        return hit
    }

    override fun parentOf(n: FsNode) = (n as Node).parent

    @Synchronized
    override fun read(n: FsNode, pos: Long, buf: ByteArray, off: Int, len: Int): Int {
        val ino = inode((n as Node).ino)
        if (isDirMode(ino.mode)) throw Ext4Exception("Is a directory")
        if (pos >= ino.size) return if (len == 0) 0 else -1
        val cnt = minOf(len.toLong(), ino.size - pos).toInt()
        java.util.Arrays.fill(buf, off, off + cnt, 0)
        val map: (Long) -> Long
        if (ino.extents) {
            val exts = extentMap(ino).first
            map = { l -> exts.firstOrNull { l >= it.lblk && l < it.lblk + it.len }?.let { if (it.uninit) 0 else it.pblk + (l - it.lblk) } ?: 0 }
        } else { val m = blockMap(ino).first; map = { l -> if (l < m.size) m[l.toInt()] else 0 } }
        var p = pos; var o = off; var left = cnt
        while (left > 0) {
            val l = p / blockSize; val inB = (p % blockSize).toInt()
            val first = map(l)
            var run = 1  // merge physically contiguous blocks
            while (first != 0L && run.toLong() * blockSize - inB < left && map(l + run) == first + run) run++
            val k = minOf(left.toLong(), run.toLong() * blockSize - inB).toInt()
            if (first != 0L) dev.readBytes(first * blockSize + inB, buf, o, k)
            p += k; o += k; left -= k
        }
        return cnt
    }

    // ---- allocation ----

    private fun requireWritable() { readOnlyReason?.let { throw Ext4Exception("Read-only: $it") } }

    private fun markDirty() {
        if (dirtyState) return
        put16(sb, 0x3A, u16(sb, 0x3A) and 1.inv())   // not cleanly unmounted until flush
        writeSuper(); c.flush()
        dirtyState = true                            // only once the drive has taken the write
    }

    private fun writeSuper() {
        put32(sb, 0x30, System.currentTimeMillis() / 1000)
        if (csum) put32(sb, 0x3FC, Crc32c.update(-1, sb, 0, 0x3FC).toLong() and 0xffffffffL)
        c.write(1024, sb)
    }

    private fun bitmapBytes() = blocksPerGroup / 8

    /** The group's block bitmap block, initializing a BLOCK_UNINIT group the way the kernel does. */
    private fun blockBitmapPos(g: Int): Long {
        val d = desc(g)
        val pos = blockBitmap(d) * blockSize
        if (u16(d, 0x12) and BG_BLOCK_UNINIT != 0) {
            val bm = ByteArray(blockSize)
            fun mark(b: Long) { val r = b - groupStart(g); if (r >= 0 && r < blocksPerGroup) bm[(r / 8).toInt()] = (bm[(r / 8).toInt()].toInt() or (1 shl (r % 8).toInt())).toByte() }
            if (hasSuper(g)) for (i in 0 until 1 + gdtBlocks + reservedGdt) mark(groupStart(g) + i)
            for (h in 0 until groupCount) {
                val dh = desc(h)
                mark(blockBitmap(dh)); mark(inodeBitmap(dh))
                val t = inodeTable(dh); for (i in 0 until inodeTableBlocks) mark(t + i)
            }
            for (r in groupBlocks(g) until blockSize * 8) bm[r / 8] = (bm[r / 8].toInt() or (1 shl (r % 8))).toByte()
            c.write(pos, bm)
            put16(d, 0x12, u16(d, 0x12) and BG_BLOCK_UNINIT.inv()); c.write(descPos(g), d)
            dirtyGroups.add(g)
        }
        return pos
    }

    private fun inodeBitmapPos(g: Int): Long {
        val d = desc(g)
        val pos = inodeBitmap(d) * blockSize
        if (u16(d, 0x12) and BG_INODE_UNINIT != 0) {
            val bm = ByteArray(blockSize)
            for (r in inodesPerGroup until blockSize * 8) bm[r / 8] = (bm[r / 8].toInt() or (1 shl (r % 8))).toByte()
            c.write(pos, bm)
            put16(d, 0x12, u16(d, 0x12) and BG_INODE_UNINIT.inv()); c.write(descPos(g), d)
            dirtyGroups.add(g)
        }
        return pos
    }

    private fun freeBlocksTotal() = u32(sb, 0x0C) or (if (incompat and INCOMPAT_64BIT != 0) u32(sb, 0x158) shl 32 else 0)
    private fun setFreeBlocksTotal(v: Long) { put32(sb, 0x0C, v); if (incompat and INCOMPAT_64BIT != 0) put32(sb, 0x158, v ushr 32) }
    private fun adjGroup(g: Int, freeBlocks: Long = 0, freeInodes: Long = 0, dirs: Long = 0) {
        val d = desc(g)
        if (freeBlocks != 0L) putLohi(d, 0x0C, 0x2C, 2, lohi(d, 0x0C, 0x2C, 2) + freeBlocks)
        if (freeInodes != 0L) putLohi(d, 0x0E, 0x2E, 2, lohi(d, 0x0E, 0x2E, 2) + freeInodes)
        if (dirs != 0L) putLohi(d, 0x10, 0x30, 2, lohi(d, 0x10, 0x30, 2) + dirs)
        c.write(descPos(g), d)
        dirtyGroups.add(g)
        if (freeBlocks != 0L) setFreeBlocksTotal(freeBlocksTotal() + freeBlocks)
        if (freeInodes != 0L) put32(sb, 0x10, u32(sb, 0x10) + freeInodes)
    }

    /** [count] blocks as contiguous runs, searching from [goal] onwards and wrapping around. */
    private fun allocBlocks(count: Int, goal: Long): List<Pair<Long, Int>> {
        if (count > freeBlocksTotal()) throw Ext4Exception("No space left on the volume")
        val runs = ArrayList<Pair<Long, Int>>()
        var need = count
        val g0 = ((goal.coerceIn(firstDataBlock, blocksCount - 1) - firstDataBlock) / blocksPerGroup).toInt()
        for (k in 0..groupCount) {               // k == groupCount revisits the goal group from its start
            val g = (g0 + k) % groupCount
            if (lohi(desc(g), 0x0C, 0x2C, 2) == 0L) continue
            val pos = blockBitmapPos(g)
            val bm = ByteArray(blockSize); c.read(pos, bm)
            var r = if (k == 0) (goal - groupStart(g)).coerceIn(0, groupBlocks(g).toLong() - 1).toInt() else 0
            var took = 0
            while (need > 0 && r < groupBlocks(g)) {
                if (bm[r / 8].toInt() shr (r % 8) and 1 == 0) {
                    bm[r / 8] = (bm[r / 8].toInt() or (1 shl (r % 8))).toByte()
                    val b = groupStart(g) + r
                    val last = runs.lastOrNull()
                    if (last != null && last.first + last.second == b) runs[runs.size - 1] = last.first to last.second + 1 else runs.add(b to 1)
                    need--; took++
                }
                r++
            }
            if (took > 0) { c.write(pos, bm); adjGroup(g, freeBlocks = -took.toLong()) }
            if (need == 0) return runs
        }
        throw Ext4Exception("No space left on the volume (counters disagree with bitmaps)")
    }

    private fun freeBlocks(start: Long, len: Long) {
        var b = start; val end = start + len
        while (b < end) {
            val g = ((b - firstDataBlock) / blocksPerGroup).toInt()
            val pos = blockBitmapPos(g)
            val bm = ByteArray(blockSize); c.read(pos, bm)
            var freed = 0L
            while (b < end && ((b - firstDataBlock) / blocksPerGroup).toInt() == g) {
                val r = (b - groupStart(g)).toInt()
                if (bm[r / 8].toInt() shr (r % 8) and 1 == 0) throw Ext4Exception("Freeing free block $b")
                bm[r / 8] = (bm[r / 8].toInt() and (1 shl (r % 8)).inv()).toByte()
                c.invalidate(b * blockSize, blockSize.toLong())
                b++; freed++
            }
            c.write(pos, bm); adjGroup(g, freeBlocks = freed)
        }
    }

    private fun allocInode(dir: Boolean, nearGroup: Int): Int {
        if (u32(sb, 0x10) == 0L) throw Ext4Exception("No free inodes")
        for (k in 0 until groupCount) {
            val g = (nearGroup + k) % groupCount
            if (lohi(desc(g), 0x0E, 0x2E, 2) == 0L) continue
            val pos = inodeBitmapPos(g)
            val bm = ByteArray(blockSize); c.read(pos, bm)
            val start = if (g == 0) firstIno - 1 else 0
            for (i in start until inodesPerGroup) {
                if (bm[i / 8].toInt() shr (i % 8) and 1 == 0) {
                    bm[i / 8] = (bm[i / 8].toInt() or (1 shl (i % 8))).toByte()
                    c.write(pos, bm)
                    adjGroup(g, freeInodes = -1, dirs = if (dir) 1 else 0)
                    val d = desc(g)
                    val unused = lohi(d, 0x1C, 0x32, 2)
                    if (i >= inodesPerGroup - unused) { putLohi(d, 0x1C, 0x32, 2, (inodesPerGroup - i - 1).toLong()); c.write(descPos(g), d) }
                    return g * inodesPerGroup + i + 1
                }
            }
        }
        throw Ext4Exception("No free inodes (counters disagree with bitmaps)")
    }

    private fun freeInode(ino: Int, dir: Boolean) {
        val g = (ino - 1) / inodesPerGroup; val i = (ino - 1) % inodesPerGroup
        val pos = inodeBitmapPos(g)
        val bm = ByteArray(blockSize); c.read(pos, bm)
        bm[i / 8] = (bm[i / 8].toInt() and (1 shl (i % 8)).inv()).toByte()
        c.write(pos, bm)
        adjGroup(g, freeInodes = 1, dirs = if (dir) -1 else 0)
    }

    // ---- extent trees ----

    /** Rewrites the inode's extent tree from [exts] (any order, mergeable); frees the old tree's blocks. */
    private fun writeExtents(n: Inode, exts: List<Ext>) {
        for (b in extentMap(n).second) freeBlocks(b, 1)
        val list = normalize(exts)
        val perBlock = (blockSize - 12) / 12
        var entries: List<Pair<Long, ByteArray>> = list.map { it.lblk to leafEntry(it) }
        var depth = 0
        var treeBlocks = 0L
        while (entries.size > 4) {
            val nodes = entries.chunked(perBlock)
            val blocks = allocBlocks(nodes.size, list.first().pblk).flatMap { (s, l) -> (0 until l).map { s + it } }
            treeBlocks += blocks.size
            entries = nodes.mapIndexed { i, node ->
                val b = ByteArray(blockSize)
                header(b, 0, node.size, perBlock, depth)
                node.forEachIndexed { k, (_, e) -> e.copyInto(b, 12 + 12 * k) }
                if (csum) put32(b, 12 + 12 * perBlock, Crc32c.update(n.seed(), b, 0, 12 + 12 * perBlock).toLong() and 0xffffffffL)
                c.write(blocks[i] * blockSize, b)
                node.first().first to indexEntry(node.first().first, blocks[i])
            }
            depth++
        }
        java.util.Arrays.fill(n.raw, 0x28, 0x28 + 60, 0)
        header(n.raw, 0x28, entries.size, 4, depth)
        entries.forEachIndexed { k, (_, e) -> e.copyInto(n.raw, 0x28 + 12 + 12 * k) }
        setBlocks(n, list.sumOf { it.len.toLong() } + treeBlocks + (if (n.fileAcl != 0L) 1 else 0))
    }

    private fun setBlocks(n: Inode, fsBlocks: Long) {
        val sectors = fsBlocks * (blockSize / 512)
        put32(n.raw, 0x1C, sectors); put16(n.raw, 0x74, (sectors ushr 32).toInt())
    }

    private fun normalize(exts: List<Ext>): List<Ext> {
        val out = ArrayList<Ext>()
        for (e in exts.sortedBy { it.lblk }) {
            val last = out.lastOrNull()
            val max = if (e.uninit) 32767 else 32768
            if (last != null && last.uninit == e.uninit && last.lblk + last.len == e.lblk && last.pblk + last.len == e.pblk && last.len + e.len <= max)
                out[out.size - 1] = Ext(last.lblk, last.pblk, last.len + e.len, e.uninit)
            else {
                var l = e.lblk; var p = e.pblk; var left = e.len
                while (left > 0) { val k = minOf(left, max); out.add(Ext(l, p, k, e.uninit)); l += k; p += k; left -= k }
            }
        }
        return out
    }

    private fun header(b: ByteArray, o: Int, entries: Int, max: Int, depth: Int) {
        put16(b, o, 0xF30A); put16(b, o + 2, entries); put16(b, o + 4, max); put16(b, o + 6, depth); put32(b, o + 8, 0)
    }

    private fun leafEntry(e: Ext) = ByteArray(12).also {
        put32(it, 0, e.lblk); put16(it, 4, if (e.uninit) e.len + 32768 else e.len)
        put16(it, 6, (e.pblk ushr 32).toInt()); put32(it, 8, e.pblk)
    }

    private fun indexEntry(lblk: Long, blk: Long) = ByteArray(12).also {
        put32(it, 0, lblk); put32(it, 4, blk); put16(it, 8, (blk ushr 32).toInt())
    }

    /** Maps logical blocks [from, to] to initialized blocks, allocating holes and converting uninit extents. */
    private fun mapRange(n: Inode, from: Long, to: Long): List<Ext> {
        val exts = extentMap(n).first.toMutableList()
        val out = ArrayList<Ext>()
        var changed = false
        // split extents around the range and turn uninit parts inside it into initialized ones
        for (e in exts) {
            val a = e.lblk; val z = e.lblk + e.len - 1
            if (!e.uninit || z < from || a > to) { out.add(e); continue }
            changed = true
            if (a < from) out.add(Ext(a, e.pblk, (from - a).toInt(), true))
            val s = maxOf(a, from); val t = minOf(z, to)
            // the block content is logically zero: write zeros so the newly initialized blocks read as such
            zeroBlocks(e.pblk + (s - a), t - s + 1)
            out.add(Ext(s, e.pblk + (s - a), (t - s + 1).toInt(), false))
            if (z > to) out.add(Ext(to + 1, e.pblk + (to + 1 - a), (z - to).toInt(), true))
        }
        // holes inside the range
        val sorted = out.sortedBy { it.lblk }
        var l = from
        val holes = ArrayList<Pair<Long, Long>>()
        for (e in sorted) {
            if (e.lblk + e.len <= l) continue
            if (e.lblk > to) break
            if (e.lblk > l) holes.add(l to minOf(e.lblk - 1, to))
            l = e.lblk + e.len
        }
        if (l <= to) holes.add(l to to)
        for ((hs, he) in holes) {
            changed = true
            val goal = sorted.lastOrNull { it.lblk < hs }?.let { it.pblk + (hs - it.lblk) }
                ?: (groupStart((n.ino - 1) / inodesPerGroup) + 0)
            var lb = hs
            for ((p, k) in allocBlocks((he - hs + 1).toInt(), goal)) { out.add(Ext(lb, p, k, false)); lb += k }
        }
        if (changed) writeExtents(n, out)
        return if (changed) normalize(out) else sorted
    }

    private fun zeroBlocks(p: Long, count: Long) {
        val z = ByteArray(blockSize * minOf(count, 256L).toInt())
        var b = p; var left = count
        while (left > 0) { val k = minOf(left, 256L).toInt(); dev.writeBytes(b * blockSize, z, 0, k * blockSize); b += k; left -= k }
    }

    // ---- writing files ----

    @Synchronized
    override fun write(n: FsNode, pos: Long, buf: ByteArray, off: Int, len: Int) {
        requireWritable()
        if (len == 0) return
        val ino = inode((n as Node).ino)
        if (isDirMode(ino.mode)) throw Ext4Exception("Is a directory")
        if (!ino.extents) throw Ext4Exception("This file uses old block maps (ext3): read-only")
        if (ino.flags and FL_HUGE_FILE != 0) throw Ext4Exception("Huge-file inodes are read-only")
        markDirty()
        val oldSize = ino.size
        val end = pos + len
        val first = pos / blockSize; val last = (end - 1) / blockSize
        val before = extentMap(ino).first
        fun hadData(l: Long) = before.any { l >= it.lblk && l < it.lblk + it.len && !it.uninit }
        val exts = mapRange(ino, first, last)
        fun phys(l: Long) = exts.first { l >= it.lblk && l < it.lblk + it.len }.let { it.pblk + (l - it.lblk) }
        // bytes past the old end of file in its last block must read as zero once the file grows over them
        if (pos > oldSize && oldSize % blockSize != 0L && hadData(oldSize / blockSize)) {
            val l = oldSize / blockSize; val from = oldSize % blockSize
            val to = if (l == first) pos % blockSize else blockSize.toLong()
            if (to > from) { val z = ByteArray((to - from).toInt()); dev.writeBytes(physOrZero(exts, l) * blockSize + from, z, 0, z.size) }
        }
        // a block that was a hole and is only partly written gets zeros around the data
        for (l in setOf(first, last)) {
            val covered = (l > first || pos % blockSize == 0L) && (l < last || end % blockSize == 0L)
            if (!covered && !hadData(l)) dev.writeBytes(phys(l) * blockSize, ByteArray(blockSize), 0, blockSize)
        }
        var p = pos; var o = off; var left = len
        while (left > 0) {
            val l = p / blockSize; val inB = (p % blockSize).toInt()
            val start = phys(l)
            var run = 1
            while (run.toLong() * blockSize - inB < left && phys(l + run) == start + run) run++
            val k = minOf(left.toLong(), run.toLong() * blockSize - inB).toInt()
            dev.writeBytes(start * blockSize + inB, buf, o, k)
            p += k; o += k; left -= k
        }
        if (end > ino.size) ino.size = end
        setTimes(ino)
        writeInode(ino)
    }

    private fun roundUp(v: Long) = (v + blockSize - 1) / blockSize * blockSize
    private fun physOrZero(exts: List<Ext>, l: Long) = exts.firstOrNull { l >= it.lblk && l < it.lblk + it.len && !it.uninit }?.let { it.pblk + (l - it.lblk) } ?: 0L

    @Synchronized
    override fun truncate(n: FsNode, size: Long) {
        requireWritable()
        val ino = inode((n as Node).ino)
        if (isDirMode(ino.mode) || !ino.extents) throw Ext4Exception("Can't truncate this file")
        if (size == ino.size) return
        markDirty()
        if (size < ino.size) {
            val keep = (size + blockSize - 1) / blockSize
            val (exts, _) = extentMap(ino)
            val out = ArrayList<Ext>()
            for (e in exts) {
                when {
                    e.lblk + e.len <= keep -> out.add(e)
                    e.lblk >= keep -> freeBlocks(e.pblk, e.len.toLong())
                    else -> { val k = (keep - e.lblk).toInt(); out.add(Ext(e.lblk, e.pblk, k, e.uninit)); freeBlocks(e.pblk + k, (e.len - k).toLong()) }
                }
            }
            writeExtents(ino, out)
            if (size % blockSize != 0L) physOrZero(out, size / blockSize).takeIf { it != 0L }?.let {
                val z = ByteArray((blockSize - size % blockSize).toInt()); dev.writeBytes(it * blockSize + size % blockSize, z, 0, z.size)
            }
        } else if (ino.size % blockSize != 0L) {
            physOrZero(extentMap(ino).first, ino.size / blockSize).takeIf { it != 0L }?.let {
                val z = ByteArray((blockSize - ino.size % blockSize).toInt()); dev.writeBytes(it * blockSize + ino.size % blockSize, z, 0, z.size)
            }
        }
        ino.size = size
        setTimes(ino)
        writeInode(ino)
    }

    // ---- directories ----

    private fun recLen(nameLen: Int) = (8 + nameLen + 3) and 3.inv()
    private val tailLen get() = if (csum) 12 else 0

    private fun writeDirBlock(dir: Inode, p: Long, b: ByteArray) {
        if (csum) {
            val t = blockSize - 12
            put32(b, t, 0); put16(b, t + 4, 12); b[t + 6] = 0; b[t + 7] = 0xDE.toByte()
            put32(b, t + 8, Crc32c.update(dir.seed(), b, 0, t).toLong() and 0xffffffffL)
        }
        c.write(p * blockSize, b)
    }

    /** Turns an htree directory into a linear one: index blocks become empty entry blocks. */
    private fun flattenIndex(dir: Inode) {
        if (dir.flags and FL_INDEX == 0) return
        val (exts, _) = extentMap(dir).let { if (dir.extents) it else throw Ext4Exception("Indexed block-mapped directory") }
        val b = ByteArray(blockSize)
        for (e in exts) for (k in 0 until e.len) {
            val p = e.pblk + k; val l = e.lblk + k
            c.read(p * blockSize, b)
            val first = u32(b, 0); val rec = u16(b, 4)
            val isRoot = l == 0L
            val isNode = !isRoot && first == 0L && rec == blockSize
            if (!isRoot && !isNode) continue
            java.util.Arrays.fill(b, 0)
            if (isRoot) {
                put32(b, 0, dir.ino.toLong()); put16(b, 4, 12); b[6] = 1; b[7] = FT_DIR.toByte(); b[8] = '.'.code.toByte()
                val parent = parentInoOfIndexRoot(p)
                put32(b, 12, parent.toLong()); put16(b, 16, blockSize - 12 - tailLen); b[18] = 2; b[19] = FT_DIR.toByte()
                b[20] = '.'.code.toByte(); b[21] = '.'.code.toByte()
            } else { put32(b, 0, 0); put16(b, 4, blockSize - tailLen) }
            writeDirBlock(dir, p, b)
        }
        put32(dir.raw, 0x20, (dir.flags and FL_INDEX.inv()).toLong())
        writeInode(dir)
    }

    private fun parentInoOfIndexRoot(p: Long): Int { val b = ByteArray(24); c.read(p * blockSize, b); return u32(b, 12).toInt() }

    private fun addEntry(dir: Inode, name: ByteArray, ino: Int, type: Int) {
        flattenIndex(dir)
        val need = recLen(name.size)
        val nb = dir.size / blockSize
        val b = ByteArray(blockSize)
        for (l in 0 until nb) {
            val p = physOf(dir, l); if (p == 0L) continue
            c.read(p * blockSize, b)
            var o = 0
            val limit = blockSize - tailLen
            while (o < limit) {
                val eIno = u32(b, o); val rec = u16(b, o + 4); val nl = b[o + 6].toInt() and 0xff
                if (rec < 8 || o + rec > limit) break
                val used = if (eIno == 0L) 0 else recLen(nl)
                if (rec - used >= need) {
                    val at = if (eIno == 0L) o else o + used
                    val newRec = if (eIno == 0L) rec else rec - used
                    if (eIno != 0L) put16(b, o + 4, used)
                    putEntry(b, at, ino, newRec, name, type)
                    writeDirBlock(dir, p, b)
                    return
                }
                o += rec
            }
        }
        // no room: append a block
        val exts = mapRange(dir, nb, nb)
        val p = exts.first { nb >= it.lblk && nb < it.lblk + it.len }.let { it.pblk + (nb - it.lblk) }
        java.util.Arrays.fill(b, 0)
        putEntry(b, 0, ino, blockSize - tailLen, name, type)
        writeDirBlock(dir, p, b)
        dir.size = dir.size + blockSize
    }

    private fun putEntry(b: ByteArray, o: Int, ino: Int, rec: Int, name: ByteArray, type: Int) {
        put32(b, o, ino.toLong()); put16(b, o + 4, rec); b[o + 6] = name.size.toByte()
        b[o + 7] = (if (incompat and INCOMPAT_FILETYPE != 0) type else 0).toByte()
        name.copyInto(b, o + 8)
    }

    private fun removeEntry(dir: Inode, name: String) {
        flattenIndex(dir)
        val nb = dir.size / blockSize
        val b = ByteArray(blockSize)
        for (l in 0 until nb) {
            val p = physOf(dir, l); if (p == 0L) continue
            c.read(p * blockSize, b)
            var o = 0; var prev = -1
            val limit = blockSize - tailLen
            while (o < limit) {
                val eIno = u32(b, o); val rec = u16(b, o + 4); val nl = b[o + 6].toInt() and 0xff
                if (rec < 8 || o + rec > limit) break
                if (eIno != 0L && String(b, o + 8, nl, Charsets.UTF_8) == name) {
                    if (prev >= 0) put16(b, prev + 4, u16(b, prev + 4) + rec) else put32(b, o, 0)
                    writeDirBlock(dir, p, b)
                    return
                }
                prev = o; o += rec
            }
        }
        throw Ext4Exception("$name not found")
    }

    private fun checkName(name: String): ByteArray {
        val b = name.toByteArray(Charsets.UTF_8)
        if (b.isEmpty() || b.size > 255 || name == "." || name == ".." || '/' in name || '\u0000' in name) throw Ext4Exception("Invalid name")
        return b
    }

    @Synchronized
    override fun create(dir: FsNode, name: String, isDir: Boolean): FsNode {
        requireWritable()
        val d = dir as Node
        val nameB = checkName(name)
        if (find(d, name) != null) throw Ext4Exception("$name already exists")
        markDirty()
        val parent = inode(d.ino)
        val ino = allocInode(isDir, (d.ino - 1) / inodesPerGroup)
        val n = Inode(ino, ByteArray(inodeSize))
        val pMode = parent.mode
        put16(n.raw, 0x00, if (isDir) 0x4000 or (pMode and 0x1ff) else 0x8000 or (pMode and 0x1b6))  // dirs inherit, files lose x bits
        put16(n.raw, 0x02, u16(parent.raw, 0x02)); put16(n.raw, 0x18, u16(parent.raw, 0x18))               // owner of the parent
        put16(n.raw, 0x78, u16(parent.raw, 0x78)); put16(n.raw, 0x7A, u16(parent.raw, 0x7A))
        if (inodeSize > 128) put16(n.raw, 0x80, u16(sb, 0x15E).takeIf { it in 4..(inodeSize - 128) } ?: minOf(32, inodeSize - 128))
        put32(n.raw, 0x64, rnd.nextInt().toLong())
        put32(n.raw, 0x20, FL_EXTENTS.toLong())
        n.links = if (isDir) 2 else 1
        val now = System.currentTimeMillis() / 1000
        put32(n.raw, 0x08, now); if (n.extra >= 0x18) put32(n.raw, 0x90, now)
        setTimes(n)
        header(n.raw, 0x28, 0, 4, 0)
        if (isDir) {
            val exts = mapRange(n, 0, 0)
            val b = ByteArray(blockSize)
            put32(b, 0, ino.toLong()); put16(b, 4, 12); b[6] = 1; b[7] = FT_DIR.toByte(); b[8] = '.'.code.toByte()
            put32(b, 12, d.ino.toLong()); put16(b, 16, blockSize - 12 - tailLen); b[18] = 2; b[19] = FT_DIR.toByte(); b[20] = '.'.code.toByte(); b[21] = '.'.code.toByte()
            writeDirBlock(n, exts[0].pblk, b)
            n.size = blockSize.toLong()
        }
        writeInode(n)
        addEntry(parent, nameB, ino, if (isDir) FT_DIR else FT_REG)
        if (isDir && parent.links < 65000) parent.links = parent.links + 1
        setTimes(parent)
        writeInode(parent)
        return Node(ino, name, d)
    }

    @Synchronized
    override fun delete(n: FsNode) {
        requireWritable()
        val node = n as Node
        if (node.isRoot) throw Ext4Exception("Can't delete the root")
        val ino = inode(node.ino)
        val isDir = isDirMode(ino.mode)
        if (isDir && list(node).isNotEmpty()) throw Ext4Exception("Directory not empty")
        markDirty()
        val parent = inode(node.parent!!.ino)
        removeEntry(parent, node.name)
        if (isDir && parent.links > 2 && parent.links < 65000) parent.links = parent.links - 1
        setTimes(parent); writeInode(parent)
        ino.links = if (isDir) 0 else ino.links - 1
        if (ino.links > 0) { setTimes(ino, m = false); writeInode(ino); return }
        releaseBlocks(ino)
        put32(ino.raw, 0x14, System.currentTimeMillis() / 1000)   // dtime
        writeInode(ino)
        freeInode(node.ino, isDir)
    }

    private fun releaseBlocks(ino: Inode) {
        val fast = ino.mode and 0xF000 == 0xA000 && ino.size < 60 && ino.fileAcl == 0L
        if (!fast) {
            if (ino.extents) {
                val (exts, tree) = extentMap(ino)
                for (e in exts) freeBlocks(e.pblk, e.len.toLong())
                for (t in tree) freeBlocks(t, 1)
            } else {
                val (map, ind) = blockMap(ino)
                for (p in map) if (p != 0L) freeBlocks(p, 1)
                for (p in ind) freeBlocks(p, 1)
            }
        }
        val acl = ino.fileAcl
        if (acl != 0L) {
            val b = ByteArray(blockSize); c.read(acl * blockSize, b)
            val refs = u32(b, 4)
            if (refs <= 1) freeBlocks(acl, 1) else {
                put32(b, 4, refs - 1)
                if (csum) { put32(b, 0x10, 0); val crc = Crc32c.update(Crc32c.update(csumSeed, ByteArray(8).also { put32(it, 0, acl); put32(it, 4, acl ushr 32) }), b); put32(b, 0x10, crc.toLong() and 0xffffffffL) }
                c.write(acl * blockSize, b)
            }
        }
    }

    @Synchronized
    override fun rename(n: FsNode, newDir: FsNode, newName: String) {
        requireWritable()
        val node = n as Node; val target = newDir as Node
        if (node.isRoot) throw Ext4Exception("Can't rename the root")
        val nameB = checkName(newName)
        var a: Node? = target
        while (a != null) { if (a.ino == node.ino) throw Ext4Exception("Can't move a directory into itself"); a = a.parent }
        val clash = find(target, newName)
        if (clash != null) { if (clash.ino == node.ino) { if (newName == node.name) return } else throw Ext4Exception("$newName already exists") }
        markDirty()
        val ino = inode(node.ino)
        val isDir = isDirMode(ino.mode)
        val oldDir = node.parent!!.ino
        val moved = target.ino != oldDir
        if (isDir && moved) flattenIndex(ino)        // its block 0 gets a new ".." and a checksum tail
        removeEntry(inode(oldDir), node.name)
        val newParent = inode(target.ino)
        addEntry(newParent, nameB, node.ino, if (isDir) FT_DIR else FT_REG)
        if (isDir && moved) {
            val dirIno = inode(node.ino)
            val p0 = physOf(dirIno, 0); val b = ByteArray(blockSize); c.read(p0 * blockSize, b)
            put32(b, 12, target.ino.toLong()); writeDirBlock(dirIno, p0, b)
            if (newParent.links < 65000) newParent.links = newParent.links + 1
        }
        setTimes(newParent); writeInode(newParent)
        if (moved) {
            val op = inode(oldDir)
            if (isDir && op.links > 2 && op.links < 65000) op.links = op.links - 1
            setTimes(op); writeInode(op)
        }
        val self = inode(node.ino); setTimes(self, m = false); writeInode(self)
    }

    override fun info(): List<Pair<String, String>> {
        val u = sb.copyOfRange(0x68, 0x78).joinToString("") { "%02x".format(it) }
        val names = listOf(
            0x5C to mapOf(0x4 to "has_journal", 0x8 to "ext_attr", 0x10 to "resize_inode", 0x20 to "dir_index", 0x1000 to "orphan_file"),
            0x60 to mapOf(0x2 to "filetype", 0x40 to "extent", 0x80 to "64bit", 0x200 to "flex_bg", 0x2000 to "metadata_csum_seed", 0x8000 to "inline_data"),
            0x64 to mapOf(0x1 to "sparse_super", 0x2 to "large_file", 0x8 to "huge_file", 0x20 to "dir_nlink", 0x40 to "extra_isize", 0x400 to "metadata_csum"),
        )
        val feats = names.flatMap { (off, m) -> val v = u32(sb, off).toInt(); m.filter { v and it.key != 0 }.values }
        return listOf(
            "UUID" to "${u.substring(0, 8)}-${u.substring(8, 12)}-${u.substring(12, 16)}-${u.substring(16, 20)}-${u.substring(20)}",
            "Block size" to "$blockSize bytes",
            "Inodes" to "%,d (%,d free)".format(inodesPerGroup.toLong() * groupCount, u32(sb, 0x10)),
            "State" to if (u16(sb, 0x3A) and 1 != 0) "clean" else "not clean (in use or needs e2fsck)",
            "Features" to feats.joinToString(" "),
        )
    }

    @Synchronized
    override fun setLabel(label: String) {
        requireWritable()
        val b = label.toByteArray(Charsets.UTF_8)
        require(b.size <= 16) { "ext4 labels are at most 16 bytes" }
        markDirty()
        java.util.Arrays.fill(sb, 0x78, 0x88, 0); b.copyInto(sb, 0x78)
        currentLabel = label
        flush()
    }

    // ---- volume ----

    override val totalBytes get() = blocksCount * blockSize
    override val freeBytes get() = freeBlocksTotal() * blockSize

    @Synchronized
    override fun flush() {
        if (!dirtyState) return
        for (g in dirtyGroups) {
            val d = desc(g)
            if (csum) {
                val bb = ByteArray(bitmapBytes()); if (u16(d, 0x12) and BG_BLOCK_UNINIT == 0) c.read(blockBitmap(d) * blockSize, bb)
                val bc = Crc32c.update(csumSeed, bb)
                put16(d, 0x18, bc and 0xffff); if (descSize >= 64) put16(d, 0x38, bc ushr 16)
                val ib = ByteArray(inodesPerGroup / 8); if (u16(d, 0x12) and BG_INODE_UNINIT == 0) c.read(inodeBitmap(d) * blockSize, ib)
                val ic = Crc32c.update(csumSeed, ib)
                put16(d, 0x1A, ic and 0xffff); if (descSize >= 64) put16(d, 0x3A, ic ushr 16)
                put16(d, 0x1E, 0)
                // the kernel feeds the (zeroed) checksum field through the CRC too
                put16(d, 0x1E, Crc32c.update(Crc32c.le32(csumSeed, g), d, 0, descSize) and 0xffff)
            }
            c.write(descPos(g), d)
        }
        dirtyGroups.clear()
        c.flush()
        put16(sb, 0x3A, u16(sb, 0x3A) or 1)
        writeSuper()
        c.flush()
        dirtyState = false
    }

    override fun close() { flush(); dev.close() }

    /** Replays the journal and clears needs_recovery; returns the blocks written home. */
    private fun replayJournal(): Int {
        val jIno = u32(sb, 0xE0).toInt()
        if (jIno == 0) throw Ext4Exception("external journal")
        val j = inode(jIno)
        fun home(l: Long) = physOf(j, l).also { if (it == 0L) throw Ext4Exception("hole in the journal") }
        val n = Jbd2(blockSize, blocksCount, ::home, { p, b -> c.read(p * blockSize, b) }, { p, b -> c.write(p * blockSize, b) }).replay()
        c.flush()
        c.read(1024, sb)   // the log may have held the superblock itself
        put32(sb, 0x60, u32(sb, 0x60) and INCOMPAT_RECOVER.toLong().inv())
        recountTotals(); writeSuper(); c.flush()
        return n
    }

    /**
     * Linux sets orphan_present while mounted and clears it at unmount; after an unplug it stays set. With no
     * orphan listed (old list empty, every orphan-file slot zero) clearing it is e2fsck's own fix.
     */
    private fun clearCleanOrphanFlag(): Boolean {
        val ino = u32(sb, 0x280).toInt()
        if (u16(sb, 0x3A) and 2 != 0 || u32(sb, 0xE8) != 0L || ino == 0) return false
        val n = inode(ino); val b = ByteArray(blockSize)
        for (l in 0 until (n.size + blockSize - 1) / blockSize) {
            readLogical(n, l, b)
            for (o in 0 until blockSize - 8 step 4) if (u32(b, o) != 0L) return false   // the last 8 bytes are the block tail
        }
        put32(sb, 0x64, u32(sb, 0x64) and RO_ORPHAN_PRESENT.toLong().inv())
        recountTotals(); writeSuper(); c.flush()
        return true
    }

    /** The superblock's free totals from the group descriptors: Linux updates them only at a clean unmount. */
    private fun recountTotals() {
        var blocks = 0L; var inodes = 0L
        for (g in 0 until groupCount) { val d = desc(g); blocks += lohi(d, 0x0C, 0x2C, 2); inodes += lohi(d, 0x0E, 0x2E, 2) }
        setFreeBlocksTotal(blocks); put32(sb, 0x10, inodes)
    }

    companion object {
        /** Mounts; a journal left by an unclean Linux unmount is replayed first, as the kernel does. */
        fun mount(dev: BlockDevice): Ext4 {
            var fs = Ext4(dev)
            if (fs.incompat and INCOMPAT_RECOVER != 0) {
                val err = try { fs.replayJournal(); null } catch (e: IOException) { e.message ?: "I/O error" }
                fs = Ext4(dev, err)
                if (err != null) return fs
            }
            if (fs.roCompat and RO_ORPHAN_PRESENT != 0 && fs.clearCleanOrphanFlag()) fs = Ext4(dev)
            return fs
        }

        fun isExt(dev: BlockDevice): Boolean {
            val b = ByteArray(maxOf(dev.sectorSize, 2048)); dev.read(0, b)
            return u16(b, 1024 + 0x38) == 0xEF53
        }

        private fun isDirMode(m: Int) = m and 0xF000 == 0x4000

        const val COMPAT_RESIZE_INODE = 0x10
        const val COMPAT_SPARSE_SUPER2 = 0x200
        const val INCOMPAT_FILETYPE = 0x2
        const val INCOMPAT_RECOVER = 0x4
        const val INCOMPAT_META_BG = 0x10
        const val INCOMPAT_EXTENTS = 0x40
        const val INCOMPAT_64BIT = 0x80
        const val INCOMPAT_MMP = 0x100
        const val INCOMPAT_FLEX_BG = 0x200
        const val INCOMPAT_CSUM_SEED = 0x2000
        const val INCOMPAT_LARGEDIR = 0x4000
        const val INCOMPAT_INLINE_DATA = 0x8000
        const val RO_SPARSE_SUPER = 0x1
        const val RO_GDT_CSUM = 0x10
        const val RO_METADATA_CSUM = 0x400
        const val RO_ORPHAN_PRESENT = 0x10000
        // sparse_super, large_file, huge_file, gdt_csum, dir_nlink, extra_isize, metadata_csum, project
        const val RO_KNOWN = 0x1 or 0x2 or 0x8 or 0x10 or 0x20 or 0x40 or 0x400 or 0x2000
        const val BG_INODE_UNINIT = 0x1
        const val BG_BLOCK_UNINIT = 0x2
        const val FL_INDEX = 0x1000
        const val FL_EXTENTS = 0x80000
        const val FL_HUGE_FILE = 0x40000
        const val FT_UNKNOWN = 0
        const val FT_REG = 1
        const val FT_DIR = 2

        internal fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
        internal fun u32(b: ByteArray, o: Int) = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)
        internal fun put16(b: ByteArray, o: Int, v: Int) { b[o] = v.toByte(); b[o + 1] = (v ushr 8).toByte() }
        internal fun put32(b: ByteArray, o: Int, v: Long) { for (i in 0 until 4) b[o + i] = (v ushr (8 * i)).toByte() }
    }
}
