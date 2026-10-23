package me.nocke.cryptic.vaults.ext4

import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.ext4.Ext4.Companion.put16
import me.nocke.cryptic.vaults.ext4.Ext4.Companion.put32
import me.nocke.cryptic.vaults.fs.writeBytes
import java.security.SecureRandom
import java.util.UUID

/**
 * mkfs.ext4: 4 KiB blocks, 256-byte inodes, one inode per 16 KiB, internal journal, metadata_csum, 64bit, extents.
 * Groups past the first start BLOCK_UNINIT/INODE_UNINIT with their whole inode table unused (lazy init, as
 * mke2fs -E lazy_itable_init), so a 2 TB drive formats by writing a few MB. No flex_bg and no resize inode:
 * each group keeps its bitmaps and inode table at its start. No reserved blocks (a data drive, not a root fs).
 * The root directory belongs to [uid]/[gid] so the Linux user can write to it (Android can't know that uid).
 */
object ExtFormat {
    private const val BS = 4096
    private const val BPG = 32768
    private const val INODE_SIZE = 256
    private const val EXTRA = 32
    private const val FIRST_INO = 11
    private const val DESC = 64

    fun format(dev: BlockDevice, label: String = "", uid: Int = 1000, gid: Int = 1000) {
        require(label.toByteArray().size <= 16) { "Label is at most 16 bytes" }
        require(dev.sectorSize <= BS)
        var blocks = dev.size / BS
        var groups = ((blocks + BPG - 1) / BPG).toInt()
        // a tiny last group can't hold its own metadata: drop it, as mke2fs does
        if (groups > 1 && blocks - (groups - 1).toLong() * BPG < 2048) { groups--; blocks = groups.toLong() * BPG }
        require(blocks >= 4096) { "Volume too small for ext4 (16 MiB minimum)" }
        var ipg = ((blocks * BS / 16384 + groups - 1) / groups).toInt()
        ipg = ((ipg + 15) / 16 * 16).coerceIn(32, BPG)
        val itb = ipg * INODE_SIZE / BS
        val gdtBlocks = (groups * DESC + BS - 1) / BS
        val rnd = SecureRandom()
        val uuid = ByteArray(16).also { b -> val u = UUID.randomUUID(); for (i in 0 until 8) { b[i] = (u.mostSignificantBits ushr (56 - 8 * i)).toByte(); b[8 + i] = (u.leastSignificantBits ushr (56 - 8 * i)).toByte() } }
        val seed = Crc32c.update(-1, uuid)
        val now = System.currentTimeMillis() / 1000

        fun start(g: Int) = g.toLong() * BPG
        fun size(g: Int) = minOf(BPG.toLong(), blocks - start(g)).toInt()
        fun hasSuper(g: Int): Boolean {
            if (g <= 1) return true
            for (p in intArrayOf(3, 5, 7)) { var x = p; while (x < g) x *= p; if (x == g) return true }
            return false
        }
        fun meta(g: Int) = if (hasSuper(g)) 1 + gdtBlocks else 0             // blocks before the bitmaps
        fun blockBitmap(g: Int) = start(g) + meta(g)
        fun inodeBitmap(g: Int) = blockBitmap(g) + 1
        fun inodeTable(g: Int) = blockBitmap(g) + 2
        fun firstFree(g: Int) = inodeTable(g) + itb
        require(size(groups - 1) > meta(groups - 1) + 2 + itb + 16) { "Last group too small" }

        // group 0 holds the root dir, lost+found and the journal right after its inode table
        val rootBlock = firstFree(0)
        val lfBlocks = 4
        val lfStart = rootBlock + 1
        val room0 = start(0) + size(0) - (lfStart + lfBlocks)
        val journalBlocks = when {
            blocks < 32768 -> 1024L
            else -> minOf(32768L, maxOf(4096L, blocks / 256))
        }.coerceAtMost(room0 - 16)
        val journalStart = lfStart + lfBlocks
        val usedInGroup0 = (journalStart + journalBlocks - start(0)).toInt()

        // ---- group descriptors ----
        val gdt = ByteArray(gdtBlocks * BS)
        var freeBlocksTotal = 0L
        val freeInodesTotal = ipg.toLong() * groups - FIRST_INO
        val bitmaps = HashMap<Int, ByteArray>()                         // initialized block bitmaps (group 0, last)
        for (g in 0 until groups) {
            val d = g * DESC
            val used = if (g == 0) usedInGroup0 else meta(g) + 2 + itb
            val free = size(g) - used
            freeBlocksTotal += free
            put32(gdt, d + 0x00, blockBitmap(g)); put32(gdt, d + 0x20, blockBitmap(g) ushr 32)
            put32(gdt, d + 0x04, inodeBitmap(g)); put32(gdt, d + 0x24, inodeBitmap(g) ushr 32)
            put32(gdt, d + 0x08, inodeTable(g)); put32(gdt, d + 0x28, inodeTable(g) ushr 32)
            put16(gdt, d + 0x0C, free and 0xffff); put16(gdt, d + 0x2C, free ushr 16)
            val fi = if (g == 0) ipg - FIRST_INO else ipg
            put16(gdt, d + 0x0E, fi and 0xffff); put16(gdt, d + 0x2E, fi ushr 16)
            put16(gdt, d + 0x10, if (g == 0) 2 else 0)
            val initBlocks = g == 0 || g == groups - 1
            put16(gdt, d + 0x12, (if (g == 0) 0 else Ext4.BG_INODE_UNINIT) or (if (initBlocks) 0 else Ext4.BG_BLOCK_UNINIT))
            put16(gdt, d + 0x1C, fi and 0xffff); put16(gdt, d + 0x32, fi ushr 16)   // itable_unused
            if (initBlocks) {
                val bm = ByteArray(BS)
                for (r in 0 until used) bm[r / 8] = (bm[r / 8].toInt() or (1 shl (r % 8))).toByte()
                for (r in size(g) until BS * 8) bm[r / 8] = (bm[r / 8].toInt() or (1 shl (r % 8))).toByte()
                bitmaps[g] = bm
                val c = Crc32c.update(seed, bm, 0, BPG / 8)
                put16(gdt, d + 0x18, c and 0xffff); put16(gdt, d + 0x38, c ushr 16)
            }
            val ib = ByteArray(BS)
            if (g == 0) for (i in 0 until FIRST_INO) ib[i / 8] = (ib[i / 8].toInt() or (1 shl (i % 8))).toByte()
            if (g == 0) {
                for (r in ipg until BS * 8) ib[r / 8] = (ib[r / 8].toInt() or (1 shl (r % 8))).toByte()
                bitmaps[-1] = ib
            }
            val ic = Crc32c.update(seed, ib, 0, ipg / 8).let { if (g == 0) it else Crc32c.update(seed, ByteArray(ipg / 8)) }
            put16(gdt, d + 0x1A, ic and 0xffff); put16(gdt, d + 0x3A, ic ushr 16)
            put16(gdt, d + 0x1E, 0)
            put16(gdt, d + 0x1E, Crc32c.update(Crc32c.le32(seed, g), gdt, d, DESC) and 0xffff)
        }

        // ---- superblock ----
        val sb = ByteArray(1024)
        put32(sb, 0x00, ipg.toLong() * groups)
        put32(sb, 0x04, blocks); put32(sb, 0x150, blocks ushr 32)
        put32(sb, 0x0C, freeBlocksTotal); put32(sb, 0x158, freeBlocksTotal ushr 32)
        put32(sb, 0x10, freeInodesTotal)
        put32(sb, 0x14, 0)
        put32(sb, 0x18, 2); put32(sb, 0x1C, 2)
        put32(sb, 0x20, BPG.toLong()); put32(sb, 0x24, BPG.toLong()); put32(sb, 0x28, ipg.toLong())
        put32(sb, 0x30, now)
        put16(sb, 0x36, 0xffff)                    // max mount count: -1
        put16(sb, 0x38, 0xEF53); put16(sb, 0x3A, 1); put16(sb, 0x3C, 1)
        put32(sb, 0x40, now); put32(sb, 0x4C, 1)
        put32(sb, 0x54, FIRST_INO.toLong()); put16(sb, 0x58, INODE_SIZE)
        put32(sb, 0x5C, (0x4 or 0x8 or 0x20).toLong())                         // has_journal, ext_attr, dir_index
        put32(sb, 0x60, (Ext4.INCOMPAT_FILETYPE or Ext4.INCOMPAT_EXTENTS or Ext4.INCOMPAT_64BIT).toLong())
        put32(sb, 0x64, (0x1 or 0x2 or 0x8 or 0x20 or 0x40 or Ext4.RO_METADATA_CSUM).toLong())
        uuid.copyInto(sb, 0x68)
        label.toByteArray().copyInto(sb, 0x78)
        put32(sb, 0xE0, 8)                                                      // journal inode
        rnd.nextBytes(ByteArray(16).also { it.copyInto(sb, 0xEC) })           // hash seed
        sb[0xFC] = 1                                                            // half_md4
        sb[0xFD] = 1                                                            // journal inode backup in s_jnl_blocks
        put16(sb, 0xFE, DESC)
        put32(sb, 0x100, 0x0C)                                                  // user_xattr, acl
        put32(sb, 0x108, now)
        put16(sb, 0x15C, EXTRA); put16(sb, 0x15E, EXTRA)
        put32(sb, 0x160, 1)                                                     // signed directory hash
        sb[0x175] = 1                                                           // crc32c

        // ---- inodes ----
        fun inode(ino: Int, mode: Int, links: Int, sizeBytes: Long, u: Int, gr: Int, ext: List<Pair<Long, Int>>, gen: Int): ByteArray {
            val n = ByteArray(INODE_SIZE)
            put16(n, 0x00, mode); put16(n, 0x02, u and 0xffff); put16(n, 0x78, u ushr 16)
            put16(n, 0x18, gr and 0xffff); put16(n, 0x7A, gr ushr 16)
            put32(n, 0x04, sizeBytes); put32(n, 0x6C, sizeBytes ushr 32)
            for (o in intArrayOf(0x08, 0x0C, 0x10)) put32(n, o, now)
            put16(n, 0x1A, links)
            val nb = ext.sumOf { it.second.toLong() } * (BS / 512)
            put32(n, 0x1C, nb)
            put16(n, 0x80, EXTRA); put32(n, 0x90, now)
            put32(n, 0x64, gen.toLong())
            if (ext.isNotEmpty() || mode != 0) {
                put32(n, 0x20, Ext4.FL_EXTENTS.toLong())
                put16(n, 0x28, 0xF30A); put16(n, 0x2A, ext.size); put16(n, 0x2C, 4); put16(n, 0x2E, 0)
                ext.forEachIndexed { k, (p, len) ->
                    val e = 0x28 + 12 + 12 * k
                    put32(n, e, ext.take(k).sumOf { it.second }.toLong()); put16(n, e + 4, len)
                    put16(n, e + 6, (p ushr 32).toInt()); put32(n, e + 8, p)
                }
            }
            if (mode == 0) put32(n, 0x20, 0)
            val crcSeed = Crc32c.le32(Crc32c.le32(seed, ino), gen)
            val crc = Crc32c.update(crcSeed, n)
            put16(n, 0x7C, crc and 0xffff); put16(n, 0x82, crc ushr 16)
            return n
        }
        val table = ByteArray(FIRST_INO * INODE_SIZE)
        for (ino in 1..FIRST_INO) {
            val n = when (ino) {
                2 -> inode(2, 0x41ED, 3, BS.toLong(), uid, gid, listOf(rootBlock to 1), 0)
                8 -> inode(8, 0x8180, 1, journalBlocks * BS, 0, 0, listOf(journalStart to journalBlocks.toInt()), 0)
                11 -> inode(11, 0x41C0, 2, lfBlocks.toLong() * BS, 0, 0, listOf(lfStart to lfBlocks), 0)
                else -> inode(ino, 0, 0, 0, 0, 0, emptyList(), 0)
            }
            n.copyInto(table, (ino - 1) * INODE_SIZE)
        }
        // s_jnl_blocks: the journal inode's i_block, then i_size_high and i_size
        table.copyInto(sb, 0x10C, 7 * INODE_SIZE + 0x28, 7 * INODE_SIZE + 0x28 + 60)
        put32(sb, 0x10C + 60, 0); put32(sb, 0x10C + 64, journalBlocks * BS)

        // ---- directory blocks ----
        fun dirent(b: ByteArray, o: Int, ino: Int, rec: Int, name: String, type: Int) {
            put32(b, o, ino.toLong()); put16(b, o + 4, rec); b[o + 6] = name.length.toByte(); b[o + 7] = type.toByte()
            name.toByteArray().copyInto(b, o + 8)
        }
        fun tail(b: ByteArray, ino: Int) {
            val t = BS - 12
            put32(b, t, 0); put16(b, t + 4, 12); b[t + 6] = 0; b[t + 7] = 0xDE.toByte()
            put32(b, t + 8, Crc32c.update(Crc32c.le32(Crc32c.le32(seed, ino), 0), b, 0, t).toLong() and 0xffffffffL)
        }
        val root = ByteArray(BS)
        dirent(root, 0, 2, 12, ".", 2); dirent(root, 12, 2, 12, "..", 2); dirent(root, 24, 11, BS - 12 - 24, "lost+found", 2); tail(root, 2)
        val lf = ByteArray(lfBlocks * BS)
        dirent(lf, 0, 11, 12, ".", 2); dirent(lf, 12, 2, BS - 12 - 12, "..", 2)
        for (k in 0 until lfBlocks) {
            val blk = lf.copyOfRange(k * BS, (k + 1) * BS)
            if (k > 0) { put32(blk, 0, 0); put16(blk, 4, BS - 12) }
            tail(blk, 11); blk.copyInto(lf, k * BS)
        }

        // ---- journal superblock (jbd2 v2, big-endian, empty) ----
        val j = ByteArray(BS)
        fun be32(o: Int, v: Long) { for (i in 0 until 4) j[o + i] = (v ushr (24 - 8 * i)).toByte() }
        be32(0x00, 0xC03B3998L); be32(0x04, 4); be32(0x0C, BS.toLong()); be32(0x10, journalBlocks)
        be32(0x14, 1); be32(0x18, 1)
        uuid.copyInto(j, 0x30); be32(0x40, 1)

        // ---- write it out ----
        val superFor = { g: Int ->
            val s = sb.copyOf(); put16(s, 0x5A, g)
            put32(s, 0x3FC, Crc32c.update(-1, s, 0, 0x3FC).toLong() and 0xffffffffL); s
        }
        val block0 = ByteArray(BS); superFor(0).copyInto(block0, 1024)
        dev.writeBytes(0, block0, 0, BS)
        dev.writeBytes(BS.toLong(), gdt, 0, gdt.size)
        for (g in 1 until groups) if (hasSuper(g)) {
            val b = ByteArray(BS); superFor(g).copyInto(b, 0)
            dev.writeBytes(start(g) * BS, b, 0, BS)
            dev.writeBytes((start(g) + 1) * BS, gdt, 0, gdt.size)
        }
        for ((g, bm) in bitmaps) if (g >= 0) dev.writeBytes(blockBitmap(g) * BS, bm, 0, BS)
        dev.writeBytes(inodeBitmap(0) * BS, bitmaps.getValue(-1), 0, BS)
        // group 0's inode table: the reserved inodes, then the rest of its first block zeroed
        val firstTableBlocks = ByteArray(((FIRST_INO * INODE_SIZE + BS - 1) / BS) * BS); table.copyInto(firstTableBlocks)
        dev.writeBytes(inodeTable(0) * BS, firstTableBlocks, 0, firstTableBlocks.size)
        dev.writeBytes(rootBlock * BS, root, 0, BS)
        dev.writeBytes(lfStart * BS, lf, 0, lf.size)
        dev.writeBytes(journalStart * BS, j, 0, BS)
        dev.flush()
    }
}
