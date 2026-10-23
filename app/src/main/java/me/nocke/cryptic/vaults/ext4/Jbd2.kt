package me.nocke.cryptic.vaults.ext4

/**
 * jbd2 journal replay (kernel.org "Journal (jbd2)", fs/jbd2/recovery.c): what Linux does at mount when ext4's
 * needs_recovery flag is set, e.g. after a drive was unplugged without unmounting. Scans the log from s_start, keeps
 * every transaction that reached its commit block, checks all checksums before writing anything, then copies each
 * journalled block home unless a revoke in the same or a later transaction cancels it, and marks the log empty.
 * Blocks are fs block numbers; [home] maps a journal block to its fs block.
 */
internal class Jbd2(
    private val bs: Int,
    private val fsBlocks: Long,
    private val home: (Long) -> Long,
    private val read: (Long, ByteArray) -> Unit,
    private val write: (Long, ByteArray) -> Unit,
) {
    private class Tag(val fsBlock: Long, val jBlock: Long, val escaped: Boolean)
    private class Tx(val tid: Int, val tags: List<Tag>)

    /** Replays the log; returns the number of blocks written home. Throws, having written nothing, on a bad log. */
    fun replay(): Int {
        val sb = block(0)
        if (be32(sb, 0) != MAGIC || be32(sb, 4).toInt() !in 3..4) throw Ext4Exception("Bad journal superblock")
        if (be32(sb, 0x0C).toInt() != bs) throw Ext4Exception("Journal block size differs from the filesystem's")
        val v2 = be32(sb, 4) == 4L
        val incompat = if (v2) be32(sb, 0x28).toInt() else 0
        if (incompat and KNOWN.inv() != 0) throw Ext4Exception("Unsupported journal features (0x%x)".format(incompat))
        val csum = incompat and (CSUM_V2 or CSUM_V3) != 0
        val v3 = incompat and CSUM_V3 != 0
        val wide = incompat and BIT64 != 0
        val seed = Crc32c.update(-1, sb, 0x30, 16)
        if (csum && sbCsum(sb) != be32(sb, 0xFC).toInt()) throw Ext4Exception("Bad journal superblock checksum")
        val maxLen = be32(sb, 0x10); val first = be32(sb, 0x14)
        var tid = be32(sb, 0x18).toInt()
        val start = be32(sb, 0x1C)
        if (start == 0L) return 0
        if (first < 1 || maxLen <= first || start !in first until maxLen) throw Ext4Exception("Bad journal geometry")
        fun next(b: Long) = if (b + 1 >= maxLen) first else b + 1
        val tagBytes = if (v3) 16 else 8 + (if (csum) 2 else 0) + (if (wide) 4 else 0)
        fun tailOk(b: ByteArray) = !csum || be32(b, bs - 4).toInt() == Crc32c.update(seed, b.copyOf().also { putBe32(it, bs - 4, 0) })

        // ---- scan: find the committed transactions and their revokes ----
        val txs = ArrayList<Tx>()
        val revoked = HashMap<Long, Int>()   // fs block -> last tid that revoked it
        var tags = ArrayList<Tag>(); var revokes = ArrayList<Long>()
        var b = start; var walked = 0L
        while (walked < maxLen) {
            val h = block(b)
            if (be32(h, 0) != MAGIC || be32(h, 8).toInt() != tid) break
            when (be32(h, 4).toInt()) {
                DESCRIPTOR -> {
                    if (!tailOk(h)) throw Ext4Exception("Bad journal descriptor checksum")
                    var o = 12
                    while (o + tagBytes <= bs - (if (csum) 4 else 0)) {
                        val flags = if (v3) be32(h, o + 4).toInt() else be16(h, o + 6)
                        val blk = be32(h, o) or (if (wide) be32(h, o + 8) shl 32 else 0)
                        b = next(b); walked++
                        if (csum) {
                            val sum = Crc32c.update(Crc32c.update(seed, be32Bytes(tid)), block(b))
                            val ok = if (v3) be32(h, o + 12).toInt() == sum else be16(h, o + 4) == sum and 0xffff
                            if (!ok) throw Ext4Exception("Bad journal data checksum")
                        }
                        if (blk >= fsBlocks) throw Ext4Exception("Journal block $blk is outside the filesystem")
                        tags.add(Tag(blk, b, flags and ESCAPE != 0))
                        o += tagBytes + (if (flags and SAME_UUID == 0) 16 else 0)
                        if (flags and LAST_TAG != 0) break
                    }
                }
                COMMIT -> {
                    if (csum) {
                        val z = h.copyOf().also { putBe32(it, 16, 0) }
                        if (be32(h, 16).toInt() != Crc32c.update(seed, z)) break   // torn commit: the log ends here
                    }
                    txs.add(Tx(tid, tags))
                    for (r in revokes) revoked[r] = tid
                    tags = ArrayList(); revokes = ArrayList(); tid++
                }
                REVOKE -> {
                    if (!tailOk(h)) throw Ext4Exception("Bad journal revoke checksum")
                    val rec = if (wide) 8 else 4
                    val end = minOf(be32(h, 12).toInt(), bs)
                    var o = 16
                    while (o + rec <= end) { revokes.add(if (wide) be32(h, o) shl 32 or be32(h, o + 4) else be32(h, o)); o += rec }
                }
                else -> break
            }
            b = next(b); walked++
        }

        // ---- replay, oldest first ----
        var n = 0
        for (tx in txs) for (t in tx.tags) {
            if (revoked[t.fsBlock]?.let { it - tx.tid >= 0 } == true) continue
            val d = block(t.jBlock)
            if (t.escaped) putBe32(d, 0, MAGIC)
            write(t.fsBlock, d); n++
        }

        // ---- empty log; the next transaction id skips any stale block of the unfinished one ----
        putBe32(sb, 0x18, (tid + 1).toLong()); putBe32(sb, 0x1C, 0)
        if (csum) putBe32(sb, 0xFC, sbCsum(sb).toLong() and 0xffffffffL)
        write(home(0), sb)
        return n
    }

    private fun block(j: Long) = ByteArray(bs).also { read(home(j), it) }
    private fun sbCsum(sb: ByteArray) = Crc32c.update(-1, sb.copyOf(1024).also { putBe32(it, 0xFC, 0) })

    companion object {
        const val MAGIC = 0xC03B3998L
        const val DESCRIPTOR = 1; const val COMMIT = 2; const val REVOKE = 5
        const val ESCAPE = 1; const val SAME_UUID = 2; const val LAST_TAG = 8
        const val REVOKE_FEATURE = 0x1; const val BIT64 = 0x2; const val ASYNC_COMMIT = 0x4
        const val CSUM_V2 = 0x8; const val CSUM_V3 = 0x10
        const val KNOWN = REVOKE_FEATURE or BIT64 or ASYNC_COMMIT or CSUM_V2 or CSUM_V3   // not fast_commit (0x20)

        fun be16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)
        fun be32(b: ByteArray, o: Int) = (be16(b, o).toLong() shl 16) or be16(b, o + 2).toLong()
        fun putBe32(b: ByteArray, o: Int, v: Long) { for (i in 0 until 4) b[o + i] = (v ushr (24 - 8 * i)).toByte() }
        fun be32Bytes(v: Int) = ByteArray(4).also { putBe32(it, 0, v.toLong()) }
    }
}
