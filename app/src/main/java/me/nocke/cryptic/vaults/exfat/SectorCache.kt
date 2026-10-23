package me.nocke.cryptic.vaults.exfat

import me.nocke.cryptic.vaults.block.BlockDevice

/**
 * Byte-level read/write over a BlockDevice for file-system metadata (boot sector, FAT, bitmap, directories),
 * cached and written back in device-sector units. Not thread-safe; ExFat serializes access.
 */
class SectorCache(private val dev: BlockDevice, private val maxUnits: Int = 8192) {
    val unit = dev.sectorSize
    private val dirty = HashSet<Long>()
    private val map = object : LinkedHashMap<Long, ByteArray>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, ByteArray>): Boolean {
            if (size <= maxUnits) return false
            if (dirty.remove(eldest.key)) dev.write(eldest.key, eldest.value)
            return true
        }
    }

    private fun load(u: Long): ByteArray = map.getOrPut(u) { ByteArray(unit).also { dev.read(u, it) } }

    fun read(pos: Long, dst: ByteArray, off: Int = 0, len: Int = dst.size - off) {
        var p = pos; var o = off; var left = len
        while (left > 0) {
            val u = p - p % unit; val i = (p - u).toInt(); val n = minOf(left, unit - i)
            load(u).copyInto(dst, o, i, i + n)
            p += n; o += n; left -= n
        }
    }

    fun write(pos: Long, src: ByteArray, off: Int = 0, len: Int = src.size - off) {
        var p = pos; var o = off; var left = len
        while (left > 0) {
            val u = p - p % unit; val i = (p - u).toInt(); val n = minOf(left, unit - i)
            val b = if (i == 0 && n == unit) map.getOrPut(u) { ByteArray(unit) } else load(u)
            src.copyInto(b, i, o, o + n)
            dirty.add(u)
            p += n; o += n; left -= n
        }
    }

    fun zero(pos: Long, len: Long) {
        val z = ByteArray(minOf(len, 1L shl 20).toInt())
        var p = pos; var left = len
        while (left > 0) { val n = minOf(left, z.size.toLong()).toInt(); write(p, z, 0, n); p += n; left -= n }
    }

    fun u8(pos: Long): Int { val b = ByteArray(1); read(pos, b); return b[0].toInt() and 0xff }
    fun u32(pos: Long): Long { val b = ByteArray(4); read(pos, b); return le32(b, 0) }
    fun putU32(pos: Long, v: Long) { val b = ByteArray(4); putLe32(b, 0, v); write(pos, b) }

    /** Drops cached units inside [pos, pos+len) without writing them (the range was freed or rewritten as data). */
    fun invalidate(pos: Long, len: Long) {
        val first = pos - pos % unit
        if (len / unit < map.size) {
            var u = first
            while (u < pos + len) { map.remove(u); dirty.remove(u); u += unit }
        } else {
            val it = map.keys.iterator()
            while (it.hasNext()) { val u = it.next(); if (u >= first && u < pos + len) { it.remove(); dirty.remove(u) } }
        }
    }

    fun flush() {
        for (u in dirty.sorted()) dev.write(u, map.getValue(u))
        dirty.clear()
        dev.flush()
    }
}

internal fun le16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
internal fun le32(b: ByteArray, o: Int) = (le16(b, o).toLong()) or (le16(b, o + 2).toLong() shl 16)
internal fun le64(b: ByteArray, o: Int) = le32(b, o) or (le32(b, o + 4) shl 32)
internal fun putLe16(b: ByteArray, o: Int, v: Int) { b[o] = v.toByte(); b[o + 1] = (v ushr 8).toByte() }
internal fun putLe32(b: ByteArray, o: Int, v: Long) { for (i in 0 until 4) b[o + i] = (v ushr (8 * i)).toByte() }
internal fun putLe64(b: ByteArray, o: Int, v: Long) { for (i in 0 until 8) b[o + i] = (v ushr (8 * i)).toByte() }
