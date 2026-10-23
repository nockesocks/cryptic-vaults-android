package me.nocke.cryptic.vaults.block

import me.nocke.cryptic.vaults.luks.Luks2

/** Where LUKS volumes sit on a drive: the whole disk, or MBR/GPT partitions. */
object Partitions {
    class Found(val name: String, val start: Long, val size: Long)

    /** LUKS volumes on [dev]: the whole disk if it starts with a LUKS header, else each partition that does. */
    fun findLuks(dev: BlockDevice): List<Found> {
        if (Luks2.isLuks(dev)) return listOf(Found("whole drive", 0, dev.size))
        return list(dev).filter { p -> runCatching { Luks2.isLuks(SliceBlockDevice(dev, p.start, p.size)) }.getOrDefault(false) }
    }

    fun list(dev: BlockDevice): List<Found> {
        val ss = dev.sectorSize
        val mbr = ByteArray(maxOf(ss, 512)); dev.read(0, mbr)
        if ((mbr[510].toInt() and 0xff) != 0x55 || (mbr[511].toInt() and 0xff) != 0xaa) return emptyList()
        val entries = (0 until 4).map { 446 + 16 * it }.filter { mbr[it + 4] != 0.toByte() }
        if (entries.any { (mbr[it + 4].toInt() and 0xff) == 0xee }) return gpt(dev)
        return entries.mapIndexedNotNull { i, e ->
            val type = mbr[e + 4].toInt() and 0xff
            if (type == 0x05 || type == 0x0f || type == 0x85) return@mapIndexedNotNull null  // extended: logical partitions not supported
            val start = le32(mbr, e + 8) * ss; val size = le32(mbr, e + 12) * ss
            if (size == 0L || start + size > dev.size) null else Found("partition ${i + 1}", start, size)
        }
    }

    private fun gpt(dev: BlockDevice): List<Found> {
        val ss = dev.sectorSize
        val h = ByteArray(ss); dev.read(ss.toLong(), h)
        if (String(h, 0, 8, Charsets.US_ASCII) != "EFI PART") return emptyList()
        val entLba = le64(h, 72); val count = le32(h, 80).toInt(); val esz = le32(h, 84).toInt()
        if (count !in 1..1024 || esz !in 128..4096) return emptyList()
        val bytes = ((count.toLong() * esz + ss - 1) / ss * ss).toInt()
        val t = ByteArray(bytes); dev.read(entLba * ss, t)
        return (0 until count).mapNotNull { i ->
            val e = i * esz
            if ((0 until 16).all { t[e + it] == 0.toByte() }) return@mapNotNull null
            val first = le64(t, e + 32); val last = le64(t, e + 40)
            val name = String(CharArray(36) { (t[e + 56 + 2 * it].toInt() and 0xff or ((t[e + 57 + 2 * it].toInt() and 0xff) shl 8)).toChar() }).trimEnd('\u0000')
            val start = first * ss; val size = (last - first + 1) * ss
            if (last < first || start + size > dev.size) null else Found(name.ifEmpty { "partition ${i + 1}" }, start, size)
        }
    }

    private fun le32(b: ByteArray, o: Int): Long = (0 until 4).fold(0L) { v, i -> v or ((b[o + i].toLong() and 0xff) shl (8 * i)) }
    private fun le64(b: ByteArray, o: Int): Long = le32(b, o) or (le32(b, o + 4) shl 32)
}
