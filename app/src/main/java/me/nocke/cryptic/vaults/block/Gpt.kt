package me.nocke.cryptic.vaults.block

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.zip.CRC32

/** Writes GUID partition tables: one Linux-filesystem partition over the drive (as `sfdisk` with ",,L"), and renames. */
object Gpt {
    private const val ENTRIES = 128
    private const val ENTRY_SIZE = 128
    private val LINUX_FS = UUID.fromString("0FC63DAF-8483-4772-8E79-3D69D8477DE4")

    /** Fresh GPT with one partition from 1 MiB to the end (1 MiB aligned); returns it as a slice. */
    fun singlePartition(dev: BlockDevice, name: String): SliceBlockDevice {
        val ss = dev.sectorSize.toLong()
        val lbas = dev.size / ss
        val entryLbas = (ENTRIES * ENTRY_SIZE + ss - 1) / ss
        val firstUsable = 2 + entryLbas
        val lastUsable = lbas - 2 - entryLbas
        val align = (1L shl 20) / ss
        val first = maxOf(align, (firstUsable + align - 1) / align * align)
        val last = (lastUsable + 1) / align * align - 1
        require(last > first) { "Drive too small" }

        val entries = ByteArray(ENTRIES * ENTRY_SIZE)
        guid(LINUX_FS).copyInto(entries, 0)
        guid(UUID.randomUUID()).copyInto(entries, 16)
        le(entries, 32, first); le(entries, 40, last)
        name.take(36).forEachIndexed { i, ch -> entries[56 + 2 * i] = ch.code.toByte(); entries[57 + 2 * i] = (ch.code ushr 8).toByte() }
        val diskGuid = guid(UUID.randomUUID())

        // clear the gap before the partition, as wipefs would: an old LUKS2 secondary header (at 16 KiB) must not survive
        val z = ByteArray((first * ss).toInt()); dev.write(0, z)
        // protective MBR, then backup and primary GPT (primary last, so a half-written table isn't trusted)
        val mbr = ByteArray(ss.toInt())
        mbr[446 + 4] = 0xEE.toByte()
        le32(mbr, 446 + 8, 1); le32(mbr, 446 + 12, minOf(lbas - 1, 0xFFFFFFFFL))
        mbr[446 + 1] = 0; mbr[446 + 2] = 2; mbr[446 + 5] = 0xFF.toByte(); mbr[446 + 6] = 0xFF.toByte(); mbr[446 + 7] = 0xFF.toByte()
        mbr[510] = 0x55; mbr[511] = 0xAA.toByte()
        val entryBytes = entries.copyOf((entryLbas * ss).toInt())
        dev.write((lbas - 1 - entryLbas) * ss, entryBytes)
        dev.write((lbas - 1) * ss, header(ss, lbas - 1, 1, firstUsable, lastUsable, diskGuid, lbas - 1 - entryLbas, entries))
        dev.write(2 * ss, entryBytes)
        dev.write(ss, header(ss, 1, lbas - 1, firstUsable, lastUsable, diskGuid, 2, entries))
        dev.write(0, mbr)
        dev.flush()
        return SliceBlockDevice(dev, first * ss, (last - first + 1) * ss)
    }

    /** Renames the partition that starts at byte [start], in both copies of the table. */
    fun renameAt(dev: BlockDevice, start: Long, name: String) {
        val ss = dev.sectorSize.toLong()
        val h = ByteArray(ss.toInt()); dev.read(ss, h)
        val bb = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN)
        val count = bb.getInt(80); val esz = bb.getInt(84)
        val t = ByteArray(((count.toLong() * esz + ss - 1) / ss * ss).toInt()); dev.read(bb.getLong(72) * ss, t)
        val i = (0 until count).firstOrNull { ByteBuffer.wrap(t, it * esz + 32, 8).order(ByteOrder.LITTLE_ENDIAN).long * ss == start }
            ?: throw IllegalStateException("No GPT partition starts there")
        rename(dev, i, name)
    }

    /** Renames partition [index] (0-based) in both copies of the table. */
    fun rename(dev: BlockDevice, index: Int, name: String) {
        val ss = dev.sectorSize.toLong()
        for (hdrLba in listOf(1L, dev.size / ss - 1)) {
            val h = ByteArray(ss.toInt()); dev.read(hdrLba * ss, h)
            if (String(h, 0, 8, Charsets.US_ASCII) != "EFI PART") continue
            val bb = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN)
            val entLba = bb.getLong(72); val count = bb.getInt(80); val esz = bb.getInt(84)
            val len = ((count.toLong() * esz + ss - 1) / ss * ss).toInt()
            val t = ByteArray(len); dev.read(entLba * ss, t)
            val o = index * esz
            java.util.Arrays.fill(t, o + 56, o + 128, 0)
            name.take(36).forEachIndexed { i, ch -> t[o + 56 + 2 * i] = ch.code.toByte(); t[o + 57 + 2 * i] = (ch.code ushr 8).toByte() }
            dev.write(entLba * ss, t)
            bb.putInt(88, crc(t, 0, count * esz))
            bb.putInt(16, 0); bb.putInt(16, crc(h, 0, bb.getInt(12)))
            dev.write(hdrLba * ss, h)
        }
        dev.flush()
    }

    /** The GPT name of the partition starting at byte [start], or null (not GPT / not found). */
    fun nameAt(dev: BlockDevice, start: Long): String? = runCatching {
        val ss = dev.sectorSize.toLong()
        val h = ByteArray(ss.toInt()); dev.read(ss, h)
        if (String(h, 0, 8, Charsets.US_ASCII) != "EFI PART") return null
        val bb = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN)
        val count = bb.getInt(80); val esz = bb.getInt(84)
        val t = ByteArray(((count.toLong() * esz + ss - 1) / ss * ss).toInt()); dev.read(bb.getLong(72) * ss, t)
        val i = (0 until count).firstOrNull { ByteBuffer.wrap(t, it * esz + 32, 8).order(ByteOrder.LITTLE_ENDIAN).long * ss == start } ?: return null
        String(CharArray(36) { k -> ((t[i * esz + 56 + 2 * k].toInt() and 0xff) or ((t[i * esz + 57 + 2 * k].toInt() and 0xff) shl 8)).toChar() }).trimEnd('\u0000')
    }.getOrNull()

    /** Partition names, in table order (GPT only). */
    fun names(dev: BlockDevice): List<String> {
        val ss = dev.sectorSize.toLong()
        val h = ByteArray(ss.toInt()); dev.read(ss, h)
        if (String(h, 0, 8, Charsets.US_ASCII) != "EFI PART") return emptyList()
        val bb = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN)
        val count = bb.getInt(80); val esz = bb.getInt(84)
        val t = ByteArray(((count.toLong() * esz + ss - 1) / ss * ss).toInt()); dev.read(bb.getLong(72) * ss, t)
        return (0 until count).filter { i -> (0 until 16).any { t[i * esz + it] != 0.toByte() } }.map { i ->
            String(CharArray(36) { k -> ((t[i * esz + 56 + 2 * k].toInt() and 0xff) or ((t[i * esz + 57 + 2 * k].toInt() and 0xff) shl 8)).toChar() }).trimEnd('\u0000')
        }
    }

    private fun header(ss: Long, my: Long, alt: Long, firstUsable: Long, lastUsable: Long, disk: ByteArray, entLba: Long, entries: ByteArray): ByteArray {
        val h = ByteArray(ss.toInt())
        val bb = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN)
        bb.put("EFI PART".toByteArray()); bb.putInt(8, 0x00010000); bb.putInt(12, 92)
        bb.putLong(24, my); bb.putLong(32, alt); bb.putLong(40, firstUsable); bb.putLong(48, lastUsable)
        disk.copyInto(h, 56)
        bb.putLong(72, entLba); bb.putInt(80, ENTRIES); bb.putInt(84, ENTRY_SIZE); bb.putInt(88, crc(entries, 0, entries.size))
        bb.putInt(16, crc(h, 0, 92))
        return h
    }

    private fun crc(b: ByteArray, off: Int, len: Int) = CRC32().apply { update(b, off, len) }.value.toInt()

    /** GUIDs on disk: the first three fields little-endian. */
    private fun guid(u: UUID): ByteArray {
        val b = ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()
        return byteArrayOf(b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]) + b.copyOfRange(8, 16)
    }

    private fun le(b: ByteArray, o: Int, v: Long) { for (i in 0 until 8) b[o + i] = (v ushr (8 * i)).toByte() }
    private fun le32(b: ByteArray, o: Int, v: Long) { for (i in 0 until 4) b[o + i] = (v ushr (8 * i)).toByte() }
}
