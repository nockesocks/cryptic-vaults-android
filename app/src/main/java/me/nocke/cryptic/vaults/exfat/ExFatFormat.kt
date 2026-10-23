package me.nocke.cryptic.vaults.exfat

import me.nocke.cryptic.vaults.block.BlockDevice
import java.security.SecureRandom

/** mkfs.exfat: an empty exFAT volume (one FAT, bitmap + up-case table + root directory), exfatprogs-style defaults. */
object ExFatFormat {
    private const val ALIGN = 1024L * 1024

    fun format(dev: BlockDevice, label: String = "") {
        require(label.length <= 11) { "Label is at most 11 characters" }
        val bps = dev.sectorSize
        val bpsShift = Integer.numberOfTrailingZeros(bps)
        val size = dev.size
        val clusterSize = when { size <= 256L shl 20 -> 4096; size <= 32L shl 30 -> 32768; else -> 131072 }.coerceAtLeast(bps)
        val spc = clusterSize / bps
        val totalSectors = size / bps

        val fatOffset = ALIGN / bps
        var clusterCount = ((totalSectors - fatOffset) / spc).toInt()
        var fatLength = 0L; var heapOffset = 0L
        repeat(3) {
            fatLength = ((clusterCount + 2) * 4L + bps - 1) / bps
            heapOffset = (fatOffset + fatLength + ALIGN / bps - 1) / (ALIGN / bps) * (ALIGN / bps)
            clusterCount = ((totalSectors - heapOffset) / spc).toInt()
        }
        require(clusterCount > 16) { "Volume too small for exFAT" }

        val bitmapLen = (clusterCount + 7) / 8
        val upcase = upcaseTable()
        val bitmapClusters = (bitmapLen + clusterSize - 1) / clusterSize
        val upcaseClusters = (upcase.size + clusterSize - 1) / clusterSize
        val bitmapFirst = 2; val upcaseFirst = bitmapFirst + bitmapClusters; val rootFirst = upcaseFirst + upcaseClusters
        val used = rootFirst + 1 - 2

        // zero boot regions, FAT and the clusters we use
        zero(dev, 0, fatOffset * bps + fatLength * bps)
        zero(dev, heapOffset * bps, used.toLong() * clusterSize)

        // FAT
        val fat = ByteArray((fatLength * bps).toInt())
        putLe32(fat, 0, 0xFFFFFFF8L); putLe32(fat, 4, 0xFFFFFFFFL)
        fun chain(first: Int, n: Int) { for (i in 0 until n) putLe32(fat, 4 * (first + i), if (i == n - 1) 0xFFFFFFFFL else (first + i + 1).toLong()) }
        chain(bitmapFirst, bitmapClusters); chain(upcaseFirst, upcaseClusters); chain(rootFirst, 1)
        dev.write(fatOffset * bps, fat)

        fun clusterPos(c: Int) = heapOffset * bps + (c - 2).toLong() * clusterSize
        // bitmap
        val bitmap = ByteArray(bitmapClusters * clusterSize)
        for (c in 0 until used) bitmap[c ushr 3] = (bitmap[c ushr 3].toInt() or (1 shl (c and 7))).toByte()
        dev.write(clusterPos(bitmapFirst), bitmap)
        // up-case table
        dev.write(clusterPos(upcaseFirst), upcase.copyOf(upcaseClusters * clusterSize))
        // root directory: label, bitmap, up-case entries
        val root = ByteArray(clusterSize)
        root[0] = 0x83.toByte(); root[1] = label.length.toByte()
        for (i in label.indices) putLe16(root, 2 + 2 * i, label[i].code)
        root[32] = 0x81.toByte(); putLe32(root, 52, bitmapFirst.toLong()); putLe64(root, 56, bitmapLen.toLong())
        root[64] = 0x82.toByte(); putLe32(root, 68, checksum(upcase, upcase.size, false)); putLe32(root, 84, upcaseFirst.toLong()); putLe64(root, 88, upcase.size.toLong())
        dev.write(clusterPos(rootFirst), root)

        // boot region (sectors 0-11) and its backup (12-23)
        val region = ByteArray(12 * bps)
        val b = region
        b[0] = 0xEB.toByte(); b[1] = 0x76; b[2] = 0x90.toByte()
        "EXFAT   ".toByteArray().copyInto(b, 3)
        putLe64(b, 72, totalSectors)
        putLe32(b, 80, fatOffset); putLe32(b, 84, fatLength)
        putLe32(b, 88, heapOffset); putLe32(b, 92, clusterCount.toLong()); putLe32(b, 96, rootFirst.toLong())
        putLe32(b, 100, SecureRandom().nextInt().toLong())
        putLe16(b, 104, 0x0100)
        b[108] = bpsShift.toByte(); b[109] = Integer.numberOfTrailingZeros(spc).toByte(); b[110] = 1; b[111] = 0x80.toByte()
        b[112] = 0
        for (i in 120 until 510) b[i] = 0xF4.toByte()
        b[510] = 0x55; b[511] = 0xAA.toByte()
        for (s in 1..8) { b[s * bps + bps - 2] = 0x55; b[s * bps + bps - 1] = 0xAA.toByte() }
        val sum = checksum(region, 11 * bps, true)
        for (i in 0 until bps / 4) putLe32(region, 11 * bps + 4 * i, sum)
        dev.write(0, region)
        dev.write(12L * bps, region)
        dev.flush()
    }

    private fun zero(dev: BlockDevice, at: Long, len: Long) {
        val z = ByteArray(1024 * 1024); var p = at; val end = at + len
        while (p < end) { val n = minOf(end - p, z.size.toLong()).toInt(); dev.write(p, z, 0, n); p += n }
    }

    /** exFAT boot (skipping VolumeFlags and PercentInUse) and up-case table checksums. */
    private fun checksum(b: ByteArray, len: Int, boot: Boolean): Long {
        var c = 0L
        for (i in 0 until len) {
            if (boot && (i == 106 || i == 107 || i == 112)) continue
            c = ((if (c and 1L != 0L) 0x80000000L else 0L) + (c ushr 1) + (b[i].toLong() and 0xff)) and 0xffffffffL
        }
        return c
    }

    /** Compressed up-case table from Java's single-char upper-case mapping: identity runs as 0xFFFF, length. */
    private fun upcaseTable(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun u16(v: Int) { out.write(v and 0xff); out.write(v ushr 8) }
        var c = 0
        while (c < 65536) {
            val up = Character.toUpperCase(c.toChar()).code
            if (up == c) {
                var run = 0
                while (c + run < 65536 && run < 30000 && Character.toUpperCase((c + run).toChar()).code == c + run) run++
                if (run > 2) { u16(0xFFFF); u16(run); c += run; continue }
                u16(c); c++
            } else { u16(up); c++ }
        }
        return out.toByteArray()
    }
}
