package me.nocke.cryptic.vaults.ext4

/** Linux crc32c_le (Castagnoli, reflected) without the final inversion, as ext4's metadata checksums use it. */
object Crc32c {
    private val table = IntArray(256) { n ->
        var c = n
        repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0x82F63B78.toInt() else c ushr 1 }
        c
    }

    fun update(crc: Int, b: ByteArray, off: Int = 0, len: Int = b.size - off): Int {
        var c = crc
        for (i in off until off + len) c = table[(c xor b[i].toInt()) and 0xff] xor (c ushr 8)
        return c
    }

    fun le32(crc: Int, v: Int) = update(crc, byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte()))
}
