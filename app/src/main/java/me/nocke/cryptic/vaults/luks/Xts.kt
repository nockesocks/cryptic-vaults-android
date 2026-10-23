package me.nocke.cryptic.vaults.luks

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * AES-XTS with the plain64 IV (little-endian sector number), as dm-crypt "aes-xts-plain64".
 * Sector lengths are multiples of 16, so no ciphertext stealing. Not thread-safe: one instance per thread.
 */
class Xts(key: ByteArray) {
    private val enc: Cipher
    private val dec: Cipher
    private val tweakCipher: Cipher

    init {
        require(key.size == 32 || key.size == 64) { "XTS key must be 256 or 512 bits" }
        val half = key.size / 2
        val k1 = SecretKeySpec(key, 0, half, "AES")
        val k2 = SecretKeySpec(key, half, half, "AES")
        enc = Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, k1) }
        dec = Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.DECRYPT_MODE, k1) }
        tweakCipher = Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, k2) }
    }

    /** [firstIv] is the IV of the first sector; each following sector adds [ivStep]. */
    fun encrypt(buf: ByteArray, off: Int, len: Int, sectorSize: Int, firstIv: Long, ivStep: Long = 1) =
        run(enc, buf, off, len, sectorSize, firstIv, ivStep)

    fun decrypt(buf: ByteArray, off: Int, len: Int, sectorSize: Int, firstIv: Long, ivStep: Long = 1) =
        run(dec, buf, off, len, sectorSize, firstIv, ivStep)

    private val tweaks = ByteArray(65536)

    private fun run(c: Cipher, buf: ByteArray, off: Int, len: Int, sectorSize: Int, firstIv: Long, ivStep: Long) {
        require(len % sectorSize == 0 && sectorSize % 16 == 0 && sectorSize <= tweaks.size)
        var s = 0
        while (s < len) {
            val p = off + s
            fillTweaks(firstIv + (s / sectorSize) * ivStep, sectorSize)
            for (i in 0 until sectorSize) buf[p + i] = (buf[p + i].toInt() xor tweaks[i].toInt()).toByte()
            c.doFinal(buf, p, sectorSize, buf, p)
            for (i in 0 until sectorSize) buf[p + i] = (buf[p + i].toInt() xor tweaks[i].toInt()).toByte()
            s += sectorSize
        }
    }

    /** tweaks[16j..16j+15] = E_K2(iv) * alpha^j in GF(2^128), little-endian. */
    private fun fillTweaks(sector: Long, sectorSize: Int) {
        val iv = ByteArray(16)
        for (i in 0 until 8) iv[i] = (sector ushr (8 * i)).toByte()
        tweakCipher.doFinal(iv, 0, 16, tweaks, 0)
        var j = 16
        while (j < sectorSize) {
            var carry = 0
            for (i in 0 until 16) {
                val b = tweaks[j - 16 + i].toInt() and 0xff
                tweaks[j + i] = ((b shl 1) or carry).toByte()
                carry = b ushr 7
            }
            if (carry != 0) tweaks[j] = (tweaks[j].toInt() xor 0x87).toByte()
            j += 16
        }
    }
}
