package me.nocke.cryptic.vaults.luks

import me.nocke.cryptic.vaults.block.BlockDevice
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

class NotLuksException(msg: String) : Exception(msg)
class WrongPassphraseException : Exception("No key slot accepts this passphrase")
class UnsupportedLuksException(msg: String) : Exception(msg)

/** LUKS2 on-disk format (gitlab.com/cryptsetup/LUKS2-docs): header parsing, unlock, decrypted segment. */
object Luks2 {
    val MAGIC = byteArrayOf('L'.code.toByte(), 'U'.code.toByte(), 'K'.code.toByte(), 'S'.code.toByte(), 0xba.toByte(), 0xbe.toByte())
    val MAGIC2 = byteArrayOf('S'.code.toByte(), 'K'.code.toByte(), 'U'.code.toByte(), 'L'.code.toByte(), 0xba.toByte(), 0xbe.toByte())
    const val BIN_SIZE = 4096
    private const val CSUM_OFF = 448

    class Header(val hdrSize: Long, val seqId: Long, val uuid: String, val json: JSONObject, val label: String = "", val subsystem: String = "")

    fun isLuks(dev: BlockDevice): Boolean {
        val b = ByteArray(maxOf(dev.sectorSize, 512)); dev.read(0, b)
        return b.copyOf(6).contentEquals(MAGIC)
    }

    /** The primary header if its checksum holds, else the secondary one; the newer when both hold. */
    fun readHeader(dev: BlockDevice): Header {
        val primary = runCatching { readHeaderAt(dev, 0, MAGIC) }
        val secOff = primary.getOrNull()?.hdrSize ?: 16384L
        val secondary = runCatching { readHeaderAt(dev, secOff, MAGIC2) }
        val p = primary.getOrNull(); val s = secondary.getOrNull()
        return when {
            p != null && s != null -> if (s.seqId > p.seqId) s else p
            p != null -> p
            s != null -> s
            else -> throw primary.exceptionOrNull()!!
        }
    }

    private fun readHeaderAt(dev: BlockDevice, at: Long, magic: ByteArray): Header {
        val bin = ByteArray(BIN_SIZE); dev.read(at, bin)
        if (!bin.copyOf(6).contentEquals(magic)) throw NotLuksException("No LUKS magic at $at")
        val version = u16(bin, 6)
        if (version != 2) throw UnsupportedLuksException("LUKS version $version (only LUKS2 is supported)")
        val hdrSize = u64(bin, 8)
        if (hdrSize < 16384 || hdrSize > 4 * 1024 * 1024 || hdrSize % 4096 != 0L) throw NotLuksException("Bad header size $hdrSize")
        val all = ByteArray(hdrSize.toInt()); dev.read(at, all)
        val alg = cstr(all, 72, 32)
        if (alg != "sha256") throw UnsupportedLuksException("Header checksum $alg")
        val stored = all.copyOfRange(CSUM_OFF, CSUM_OFF + 32)
        java.util.Arrays.fill(all, CSUM_OFF, CSUM_OFF + 64, 0)
        if (!MessageDigest.getInstance("SHA-256").digest(all).contentEquals(stored)) throw NotLuksException("Header checksum mismatch at $at")
        val jsonText = cstr(all, BIN_SIZE, all.size - BIN_SIZE)
        return Header(hdrSize, u64(bin, 16), cstr(bin, 168, 40), JSONObject(jsonText), cstr(bin, 24, 48), cstr(bin, 208, 48))
    }

    /** Tries every key slot; returns the volume key. */
    fun unlock(dev: BlockDevice, hdr: Header, passphrase: ByteArray): ByteArray = unlockSlot(dev, hdr, passphrase).second

    /** The key slot id the passphrase opens, and the volume key. */
    fun unlockSlot(dev: BlockDevice, hdr: Header, passphrase: ByteArray): Pair<String, ByteArray> {
        val slots = hdr.json.getJSONObject("keyslots")
        val digests = hdr.json.getJSONObject("digests")
        for (id in slots.keys().asSequence().sortedBy { it.toInt() }) {
            val ks = slots.getJSONObject(id)
            if (ks.getString("type") != "luks2") continue
            val key = openKeyslot(dev, ks, passphrase)
            for (dId in digests.keys()) {
                val d = digests.getJSONObject(dId)
                val covers = d.getJSONArray("keyslots").let { a -> (0 until a.length()).any { a.getString(it) == id } }
                if (covers && checkDigest(d, key)) return id to key
            }
            key.fill(0)
        }
        throw WrongPassphraseException()
    }

    private fun openKeyslot(dev: BlockDevice, ks: JSONObject, pass: ByteArray): ByteArray {
        val area = ks.getJSONObject("area")
        if (area.getString("type") != "raw") throw UnsupportedLuksException("Key slot area ${area.getString("type")}")
        val enc = area.getString("encryption")
        if (enc != "aes-xts-plain64") throw UnsupportedLuksException("Key slot cipher $enc")
        val af = ks.getJSONObject("af")
        if (af.getString("type") != "luks1") throw UnsupportedLuksException("AF ${af.getString("type")}")
        val keySize = ks.getInt("key_size")
        val stripes = af.getInt("stripes")
        val kek = kdf(ks.getJSONObject("kdf"), pass, area.getInt("key_size"))
        val len = keySize * stripes
        val padded = (len + 511) / 512 * 512
        val buf = ByteArray(padded)
        dev.read(area.getString("offset").toLong(), buf)
        Xts(kek).decrypt(buf, 0, padded, 512, 0)
        kek.fill(0)
        return Af.merge(buf, keySize, stripes, af.getString("hash"))
    }

    fun kdf(k: JSONObject, pass: ByteArray, outLen: Int): ByteArray {
        val salt = Base64.getDecoder().decode(k.getString("salt"))
        val out = ByteArray(outLen)
        when (val type = k.getString("type")) {
            "pbkdf2" -> pbkdf2(k.getString("hash"), pass, salt, k.getInt("iterations"), out)
            "argon2i", "argon2id" -> if (NativeArgon2.available) {
                val rc = NativeArgon2.hash(if (type == "argon2id") 2 else 1, k.getInt("time"), k.getInt("memory"), k.getInt("cpus"), pass, salt, out)
                if (rc != 0) throw IllegalStateException("Argon2 failed (code $rc): not enough memory for ${k.getInt("memory") / 1024} MiB?")
            } else {
                val p = Argon2Parameters.Builder(if (type == "argon2id") Argon2Parameters.ARGON2_id else Argon2Parameters.ARGON2_i)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(k.getInt("time")).withMemoryAsKB(k.getInt("memory"))
                    .withParallelism(k.getInt("cpus")).withSalt(salt).build()
                Argon2BytesGenerator().apply { init(p) }.generateBytes(pass, out)
            }
            else -> throw UnsupportedLuksException("KDF $type")
        }
        return out
    }

    fun pbkdf2(hash: String, pass: ByteArray, salt: ByteArray, iterations: Int, out: ByteArray) {
        val g = PKCS5S2ParametersGenerator(digest(hash))
        g.init(pass, salt, iterations)
        (g.generateDerivedParameters(out.size * 8) as KeyParameter).key.copyInto(out)
    }

    private fun checkDigest(d: JSONObject, key: ByteArray): Boolean {
        if (d.getString("type") != "pbkdf2") return false
        val want = Base64.getDecoder().decode(d.getString("digest"))
        val got = ByteArray(want.size)
        pbkdf2(d.getString("hash"), key, Base64.getDecoder().decode(d.getString("salt")), d.getInt("iterations"), got)
        return MessageDigest.isEqual(want, got)
    }

    /** The decrypted data segment (segment 0) as a read-write block device. */
    fun open(dev: BlockDevice, passphrase: ByteArray): CryptBlockDevice {
        val hdr = readHeader(dev)
        val seg = hdr.json.getJSONObject("segments").getJSONObject("0")
        if (seg.getString("type") != "crypt") throw UnsupportedLuksException("Segment ${seg.getString("type")}")
        val enc = seg.getString("encryption")
        if (enc != "aes-xts-plain64") throw UnsupportedLuksException("Data cipher $enc")
        if (seg.has("integrity")) throw UnsupportedLuksException("dm-integrity segments")
        if (hdr.json.optJSONObject("config")?.optJSONArray("requirements") != null) throw UnsupportedLuksException("Header has requirements (reencryption in progress?)")
        val key = unlock(dev, hdr, passphrase)
        val offset = seg.getString("offset").toLong()
        val sizeStr = seg.getString("size")
        val size = if (sizeStr == "dynamic") dev.size - offset else sizeStr.toLong()
        return CryptBlockDevice(dev, key, offset, size, seg.getInt("sector_size"), seg.optString("iv_tweak", "0").toLong(), hdr.uuid, hdr.label)
    }

    fun digest(name: String): Digest = when (name) {
        "sha1" -> SHA1Digest()
        "sha256" -> SHA256Digest()
        "sha512" -> SHA512Digest()
        else -> throw UnsupportedLuksException("Hash $name")
    }

    internal fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)
    internal fun u64(b: ByteArray, o: Int): Long { var v = 0L; for (i in 0 until 8) v = (v shl 8) or (b[o + i].toLong() and 0xff); return v }
    private fun cstr(b: ByteArray, o: Int, max: Int): String {
        var e = o; while (e < o + max && b[e] != 0.toByte()) e++
        return String(b, o, e - o, Charsets.UTF_8)
    }
}

/** LUKS1-style anti-forensic splitter (used by LUKS2 "af": {"type": "luks1"}). */
object Af {
    fun merge(src: ByteArray, keySize: Int, stripes: Int, hash: String): ByteArray {
        val d = ByteArray(keySize)
        for (i in 0 until stripes - 1) {
            for (j in 0 until keySize) d[j] = (d[j].toInt() xor src[i * keySize + j].toInt()).toByte()
            diffuse(d, hash)
        }
        val last = (stripes - 1) * keySize
        return ByteArray(keySize) { (d[it].toInt() xor src[last + it].toInt()).toByte() }
    }

    /** Inverse of [merge]: random stripes such that merge(split(key)) == key. */
    fun split(key: ByteArray, stripes: Int, hash: String, random: java.security.SecureRandom): ByteArray {
        val n = key.size
        val out = ByteArray(n * stripes)
        random.nextBytes(out)
        val d = ByteArray(n)
        for (i in 0 until stripes - 1) {
            for (j in 0 until n) d[j] = (d[j].toInt() xor out[i * n + j].toInt()).toByte()
            diffuse(d, hash)
        }
        for (j in 0 until n) out[(stripes - 1) * n + j] = (d[j].toInt() xor key[j].toInt()).toByte()
        return out
    }

    private fun diffuse(d: ByteArray, hash: String) {
        val md = Luks2.digest(hash)
        val hs = md.digestSize
        val h = ByteArray(hs)
        var block = 0
        var pos = 0
        while (pos < d.size) {
            val len = minOf(hs, d.size - pos)
            md.update((block ushr 24).toByte()); md.update((block ushr 16).toByte())
            md.update((block ushr 8).toByte()); md.update(block.toByte())
            md.update(d, pos, len)
            md.doFinal(h, 0)
            h.copyInto(d, pos, 0, len)
            pos += len; block++
        }
    }
}

/** Plaintext view of an aes-xts-plain64 segment; IVs count 512-byte units whatever the sector size (dm-crypt without iv_large_sectors). */
class CryptBlockDevice(
    /** The device holding the LUKS2 header (a partition slice or a container file). */
    val base: BlockDevice,
    key: ByteArray,
    private val dataOffset: Long,
    override val size: Long,
    override val sectorSize: Int,
    private val ivTweak: Long,
    /** The LUKS header UUID: a stable identity for the volume across unlocks. */
    val uuid: String = "",
    /** The LUKS header label as it was at unlock. */
    val label: String = "",
) : BlockDevice {
    private val xts = Xts(key).also { key.fill(0) }
    private var scratch = ByteArray(0)

    // One lock per device; per-thread Xts instances if parallel I/O matters
    @Synchronized
    override fun read(offset: Long, buf: ByteArray, off: Int, len: Int) {
        check(offset % sectorSize == 0L && len % sectorSize == 0 && offset + len <= size)
        base.read(dataOffset + offset, buf, off, len)
        xts.decrypt(buf, off, len, sectorSize, ivTweak + offset / 512, sectorSize / 512L)
    }

    @Synchronized
    override fun write(offset: Long, buf: ByteArray, off: Int, len: Int) {
        check(offset % sectorSize == 0L && len % sectorSize == 0 && offset + len <= size)
        if (scratch.size < len) scratch = ByteArray(len)
        buf.copyInto(scratch, 0, off, off + len)
        xts.encrypt(scratch, 0, len, sectorSize, ivTweak + offset / 512, sectorSize / 512L)
        base.write(dataOffset + offset, scratch, 0, len)
    }

    override fun flush() = base.flush()
    override fun close() = base.close()
}
