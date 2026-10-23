package me.nocke.cryptic.vaults.luks

import me.nocke.cryptic.vaults.block.BlockDevice
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * luksFormat: writes a LUKS2 header laid out like cryptsetup 2.7's defaults (16 KiB headers, keyslots area up to
 * 16 MiB, data at 16 MiB, aes-xts-plain64 with a 512-bit key, one argon2id key slot, 4096-byte sectors).
 */
object LuksFormat {
    class Kdf(val memoryKib: Int = 1048576, val time: Int = 4, val lanes: Int = 4)

    private const val HDR = 16384L
    private const val KEYSLOTS_OFF = 2 * HDR
    const val DATA_OFFSET = 16L * 1024 * 1024
    private const val KEY = 64
    private const val STRIPES = 4000

    /** Destroys whatever is on [dev]. Returns the unlocked data segment. */
    fun format(dev: BlockDevice, passphrase: ByteArray, kdf: Kdf = Kdf(), sectorSize: Int = 4096, digestIterations: Int = 100_000,
               label: String = "", hash: String = "sha512"): CryptBlockDevice {
        require(label.toByteArray().size < 48) { "LUKS label is at most 47 bytes" }
        require(dev.size > DATA_OFFSET + 1024 * 1024) { "Device too small for LUKS2" }
        require(sectorSize % dev.sectorSize == 0 && sectorSize in listOf(512, 1024, 2048, 4096))
        val rnd = SecureRandom()
        val volumeKey = ByteArray(KEY).also { rnd.nextBytes(it) }

        // wipe headers and keyslot area so no old key material survives
        val z = ByteArray(1024 * 1024)
        var p = 0L
        while (p < DATA_OFFSET) { dev.write(p, z); p += z.size }

        // key slot 0: argon2id KEK -> AF-split volume key, encrypted into the area
        val kdfSalt = ByteArray(32).also { rnd.nextBytes(it) }
        val kdfJson = JSONObject().put("type", "argon2id").put("time", kdf.time).put("memory", kdf.memoryKib)
            .put("cpus", kdf.lanes).put("salt", b64(kdfSalt))
        val kek = Luks2.kdf(kdfJson, passphrase, KEY)
        val split = Af.split(volumeKey, STRIPES, hash, rnd)
        val areaLen = (split.size + 4095) / 4096 * 4096L
        val area = split.copyOf(((split.size + 511) / 512) * 512)
        Xts(kek).encrypt(area, 0, area.size, 512, 0)
        kek.fill(0)
        dev.write(KEYSLOTS_OFF, area.copyOf((area.size + dev.sectorSize - 1) / dev.sectorSize * dev.sectorSize))

        val digestSalt = ByteArray(32).also { rnd.nextBytes(it) }
        val digest = ByteArray(Luks2.digest(hash).digestSize).also { Luks2.pbkdf2(hash, volumeKey, digestSalt, digestIterations, it) }

        val json = JSONObject()
            .put("keyslots", JSONObject().put("0", JSONObject()
                .put("type", "luks2").put("key_size", KEY)
                .put("af", JSONObject().put("type", "luks1").put("stripes", STRIPES).put("hash", hash))
                .put("area", JSONObject().put("type", "raw").put("offset", KEYSLOTS_OFF.toString()).put("size", areaLen.toString())
                    .put("encryption", "aes-xts-plain64").put("key_size", KEY))
                .put("kdf", kdfJson)))
            .put("tokens", JSONObject())
            .put("segments", JSONObject().put("0", JSONObject()
                .put("type", "crypt").put("offset", DATA_OFFSET.toString()).put("size", "dynamic")
                .put("iv_tweak", "0").put("encryption", "aes-xts-plain64").put("sector_size", sectorSize)))
            .put("digests", JSONObject().put("0", JSONObject()
                .put("type", "pbkdf2").put("keyslots", JSONArray().put("0")).put("segments", JSONArray().put("0"))
                .put("hash", hash).put("iterations", digestIterations).put("salt", b64(digestSalt)).put("digest", b64(digest))))
            .put("config", JSONObject().put("json_size", (HDR - Luks2.BIN_SIZE).toString())
                .put("keyslots_size", (DATA_OFFSET - KEYSLOTS_OFF).toString()))
        val uuid = UUID.randomUUID().toString()
        writeHeaders(dev, uuid, label, 1, json.toString().toByteArray(Charsets.UTF_8))

        return CryptBlockDevice(dev, volumeKey, DATA_OFFSET, dev.size - DATA_OFFSET, sectorSize, 0, uuid, label)
    }

    /** Both binary headers + JSON areas; the secondary first, so a torn write leaves the old primary valid. */
    fun writeHeaders(dev: BlockDevice, uuid: String, label: String, seqId: Long, json: ByteArray, subsystem: String = "") {
        check(json.size < HDR - Luks2.BIN_SIZE)
        val salt = ByteArray(64).also { SecureRandom().nextBytes(it) }
        dev.write(HDR, header(Luks2.MAGIC2, HDR, uuid, salt, json, label, seqId, subsystem))
        dev.write(0, header(Luks2.MAGIC, 0, uuid, salt, json, label, seqId, subsystem))
        dev.flush()
    }

    private fun header(magic: ByteArray, offset: Long, uuid: String, salt: ByteArray, json: ByteArray, label: String, seqId: Long, subsystem: String): ByteArray {
        val h = ByteArray(HDR.toInt())
        magic.copyInto(h, 0)
        h[7] = 2
        putBe64(h, 8, HDR)
        putBe64(h, 16, seqId)
        label.toByteArray().copyInto(h, 24)
        subsystem.toByteArray().copyInto(h, 208)
        "sha256".toByteArray().copyInto(h, 72)
        salt.copyInto(h, 104)
        uuid.toByteArray().copyInto(h, 168)
        putBe64(h, 256, offset)
        json.copyInto(h, Luks2.BIN_SIZE)
        MessageDigest.getInstance("SHA-256").digest(h).copyInto(h, 448)
        return h
    }

    private fun putBe64(b: ByteArray, o: Int, v: Long) { for (i in 0 until 8) b[o + i] = (v ushr (56 - 8 * i)).toByte() }
    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)
}
