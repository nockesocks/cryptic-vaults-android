package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.luks.Luks2
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The app passphrase (Settings → App lock → App passphrase). The secret itself is never kept: one Argon2id run gives
 * 64 bytes, the first half stored as the verifier, the second half the key that protects saved vault passphrases.
 * The stored record is JSON: the KDF parameters with their salt, the verifier, and whether the passphrase met
 * [acceptable] when it was set.
 */
object AppSecret {
    /** A new record for [secret], and the key half. */
    fun create(secret: String, memoryKib: Int = 65536): Pair<String, ByteArray> {
        val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val kdf = JSONObject().put("type", "argon2id").put("time", 3).put("memory", memoryKib).put("cpus", 4)
            .put("salt", Base64.getEncoder().encodeToString(salt))
        val d = derive(kdf, secret)
        val record = JSONObject().put("kdf", kdf).put("check", Base64.getEncoder().encodeToString(d.copyOf(32)))
            .put("strong", acceptable(secret))
        return record.toString() to d.copyOfRange(32, 64).also { d.fill(0) }
    }

    const val MIN_LENGTH = 8

    /**
     * Whether [secret] may be an app passphrase at all: [MIN_LENGTH] or more characters and not digits only. A saved
     * passphrase is only as strong as this secret, so a PIN is refused at any length; eight characters is the
     * floor, with [weak] ones allowed only past a warning.
     */
    fun acceptable(secret: String) = secret.length >= MIN_LENGTH && secret.any { !it.isDigit() }

    /** Below "good" (64 bits) on the strength meter: allowed, but the user has to accept a warning first. */
    fun weak(secret: String) = Form.strength(secret).first < 64

    /** Whether the secret behind [record] was [acceptable] when it was set (records from before the rule may not be). */
    fun strong(record: String) = JSONObject(record).optBoolean("strong")

    /** The key half when [secret] is the one [record] was made from, else null. Slow (Argon2): off the main thread. */
    fun key(record: String, secret: String): ByteArray? {
        val r = JSONObject(record)
        val d = derive(r.getJSONObject("kdf"), secret)
        val ok = MessageDigest.isEqual(d.copyOf(32), Base64.getDecoder().decode(r.getString("check")))
        return (if (ok) d.copyOfRange(32, 64) else null).also { d.fill(0) }
    }

    private fun derive(kdf: JSONObject, secret: String): ByteArray {
        val pass = secret.toByteArray(Charsets.UTF_8)
        return try { Luks2.kdf(kdf, pass, 64) } finally { pass.fill(0) }
    }

    /** AES-256-GCM under [key]: a random 12-byte nonce, then the ciphertext with its tag. */
    fun seal(key: ByteArray, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES")) }
        return c.iv + c.doFinal(plain)
    }

    /** Inverse of [seal]; throws when the key is wrong or the data was altered. */
    fun open(key: ByteArray, blob: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob, 0, 12)) }
        return c.doFinal(blob, 12, blob.size - 12)
    }
}
