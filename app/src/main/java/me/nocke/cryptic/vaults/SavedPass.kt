package me.nocke.cryptic.vaults

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Vault passphrases saved on this phone, by LUKS UUID (Settings → App lock → Saved vault passphrases; only with app
 * lock on, and only where [problem] is null). A saved passphrase is exactly as strong as what releases it, so only two
 * protections exist, never a PIN of any length:
 *  - fingerprint-or-face method: an RSA key pair in the Android Keystore. Saving encrypts with the public half and
 *    needs no prompt (so a changed vault passphrase can be updated by itself); reading back needs a strong biometric
 *    for every use. The phone's PIN, pattern or password can't release the private half, and enrolling a new biometric
 *    destroys it. Stored: the RSA-wrapped one-time AES key (256 bytes), then AES-GCM of the passphrase;
 *  - app-passphrase method (the passphrase passes [AppSecret.acceptable]) and YubiKey method: AES-GCM under the key
 *    derived from the passphrase, or from the secret the YubiKey returns for its PIN and a touch; wrapped once more by
 *    a Keystore key so the stored data is useless off this phone.
 * Kept in the app's private preferences (never backed up: allowBackup is off): the UUID maps to base64 of the above,
 * and "name:UUID" to the vault's name for the Manage screen.
 */
class SavedPass(private val a: Activity) {
    private val p = a.getSharedPreferences("saved_pass", Context.MODE_PRIVATE)
    private val prefs = Prefs(a)
    private val biometric get() = prefs.lockMethod == Prefs.LockMethod.PHONE

    class Entry(val uuid: String, val name: String)

    /** The saved vaults, by name. */
    fun list(): List<Entry> = p.all.keys.filter { !it.startsWith(NAME) }.map { Entry(it, p.getString(NAME + it, null) ?: it) }.sortedBy { it.name.lowercase() }
    val count get() = p.all.keys.count { !it.startsWith(NAME) }
    fun has(uuid: String) = uuid.isNotEmpty() && p.contains(uuid)
    fun forget(uuid: String) = p.edit().remove(uuid).remove(NAME + uuid).apply()

    /** Forgets every saved passphrase and destroys the keys that protected them; the warning shows again before the next first save. */
    fun clear() {
        p.edit().clear().apply()
        prefs.saveWarned = false
        val ks = keyStore()
        for (alias in listOf(BIO, WRAP)) runCatching { ks.deleteEntry(alias) }
    }

    /** What the user sees as the protection, for texts. */
    val protection get() = when (prefs.lockMethod) {
        Prefs.LockMethod.PHONE -> "your fingerprint or face"
        Prefs.LockMethod.APP -> "your app passphrase"
        Prefs.LockMethod.YUBIKEY -> "your YubiKey and its PIN"
    }

    /** Why passphrases can't be saved under the current app lock, or null when they can. */
    val problem: String? get() = when {
        !prefs.appLock -> "Turn on app lock first."
        biometric -> if (LockedActivity.biometricReady(a)) null
            else "Saving needs a fingerprint or face unlock that Android rates as strong, and this phone has none set up. " +
                "Add one in Android settings, or switch Cryptic Vaults' unlock to an app passphrase."
        prefs.lockMethod == Prefs.LockMethod.YUBIKEY || AppSecret.strong(prefs.appSecret!!) -> null
        else -> "Saving needs an app passphrase of ${AppSecret.MIN_LENGTH} or more characters that isn't only digits. " +
            "Yours was set before that rule. Change it under App lock."
    }

    /**
     * Before the first passphrase is saved under the unlock method in force: what saving means, in plain words: the
     * saved passphrases are only as strong as what unlocks the app. [save] runs
     * at once when the user has already seen it, or on "Save"; [no] on "Don't save".
     */
    fun confirmFirst(save: () -> Unit, no: () -> Unit) {
        if (prefs.saveWarned) return save()
        android.app.AlertDialog.Builder(a).setTitle("Save this passphrase on the phone?")
            .setMessage("Cryptic Vaults keeps it here, encrypted, so you open this vault with $protection instead of typing it.\n\n" +
                "Before you save your first one:\n\n" +
                "• A saved passphrase is only as strong as what unlocks it. Whoever gets past $protection opens every vault saved here, however long those vaults' own passphrases are.\n\n" +
                when (prefs.lockMethod) {
                    Prefs.LockMethod.PHONE -> "• The key sits in this phone's secure hardware and only a fingerprint or face releases it. The phone's PIN or pattern can't, on purpose: " +
                        "a 4-digit PIN in front of a long passphrase would turn that vault into a 4-digit vault.\n\n" +
                        "• A fingerprint or face can be forced or taken from you. A passphrase in your head can't.\n\n" +
                        "• Adding or removing a fingerprint or face erases the saved passphrases.\n\n"
                    Prefs.LockMethod.APP -> "• They're encrypted with your app passphrase, which is why Cryptic Vaults insists on a long one and refuses a PIN of any length.\n\n" +
                        "• Changing the app passphrase, or how Cryptic Vaults unlocks, erases the saved passphrases.\n\n"
                    Prefs.LockMethod.YUBIKEY -> "• They're encrypted with a secret that only your YubiKey gives out, and only for its PIN and a touch. The key alone isn't enough, and neither is the PIN.\n\n" +
                        "• If the YubiKey is lost, broken or reset, the saved passphrases are gone for good. So is the way into Cryptic Vaults, short of clearing its data.\n\n" +
                        "• Changing how Cryptic Vaults unlocks erases the saved passphrases.\n\n"
                } +
                "• Don't save the passphrase of a vault you couldn't afford to have opened, and keep every passphrase somewhere else as well: this is a convenience, not a backup.")
            .setPositiveButton("Save") { _, _ -> prefs.saveWarned = true; save() }
            .setNegativeButton("Don't save") { _, _ -> no() }.setOnCancelListener { no() }.show()
    }

    /** Saves [pass] (wiped here) for the vault [uuid], shown as [name]; returns whether it was saved. No prompt. */
    fun save(uuid: String, name: String, pass: ByteArray): Boolean = try {
        val blob = if (biometric) {
            val once = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val wrap = Cipher.getInstance(RSA).apply { init(Cipher.ENCRYPT_MODE, publicKey(), OAEP) }
            (wrap.doFinal(once) + AppSecret.seal(once, pass)).also { once.fill(0) }
        } else {
            val key = LockedActivity.appKey ?: throw IllegalStateException("the app passphrase key isn't in memory")
            val c = Cipher.getInstance(GCM).apply { init(Cipher.ENCRYPT_MODE, wrapKey()) }
            c.iv + c.doFinal(AppSecret.seal(key, pass))
        }
        p.edit().putString(uuid, Base64.getEncoder().encodeToString(blob)).putString(NAME + uuid, name).apply()
        true
    } catch (e: Exception) { AppLog.e("save passphrase", e); false } finally { pass.fill(0) }

    /** The saved passphrase for [uuid], or null (cancelled, or it could no longer be decrypted and all were dropped). */
    fun load(uuid: String, title: String, done: (ByteArray?) -> Unit) {
        try {
            val blob = Base64.getDecoder().decode(p.getString(uuid, null) ?: return done(null))
            if (!biometric) {
                val key = LockedActivity.appKey ?: return done(null)
                val c = Cipher.getInstance(GCM).apply { init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, blob, 0, 12)) }
                return done(AppSecret.open(key, c.doFinal(blob, 12, blob.size - 12)))
            }
            val unwrap = Cipher.getInstance(RSA).apply { init(Cipher.DECRYPT_MODE, keyStore().getKey(BIO, null) as PrivateKey, OAEP) }
            prompt("Unlock $title", unwrap) { ready ->
                done(ready?.let { r ->
                    runCatching { val once = r.doFinal(blob, 0, WRAPPED); AppSecret.open(once, blob.copyOfRange(WRAPPED, blob.size)).also { once.fill(0) } }
                        .onFailure { lost(it) }.getOrNull()
                })
            }
        } catch (e: Exception) { lost(e); done(null) }
    }

    /** The key is gone (a biometric was added or removed, the screen lock was taken off) or the data doesn't decrypt: start clean. */
    private fun lost(e: Throwable) {
        AppLog.e("saved passphrases unreadable, erased", e)
        clear()
        android.widget.Toast.makeText(a, "The saved passphrases could no longer be read (did the phone's fingerprints, face or screen lock change?) and were erased. Enter the passphrase.", android.widget.Toast.LENGTH_LONG).show()
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** The biometric pair's public half as a plain key (the Keystore's own handle would ask for the biometric even to encrypt). */
    private fun publicKey(): PublicKey {
        val pub = keyStore().getCertificate(BIO)?.publicKey ?: KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(BIO, KeyProperties.PURPOSE_DECRYPT).setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                // a strong biometric for every single use; no PIN/pattern/password fallback; dies with a new enrolment
                .setUserAuthenticationRequired(true).setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true).build())
        }.generateKeyPair().public
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pub.encoded))
    }

    private fun wrapKey(): SecretKey = keyStore().getKey(WRAP, null) as? SecretKey
        ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(WRAP, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
        }.generateKey()

    /** The system's biometric-only prompt; [done] gets the cipher once the biometric released its key, or null. */
    private fun prompt(title: String, cipher: Cipher, done: (Cipher?) -> Unit) {
        var answered = false
        fun answer(c: Cipher?) { if (!answered) { answered = true; done(c) } }
        BiometricPrompt.Builder(a).setTitle(title).setSubtitle("Fingerprint or face")
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton("Type the passphrase", a.mainExecutor) { _, _ -> answer(null) }.build()
            .authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), a.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = answer(result.cryptoObject?.cipher)
                override fun onAuthenticationError(code: Int, msg: CharSequence) = answer(null)
            })
    }

    companion object {
        private const val GCM = "AES/GCM/NoPadding"
        private const val RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        // the Keystore's OAEP uses SHA-1 inside MGF1 unless told otherwise; both sides must agree
        private val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        private const val WRAPPED = 256                      // bytes of an RSA-2048 block
        private const val BIO = "cryptic_saved_biometric_rsa"
        private const val WRAP = "cryptic_saved_wrap"
        private const val NAME = "name:"
    }
}
