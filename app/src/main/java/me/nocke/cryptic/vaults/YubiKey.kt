package me.nocke.cryptic.vaults

import android.app.Activity
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import com.yubico.yubikit.fido.webauthn.AuthenticatorData
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

/**
 * A YubiKey plugged into the phone as the app lock (Settings → App lock → YubiKey), through FIDO2's hmac-secret
 * extension with the key's own PIN: the key alone is not enough. The key holds a credential
 * made for Cryptic Vaults; given a stored salt, the right PIN and a touch, it returns a 32-byte secret. Without the PIN the
 * key answers with a different secret, so the PIN can't be skipped. From that secret come a verifier (stored) and the
 * key that protects saved vault passphrases (kept in memory while the app is unlocked), as [AppSecret] does for the
 * app passphrase. Stored record: JSON with the credential id, the salt and the verifier; never the secret or the PIN.
 * USB, CTAP2 and the PIN protocol are Yubico's SDK (yubikit); it has no network code.
 */
class YubiKey(private val a: Activity, private val status: (String) -> Unit) {
    private val kit = YubiKitManager(a)
    @Volatile private var device: UsbYubiKeyDevice? = null

    /** Watches for a key: one already plugged in, or the next one. Android asks for USB access to it the first time. */
    fun start() = kit.startUsbDiscovery(UsbConfiguration()) { d ->
        device = d
        d.setOnClosed { device = null; say(WAITING) }
        say("YubiKey connected. Enter its PIN.")
    }

    fun stop() = kit.stopUsbDiscovery()

    private fun say(s: String) = a.runOnUiThread { status(s) }

    /**
     * Runs [work] on the plugged-in key, off the main thread; it gets the CTAP2 session and a way to tell the user
     * what to do next. [done], on the main thread, gets the result, or null and what went wrong.
     */
    fun <T : Any> run(work: (Ctap2Session, (String) -> Unit) -> T, done: (T?, String?) -> Unit) {
        val d = device ?: return done(null, "Plug your YubiKey into the phone first")
        thread(name = "yubikey") {
            val r = runCatching { d.openConnection(FidoConnection::class.java).use { c -> Ctap2Session(c).use { s -> work(s, ::say) } } }
            a.runOnUiThread { r.fold({ done(it, null) }, { AppLog.e("YubiKey", it); done(null, explain(it)) }) }
        }
    }

    companion object {
        const val WAITING = "Plug in your YubiKey"
        private const val RP_ID = "vaults.cryptic.nocke.me"      // names the credential on the key; never looked up anywhere
        private const val TOUCH = "Touch your YubiKey"

        /** Makes Cryptic Vaults' credential on the key (one touch) and reads its secret (a second touch): the record to store, and the key. */
        fun enrol(s: Ctap2Session, pin: CharArray, say: (String) -> Unit): Pair<String, ByteArray> {
            val info = s.cachedInfo
            if ("hmac-secret" !in info.extensions) throw IllegalStateException("This key doesn't support what Cryptic Vaults needs (FIDO2 hmac-secret)")
            if (info.options["clientPin"] != true) throw IllegalStateException("This YubiKey has no FIDO2 PIN yet. Set one first (for example with Yubico Authenticator), then try again.")
            val protocol = protocol(s)
            val rnd = SecureRandom()
            val hash = ByteArray(32).also { rnd.nextBytes(it) }
            val token = ClientPin(s, protocol).getPinToken(pin, ClientPin.PIN_PERMISSION_MC, RP_ID)
            say(TOUCH)
            val made = s.makeCredential(hash, mapOf("id" to RP_ID, "name" to "Cryptic Vaults"),
                mapOf("id" to ByteArray(16).also { rnd.nextBytes(it) }, "name" to "Cryptic Vaults app lock"),
                listOf(mapOf("type" to "public-key", "alg" to -7)), null,
                mapOf("hmac-secret" to true), mapOf("rk" to false), protocol.authenticate(token, hash), protocol.version, null, null)
            val cred = AuthenticatorData.parseFrom(ByteBuffer.wrap(made.authenticatorData)).attestedCredentialData?.credentialId
                ?: throw IllegalStateException("The key returned no credential")
            val salt = ByteArray(32).also { rnd.nextBytes(it) }
            say("Touch your YubiKey once more")
            val d = derive(secret(s, protocol, pin, cred, salt))
            val b64 = Base64.getEncoder()
            val record = JSONObject().put("cred", b64.encodeToString(cred)).put("salt", b64.encodeToString(salt)).put("check", b64.encodeToString(d.copyOf(32)))
                .put("numeric", pin.all { it.isDigit() })
            return record.toString() to d.copyOfRange(32, 64).also { d.fill(0) }
        }

        /** Whether the PIN last used with [record] was all digits: the number pad is enough to type it. A FIDO2 PIN may hold any characters. */
        fun numeric(record: String) = JSONObject(record).optBoolean("numeric")

        /** [record] with that flag set from the PIN that just worked. */
        fun noting(record: String, pin: CharArray): String = JSONObject(record).put("numeric", pin.all { it.isDigit() }).toString()

        /** The key for [record] from the plugged-in YubiKey, its [pin] and a touch; throws when it isn't the same key. */
        fun unlock(s: Ctap2Session, record: String, pin: CharArray, say: (String) -> Unit): ByteArray {
            val r = JSONObject(record); val b64 = Base64.getDecoder()
            say(TOUCH)
            val d = derive(secret(s, protocol(s), pin, b64.decode(r.getString("cred")), b64.decode(r.getString("salt"))))
            if (!MessageDigest.isEqual(d.copyOf(32), b64.decode(r.getString("check")))) { d.fill(0); throw IllegalStateException(WRONG_KEY) }
            return d.copyOfRange(32, 64).also { d.fill(0) }
        }

        private const val WRONG_KEY = "This isn't the YubiKey Cryptic Vaults was set up with"

        private fun protocol(s: Ctap2Session): PinUvAuthProtocol =
            if (PinUvAuthProtocolV2.VERSION in s.cachedInfo.pinUvAuthProtocols) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()

        /** getAssertion with hmac-secret, verified by the PIN: the credential's with-PIN secret for [salt]. */
        private fun secret(s: Ctap2Session, protocol: PinUvAuthProtocol, pin: CharArray, cred: ByteArray, salt: ByteArray): ByteArray {
            val clientPin = ClientPin(s, protocol)
            val token = clientPin.getPinToken(pin, ClientPin.PIN_PERMISSION_GA, RP_ID)
            val shared = clientPin.sharedSecret              // the phone's key-agreement key, and the secret shared with the key
            val saltEnc = protocol.encrypt(shared.second, salt)
            val hmacSecret = HashMap<Int, Any>().apply {
                put(1, shared.first); put(2, saltEnc); put(3, protocol.authenticate(shared.second, saltEnc))
                if (protocol.version > 1) put(4, protocol.version)
            }
            val hash = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val got = s.getAssertions(RP_ID, hash, listOf(mapOf("type" to "public-key", "id" to cred)), mapOf("hmac-secret" to hmacSecret),
                mapOf("up" to true), protocol.authenticate(token, hash), protocol.version, null)
            val data = AuthenticatorData.parseFrom(ByteBuffer.wrap(got[0].authenticatorData))
            if (!data.isUv) throw IllegalStateException("The key didn't check its PIN")
            val enc = data.extensions?.get("hmac-secret") as? ByteArray ?: throw IllegalStateException("The key returned no secret")
            return protocol.decrypt(shared.second, enc)
        }

        /** 64 bytes from the key's secret: the verifier half and the key half. */
        internal fun derive(secret: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA512").apply { init(SecretKeySpec(secret, "HmacSHA512")) }.doFinal("Cryptic Vaults app lock v1".toByteArray()).also { secret.fill(0) }

        private fun explain(e: Throwable): String = when (val code = (e as? CtapException)?.ctapError) {
            null -> e.message ?: e.javaClass.simpleName
            CtapException.ERR_PIN_INVALID -> "Wrong YubiKey PIN"
            CtapException.ERR_PIN_AUTH_BLOCKED -> "Too many wrong PINs in a row: unplug the YubiKey, plug it back in and try again"
            CtapException.ERR_PIN_BLOCKED -> "The YubiKey's PIN is blocked after too many wrong tries. The key's FIDO2 function has to be reset."
            CtapException.ERR_PIN_NOT_SET -> "This YubiKey has no FIDO2 PIN yet. Set one first, then try again."
            CtapException.ERR_NO_CREDENTIALS, CtapException.ERR_INVALID_CREDENTIAL -> WRONG_KEY
            CtapException.ERR_USER_ACTION_TIMEOUT, CtapException.ERR_ACTION_TIMEOUT, CtapException.ERR_KEEPALIVE_CANCEL -> "The YubiKey wasn't touched in time. Try again."
            CtapException.ERR_OPERATION_DENIED -> "The YubiKey refused the request"
            else -> "The YubiKey answered with error 0x%02x".format(code)
        }
    }
}
