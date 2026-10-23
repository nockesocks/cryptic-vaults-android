package me.nocke.cryptic.vaults

import android.app.UiModeManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import me.nocke.cryptic.vaults.fs.Create
import org.json.JSONArray
import org.json.JSONObject

/** The user's settings and remembered containers; stays on the device (allowBackup is off). */
class Prefs(private val ctx: Context) {
    private val p = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    var defaultFs: Create.Fs
        get() = runCatching { Create.Fs.valueOf(p.getString("default_fs", "EXFAT")!!) }.getOrDefault(Create.Fs.EXFAT)
        set(v) { p.edit().putString("default_fs", v.name).apply() }

    var appLock: Boolean
        get() = p.getBoolean("app_lock", false)
        set(v) { p.edit().putBoolean("app_lock", v).apply() }

    /**
     * How the app lock is passed: a strong biometric enrolled on the phone, a passphrase of the app's own, or a YubiKey
     * with its FIDO2 PIN. Never a PIN on its own.
     */
    enum class LockMethod(val title: String) { PHONE("Fingerprint or face"), APP("App passphrase"), YUBIKEY("YubiKey") }

    /** The method in force; one whose record is missing falls back to the biometric. */
    var lockMethod: LockMethod
        get() = runCatching { LockMethod.valueOf(p.getString("lock_method", "PHONE")!!) }.getOrDefault(LockMethod.PHONE).let {
            if ((it == LockMethod.APP && appSecret == null) || (it == LockMethod.YUBIKEY && yubiKey == null)) LockMethod.PHONE else it
        }
        set(v) { p.edit().putString("lock_method", v.name).apply() }

    /** YubiKey's record for the enrolled key (credential id, salt, verifier; never the secret or the PIN). */
    var yubiKey: String?
        get() = p.getString("yubikey", null)
        set(v) { p.edit().putString("yubikey", v).apply() }

    /**
     * With the YubiKey as the lock: what Cryptic Vaults also asks for once the key has passed (optional).
     * A check at the door only. It isn't mixed into the key that encrypts saved passphrases, which stays the
     * YubiKey's secret; derive that key from both if the second requirement has to hold against a copied phone.
     */
    enum class Second(val title: String) { NONE("Nothing more"), BIOMETRIC("Fingerprint or face"), PASSPHRASE("App passphrase") }

    var yubiSecond: Second
        get() = runCatching { Second.valueOf(p.getString("yubi_second", "NONE")!!) }.getOrDefault(Second.NONE).let {
            if (it == Second.PASSPHRASE && secondSecret == null) Second.NONE else it
        }
        set(v) { p.edit().putString("yubi_second", v.name).apply() }

    /** AppSecret's record for the passphrase asked after the YubiKey (a verifier, never the passphrase). */
    var secondSecret: String?
        get() = p.getString("second_secret", null)
        set(v) { p.edit().putString("second_secret", v).apply() }

    /** AppSecret's record for the app-level PIN or passphrase (KDF parameters and a verifier, never the secret). */
    var appSecret: String?
        get() = p.getString("app_secret", null)
        set(v) { p.edit().putString("app_secret", v).apply() }

    /** Wrong tries at the app-level secret since the last right one, and when the last one was (wall clock, ms). */
    var failedTries: Int
        get() = p.getInt("failed_tries", 0)
        set(v) { p.edit().putInt("failed_tries", v).apply() }
    var lastFail: Long
        get() = p.getLong("last_fail", 0)
        set(v) { p.edit().putLong("last_fail", v).apply() }

    /** The user has seen SavedPass's warning for the unlock method in force (shown before the first passphrase is saved). */
    var saveWarned: Boolean
        get() = p.getBoolean("save_warned", false)
        set(v) { p.edit().putBoolean("save_warned", v).apply() }

    /**
     * Minutes Cryptic Vaults may be off the screen before the app lock asks again; 0 = immediately, so
     * the file picker and the Files app, which take it off the screen during normal use, then ask again too.
     */
    var lockAfterMinutes: Int
        get() = p.getInt("lock_after_min", 1).coerceAtLeast(0)
        set(v) { p.edit().putInt("lock_after_min", v).apply() }

    /** Minutes without use after which an unlocked vault locks itself; 0 = never, [IMMEDIATELY] = when Cryptic Vaults leaves the screen. */
    var autoLockMinutes: Int
        get() = p.getInt("auto_lock_min", 0)
        set(v) { p.edit().putInt("auto_lock_min", v).apply() }

    enum class Theme(val title: String, val mode: Int) {
        AUTO("Auto", UiModeManager.MODE_NIGHT_AUTO), DARK("Dark", UiModeManager.MODE_NIGHT_YES), LIGHT("Light", UiModeManager.MODE_NIGHT_NO)
    }

    var theme: Theme
        get() = runCatching { Theme.valueOf(p.getString("theme", "DARK")!!) }.getOrDefault(Theme.DARK)
        set(v) { p.edit().putString("theme", v.name).apply(); applyTheme() }

    /** Per-app night mode (Android 12+): the system persists it and recreates activities. */
    fun applyTheme() = ctx.getSystemService(UiModeManager::class.java).setApplicationNightMode(theme.mode)

    /**
     * USB drives Cryptic Vaults has unlocked, by USB serial number: the label of the encrypted volume on each, so a drive is
     * listed by that label the next time it's plugged in (identical sticks all report the same USB name).
     */
    fun driveLabel(serial: String): String? = runCatching { JSONObject(p.getString("drive_labels", "{}")!!).optString(serial).ifEmpty { null } }.getOrNull()

    fun nameDrive(serial: String, label: String) {
        if (driveLabel(serial) == label) return
        val all = runCatching { JSONObject(p.getString("drive_labels", "{}")!!) }.getOrDefault(JSONObject())
        p.edit().putString("drive_labels", all.put(serial, label).toString()).apply()
    }

    class Container(val uri: Uri, val name: String)

    var containers: List<Container>
        get() = runCatching {
            val a = JSONArray(p.getString("containers", "[]"))
            (0 until a.length()).map { a.getJSONObject(it).let { o -> Container(Uri.parse(o.getString("uri")), o.getString("name")) } }
        }.getOrDefault(emptyList())
        private set(v) { p.edit().putString("containers", JSONArray(v.map { JSONObject().put("uri", it.uri.toString()).put("name", it.name) }).toString()).apply() }

    /** Keeps read/write access to the file across reboots and lists it on the main screen. */
    fun remember(uri: Uri, name: String) {
        runCatching { ctx.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
            .onFailure { AppLog.e("remember $name: no persistable permission", it) }
        containers = containers.filter { it.uri != uri } + Container(uri, name)
    }

    fun forget(uri: Uri) {
        runCatching { ctx.contentResolver.releasePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
        containers = containers.filter { it.uri != uri }
    }

    fun isRemembered(uri: Uri) = containers.any { it.uri == uri }

    companion object { const val IMMEDIATELY = -1 }   // autoLockMinutes: lock when Cryptic Vaults leaves the screen
}
