package me.nocke.cryptic.vaults

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.concurrent.thread

/**
 * Optional app lock (Settings → App lock, off by default), asked when the app starts or returns after more than
 * the chosen time (Prefs.lockAfterMinutes) off the screen — that time also lets the file picker, the USB permission dialog and the Files app come and
 * go without a prompt each time. Two ways to unlock (Prefs.LockMethod): a fingerprint or face through the system
 * prompt, or a passphrase of the app's own, typed on the cover; never a PIN. While locking is on, the window is FLAG_SECURE
 * (no screenshots, blank in recents). Until the lock is passed a cover in the splash's look hides the activity's
 * content, so nothing of the page shows behind or after a dismissed prompt.
 */
open class LockedActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppLog.init(this)
        if (Prefs(this).appLock) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        noAutofill(window)
    }

    override fun onStart() {
        super.onStart()
        started++
        if (backgroundSince != 0L && System.currentTimeMillis() - backgroundSince > Prefs(this).lockAfterMinutes * 60_000L) { unlocked = false; dropKey() }
        backgroundSince = 0L
        if (locked && usesPhoneLock && !biometricReady(this)) {
            // The phone has no fingerprint or face left, and its PIN, pattern or password never passes this lock.
            // So the lock resets: off, and the saved passphrases go with it. Removing the biometrics
            // already destroyed the key that could read them, so nothing protected is exposed by this.
            AppLog.i("app lock reset: the phone has no strong biometric any more")
            Prefs(this).appLock = false; SavedPass(this).clear()
            android.widget.Toast.makeText(this, "App lock was turned off: this phone has no fingerprint or face set up any more. Saved passphrases were erased.", android.widget.Toast.LENGTH_LONG).show()
        }
        if (!locked) { opened(); return }
        if (cover != null) yubi?.start()     // back in front, still locked: watch for the key again
        showCover()
        if (usesPhoneLock && !prompting) prompt(this, "Unlock Cryptic Vaults", { unlocked = true; opened() }) { finishAffinity() }
    }

    override fun onStop() {
        super.onStop()
        forgetAutofill(this)
        yubi?.stop()
        if (--started == 0 && !isChangingConfigurations) {
            backgroundSince = System.currentTimeMillis()
            if (Prefs(this).autoLockMinutes == Prefs.IMMEDIATELY) Volumes.lockAll(this)   // vault auto-lock "Immediately"
        }
    }

    private var cover: View? = null
    private val waiting = ArrayList<() -> Unit>()

    val locked get() = Prefs(this).appLock && !unlocked

    /** The system prompt floats over the activity (the splash can stay behind it); the other methods are typed on the cover. */
    val usesPhoneLock get() = Prefs(this).lockMethod == Prefs.LockMethod.PHONE

    /** Runs [f] now, or once the app lock is passed: for anything that would show over the cover (dialogs, animations). */
    fun whenUnlocked(f: () -> Unit) { if (locked) waiting += f else f() }

    /** The splash's look: the background and the padlock at the splash circle's size; below it the entry for the app's own secret. */
    private fun showCover() {
        if (cover != null) return
        val size = (192 * resources.displayMetrics.density).toInt()
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL }
        col.addView(LockIcon(this, shut = true), LinearLayout.LayoutParams(size, size))
        when (Prefs(this).lockMethod) {
            Prefs.LockMethod.PHONE -> {}
            Prefs.LockMethod.APP -> entry(col, "Cryptic Vaults is locked", "App passphrase") { typed, done -> checkSecret(this, typed, done = done) }
            Prefs.LockMethod.YUBIKEY -> yubiEntry(col)
        }
        cover = FrameLayout(this).apply {
            setBackgroundColor(getColor(R.color.bg)); isClickable = true   // swallows touches meant for the page
            addView(col, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER))
        }
        // the page itself goes invisible, so a screen reader (or anything else reading the view tree) can't see it either
        pageViews().forEach { it.visibility = View.INVISIBLE }
        addContentView(cover, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    }

    private fun pageViews(): List<View> = findViewById<ViewGroup>(android.R.id.content).let { c -> (0 until c.childCount).map { c.getChildAt(it) }.filter { it !== cover } }

    /**
     * The typed part of the cover: a caption, a masked field, an error line and Unlock. [check] gets what was typed
     * and answers with the derived key, or null and what to tell the user. Returns the caption, for status updates.
     */
    private fun entry(col: LinearLayout, caption: String, hint: String, numberPad: Boolean = false, check: (String, (ByteArray?, String?) -> Unit) -> Unit): TextView {
        val ui = Ui(this)
        val field = EditText(this).apply {
            isSingleLine = true; gravity = Gravity.CENTER; this.hint = hint; imeOptions = EditorInfo.IME_ACTION_GO
            inputType = if (numberPad) InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
                else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val error = TextView(this).apply { setTextColor(getColor(R.color.danger)); textSize = 13f; gravity = Gravity.CENTER }
        var submit = {}
        val go = ui.button("Unlock", Ui.Kind.PRIMARY) { submit() }
        submit = submit@{
            if (!go.isEnabled) return@submit        // a check is running (a hardware Enter key also arrives twice, down and up)
            go.isEnabled = false; error.text = ""
            check(field.text.toString()) { key, problem ->
                go.isEnabled = true; field.text.clear()
                if (key == null) error.text = problem else {
                    holdKey(key)
                    getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(field.windowToken, 0)
                    unlocked = true; opened()
                }
            }
        }
        field.setOnEditorActionListener { _, _, e -> if (e == null || e.action == android.view.KeyEvent.ACTION_DOWN) submit(); true }
        field.post { field.requestFocus(); getSystemService(InputMethodManager::class.java).showSoftInput(field, 0) }   // ready to type
        val w = ui.dp(260)
        val head = TextView(this).apply { text = caption; textSize = 16f; setTextColor(getColor(R.color.text_muted)); gravity = Gravity.CENTER }
        col.addView(head, LinearLayout.LayoutParams(w, -2))
        col.addView(field, LinearLayout.LayoutParams(w, -2).apply { topMargin = ui.dp(12) })
        col.addView(error, LinearLayout.LayoutParams(w, -2).apply { topMargin = ui.dp(4) })
        col.addView(go, LinearLayout.LayoutParams(w, -2).apply { topMargin = ui.dp(8) })
        // the number pad can't type letters: a way back to the full keyboard, for a secret that now has some
        if (numberPad) col.addView(ui.link("Use the full keyboard") {}.apply {
            setOnClickListener {
                field.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                visibility = View.GONE
                getSystemService(InputMethodManager::class.java).restartInput(field)
            }
        }, LinearLayout.LayoutParams(w, -2))
        return head
    }

    private var yubi: YubiKey? = null   // watching for the key while this activity's cover asks for it

    /** The YubiKey entry: the caption says what to do next (plug in, enter the PIN, touch); the field takes the key's FIDO2 PIN. */
    private fun yubiEntry(col: LinearLayout) {
        val record = Prefs(this).yubiKey!!
        lateinit var caption: TextView
        val key = YubiKey(this) { caption.text = it }
        caption = entry(col, YubiKey.WAITING, "YubiKey PIN", numberPad = YubiKey.numeric(record)) { typed, done ->
            if (typed.isEmpty()) done(null, "Enter the YubiKey's PIN")
            else key.run({ s, say ->
                // the PIN worked: note whether the number pad is enough for it next time
                YubiKey.unlock(s, record, typed.toCharArray(), say).also { Prefs(this).yubiKey = YubiKey.noting(record, typed.toCharArray()) }
            }) { k, problem ->
                if (k == null) done(null, problem) else second({ done(k, null) }) { why -> k.fill(0); done(null, why) }
            }
        }
        yubi = key; key.start()
    }

    /** The optional second requirement once the YubiKey has passed (Prefs.Second): [ok], or [fail] with what to tell the user. */
    private fun second(ok: () -> Unit, fail: (String) -> Unit) {
        val prefs = Prefs(this)
        when (prefs.yubiSecond) {
            Prefs.Second.NONE -> ok()
            Prefs.Second.BIOMETRIC ->
                if (biometricReady(this)) prompt(this, "Confirm it's you", ok) { fail("Your fingerprint or face wasn't confirmed") }
                else {
                    // none enrolled any more, and the phone's PIN never stands in: skip rather than shut the user out; the key and its PIN did pass
                    android.widget.Toast.makeText(this, "The fingerprint or face check was skipped: this phone has none set up any more.", android.widget.Toast.LENGTH_LONG).show()
                    ok()
                }
            Prefs.Second.PASSPHRASE -> Form(this, "App passphrase").note("Your YubiKey passed. Now your app passphrase.").password("pw", "App passphrase")
                .show("Unlock", onCancel = { fail("The app passphrase wasn't entered") }, validate = { if (it.text["pw"].isNullOrEmpty()) "Enter your app passphrase" else null }) { v ->
                    checkSecret(this, v.text.getValue("pw"), prefs.secondSecret) { key, problem ->
                        if (key == null) fail(problem ?: "Wrong passphrase") else { key.fill(0); ok() }
                    }
                }
        }
    }

    private fun opened() {
        yubi?.stop(); yubi = null
        if (cover != null) forgetAutofill(this)      // the passphrase or PIN typed on the cover
        cover?.let { (it.parent as? ViewGroup)?.removeView(it); cover = null; pageViews().forEach { v -> v.visibility = View.VISIBLE } }
        waiting.toList().also { waiting.clear() }.forEach { it() }
    }

    companion object {
        private var started = 0
        private var unlocked = false
        private var prompting = false
        private var backgroundSince = 0L
        private const val FREE_TRIES = 5
        private const val RETRY_MS = 30_000L

        /**
         * Keeps the phone's autofill service (a password manager) away from everything in [w]: nothing typed into
         * Cryptic Vaults is offered to it, and it doesn't ask to save a vault passphrase, the app passphrase or a YubiKey PIN
         * afterwards. Every window with a field needs this; a dialog is a window of its own.
         */
        fun noAutofill(w: android.view.Window?) { w?.decorView?.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS }

        /**
         * Drops whatever the autofill service gathered from the fields just used, so it has nothing to offer to save.
         * Needed besides [noAutofill]: Android can start an autofill session for a password field by its own
         * heuristics even when the view opted out. Call it when a field with a secret goes away.
         */
        fun forgetAutofill(c: android.content.Context) { c.getSystemService(android.view.autofill.AutofillManager::class.java)?.cancel() }

        /** After a successful prompt elsewhere (turning the lock on in Settings). */
        fun markUnlocked() { unlocked = true }

        /**
         * The key derived from the app's own passphrase, held while the app is unlocked: it opens saved vault passphrases.
         * Dropped when the app relocks, which is noticed on the next return to the app, not the moment the
         * chosen time runs out off the screen; a timer if it has to leave memory on time.
         */
        var appKey: ByteArray? = null; private set
        fun holdKey(k: ByteArray) { dropKey(); appKey = k }
        fun dropKey() { appKey?.fill(0); appKey = null }

        /** A fingerprint or face that Android rates as strong is enrolled. */
        fun biometricReady(a: Activity) =
            a.getSystemService(BiometricManager::class.java).canAuthenticate(Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

        /**
         * The system prompt: a strong biometric only. The phone's PIN, pattern or password is never accepted: an
         * app can't tell a phone passphrase from a PIN, so none of them is.
         */
        fun prompt(a: Activity, title: String, ok: () -> Unit, fail: () -> Unit) {
            prompting = true
            var answered = false
            fun answer(f: () -> Unit) { if (!answered) { answered = true; prompting = false; f() } }
            BiometricPrompt.Builder(a).setTitle(title).setSubtitle("Fingerprint or face").setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                .setNegativeButton("Cancel", a.mainExecutor) { _, _ -> answer(fail) }.build()
                .authenticate(CancellationSignal(), a.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = answer(ok)
                    override fun onAuthenticationError(code: Int, msg: CharSequence) = answer(fail)
                })
        }

        /**
         * Checks the app's own passphrase off the main thread: [done] gets the derived key, or null and what to
         * tell the user. After [FREE_TRIES] wrong tries each further one waits [RETRY_MS]. That only slows guessing on
         * the lock screen (someone holding the unlocked phone can move its clock); the Argon2 cost of every try, and
         * the length floor where the secret protects saved passphrases, are what hold.
         */
        fun checkSecret(a: Activity, secret: String, record: String? = Prefs(a).appSecret, done: (ByteArray?, String?) -> Unit) {
            val prefs = Prefs(a)
            if (record == null || secret.isEmpty()) return done(null, "Enter your app passphrase")
            val wait = minOf(RETRY_MS, prefs.lastFail + RETRY_MS - System.currentTimeMillis())
            if (prefs.failedTries >= FREE_TRIES && wait > 0) return done(null, "Too many wrong tries. Try again in ${(wait + 999) / 1000} s.")
            thread(name = "app-secret") {
                val key = runCatching { AppSecret.key(record, secret) }.onFailure { AppLog.e("app secret check", it) }.getOrNull()
                a.runOnUiThread {
                    if (key == null) { prefs.failedTries++; prefs.lastFail = System.currentTimeMillis(); done(null, "Wrong passphrase") }
                    else { prefs.failedTries = 0; done(key, null) }
                }
            }
        }
    }
}
