package me.nocke.cryptic.vaults

import android.content.Intent
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.Toast
import me.nocke.cryptic.vaults.fs.Create

/** Settings on one page: appearance, default filesystem, app lock, About, then the tip jar. */
class SettingsActivity : LockedActivity() {
    private val ui by lazy { Ui(this) }
    private val prefs by lazy { Prefs(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = ui.column(16)
        col.addView(ui.back("Settings") { finish() })
        col.addView(ui.card().apply { updates(this) })

        col.addView(ui.section("Appearance"))
        col.addView(ui.card().apply {
            addView(ui.note("Theme", top = 0))
            addView(ui.chips(Prefs.Theme.values().map { it.name to it.title }, prefs.theme.name) { prefs.theme = Prefs.Theme.valueOf(it) })
            addView(ui.note("Auto follows the phone's dark-mode setting.", top = 6))
        })

        col.addView(ui.section("New volumes"))
        col.addView(ui.card().apply {
            addView(ui.note("Default filesystem", top = 0))
            addView(ui.chips(Create.Fs.values().map { it.name to it.title }, prefs.defaultFs.name) { prefs.defaultFs = Create.Fs.valueOf(it) })
            addView(ui.note("exFAT works on Windows, macOS and Linux. ext4 is Linux-native, keeps owners and permissions, and suits drives you mainly use on Linux.", top = 6))
        })

        col.addView(ui.section("USB drives"))
        col.addView(ui.card().apply {
            // the USB registration sits on an activity alias, so it can be switched off and on
            val alias = android.content.ComponentName(this@SettingsActivity, "$packageName.UsbAttach")
            val off = android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            addView(Switch(this@SettingsActivity).apply {
                text = "Open Cryptic Vaults when a drive is plugged in"; textSize = 16f; setTextColor(getColor(R.color.text))
                isChecked = packageManager.getComponentEnabledSetting(alias) != off
                setOnCheckedChangeListener { _, on ->
                    packageManager.setComponentEnabledSetting(alias, if (on) android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED else off,
                        android.content.pm.PackageManager.DONT_KILL_APP)
                }
            })
            addView(ui.note("On: Android offers Cryptic Vaults for any USB drive you plug in. The first time it sees a drive it asks whether to always open Cryptic Vaults for that one; that question is Android's own. " +
                "Off: Cryptic Vaults never starts by itself. Open it first; plugged-in drives are listed on its main page.", top = 6))
        })

        col.addView(ui.section("Security"))
        col.addView(ui.card().apply { appLock(this) })

        col.addView(ui.card().apply { autoLock(this) })

        col.addView(ui.section("About"))
        col.addView(ui.card().apply { about(this) })
        col.addView(ui.card().apply { family(this) })

        if (SHOW_LOG_SHARE) {
            col.addView(ui.section("Having issues?"))
            col.addView(ui.card().apply {
                addView(ui.item(R.drawable.ic_bug, "Share the error log", "Errors and what Cryptic Vaults was doing; never passphrases or keys"))
                addView(ui.full(ui.button("Share error log") { shareLog() }, top = 14))
            })
        }

        col.addView(ui.rule())
        col.addView(ui.card().apply {
            addView(ui.item(R.drawable.ic_coffee, "Buy the dev a coffee!", null))
            addView(ui.note("Opens the tip page in your browser: Bitcoin Lightning, Bitcoin on-chain or Monero. Cryptic Vaults itself never goes online."))
            addView(ui.row(
                ui.tile(R.drawable.ic_cup_togo, "$1") { Tips.open(this@SettingsActivity, 1) },
                ui.tile(R.drawable.ic_cup_cappuccino, "$3") { Tips.open(this@SettingsActivity, 3) },
                ui.tile(R.drawable.ic_cup_frappe, "$5") { Tips.open(this@SettingsActivity, 5) },
            ))        })
        col.addView(ui.rule(short = true))
        col.addView(ui.link("Licensed under PolyForm Noncommercial 1.0.0\nOpen-source licenses", size = 12f) { showLicenses() }.apply {
            (layoutParams as LinearLayout.LayoutParams).topMargin = 0
        })
        // the id lets the page keep its scroll position when a setting rebuilds it (recreate)
        setContentView(ScrollView(this).apply { id = SCROLL_ID; addView(col); fitsSystemWindows = true; setBackgroundColor(getColor(R.color.bg)) })
    }

    /** Cryptic Vaults' license (its URL, which the license accepts in place of the text) and the third-party licenses the APK carries. */
    private fun showLicenses() {
        val third = assets.open("third_party_licenses.txt").bufferedReader().use { it.readText() }
        android.app.AlertDialog.Builder(this).setTitle("Licenses")
            .setMessage("Cryptic Vaults is licensed under the PolyForm Noncommercial License 1.0.0:\nhttps://polyformproject.org/licenses/noncommercial/1.0.0\n\n" + third)
            .setPositiveButton("Close", null).show()
    }

    /** Vault auto-lock: a switch, and when on the time an unlocked vault may go unused before it locks itself. */
    private fun autoLock(card: LinearLayout) {
        val minutes = prefs.autoLockMinutes
        card.addView(Switch(this).apply {
            text = "Vault auto-lock"; textSize = 16f; setTextColor(getColor(R.color.text)); isChecked = minutes != 0
            setOnCheckedChangeListener { _, on -> prefs.autoLockMinutes = if (on) 5 else 0; recreate() }
        })
        card.addView(ui.note("Locks an unlocked vault by itself once it hasn't been used for the time you choose. Copying or opening files counts as use, so a transfer is never cut off.", top = 6))
        if (minutes == 0) return
        card.addView(ui.note("Lock after", top = 12))
        card.addView(minutesChips("Vault auto-lock", "Lock after this many minutes without use", if (minutes == Prefs.IMMEDIATELY) 0 else minutes) { prefs.autoLockMinutes = if (it == 0) Prefs.IMMEDIATELY else it })
    }

    /** Immediately (0), 1, 2, 5, 10 minutes or a custom number up to 6 hours (anything over 10 is typed in); [set] stores the choice. */
    private fun minutesChips(title: String, question: String, minutes: Int, set: (Int) -> Unit): android.view.View {
        val presets = listOf(0, 1, 2, 5, 10)
        val options = presets.map { it.toString() to if (it == 0) "Immediately" else "$it min" } + ("custom" to if (minutes in presets) "Custom…" else "Custom: $minutes min")
        return ui.chips(options, if (minutes in presets) minutes.toString() else "custom", perRow = 3) {
            if (it != "custom") { set(it.toInt()); recreate(); return@chips }
            Form(this, title).text("min", question, if (minutes in presets) "" else minutes.toString(), number = true)
                .show("Set", onCancel = { recreate() }, validate = { v -> if ((v.text["min"]?.toIntOrNull() ?: 0) in 1..360) null else "Enter a number of minutes from 1 to 360 (6 hours)" }) { v ->
                    set(v.text.getValue("min").toInt()); recreate()
                }
        }
    }

    private val version get() = runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull() ?: ""

    /** No network access, so no update check of our own: the latest release opens in the browser to compare by eye. */
    private fun updates(card: LinearLayout) {
        card.addView(ui.note("Installed version", top = 0))
        card.addView(android.widget.TextView(this).apply {
            text = "Cryptic Vaults $version"; textSize = 22f; setTextColor(getColor(R.color.text))
            typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
        })
        card.addView(ui.note("Opens the latest release on GitHub in your browser. If its version is newer, download the APK there and open it to update."))
        card.addView(ui.full(ui.button("Check for updates", Ui.Kind.PRIMARY) {
            runCatching { startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(RELEASES))) }
                .onFailure { Toast.makeText(this, "No browser on this phone can open the release page.", Toast.LENGTH_LONG).show() }
        }, top = 14))
    }

    private fun about(card: LinearLayout) {
        card.addView(android.widget.LinearLayout(this).apply {
            gravity = android.view.Gravity.CENTER_VERTICAL
            addView(LockIcon(this@SettingsActivity, shut = true), android.widget.LinearLayout.LayoutParams(ui.dp(44), ui.dp(44)))   // the home padlock, still
            addView(ui.column().apply {
                addView(android.widget.TextView(this@SettingsActivity).apply { text = "Cryptic Vaults $version"; textSize = 16f; setTextColor(getColor(R.color.text)); typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL) })
                addView(android.widget.TextView(this@SettingsActivity).apply { text = "LUKS2 removable disk & container encryption utility for Android"; textSize = 13f; setTextColor(getColor(R.color.text_muted)) })
            }, android.widget.LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = ui.dp(12) })
        })
        card.addView(ui.heading(android.text.SpannableString("Security is a right, not a privilege.").apply {
            // "right" in the accent purple, italic
            val st = indexOf("right"); val en = st + 5
            setSpan(android.text.style.ForegroundColorSpan(getColor(R.color.accent_light)), st, en, 0)
            setSpan(android.text.style.StyleSpan(android.graphics.Typeface.BOLD_ITALIC), st, en, 0)
        }))
        card.addView(ui.paragraph("Android can encrypt the phone itself, but not the drives you plug into it or the files you carry around. " +
            "There was no baked-in way to manage industry standard drive and container encryption, and the few apps that claimed to " +
            "add this were jank and lived behind a paywall. The developer rejected these options for both reasons, and Cryptic Vaults was born."))
        card.addView(ui.heading("Built for privacy"))
        card.addView(ui.bullets(listOf(
            "Zero telemetry, analytics or ads.",
            "No sign-up or account required.",
            "No network access at all: Cryptic Vaults doesn't even ask for the internet permission.",
            "Nothing leaves your device. Passphrases and keys are only held in memory while a volume is unlocked. None is stored unless you turn on App lock and choose to save a vault's passphrase; those stay encrypted on this phone.",
            "Standard LUKS2, so your drives open with cryptsetup on any Linux machine, with or without Cryptic Vaults.",
        )))
        card.addView(ui.heading("Free, as it should be."))
        card.addView(ui.paragraph("No paywall, no gotcha, no upsell, no monetizing your data. Free forever, because it's the right thing to do. " +
            "If you don't think that's fair, you can always buy me a coffee! \uD83D\uDE0A"))
    }

    /** The other Cryptic apps, each on its own panel; the one ™ is on the heading. */
    private fun family(card: LinearLayout) {
        card.addView(ui.heading("").apply {
            (layoutParams as LinearLayout.LayoutParams).topMargin = 0
            val word = "Cryptic"; val prefix = "The "
            text = android.text.SpannableString(softTm("$prefix$word™ family")).apply {
                setSpan(SheenSpan(this@SettingsActivity, paint.measureText(prefix), paint.measureText(word)), prefix.length, prefix.length + word.length, 0)
            }
        })
        card.addView(ui.paragraph("Cryptic Vaults is a member of the Cryptic family of utilities. Check out our other apps:"))
        card.addView(ui.subcard("Cryptic Vaults for Linux and macOS", "The same LUKS2 drives and containers on your computer.") { openPage(DESKTOP) }
            .apply { (layoutParams as LinearLayout.LayoutParams).topMargin = ui.dp(14) })
        card.addView(ui.subcard("Cryptic Pass", "A password manager. Coming soon."))
        card.addView(ui.link("See all Cryptic apps on github.com/nockesocks") { openPage(GITHUB) }.apply { (layoutParams as LinearLayout.LayoutParams).topMargin = ui.dp(8) })
    }

    private fun openPage(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))) }
            .onFailure { Toast.makeText(this, "No browser on this phone can open the page.", Toast.LENGTH_LONG).show() }
    }

    companion object {
        /** Off for now; the log is still kept on the device. */
        private const val SHOW_LOG_SHARE = false
        private const val SCROLL_ID = 1
        private const val RELEASES = "https://github.com/nockesocks/cryptic-vaults-android/releases/latest"
        private const val DESKTOP = "https://github.com/nockesocks/cryptic-vaults"
        private const val GITHUB = "https://github.com/nockesocks"
    }

    private fun shareLog() {
        val text = AppLog.text().ifEmpty { "(log is empty)" }
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, "Cryptic Vaults log").putExtra(Intent.EXTRA_TEXT, text), "Share log"))
    }

    /**
     * App lock: the switch; when on, what unlocks Cryptic Vaults (a fingerprint or face, or a passphrase of the app's own; never
     * a PIN), and below that the saved vault passphrases the lock protects.
     */
    private fun appLock(card: LinearLayout) {
        val sw = Switch(this).apply { text = "App lock"; textSize = 16f; setTextColor(getColor(R.color.text)); isChecked = prefs.appLock }
        sw.setOnCheckedChangeListener { _, on -> toggleLock(sw, on) }
        card.addView(sw)
        card.addView(ui.note("Asks you to unlock Cryptic Vaults when it opens, or returns after being off the screen for the time you set, and lets you save vault passphrases on this phone behind that lock. " +
            "Screenshots of the app are blocked while it's on. Unlocked volumes stay unlocked; lock them separately.", top = 6))
        if (!prefs.appLock) return
        val method = prefs.lockMethod
        card.addView(ui.note("Unlock with", top = 12))
        card.addView(ui.chips(Prefs.LockMethod.values().map { it.name to it.title }, method.name, perRow = 2) { setMethod(Prefs.LockMethod.valueOf(it)) })
        when (method) {
            Prefs.LockMethod.PHONE -> card.addView(ui.note("The fingerprint or face set up on this phone. The phone's PIN, pattern or password doesn't unlock Cryptic Vaults.", top = 6))
            Prefs.LockMethod.APP -> {
                card.addView(ui.note("A passphrase used only by Cryptic Vaults. There is no way to recover it: if you forget it, clearing Cryptic Vaults' data in Android settings is the only way back in. Your drives and containers aren't affected by that.", top = 6))
                card.addView(ui.full(ui.button("Change passphrase") {
                    erasingSaved({ confirmCurrent("Change passphrase", { newSecret { recreate() } }) {} }) {}
                }, top = 12))
            }
            Prefs.LockMethod.YUBIKEY -> {
                card.addView(ui.note("Your YubiKey, plugged in or held to the phone, its FIDO2 PIN and a touch (over NFC, the tap is the touch). If the key is lost there is no way back in except clearing Cryptic Vaults' data in Android settings. Your drives and containers aren't affected by that.", top = 6))
                card.addView(ui.note("After the YubiKey, also require", top = 16))
                card.addView(ui.chips(Prefs.Second.values().map { it.name to it.title }, prefs.yubiSecond.name, perRow = 2) { setSecond(Prefs.Second.valueOf(it)) })
                card.addView(ui.note("Optional. Once the key has passed, Cryptic Vaults asks for this as well before it opens.", top = 6))
            }
        }
        card.addView(ui.note("Ask again after Cryptic Vaults has been off the screen for", top = 16))
        card.addView(minutesChips("App lock", "Ask again after this many minutes off the screen", prefs.lockAfterMinutes) { prefs.lockAfterMinutes = it })
        card.addView(ui.rule())
        savedPass(card)
    }

    /** Makes [m] the unlock method; the other methods' records go. */
    private fun adopt(m: Prefs.LockMethod) {
        if (m != Prefs.LockMethod.APP) prefs.appSecret = null
        if (m != Prefs.LockMethod.YUBIKEY) { prefs.yubiKey = null; prefs.yubiSecond = Prefs.Second.NONE; prefs.secondSecret = null }
        prefs.lockMethod = m
    }

    /** The optional second requirement after the YubiKey; the key confirms the change first. */
    private fun setSecond(s: Prefs.Second) {
        if (s == prefs.yubiSecond) return
        val back = { recreate() }     // puts the chips back on the choice still in force
        if (s == Prefs.Second.BIOMETRIC && !LockedActivity.biometricReady(this)) { toast("Set up a fingerprint or face unlock in Android settings first"); return back() }
        confirmCurrent("Change what follows the YubiKey", {
            when (s) {
                Prefs.Second.NONE -> { prefs.yubiSecond = s; prefs.secondSecret = null; recreate() }
                // it must pass once now, so the setting can't lock the user out
                Prefs.Second.BIOMETRIC -> LockedActivity.prompt(this, "Confirm your fingerprint or face", { prefs.yubiSecond = s; prefs.secondSecret = null; recreate() }, back)
                Prefs.Second.PASSPHRASE -> makeSecret("Asked for after your YubiKey has passed, each time Cryptic Vaults unlocks.", back, afterYubiKey = true) { record, key ->
                    key.fill(0); prefs.secondSecret = record; prefs.yubiSecond = s; recreate()
                }
            }
        }, back)
    }

    /**
     * The dialog for anything that needs the YubiKey: [note] says why, a status line says what to do next (plug in,
     * enter the PIN, touch), the field takes the key's FIDO2 PIN, and [work] runs on the key; [done] gets its result.
     */
    private fun <T : Any> yubiKeyDialog(title: String, note: String, action: String, cancel: () -> Unit,
                                        work: (com.yubico.yubikit.fido.ctap.Ctap2Session, CharArray, (String) -> Unit) -> T, done: (T) -> Unit) {
        val status = android.widget.TextView(this).apply { text = YubiKey.WAITING; textSize = 15f; setTextColor(getColor(R.color.accent_light)); setPadding(0, ui.dp(12), 0, ui.dp(4)) }
        val key = YubiKey(this) { status.text = it }
        val pin = android.widget.EditText(this).apply {
            isSingleLine = true; hint = "YubiKey PIN"
            // the number pad when the enrolled key's PIN is known to be all digits; the full keyboard for a new key
            inputType = if (prefs.yubiKey?.let { YubiKey.numeric(it) } == true) android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
                else android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val error = android.widget.TextView(this).apply { setTextColor(getColor(R.color.danger)); textSize = 13f }
        val body = ui.column().apply {
            setPadding(ui.dp(24), ui.dp(8), ui.dp(24), 0)
            addView(ui.note(note, top = 0)); addView(status); addView(pin); addView(error)
        }
        val dlg = android.app.AlertDialog.Builder(this).setTitle(title).setView(ScrollView(this).apply { addView(body) })
            .setPositiveButton(action, null).setNegativeButton("Cancel") { _, _ -> cancel() }.setOnCancelListener { cancel() }
            .setOnDismissListener { key.stop(); LockedActivity.forgetAutofill(this) }.create()
        LockedActivity.noAutofill(dlg.window)
        dlg.setOnShowListener {
            val go = dlg.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
            go.setOnClickListener {
                val typed = pin.text.toString().toCharArray()
                if (typed.isEmpty()) { error.text = "Enter the YubiKey's PIN"; return@setOnClickListener }
                go.isEnabled = false; error.text = ""
                key.run({ s, say -> work(s, typed, say) }) { result, problem ->
                    go.isEnabled = true; pin.text.clear(); typed.fill('\u0000')
                    if (result == null) error.text = problem else { dlg.dismiss(); done(result) }
                }
            }
        }
        dlg.show(); key.start()
    }

    private val saved by lazy { SavedPass(this) }

    /** Saved passphrases are protected by what unlocks the app: a change to that erases them. Says so first. */
    private fun erasingSaved(then: () -> Unit, cancel: () -> Unit) {
        if (saved.count == 0) return then()
        android.app.AlertDialog.Builder(this).setTitle("Saved passphrases will be erased")
            .setMessage("The saved vault passphrases (${saved.count}) are protected by the way Cryptic Vaults unlocks now, so this change erases them. " +
                "Your drives and containers aren't touched; you'll type their passphrases again.")
            .setPositiveButton("Continue") { _, _ -> then() }.setNegativeButton("Cancel") { _, _ -> cancel() }
            .setOnCancelListener { cancel() }.show()
    }

    private fun wipeSaved() = saved.clear()

    /**
     * Saved vault passphrases, inside the App lock card. There is no switch: saving comes with the app lock, and the
     * user decides per vault with "Save this passphrase" when unlocking.
     */
    private fun savedPass(card: LinearLayout) {
        card.addView(android.widget.TextView(this).apply { text = "Saved vault passphrases"; textSize = 16f; setTextColor(getColor(R.color.text)) })
        savedCount = saved.count
        card.addView(ui.note(saved.problem
            ?: ("Tick \"Save this passphrase\" when you unlock a drive or container, and from then on you open it with ${saved.protection} instead of typing its passphrase. " +
                "A saved passphrase is only as strong as what unlocks Cryptic Vaults. " + if (savedCount == 0) "Nothing is saved yet." else "$savedCount saved."), top = 6))
        card.addView(ui.full(ui.button("Manage vault passphrases") { startActivity(Intent(this, SavedPassActivity::class.java)) }, top = 12))
    }

    private var savedCount = 0   // as shown when the card was built

    override fun onResume() {
        super.onResume()
        if (prefs.appLock && saved.count != savedCount) recreate()     // back from Manage vault passphrases
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    /** Asks for the current unlock (the biometric, the app passphrase, or the YubiKey) before a security setting changes. */
    private fun confirmCurrent(title: String, ok: () -> Unit, cancel: () -> Unit) {
        if (!prefs.appLock) return ok()
        if (prefs.lockMethod == Prefs.LockMethod.PHONE) return LockedActivity.prompt(this, title, ok, cancel)
        if (prefs.lockMethod == Prefs.LockMethod.YUBIKEY) return yubiKeyDialog(title, "Enter the PIN of the YubiKey Cryptic Vaults is set up with, then touch it while plugged in, or hold it to the phone.", "Continue", cancel,
            { s, pin, say -> YubiKey.unlock(s, prefs.yubiKey!!, pin, say) }) { k -> k.fill(0); ok() }
        Form(this, title).password("cur", "Current app passphrase")
            .show("Continue", onCancel = cancel, validate = { if (it.text["cur"].isNullOrEmpty()) "Enter your current app passphrase" else null }) { v ->
                LockedActivity.checkSecret(this, v.text.getValue("cur")) { key, problem ->
                    if (key == null) { toast(problem ?: "Wrong passphrase"); cancel() } else { key.fill(0); ok() }
                }
            }
    }

    /** Sets a new app passphrase and makes it the unlock method, then [done]. */
    private fun newSecret(cancel: () -> Unit = {}, done: () -> Unit) = makeSecret("Used only to unlock Cryptic Vaults, and it is what protects any vault passphrases you save.", cancel) { record, key ->
        wipeSaved()                 // whatever was saved was protected by the previous unlock
        LockedActivity.holdKey(key)
        prefs.appSecret = record; adopt(Prefs.LockMethod.APP); prefs.failedTries = 0
        done()
    }

    /**
     * Asks for a new app passphrase and derives its record and key off the main thread. Eight characters, not only
     * digits; a weak one (below "good" on the meter) is set only after the user accepts a warning.
     */
    private fun makeSecret(purpose: String, cancel: () -> Unit, afterYubiKey: Boolean = false, made: (String, ByteArray) -> Unit) {
        fun set(secret: String) {
            val wait = android.app.AlertDialog.Builder(this).setMessage("Setting it up…").setCancelable(false).show()
            kotlin.concurrent.thread(name = "app-secret") {
                val (record, key) = AppSecret.create(secret)
                runOnUiThread { wait.dismiss(); made(record, key) }
            }
        }
        // After the YubiKey the passphrase only adds to the key and its PIN, and encrypts nothing: eight characters is
        // all that's asked, with no complexity warning. On its own it is what encrypts the saved
        // passphrases: not digits only, and a weak one needs the warning accepted.
        Form(this, "App passphrase")
            .note(if (afterYubiKey) "$purpose ${AppSecret.MIN_LENGTH} characters or more. There is no way to recover it."
                else "$purpose ${AppSecret.MIN_LENGTH} characters or more, not only digits; longer and more varied is much stronger. A PIN isn't accepted. There is no way to recover it.")
            .password("new", "New passphrase", meter = true).password("new2", "Repeat it")
            .show("Set", onCancel = cancel, validate = { v ->
                val typed = v.text.getValue("new")
                when {
                    typed.length < AppSecret.MIN_LENGTH -> "Use ${AppSecret.MIN_LENGTH} or more characters"
                    !afterYubiKey && !AppSecret.acceptable(typed) -> "Not only digits: a PIN isn't accepted"
                    typed != v.text["new2"] -> "The two entries don't match"
                    else -> null
                }
            }) { v ->
                val secret = v.text.getValue("new")
                if (afterYubiKey || !AppSecret.weak(secret)) return@show set(secret)
                android.app.AlertDialog.Builder(this).setTitle("This passphrase is weak")
                    .setMessage("The meter rates it ${Form.strength(secret).second}: ${secret.length} characters with little variety can be guessed far faster than its length suggests.\n\n" +
                        "It is all that stands between someone holding this phone and Cryptic Vaults, including any vault passphrases you save. " +
                        "A longer one, or one mixing upper and lower case, digits and symbols, holds up much better.\n\nUse it anyway?")
                    .setPositiveButton("Use it anyway") { _, _ -> set(secret) }
                    .setNegativeButton("Choose another") { _, _ -> makeSecret(purpose, cancel, afterYubiKey, made) }
                    .setOnCancelListener { cancel() }.show()
            }
    }

    private fun setMethod(m: Prefs.LockMethod) {
        if (m == prefs.lockMethod) return
        val back = { recreate() }     // puts the chips back on the method still in force
        if (m == Prefs.LockMethod.PHONE && !LockedActivity.biometricReady(this)) { toast("Set up a fingerprint or face unlock in Android settings first"); return back() }
        erasingSaved({
            when (m) {
                Prefs.LockMethod.APP -> confirmCurrent("Use an app passphrase", { newSecret(back) { recreate() } }, back)
                Prefs.LockMethod.YUBIKEY -> confirmCurrent("Use a YubiKey", { newYubiKey(back) }, back)
                Prefs.LockMethod.PHONE -> confirmCurrent("Use fingerprint or face", {
                    // the biometric must pass too, so the switch can't lock the user out
                    LockedActivity.prompt(this, "Use fingerprint or face", { wipeSaved(); LockedActivity.dropKey(); adopt(Prefs.LockMethod.PHONE); recreate() }, back)
                }, back)
            }
        }, back)
    }

    /** Sets a YubiKey up as the app lock: a credential on the key, its secret read once, then the method switches. */
    private fun newYubiKey(cancel: () -> Unit) = yubiKeyDialog("Set up your YubiKey",
        "Plug your YubiKey into the phone, or enter its PIN and hold it to the back of the phone. Cryptic Vaults makes a credential on it; from then on Cryptic Vaults unlocks with the key, plugged in or held to the phone, its FIDO2 PIN and a touch. " +
            "The key must already have a FIDO2 PIN (set one with Yubico Authenticator if it has none). Plugged in, you'll be asked to touch the key twice; over NFC, keep it held until it's done.\n\n" +
            "If the key is lost there is no way back in except clearing Cryptic Vaults' data. Your drives and containers aren't affected by that.",
        "Set up", cancel, { s, pin, say -> YubiKey.enrol(s, pin, say) }) { (record, key) ->
            wipeSaved()                 // whatever was saved was protected by the previous unlock
            LockedActivity.holdKey(key)
            prefs.yubiKey = record; adopt(Prefs.LockMethod.YUBIKEY)
            recreate()
        }

    private fun toggleLock(sw: Switch, on: Boolean) {
        if (on == prefs.appLock) return
        val undo = { sw.isChecked = prefs.appLock }
        // confirm with the unlock itself, so nobody can switch it off (or on) without it
        if (!on) return erasingSaved({
            confirmCurrent("Turn off app lock", {
                wipeSaved(); LockedActivity.dropKey()
                prefs.appLock = false; adopt(Prefs.LockMethod.PHONE); recreate()
            }, undo)
        }, undo)
        // no fingerprint or face on the phone: the app's own passphrase is the way to lock Cryptic Vaults
        if (!LockedActivity.biometricReady(this)) return newSecret(undo) { prefs.appLock = true; LockedActivity.markUnlocked(); recreate() }
        LockedActivity.prompt(this, "Turn on app lock", { prefs.appLock = true; LockedActivity.markUnlocked(); recreate() }, undo)
    }
}
