package me.nocke.cryptic.vaults

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.ln

/** Dialog forms: labelled fields, a passphrase strength meter, choice chips, inline errors. */
class Form(private val a: Activity, private val title: String) {
    private val ui = Ui(a)
    private val body = ui.column().apply { setPadding(ui.dp(24), ui.dp(8), ui.dp(24), 0) }
    private val error = TextView(a).apply { setTextColor(a.getColor(R.color.danger)); textSize = 13f; visibility = View.GONE }
    private val texts = LinkedHashMap<String, EditText>()
    private val checks = HashMap<String, CheckBox>()
    private val choices = HashMap<String, String>()

    fun note(text: String, danger: Boolean = false) = apply {
        body.addView(TextView(a).apply {
            this.text = text; textSize = 13f; setPadding(0, ui.dp(4), 0, ui.dp(8))
            setTextColor(a.getColor(if (danger) R.color.danger else R.color.text_muted))
        })
    }

    private fun caption(text: String) = TextView(a).apply {
        this.text = text; textSize = 12f; setTextColor(a.getColor(R.color.text_muted)); setPadding(0, ui.dp(10), 0, 0)
    }

    fun text(key: String, label: String, value: String = "", hint: String = "", number: Boolean = false) = apply {
        body.addView(caption(label))
        texts[key] = EditText(a).apply {
            isSingleLine = true; setText(value); this.hint = hint
            inputType = if (number) InputType.TYPE_CLASS_NUMBER
                else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS   // names and labels: no autocorrect
        }
        body.addView(texts[key])
    }

    /** A passphrase field; with [meter], a strength line underneath. */
    fun password(key: String, label: String, meter: Boolean = false) = apply {
        body.addView(caption(label))
        // single-line first: setSingleLine() swaps in its own transformation and would undo the masking
        val f = EditText(a).apply { isSingleLine = true; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD }
        texts[key] = f; body.addView(f)
        if (meter) {
            val m = TextView(a).apply { textSize = 12f; typeface = Typeface.MONOSPACE }
            body.addView(m)
            f.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, af: Int) {}
                override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    val (bits, verdict, color) = strength(s?.toString() ?: "")
                    m.text = if (s.isNullOrEmpty()) "" else "■".repeat((bits / 15).coerceIn(1, 8)) + "  $bits bits · $verdict"
                    m.setTextColor(a.getColor(color))
                }
            })
        }
    }

    /** One of several options as chips; [key] holds the chosen value. */
    fun choice(key: String, label: String, options: List<Pair<String, String>>, selected: String, onChange: (String) -> Unit = {}) = apply {
        body.addView(caption(label))
        choices[key] = selected
        body.addView(ui.chips(options, selected) { choices[key] = it; onChange(it) })
    }

    fun check(key: String, label: String, value: Boolean) = apply {
        checks[key] = CheckBox(a).apply { text = label; isChecked = value; setTextColor(a.getColor(R.color.text)); textSize = 14f }
        body.addView(checks[key])
    }

    fun field(key: String) = texts.getValue(key)

    class Values(val text: Map<String, String>, val checks: Map<String, Boolean>, val choices: Map<String, String>)

    /**
     * Shows the form. [validate] returns an error to show inline (the dialog stays open) or null to accept;
     * then [ok] runs. Password fields are cleared once the dialog closes. Returns the dialog; cancel() on it acts as Cancel.
     */
    fun show(okLabel: String, danger: Boolean = false, onCancel: () -> Unit = {}, validate: (Values) -> String?, ok: (Values) -> Unit): AlertDialog {
        body.addView(error)
        val dlg = AlertDialog.Builder(a).setTitle(title).setView(android.widget.ScrollView(a).apply { addView(body) })
            .setPositiveButton(okLabel, null).setNegativeButton("Cancel") { _, _ -> onCancel() }
            .setOnCancelListener { onCancel() }.create()
        // resize above the keyboard (fields scroll) instead of letting it cover Cancel/OK
        dlg.window?.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        LockedActivity.noAutofill(dlg.window)
        dlg.setOnDismissListener { LockedActivity.forgetAutofill(a) }
        dlg.setOnShowListener {
            val b = dlg.getButton(AlertDialog.BUTTON_POSITIVE)
            if (danger) b.setTextColor(a.getColor(R.color.danger))
            b.setOnClickListener {
                val v = Values(texts.mapValues { it.value.text.toString() }, checks.mapValues { it.value.isChecked }, HashMap(choices))
                val problem = validate(v)
                if (problem != null) { error.text = problem; error.visibility = View.VISIBLE; return@setOnClickListener }
                texts.values.filter { it.inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD != 0 }.forEach { it.text.clear() }
                dlg.dismiss(); ok(v)
            }
        }
        dlg.show()
        return dlg
    }

    companion object {
        /** A rough entropy estimate: (bits, verdict, colour). */
        fun strength(pw: String): Triple<Int, String, Int> {
            var pool = 0
            if (pw.any { it in 'a'..'z' }) pool += 26
            if (pw.any { it in 'A'..'Z' }) pool += 26
            if (pw.any { it.isDigit() }) pool += 10
            if (pw.any { !it.isLetterOrDigit() && it != '_' }) pool += 33
            val bits = if (pool == 0) 0 else (pw.length * ln(pool.toDouble()) / ln(2.0)).toInt()
            return when {
                bits < 40 -> Triple(bits, "weak", R.color.danger)
                bits < 64 -> Triple(bits, "fair", R.color.warn)
                bits < 90 -> Triple(bits, "good", R.color.ok)
                else -> Triple(bits, "strong", R.color.accent_light)
            }
        }

        /** Sizes: "500M", "1G", "1.5T" (binary units). */
        fun parseSize(s: String): Long? {
            val m = Regex("""\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*""", RegexOption.IGNORE_CASE).matchEntire(s) ?: return null
            val mult = when (m.groupValues[2].uppercase()) { "" -> 1L; "K" -> 1L shl 10; "M" -> 1L shl 20; "G" -> 1L shl 30; else -> 1L shl 40 }
            return (m.groupValues[1].toDouble() * mult).toLong()
        }
    }
}
