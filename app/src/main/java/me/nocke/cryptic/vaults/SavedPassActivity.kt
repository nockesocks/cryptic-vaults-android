package me.nocke.cryptic.vaults

import android.app.AlertDialog
import android.os.Bundle
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView

/**
 * Manage vault passphrases (Settings → App lock): the saved passphrases by vault name; tick one or more and remove
 * them. A saved passphrase is never shown: that would make the app lock a way to read every vault's passphrase off the
 * phone. Nor is it edited here; changing a vault's passphrase through Edit updates the saved one.
 */
class SavedPassActivity : LockedActivity() {
    private val ui by lazy { Ui(this) }
    private val saved by lazy { SavedPass(this) }
    private lateinit var list: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = ui.column(16)
        col.addView(ui.back("Vault passphrases") { finish() })
        col.addView(ui.paragraph("Passphrases saved on this phone, protected by ${saved.protection}. Cryptic Vaults never shows them. " +
            "To add one, tick \"Save this passphrase\" when you unlock a drive or container."))
        list = ui.column(); col.addView(list)
        setContentView(ScrollView(this).apply { addView(col); fitsSystemWindows = true; setBackgroundColor(getColor(R.color.bg)) })
        render()
    }

    private fun render() {
        list.removeAllViews()
        val entries = saved.list()
        if (entries.isEmpty()) { list.addView(ui.empty("Nothing saved yet.", R.drawable.ic_lock_small)); return }
        val ticked = LinkedHashSet<SavedPass.Entry>()
        val remove = ui.button("Remove selected", Ui.Kind.DANGER) { remove(ticked.toList()) }
        fun refresh() { remove.isEnabled = ticked.isNotEmpty(); remove.alpha = if (ticked.isEmpty()) 0.4f else 1f }
        for (e in entries) list.addView(ui.card().apply {
            addView(CheckBox(this@SavedPassActivity).apply {
                text = "${e.name}\nLUKS ${e.uuid.take(8)}…"; textSize = 15f; setTextColor(getColor(R.color.text)); setPadding(ui.dp(8), 0, 0, 0)
                setOnCheckedChangeListener { _, on -> if (on) ticked += e else ticked -= e; refresh() }
            })
        })
        list.addView(ui.full(remove, top = 16)); refresh()
    }

    private fun remove(entries: List<SavedPass.Entry>) {
        AlertDialog.Builder(this).setTitle(if (entries.size == 1) "Remove the passphrase for ${entries[0].name}?" else "Remove ${entries.size} saved passphrases?")
            .setMessage((if (entries.size == 1) "" else entries.joinToString("\n") { "• ${it.name}" } + "\n\n") +
                "Erased from this phone only. The drives and containers aren't touched; you'll type the passphrase the next time you unlock one.")
            .setPositiveButton("Remove") { _, _ -> entries.forEach { saved.forget(it.uuid) }; render() }.setNegativeButton("Cancel", null).show()
    }
}
