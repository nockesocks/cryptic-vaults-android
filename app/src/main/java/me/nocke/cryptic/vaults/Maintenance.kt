package me.nocke.cryptic.vaults

import android.app.ActivityManager
import android.app.AlertDialog
import android.net.Uri
import android.os.Environment
import android.os.StatFs
import android.system.Os
import android.text.format.Formatter
import android.widget.Toast
import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.block.Gpt
import me.nocke.cryptic.vaults.block.Partitions
import me.nocke.cryptic.vaults.block.PfdBlockDevice
import me.nocke.cryptic.vaults.block.SliceBlockDevice
import me.nocke.cryptic.vaults.fs.Create
import me.nocke.cryptic.vaults.luks.Luks2
import me.nocke.cryptic.vaults.luks.LuksEdit
import me.nocke.cryptic.vaults.luks.LuksFormat
import me.nocke.cryptic.vaults.luks.WrongPassphraseException
import java.security.SecureRandom
import kotlin.concurrent.thread

/** Creating, editing and destroying flows: encrypt a drive, new container, edit, wipe. */
class Maintenance(private val a: MainActivity) {
    private val prefs = Prefs(a)

    private fun toast(s: String) = Toast.makeText(a, s, Toast.LENGTH_LONG).show()
    private fun size(n: Long) = Formatter.formatFileSize(a, n)

    /** Argon2id like cryptsetup on a big machine (1 GiB), but at most a quarter of this phone's RAM. */
    private fun kdf(): LuksFormat.Kdf {
        val mi = ActivityManager.MemoryInfo().also { a.getSystemService(ActivityManager::class.java).getMemoryInfo(it) }
        val kib = minOf(1048576L, mi.totalMem / 4 / 1024).toInt()
        return LuksFormat.Kdf(memoryKib = kib, time = 4, lanes = 4)
    }

    private var defaultFs: Create.Fs
        get() = prefs.defaultFs
        set(v) { prefs.defaultFs = v }

    private fun fsChoice(f: Form) = f.choice("fs", "Filesystem inside", Create.Fs.values().map { it.name to it.title }, defaultFs.name)

    /** Shared checks for a new passphrase + filesystem + label. */
    private fun newVolumeProblem(v: Form.Values): String? {
        val pw = v.text.getValue("pw")
        val fs = Create.Fs.valueOf(v.choices.getValue("fs"))
        return when {
            pw.length < 8 -> "Use a passphrase of 8 or more characters"
            pw != v.text.getValue("pw2") -> "The passphrases don't match"
            else -> Create.labelProblem(fs, v.text.getValue("label").trim())
        }
    }

    /** Runs [work] off the main thread behind a progress dialog; [work] reports 0..100 and returns a message. */
    private fun busy(title: String, cancellable: Boolean = false, work: ((Int) -> Unit, () -> Boolean) -> String?) {
        var cancelled = false
        val b = AlertDialog.Builder(a).setTitle(title).setMessage("Working…").setCancelable(false)
        if (cancellable) b.setNegativeButton("Stop") { _, _ -> cancelled = true }
        val dlg = b.show()
        thread(name = "maintenance") {
            val msg = try { work({ pct -> a.runOnUiThread { dlg.setMessage("$pct %") } }, { cancelled }) } catch (e: WrongPassphraseException) {
                "The current passphrase is wrong"
            } catch (e: Throwable) {
                AppLog.e("$title failed", e); "$title failed: ${e.message ?: e.javaClass.simpleName}"
            }
            a.runOnUiThread { dlg.dismiss(); if (msg != null) toast(msg); a.refresh() }
        }
    }

    // ---- encrypt a whole drive ----

    /** Danger text: what the drive is and what's on it. */
    private fun dangerText(dev: BlockDevice, name: String): String {
        val parts = runCatching { Partitions.list(dev) }.getOrDefault(emptyList())
        val contents = when {
            runCatching { Luks2.isLuks(dev) }.getOrDefault(false) -> "a LUKS2 volume"
            parts.isEmpty() -> "no partitions"
            else -> parts.joinToString(", ") { p ->
                val luks = runCatching { Luks2.isLuks(SliceBlockDevice(dev, p.start, p.size)) }.getOrDefault(false)
                "${p.name} (${size(p.size)}${if (luks) ", LUKS2" else ""})"
            }
        }
        return "Drive: $name (${size(dev.size)})\nContains: $contents\n\nALL DATA ON IT WILL BE PERMANENTLY DESTROYED."
    }

    private fun confirmErase(dev: BlockDevice, name: String, then: () -> Unit) {
        Form(a, "Erase $name?").note(dangerText(dev, name), danger = true).text("confirm", "Type ERASE to continue")
            .show("Continue", danger = true, onCancel = { dev.close() }, validate = { if (it.text["confirm"] == "ERASE") null else "Type ERASE exactly" }) { then() }
    }

    fun formatDrive(dev: BlockDevice, name: String, source: String) = confirmErase(dev, name) {
        val f = Form(a, "Encrypt $name")
            .password("pw", "New passphrase (LUKS2 · aes-xts-512 · argon2id)", meter = true)
            .password("pw2", "Repeat passphrase")
        fsChoice(f).text("label", "Name / label", "secure")
            .check("keep", "Leave it unlocked when done", true)
            .note("The drive gets a GPT partition table with one partition, encrypted with LUKS2.")
            .show("Encrypt", danger = true, onCancel = { dev.close() }, validate = ::newVolumeProblem) { v ->
                val fs = Create.Fs.valueOf(v.choices.getValue("fs")); defaultFs = fs
                val pw = v.text.getValue("pw").toByteArray(Charsets.UTF_8); val label = v.text.getValue("label").trim()
                busy("Encrypting $name") { _, _ ->
                    try {
                        AppLog.i("encrypting $name (${dev.size} bytes): GPT + LUKS2 + ${fs.title}")
                        val crypt = Create.encrypted(dev, true, pw, fs, label, kdf())
                        if (v.checks["keep"] == true) { Volumes.mount(a, crypt, name, source); "$name is encrypted and unlocked" }
                        else { crypt.close(); "$name is encrypted (${fs.title}) and locked" }
                    } catch (e: Exception) { runCatching { dev.close() }; throw e } finally { pw.fill(0) }
                }
            }
    }

    // ---- new container file ----

    fun createContainer(uri: Uri, name: String) {
        val free = runCatching { StatFs(Environment.getExternalStorageDirectory().path).availableBytes }.getOrNull()
        val f = Form(a, "New encrypted container $name")
            .text("size", "Size, e.g. 1G or 500M" + (free?.let { "  (free on the phone: ${size(it)})" } ?: ""), "1G")
            .password("pw", "New passphrase", meter = true)
            .password("pw2", "Repeat passphrase")
        fsChoice(f).text("label", "Label", "vault")
            .check("rand", "Pre-fill with random data (slower, hides how full it is)", false)
            .check("remember", "Remember this container on this phone", true)
            .show("Create", onCancel = { runCatching { android.provider.DocumentsContract.deleteDocument(a.contentResolver, uri) } }, validate = { v ->
                val bytes = Form.parseSize(v.text.getValue("size"))
                when {
                    bytes == null -> "Size like 500M or 1G"
                    bytes < 40L shl 20 -> "A container must be at least 40M"
                    free != null && bytes > free -> "Not enough free space (${size(free)} free)"
                    else -> newVolumeProblem(v)
                }
            }) { v ->
                val fs = Create.Fs.valueOf(v.choices.getValue("fs")); defaultFs = fs
                val bytes = Form.parseSize(v.text.getValue("size"))!! / 4096 * 4096
                val pw = v.text.getValue("pw").toByteArray(Charsets.UTF_8); val label = v.text.getValue("label").trim()
                busy("Creating $name") { progress, _ ->
                    val pfd = a.contentResolver.openFileDescriptor(uri, "rw") ?: error("Can't open $name")
                    val dev = try {
                        Os.ftruncate(pfd.fileDescriptor, bytes)
                        PfdBlockDevice(pfd).also { if (v.checks["rand"] == true) randomFill(it, progress) }
                    } catch (e: Exception) { pfd.close(); throw e }
                    try {
                        val crypt = Create.encrypted(dev, false, pw, fs, label, kdf())
                        if (v.checks["remember"] == true) prefs.remember(uri, name)
                        Volumes.mount(a, crypt, name, uri.toString())
                        "$name created and unlocked"
                    } catch (e: Exception) { runCatching { dev.close() }; throw e } finally { pw.fill(0) }
                }
            }
    }

    private fun randomFill(dev: BlockDevice, progress: (Int) -> Unit) {
        val chunk = ByteArray(4 shl 20); val rnd = SecureRandom()
        var p = 0L; var last = -1
        while (p < dev.size) {
            val n = minOf(chunk.size.toLong(), dev.size - p).toInt()
            rnd.nextBytes(chunk); dev.write(p, chunk, 0, n); p += n
            val pct = (p * 100 / dev.size).toInt(); if (pct != last) { last = pct; progress(pct) }
        }
        dev.flush()
    }

    // ---- edit: partition name, LUKS label, filesystem label, passphrase ----

    /** Edit an unlocked volume. */
    fun editVolume(v: Volumes.Volume) { v.touch(); edit(v.crypt.base, v.fs, v.title, used = v::touch) {} }   // editing counts as use for vault auto-lock

    /** Edit a locked LUKS2 volume on a drive (the filesystem inside can't be renamed until it's unlocked). */
    fun editLocked(dev: BlockDevice, title: String) = edit(dev, null, title) { dev.close() }

    private fun edit(luks: BlockDevice, fs: me.nocke.cryptic.vaults.fs.FileSystem?, title: String, used: () -> Unit = {}, done: () -> Unit) {
        val slice = luks as? SliceBlockDevice
        val partName = slice?.let { Gpt.nameAt(it.base, it.start) }
        val header = runCatching { Luks2.readHeader(luks) }.getOrNull()
        val luksLabel = header?.label ?: ""
        val uuid = header?.uuid ?: ""
        val f = Form(a, "Edit $title")
        if (partName != null) f.text("part", "Partition name (GPT)", partName)
        f.text("luks", "Encrypted volume label (LUKS)", luksLabel)
        if (fs != null && fs.readOnlyReason == null) f.text("fslabel", "Filesystem label (${fs.type})", fs.label)
        else if (fs == null) f.note("Unlock it first to rename the filesystem inside.")
        f.password("cur", "Current passphrase (only to change it)")
            .password("new", "New passphrase", meter = true)
            .password("new2", "Repeat new passphrase")
            .show("Save", onCancel = done, validate = { v ->
                val wantsPw = v.text["cur"]!!.isNotEmpty() || v.text["new"]!!.isNotEmpty()
                when {
                    wantsPw && v.text["new"] != v.text["new2"] -> "The new passphrases don't match"
                    wantsPw && (v.text["new"]!!.length < 8 || v.text["cur"]!!.isEmpty()) -> "Enter the current passphrase and a new one of 8+ characters"
                    v.text["luks"]!!.toByteArray().size > 47 -> "The LUKS label is at most 47 bytes"
                    fs != null && v.text["fslabel"] != null && fs.type == "exFAT" && v.text["fslabel"]!!.length > 11 -> "exFAT labels are at most 11 characters"
                    fs != null && v.text["fslabel"] != null && v.text["fslabel"]!!.toByteArray().size > 16 -> "ext4 labels are at most 16 bytes"
                    else -> null
                }
            }) { v ->
                val cur = v.text["cur"]!!.toByteArray(Charsets.UTF_8); val new = v.text["new"]!!.toByteArray(Charsets.UTF_8)
                // for the saved passphrases: the new one, kept until the change has gone through
                var keep = if (new.isNotEmpty() && prefs.appLock && uuid.isNotEmpty()) new.copyOf() else null
                used()
                busy("Saving changes") { _, _ ->
                    try {
                        val changed = ArrayList<String>()
                        v.text["part"]?.trim()?.let { if (it != partName) { Gpt.renameAt(slice!!.base, slice.start, it); changed += "partition name" } }
                        v.text["luks"]!!.trim().let { if (it != luksLabel) { LuksEdit.setLabel(luks, it); changed += "LUKS label" } }
                        v.text["fslabel"]?.trim()?.let { if (fs != null && it != fs.label) { fs.setLabel(it); changed += "filesystem label" } }
                        if (new.isNotEmpty()) {
                            LuksEdit.changePassphrase(luks, cur, new, kdf()); changed += "passphrase"
                            keep?.let { k -> keep = null; a.runOnUiThread { savedAfterChange(uuid, title, k) } }
                        }
                        AppLog.i("edited $title: ${changed.joinToString()}")
                        if (changed.isEmpty()) "Nothing changed" else "Saved: ${changed.joinToString()}"
                    } finally { cur.fill(0); new.fill(0); keep?.fill(0); a.runOnUiThread(done) }
                }
            }
    }

    /** After the app changed a vault's passphrase: a saved one follows by itself; otherwise offer to save the new one. */
    private fun savedAfterChange(uuid: String, title: String, pass: ByteArray) {
        val saved = SavedPass(a)
        if (saved.has(uuid)) return toast(if (saved.save(uuid, title, pass)) "The saved passphrase for $title was updated too"
            else "The saved passphrase for $title could not be updated; it will be removed at the next unlock")
        if (saved.problem != null) return pass.fill(0)
        AlertDialog.Builder(a).setTitle("Save the new passphrase?")
            .setMessage("Keep the new passphrase for $title on this phone, protected by ${saved.protection}, so you don't have to type it to unlock?")
            .setPositiveButton("Save") { _, _ -> saved.confirmFirst({ toast(if (saved.save(uuid, title, pass)) "Passphrase saved for $title" else "It could not be saved") }) { pass.fill(0) } }
            .setNegativeButton("Not now") { _, _ -> pass.fill(0) }.setOnCancelListener { pass.fill(0) }.show()
    }

    // ---- wipe ----

    fun wipeDrive(dev: BlockDevice, name: String) {
        AlertDialog.Builder(a).setTitle("Wipe $name")
            .setItems(arrayOf("Quick: destroy headers and partition tables", "Full: overwrite the whole drive with random data")) { _, which ->
                confirmErase(dev, name) { wipe(dev, name, full = which == 1) }
            }.setOnCancelListener { dev.close() }.show()
    }

    private fun wipe(dev: BlockDevice, name: String, full: Boolean) = busy("Wiping $name", cancellable = full) { progress, cancelled ->
        try {
            val chunk = ByteArray(4 * 1024 * 1024)
            val rnd = SecureRandom()
            // quick: first 32 MiB (LUKS headers, key slots, MBR/GPT) and last 1 MiB (backup GPT)
            val ranges = if (full) listOf(0L to dev.size) else listOf(0L to minOf(dev.size, 32L shl 20), maxOf(0L, dev.size - (1L shl 20)) to dev.size)
            val total = ranges.sumOf { it.second - it.first }
            var done = 0L; var last = -1
            for ((from, to) in ranges) {
                var p = from
                while (p < to) {
                    if (cancelled()) { AppLog.i("wipe of $name stopped at $p"); return@busy "Wipe stopped: $name is partly overwritten" }
                    val n = minOf(chunk.size.toLong(), to - p).toInt()
                    if (full) rnd.nextBytes(chunk) else java.util.Arrays.fill(chunk, 0)
                    dev.write(p, chunk, 0, n)
                    p += n; done += n
                    val pct = (done * 100 / total).toInt(); if (pct != last) { last = pct; progress(pct) }
                }
            }
            dev.flush()
            AppLog.i("wiped $name (${if (full) "full" else "quick"})")
            "$name wiped"
        } finally { dev.close() }
    }
}
