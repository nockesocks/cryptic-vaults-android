package me.nocke.cryptic.vaults

import android.app.AlertDialog
import android.graphics.Typeface
import android.hardware.usb.UsbDevice
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.format.Formatter
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.widget.ScrollView
import android.widget.TextView
import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.block.Gpt
import me.nocke.cryptic.vaults.block.Partitions
import me.nocke.cryptic.vaults.block.PfdBlockDevice
import me.nocke.cryptic.vaults.block.SliceBlockDevice
import me.nocke.cryptic.vaults.block.UsbBlockDevice
import me.nocke.cryptic.vaults.luks.Luks2
import kotlin.concurrent.thread

/** The details panel: Device, Disk, USB, Partitions, LUKS header, Health — monospace key/value sections. */
class Details(private val a: MainActivity) {
    private class Text(private val a: MainActivity) {
        val sb = SpannableStringBuilder()
        /** Wrapped value lines start under the value column (hanging indent), not at the left edge. */
        private val indent = android.graphics.Paint().apply {
            typeface = Typeface.MONOSPACE; textSize = 12f * a.resources.displayMetrics.scaledDensity
        }.measureText(" ".repeat(KEY + 2)).toInt()
        private fun span(s: String, color: Int, bold: Boolean = false) {
            val st = sb.length; sb.append(s)
            sb.setSpan(ForegroundColorSpan(a.getColor(color)), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            if (bold) sb.setSpan(StyleSpan(Typeface.BOLD), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        fun h(title: String) { if (sb.isNotEmpty()) sb.append("\n"); span("$title\n", R.color.accent_light, true); span("─".repeat(30) + "\n", R.color.divider) }
        fun kv(k: String, v: Any?) {
            val st = sb.length
            span("  " + k.take(KEY - 1).padEnd(KEY), R.color.text_muted); span(((v?.toString())?.ifEmpty { null } ?: "—") + "\n", R.color.text)
            sb.setSpan(android.text.style.LeadingMarginSpan.Standard(0, indent), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        fun line(s: String, muted: Boolean = false) = span("  $s\n", if (muted) R.color.text_muted else R.color.text)
        companion object { const val KEY = 13 }
    }

    private fun size(n: Long) = "${Formatter.formatFileSize(a, n)}  (%,d bytes)".format(n)

    /** A drive opened just for this; closed when the panel is built. */
    fun showDrive(dev: UsbBlockDevice, d: UsbDevice, found: List<Partitions.Found>) = build("Details", { dev.close() }) { t ->
        val luks = found.firstOrNull()
        t.h("Device  ${luks?.name ?: "whole drive"}")
        if (luks != null) {
            val slice = if (luks.start == 0L && luks.size == dev.size) dev else SliceBlockDevice(dev, luks.start, luks.size)
            t.kv("Type", if (slice === dev) "LUKS2 on the whole drive" else "partition with LUKS2")
            t.kv("Size", size(luks.size))
            t.kv("GPT name", if (slice is SliceBlockDevice) Gpt.nameAt(dev, slice.start) else null)
            t.kv("Unlocked", "no (filesystem inside unknown until unlocked)")
        } else t.kv("Encrypted", "no LUKS2 volume found")
        disk(t, dev); usb(t, dev, d); partitions(t, dev)
        if (luks != null) header(t, if (luks.start == 0L && luks.size == dev.size) dev else SliceBlockDevice(dev, luks.start, luks.size))
        health(t, dev)
    }

    fun showVolume(v: Volumes.Volume) = build("Details  ${v.title}", {}) { t ->
        val luks = v.crypt.base
        val fs = v.fs
        t.h("Device  ${v.title}")
        val drive = (luks as? SliceBlockDevice)?.base ?: luks.takeIf { it is UsbBlockDevice }
        t.kv("Type", when { luks is PfdBlockDevice -> "container file (LUKS2)"; luks is SliceBlockDevice -> "partition with LUKS2"; else -> "LUKS2 on the whole drive" })
        t.kv("Size", size(luks.size))
        t.kv("Filesystem", fs.type)
        t.kv("Label", fs.label)
        fs.info().forEach { (k, value) -> t.kv(k, value) }
        t.kv("Usage", "${Formatter.formatFileSize(a, fs.totalBytes - fs.freeBytes)} used, ${Formatter.formatFileSize(a, fs.freeBytes)} free")
        t.kv("Unlocked", "yes" + (fs.readOnlyReason?.let { " · read-only: $it" } ?: ""))
        if (drive is UsbBlockDevice) { disk(t, drive); usb(t, drive, drive.device); partitions(t, drive) }
        header(t, luks)
        if (drive is UsbBlockDevice) health(t, drive)
    }

    private fun disk(t: Text, dev: UsbBlockDevice) {
        val info = runCatching { dev.info() }.getOrNull()
        t.h("Disk  ${dev.device.productName ?: "USB drive"}")
        t.kv("Model", info?.product); t.kv("Vendor", info?.vendor); t.kv("Revision", info?.revision)
        t.kv("Serial", runCatching { dev.device.serialNumber }.getOrNull())
        t.kv("Transport", "usb")
        t.kv("Media", when (info?.rotationRate) { null, 0 -> "not reported"; 1 -> "solid-state"; else -> "rotational (HDD, ${info.rotationRate} rpm)" })
        t.kv("Removable", if (info?.removable == true) "yes" else "no (fixed media behind USB)")
        t.kv("Read-only", when (info?.writeProtected) { true -> "yes (write-protected)"; false -> "no"; null -> "not reported" })
        t.kv("Capacity", size(dev.size))
        t.kv("Block size", "${dev.sectorSize} bytes")
        t.kv("Table", partitionTable(dev))
    }

    private fun usb(t: Text, dev: UsbBlockDevice, d: UsbDevice) {
        t.h("USB")
        t.line("ID %04x:%04x %s %s".format(d.vendorId, d.productId, d.manufacturerName ?: "", d.productName ?: ""))
        t.kv("Version", "USB ${dev.usbVersion}"); t.kv("Speed", dev.speed)
        t.kv("UAS capable", if (dev.uasCapable) "yes (Cryptic Vaults talks bulk-only to it)" else "no")
        t.kv("Driver", "Cryptic Vaults bulk-only (Android's own driver detached)")
    }

    private fun partitionTable(dev: BlockDevice): String {
        val mbr = ByteArray(maxOf(512, dev.sectorSize)); runCatching { dev.read(0, mbr) }
        val sig = (mbr[510].toInt() and 0xff) == 0x55 && (mbr[511].toInt() and 0xff) == 0xaa
        return when {
            runCatching { Luks2.isLuks(dev) }.getOrDefault(false) -> "none (LUKS2 on the whole drive)"
            !sig -> "none"
            (0 until 4).any { (mbr[446 + 16 * it + 4].toInt() and 0xff) == 0xee } -> "gpt"
            else -> "dos (MBR)"
        }
    }

    private fun partitions(t: Text, dev: BlockDevice) {
        val parts = runCatching { Partitions.list(dev) }.getOrDefault(emptyList())
        if (parts.isEmpty()) return
        t.h("Partitions")
        t.line("%-14s %9s  %s".format("NAME", "SIZE", "TYPE"), muted = true)
        for (p in parts) {
            val luks = runCatching { Luks2.isLuks(SliceBlockDevice(dev, p.start, p.size)) }.getOrDefault(false)
            t.line("%-14s %9s  %s".format(p.name.take(14), Formatter.formatShortFileSize(a, p.size), if (luks) "LUKS2" else "—"))
        }
    }

    private fun header(t: Text, luks: BlockDevice) {
        val h = runCatching { Luks2.readHeader(luks) }.getOrElse { t.h("LUKS header"); t.line("unreadable: ${it.message}"); return }
        t.h("LUKS header")
        t.kv("Version", "2"); t.kv("UUID", h.uuid); t.kv("Label", h.label.ifEmpty { "(no label)" })
        t.kv("Subsystem", h.subsystem.ifEmpty { "(no subsystem)" }); t.kv("Epoch", h.seqId)
        val segs = h.json.getJSONObject("segments")
        for (id in segs.keys()) {
            val s = segs.getJSONObject(id)
            t.line("Data segment $id: ${s.getString("type")}")
            t.kv("  offset", "${s.getString("offset")} bytes"); t.kv("  cipher", s.optString("encryption")); t.kv("  sector", "${s.optInt("sector_size")} bytes")
        }
        val slots = h.json.getJSONObject("keyslots")
        for (id in slots.keys().asSequence().sortedBy { it.toInt() }) {
            val k = slots.getJSONObject(id); val kdf = k.getJSONObject("kdf"); val area = k.getJSONObject("area")
            t.line("Key slot $id: ${k.getString("type")}")
            t.kv("  cipher", "${area.optString("encryption")}, ${k.optInt("key_size") * 8}-bit key")
            t.kv("  PBKDF", kdf.getString("type"))
            if (kdf.has("time")) { t.kv("  time cost", kdf.getInt("time")); t.kv("  memory", "${kdf.getInt("memory")} KiB"); t.kv("  threads", kdf.getInt("cpus")) }
            if (kdf.has("iterations")) t.kv("  iterations", kdf.getInt("iterations"))
            t.kv("  AF hash", k.getJSONObject("af").optString("hash"))
        }
        val digests = h.json.getJSONObject("digests")
        for (id in digests.keys()) { val d = digests.getJSONObject(id); t.line("Digest $id: ${d.getString("type")}, ${d.optString("hash")}, ${d.optInt("iterations")} iterations") }
    }

    private fun health(t: Text, dev: UsbBlockDevice) {
        t.h("Health")
        val rows = runCatching { Smart.read(dev) }.getOrElse { listOf("SMART" to "unsupported by device/bridge") }
        rows.forEach { (k, v) -> t.kv(k, v) }
    }

    private fun build(title: String, done: () -> Unit, fill: (Text) -> Unit) {
        val wait = AlertDialog.Builder(a).setTitle(title).setMessage("Reading…").setCancelable(false).show()
        thread(name = "details") {
            val t = Text(a)
            try { fill(t) } catch (e: Exception) { AppLog.e("details", e); t.h("Error"); t.line(e.message ?: e.javaClass.simpleName) } finally { runCatching(done) }
            a.runOnUiThread {
                wait.dismiss()
                val view = TextView(a).apply {
                    text = t.sb; typeface = Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true)
                    val p = (20 * resources.displayMetrics.density).toInt(); setPadding(p, p / 2, p, p)
                }
                AlertDialog.Builder(a).setTitle(title).setView(ScrollView(a).apply { addView(view) }).setPositiveButton("Close", null).show()
            }
        }
    }
}
