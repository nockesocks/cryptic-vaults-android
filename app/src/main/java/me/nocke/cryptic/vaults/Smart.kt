package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.UsbBlockDevice

/** Health rows from SMART over SAT: verdict from attribute vs threshold, temperature, power-on, error counters. */
object Smart {
    private val counters = mapOf(5 to "Reallocated sectors", 187 to "Reported uncorrectable", 197 to "Pending sectors",
        198 to "Offline uncorrectable", 231 to "SSD life left", 233 to "Media wearout")

    /** Throws when the drive or its USB bridge doesn't pass SMART through (NVMe bridges usually don't). */
    fun read(dev: UsbBlockDevice): List<Pair<String, String>> {
        val data = dev.ataSmart(0xD0)
        val thr = runCatching { dev.ataSmart(0xD1) }.getOrNull()
        class Attr(val id: Int, val value: Int, val raw: Long, val prefail: Boolean)
        val attrs = (0 until 30).mapNotNull { i ->
            val o = 2 + 12 * i
            val id = data[o].toInt() and 0xff
            if (id == 0) null else Attr(id, data[o + 3].toInt() and 0xff,
                (0 until 6).fold(0L) { v, k -> v or ((data[o + 5 + k].toLong() and 0xff) shl (8 * k)) }, data[o + 1].toInt() and 1 != 0)
        }
        if (attrs.isEmpty()) throw IllegalStateException("no SMART attributes")
        val thresholds = thr?.let { t -> (0 until 30).associate { i -> (t[2 + 12 * i].toInt() and 0xff) to (t[3 + 12 * i].toInt() and 0xff) } } ?: emptyMap()
        val failing = attrs.filter { a -> a.prefail && (thresholds[a.id] ?: 0) in 1..255 && a.value <= thresholds.getValue(a.id) }
        val rows = ArrayList<Pair<String, String>>()
        rows += "SMART" to when { thr == null -> "attributes read (no thresholds)"; failing.isEmpty() -> "PASSED"; else -> "FAILED (attribute ${failing.joinToString { it.id.toString() }})" }
        attrs.firstOrNull { it.id == 194 || it.id == 190 }?.let { rows += "Temperature" to "${it.raw and 0xff} °C" }
        attrs.firstOrNull { it.id == 9 }?.let { rows += "Power-on" to "${it.raw and 0xffffffffL} h" }
        for (a in attrs) counters[a.id]?.let { name -> rows += name to (if (a.id >= 231) "${a.value} %" else a.raw.toString()) }
        return rows
    }
}
