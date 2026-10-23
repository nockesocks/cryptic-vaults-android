package me.nocke.cryptic.vaults

import android.content.Context
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/** App-private log the user can share without adb. Never log passphrases, keys or file contents. */
object AppLog {
    private const val MAX = 512 * 1024
    private var file: File? = null
    private val fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")

    fun init(ctx: Context) { if (file == null) file = File(ctx.applicationContext.filesDir, "app.log") }

    fun i(msg: String) = put("I", msg, null)
    fun e(msg: String, t: Throwable? = null) = put("E", msg, t)

    @Synchronized
    private fun put(level: String, msg: String, t: Throwable?) {
        if (level == "E") Log.e("Cryptic Vaults", msg, t) else Log.i("Cryptic Vaults", msg)
        val f = file ?: return
        runCatching {
            if (f.length() > MAX) f.renameTo(File(f.path + ".1"))
            val trace = t?.let { StringWriter().also { w -> it.printStackTrace(PrintWriter(w)) }.toString() } ?: ""
            f.appendText("${LocalDateTime.now().format(fmt)} $level $msg\n$trace")
        }
    }

    /** The last [max] characters of the log, older file first. */
    @Synchronized
    fun text(max: Int = 200_000): String {
        val f = file ?: return ""
        val s = listOf(File(f.path + ".1"), f).filter { it.exists() }.joinToString("") { it.readText() }
        return s.takeLast(max)
    }
}
