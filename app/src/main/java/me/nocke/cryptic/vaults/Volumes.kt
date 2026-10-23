package me.nocke.cryptic.vaults

import android.content.Context
import android.content.Intent
import android.provider.DocumentsContract
import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.exfat.ExFat
import me.nocke.cryptic.vaults.ext4.Ext4
import me.nocke.cryptic.vaults.fs.FileSystem
import me.nocke.cryptic.vaults.luks.CryptBlockDevice
import me.nocke.cryptic.vaults.luks.Luks2
import me.nocke.cryptic.vaults.luks.WrongPassphraseException
import kotlin.concurrent.thread

/** Unlocked volumes, shared by the UI, the service and the DocumentsProvider. */
object Volumes {
    /** [source]: the USB device name for a drive, so unplugging it locks the volume; null for a container file. */
    class Volume(val id: String, private val name: String, val fs: FileSystem, val source: String?, val crypt: CryptBlockDevice) {
        /** The filesystem label, else the drive or file name; follows relabels. */
        val title get() = fs.label.ifEmpty { name }
        /** Set while the final flush runs off the main thread; the provider stops serving it at once. */
        @Volatile var closing = false
        /** When it was last used (unlock, or a file operation through the provider): what vault auto-lock counts from. */
        @Volatile var lastUsed = android.os.SystemClock.elapsedRealtime(); private set
        fun touch() { lastUsed = android.os.SystemClock.elapsedRealtime() }
    }

    private val open = LinkedHashMap<String, Volume>()
    private var nextId = 1
    val listeners = ArrayList<() -> Unit>()

    @Synchronized fun all(): List<Volume> = open.values.toList()
    /** For the provider: looking a volume up counts as using it. */
    @Synchronized fun get(id: String): Volume? = open[id]?.takeUnless { it.closing }?.also { it.touch() }

    /** Unlocks LUKS2 on [dev] and mounts the exFAT inside. Slow (key derivation): call off the main thread. */
    fun unlock(ctx: Context, dev: BlockDevice, passphrase: ByteArray, title: String, source: String? = null): Volume {
        try {
            return mount(ctx, Luks2.open(dev, passphrase), title, source)
        } catch (e: Exception) {
            if (e !is WrongPassphraseException) runCatching { dev.close() }  // a wrong passphrase gets another try
            throw e
        } finally {
            passphrase.fill(0)
        }
    }

    /** Mounts the exFAT on an already unlocked (or just formatted) LUKS2 segment. */
    fun mount(ctx: Context, crypt: CryptBlockDevice, title: String, source: String?): Volume {
        // the id is the LUKS UUID, so document ids (and apps' saved grants to them) survive lock/unlock
        val id = crypt.uuid.ifEmpty { "v${nextId++}" }
        if (synchronized(this) { open.containsKey(id) }) { crypt.close(); throw IllegalStateException("This volume is already unlocked") }
        val fs = try { mountFs(crypt) } catch (e: Exception) { crypt.close(); throw e }
        val v = synchronized(this) { Volume(id, title, fs, source, crypt).also { open[it.id] = it } }
        AppLog.i("unlocked volume ${v.id} ($title): ${fs.type}, ${fs.totalBytes} bytes" + (fs.readOnlyReason?.let { ", read-only: $it" } ?: ""))
        changed(ctx)
        return v
    }

    /** exFAT or ext2/3/4, by signature. */
    private fun mountFs(dev: BlockDevice): FileSystem {
        val b = ByteArray(maxOf(dev.sectorSize, 2048)); dev.read(0, b)
        return when {
            String(b, 3, 8, Charsets.US_ASCII) == "EXFAT   " -> ExFat.mount(dev)
            Ext4.isExt(dev) -> Ext4.mount(dev)
            else -> throw java.io.IOException("Unknown filesystem inside the LUKS volume (supported: exFAT, ext4)")
        }
    }

    /** Flushes and closes on a worker thread: a stuck or unplugged drive must never block the main thread. */
    fun lock(ctx: Context, id: String) {
        val v = synchronized(this) { open[id]?.takeUnless { it.closing } } ?: return
        v.closing = true
        changed(ctx)
        thread(name = "lock-${v.id.take(8)}") {
            runCatching { v.fs.close() }.onFailure { AppLog.e("lock ${v.id}: flush failed", it) }
            synchronized(this) { open.remove(id) }
            AppLog.i("locked volume ${v.id}")
            changed(ctx)
        }
    }

    fun lockAll(ctx: Context) { for (v in all()) lock(ctx, v.id) }

    /** Vault auto-lock: locks every volume not used for [minutes]. */
    fun lockIdle(ctx: Context, minutes: Int) {
        val now = android.os.SystemClock.elapsedRealtime()
        for (v in all()) if (!v.closing && now - v.lastUsed >= minutes * 60_000L) {
            AppLog.i("auto-lock: ${v.title} unused for $minutes min"); lock(ctx, v.id)
        }
    }

    @Synchronized fun anyOpen() = open.isNotEmpty()

    /** The drive is gone: drop its volumes (the final flush fails; exFAT's VolumeDirty flag tells Linux to fsck). */
    fun unplugged(ctx: Context, source: String) {
        for (v in all().filter { it.source == source }) { AppLog.i("drive ${v.title} unplugged while unlocked"); lock(ctx, v.id) }
    }

    @Synchronized fun isOpen(source: String) = open.values.any { it.source == source }

    private fun changed(ctx: Context) {
        ctx.contentResolver.notifyChange(DocumentsContract.buildRootsUri(VolumeProvider.AUTHORITY), null)
        val svc = Intent(ctx, VolumeService::class.java)
        if (!anyOpen()) ctx.stopService(svc) else ctx.startForegroundService(svc)
        android.os.Handler(android.os.Looper.getMainLooper()).post { listeners.toList().forEach { it() } }
    }
}
