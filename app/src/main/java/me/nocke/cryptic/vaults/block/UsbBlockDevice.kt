package me.nocke.cryptic.vaults.block

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import me.nocke.cryptic.vaults.AppLog
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Raw access to a USB mass-storage drive: Bulk-Only Transport (USB MSC BOT 1.0) carrying SCSI block commands.
 * claimInterface(force) detaches the kernel's usb-storage driver, so Android stops seeing the drive until it's replugged.
 */
class UsbBlockDevice private constructor(
    val device: UsbDevice,
    private val conn: UsbDeviceConnection,
    private val intf: UsbInterface,
    private val inEp: UsbEndpoint,
    private val outEp: UsbEndpoint,
) : BlockDevice {
    override var sectorSize = 512; private set
    override var size = 0L; private set
    private var blocks = 0L
    private var tag = 1

    private fun init() {
        for (i in 0 until 5) if (runCatching { scsi(byteArrayOf(0x00, 0, 0, 0, 0, 0), null, false) }.isSuccess) break  // TEST UNIT READY
        val cap = ByteArray(8)
        scsi(byteArrayOf(0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0), cap, true)
        val bb = ByteBuffer.wrap(cap).order(ByteOrder.BIG_ENDIAN)
        var last = bb.int.toLong() and 0xffffffffL
        sectorSize = bb.int
        if (last == 0xffffffffL) {
            val c16 = ByteArray(32)
            scsi(byteArrayOf(0x9e.toByte(), 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0), c16, true)
            val b16 = ByteBuffer.wrap(c16).order(ByteOrder.BIG_ENDIAN)
            last = b16.long; sectorSize = b16.int
        }
        if (sectorSize !in listOf(512, 1024, 2048, 4096)) throw IOException("Unsupported block size $sectorSize")
        blocks = last + 1
        size = blocks * sectorSize
    }

    override fun read(offset: Long, buf: ByteArray, off: Int, len: Int) = rw(offset, buf, off, len, false)
    override fun write(offset: Long, buf: ByteArray, off: Int, len: Int) = rw(offset, buf, off, len, true)

    @Synchronized
    private fun rw(offset: Long, buf: ByteArray, off: Int, len: Int, write: Boolean) {
        require(offset % sectorSize == 0L && len % sectorSize == 0 && offset + len <= size)
        val maxBlocks = MAX_TRANSFER / sectorSize
        var lba = offset / sectorSize; var o = off; var left = len / sectorSize
        val chunk = ByteArray(minOf(left, maxBlocks) * sectorSize)
        while (left > 0) {
            val n = minOf(left, maxBlocks)
            val bytes = n * sectorSize
            val data = if (bytes == chunk.size) chunk else ByteArray(bytes)
            if (write) buf.copyInto(data, 0, o, o + bytes)
            scsi(rwCommand(lba, n, write), data, !write)
            if (!write) data.copyInto(buf, o, 0, bytes)
            lba += n; o += bytes; left -= n
        }
    }

    private fun rwCommand(lba: Long, n: Int, write: Boolean): ByteArray =
        if (lba + n <= 0xffffffffL) ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
            .put((if (write) 0x2a else 0x28).toByte()).put(0).putInt(lba.toInt()).put(0).putShort(n.toShort()).put(0).array()
        else ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
            .put((if (write) 0x8a else 0x88).toByte()).put(0).putLong(lba).putInt(n).put(0).put(0).array()

    /** What the drive says about itself (SCSI INQUIRY, VPD B1 rotation rate, MODE SENSE write protect). */
    class Info(val vendor: String, val product: String, val revision: String, val removable: Boolean, val rotationRate: Int?, val writeProtected: Boolean?)

    @Synchronized
    fun info(): Info {
        val inq = ByteArray(36); scsi(byteArrayOf(0x12, 0, 0, 0, 36, 0), inq, true)
        fun ascii(from: Int, to: Int) = String(inq, from, to - from, Charsets.US_ASCII).trim()
        val rot = runCatching {
            val v = ByteArray(64); scsi(byteArrayOf(0x12, 1, 0xB1.toByte(), 0, 64, 0), v, true, retry = false)
            if (v[1] == 0xB1.toByte()) ((v[4].toInt() and 0xff) shl 8) or (v[5].toInt() and 0xff) else null
        }.getOrNull()
        val wp = runCatching { val m = ByteArray(4); scsi(byteArrayOf(0x1A, 0, 0x3F, 0, 4, 0), m, true, retry = false); m[2].toInt() and 0x80 != 0 }.getOrNull()
        return Info(ascii(8, 16), ascii(16, 32), ascii(32, 36), inq[1].toInt() and 0x80 != 0, rot, wp)
    }

    /** SMART READ DATA (0xD0) / READ THRESHOLDS (0xD1) through SAT ATA PASS-THROUGH(16); 512 bytes. */
    @Synchronized
    fun ataSmart(feature: Int): ByteArray {
        val data = ByteArray(512)
        val cdb = byteArrayOf(0x85.toByte(), 0x08, 0x0E, 0, feature.toByte(), 0, 1, 0, 0, 0, 0x4F, 0, 0xC2.toByte(), 0, 0xB0.toByte(), 0)
        scsi(cdb, data, true, retry = false)
        return data
    }

    /** Link speed guessed from the bulk endpoint's packet size (Android doesn't report the negotiated speed). */
    val speed: String get() = when (inEp.maxPacketSize) { 1024 -> "SuperSpeed (5 Gb/s or more)"; 512 -> "High-Speed (480 Mb/s)"; else -> "Full-Speed (12 Mb/s)" }
    val usbVersion: String get() = conn.rawDescriptors?.takeIf { it.size >= 4 }?.let { "%d.%d".format(it[3].toInt(), (it[2].toInt() and 0xff) shr 4) } ?: "?"
    val uasCapable: Boolean get() = (0 until device.interfaceCount).any { device.getInterface(it).interfaceProtocol == 0x62 }

    override fun flush() { synchronized(this) { runCatching { scsi(byteArrayOf(0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0), null, false) } } }

    override fun close() {
        runCatching { flush() }
        conn.releaseInterface(intf)
        conn.close()
    }

    /** One SCSI command: CBW, optional data phase, CSW. Retries once after REQUEST SENSE (e.g. unit attention). */
    private fun scsi(cdb: ByteArray, data: ByteArray?, dataIn: Boolean, retry: Boolean = true) {
        val t = tag++
        val cbw = ByteBuffer.allocate(31).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x43425355).putInt(t).putInt(data?.size ?: 0)
            .put(if (dataIn) 0x80.toByte() else 0).put(0).put(cdb.size.toByte()).put(cdb.copyOf(16)).array()
        bulk(outEp, cbw, 31)
        if (data != null && data.isNotEmpty()) {
            val ep = if (dataIn) inEp else outEp
            val n = conn.bulkTransfer(ep, data, data.size, TIMEOUT_MS)
            if (n != data.size) {
                AppLog.e("USB data phase 0x%02x: %d of %d bytes %s".format(cdb[0], n, data.size, if (dataIn) "in" else "out"))
                if (n < 0) { reset(); throw IOException("USB: data transfer failed") }
            }
        }
        val csw = ByteArray(13)
        if (conn.bulkTransfer(inEp, csw, 13, TIMEOUT_MS) != 13) {
            AppLog.e("USB status phase 0x%02x: no status block, resetting".format(cdb[0])); reset(); throw IOException("USB: the drive didn't answer")
        }
        val b = ByteBuffer.wrap(csw).order(ByteOrder.LITTLE_ENDIAN)
        if (b.int != 0x53425355 || b.int != t) { AppLog.e("USB: bad status block for 0x%02x, resetting".format(cdb[0])); reset(); throw IOException("USB: bad status block") }
        b.int
        when (val status = b.get().toInt()) {
            0 -> return
            1 -> {
                if (cdb[0] != 0x03.toByte()) runCatching {
                    val sense = ByteArray(18); scsi(byteArrayOf(0x03, 0, 0, 0, 18, 0), sense, true, false)
                    AppLog.e("USB command 0x%02x failed: sense key %x asc %02x ascq %02x".format(cdb[0], sense[2].toInt() and 0xf, sense[12], sense[13]))
                }
                if (retry) return scsi(cdb, data, dataIn, false)
                throw IOException("USB: command 0x%02x failed".format(cdb[0]))
            }
            else -> { AppLog.e("USB phase error on 0x%02x (status %d): resetting".format(cdb[0], status)); reset(); throw IOException("USB: phase error ($status)") }
        }
    }

    private fun bulk(ep: UsbEndpoint, b: ByteArray, n: Int) {
        if (conn.bulkTransfer(ep, b, n, TIMEOUT_MS) != n) throw IOException("USB transfer failed (drive unplugged?)")
    }

    /**
     * Bulk-Only Mass Storage Reset, then SET_INTERFACE to the bulk-only alternate setting. SET_INTERFACE resets the
     * data toggles on both the drive and the phone; a bare CLEAR_FEATURE sent with controlTransfer would only reset
     * the drive's side and leave the two out of step (writes then vanish and the drive never answers).
     */
    private fun reset() {
        conn.controlTransfer(0x21, 0xff, 0, intf.id, null, 0, 5000)
        if (!conn.setInterface(intf)) AppLog.e("USB: SET_INTERFACE failed during reset")
    }

    companion object {
        private const val TIMEOUT_MS = 20_000
        private const val MAX_TRANSFER = 512 * 1024

        fun massStorageInterface(d: UsbDevice): UsbInterface? = (0 until d.interfaceCount).map { d.getInterface(it) }.firstOrNull {
            it.interfaceClass == UsbConstants.USB_CLASS_MASS_STORAGE && it.interfaceSubclass == 6 && it.interfaceProtocol == 0x50
        }

        fun open(usb: UsbManager, d: UsbDevice): UsbBlockDevice {
            val intf = massStorageInterface(d) ?: throw IOException("Not a USB mass-storage (SCSI, bulk-only) device")
            val eps = (0 until intf.endpointCount).map { intf.getEndpoint(it) }.filter { it.type == UsbConstants.USB_ENDPOINT_XFER_BULK }
            val inEp = eps.firstOrNull { it.direction == UsbConstants.USB_DIR_IN } ?: throw IOException("No bulk IN endpoint")
            val outEp = eps.firstOrNull { it.direction == UsbConstants.USB_DIR_OUT } ?: throw IOException("No bulk OUT endpoint")
            val conn = usb.openDevice(d) ?: throw IOException("No permission for the USB device")
            if (!conn.claimInterface(intf, true)) { conn.close(); throw IOException("Can't claim the USB drive") }
            // UAS drives (alternate setting 1) were left in UAS mode by Android's driver: select bulk-only explicitly
            if (!conn.setInterface(intf)) AppLog.e("USB: SET_INTERFACE to bulk-only failed")
            return UsbBlockDevice(d, conn, intf, inEp, outEp).also {
                try { it.reset(); it.init() } catch (e: Exception) { it.close(); throw e }
            }
        }
    }
}

/** A window [start, start+size) of another device: a partition. */
class SliceBlockDevice(val base: BlockDevice, val start: Long, override val size: Long) : BlockDevice {
    override val sectorSize get() = base.sectorSize
    override fun read(offset: Long, buf: ByteArray, off: Int, len: Int) { check(offset + len <= size); base.read(start + offset, buf, off, len) }
    override fun write(offset: Long, buf: ByteArray, off: Int, len: Int) { check(offset + len <= size); base.write(start + offset, buf, off, len) }
    override fun flush() = base.flush()
    override fun close() = base.close()
}
