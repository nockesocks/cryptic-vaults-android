package me.nocke.cryptic.vaults.block

import android.os.ParcelFileDescriptor
import android.system.Os

/** A container file opened through the Storage Access Framework ("rw"), with positional I/O. */
class PfdBlockDevice(private val pfd: ParcelFileDescriptor, override val sectorSize: Int = 512) : BlockDevice {
    private val fd = pfd.fileDescriptor
    override val size: Long = Os.fstat(fd).st_size / sectorSize * sectorSize

    override fun read(offset: Long, buf: ByteArray, off: Int, len: Int) {
        var done = 0
        while (done < len) {
            val n = Os.pread(fd, buf, off + done, len - done, offset + done)
            if (n <= 0) throw java.io.EOFException("read past end at ${offset + done}")
            done += n
        }
    }

    override fun write(offset: Long, buf: ByteArray, off: Int, len: Int) {
        var done = 0
        while (done < len) done += Os.pwrite(fd, buf, off + done, len - done, offset + done)
    }

    override fun flush() = Os.fsync(fd)
    override fun close() = pfd.close()
}
