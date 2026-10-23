package me.nocke.cryptic.vaults.block

import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/** Byte-addressed storage. Offsets and lengths are multiples of [sectorSize]. */
interface BlockDevice : Closeable {
    val sectorSize: Int
    val size: Long
    fun read(offset: Long, buf: ByteArray, off: Int = 0, len: Int = buf.size - off)
    fun write(offset: Long, buf: ByteArray, off: Int = 0, len: Int = buf.size - off)
    fun flush() {}
}

/** A file or anything with a FileChannel (a container file, a test image). */
class ChannelBlockDevice(
    private val ch: FileChannel,
    override val sectorSize: Int = 512,
    private val onClose: () -> Unit = { ch.close() },
) : BlockDevice {
    override val size: Long get() = ch.size() / sectorSize * sectorSize

    override fun read(offset: Long, buf: ByteArray, off: Int, len: Int) {
        val bb = ByteBuffer.wrap(buf, off, len)
        var pos = offset
        while (bb.hasRemaining()) {
            val n = ch.read(bb, pos)
            if (n < 0) throw java.io.EOFException("read past end at $pos")
            pos += n
        }
    }

    override fun write(offset: Long, buf: ByteArray, off: Int, len: Int) {
        val bb = ByteBuffer.wrap(buf, off, len)
        var pos = offset
        while (bb.hasRemaining()) pos += ch.write(bb, pos)
    }

    override fun flush() = ch.force(false)
    override fun close() = onClose()

    companion object {
        fun open(file: File, writable: Boolean = true): ChannelBlockDevice {
            val raf = RandomAccessFile(file, if (writable) "rw" else "r")
            return ChannelBlockDevice(raf.channel) { raf.close() }
        }
    }
}
