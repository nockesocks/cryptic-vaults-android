package me.nocke.cryptic.vaults.fs

import me.nocke.cryptic.vaults.block.BlockDevice
import java.io.Closeable

/** A file or directory, addressed by path; values are current (read from the volume). */
interface FsNode {
    val name: String
    val isDir: Boolean
    val length: Long
    val mtime: Long
    val path: String
    val isRoot: Boolean
}

/** What the DocumentsProvider needs from a mounted volume (exFAT or ext4). */
interface FileSystem : Closeable {
    val type: String
    val root: FsNode
    val label: String
    val totalBytes: Long
    val freeBytes: Long
    /** Non-null when the volume is mounted read-only, saying why. */
    val readOnlyReason: String?
    fun list(dir: FsNode): List<FsNode>
    fun lookup(path: String): FsNode?
    fun parentOf(n: FsNode): FsNode?
    fun read(n: FsNode, pos: Long, buf: ByteArray, off: Int = 0, len: Int = buf.size - off): Int
    fun write(n: FsNode, pos: Long, buf: ByteArray, off: Int = 0, len: Int = buf.size - off)
    fun truncate(n: FsNode, size: Long)
    fun create(dir: FsNode, name: String, isDir: Boolean): FsNode
    fun delete(n: FsNode)
    fun rename(n: FsNode, newDir: FsNode, newName: String)
    fun flush()
    /** Rows for the Details panel: UUID, version, block size and the like. */
    fun info(): List<Pair<String, String>>
    /** The filesystem's own volume label (exFAT ≤ 11 characters, ext4 ≤ 16 bytes). */
    fun setLabel(label: String)
}

/** Byte-granular I/O on a sector-addressed device (read-modify-write for partial sectors). */
fun BlockDevice.readBytes(at: Long, buf: ByteArray, off: Int, len: Int) = io(at, buf, off, len, false)
fun BlockDevice.writeBytes(at: Long, buf: ByteArray, off: Int, len: Int) = io(at, buf, off, len, true)

private fun BlockDevice.io(at: Long, buf: ByteArray, off: Int, len: Int, write: Boolean) {
    val u = sectorSize
    val head = (at % u).toInt()
    if (head == 0 && len % u == 0) { if (write) write(at, buf, off, len) else read(at, buf, off, len); return }
    val start = at - head
    val span = ((head + len + u - 1) / u) * u
    val b = ByteArray(span)
    read(start, b, 0, span)
    if (write) { buf.copyInto(b, head, off, off + len); write(start, b, 0, span) } else b.copyInto(buf, off, head, head + len)
}
