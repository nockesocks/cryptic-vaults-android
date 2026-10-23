package me.nocke.cryptic.vaults

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.system.ErrnoException
import android.system.OsConstants
import android.webkit.MimeTypeMap
import me.nocke.cryptic.vaults.fs.FileSystem
import me.nocke.cryptic.vaults.fs.FsNode
import java.io.FileNotFoundException

/** Each unlocked volume is a root in the Files app. Document id: "<volume id>:<path>". */
class VolumeProvider : DocumentsProvider() {
    private val io by lazy { Handler(HandlerThread("volume-io").apply { start() }.looper) }

    override fun onCreate(): Boolean { AppLog.init(context!!); return true }

    private val rootCols = arrayOf(Root.COLUMN_ROOT_ID, Root.COLUMN_DOCUMENT_ID, Root.COLUMN_TITLE, Root.COLUMN_SUMMARY,
        Root.COLUMN_FLAGS, Root.COLUMN_ICON, Root.COLUMN_AVAILABLE_BYTES, Root.COLUMN_CAPACITY_BYTES)
    private val docCols = arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE,
        Document.COLUMN_SIZE, Document.COLUMN_LAST_MODIFIED, Document.COLUMN_FLAGS)

    override fun queryRoots(projection: Array<String>?): Cursor {
        val c = MatrixCursor(projection ?: rootCols)
        for (v in Volumes.all()) c.newRow().apply {
            add(Root.COLUMN_ROOT_ID, v.id)
            add(Root.COLUMN_DOCUMENT_ID, "${v.id}:/")
            add(Root.COLUMN_TITLE, v.title)
            add(Root.COLUMN_SUMMARY, "LUKS2 · ${v.fs.type}" + if (v.fs.readOnlyReason != null) " · read-only" else "")
            add(Root.COLUMN_FLAGS, (if (v.fs.readOnlyReason == null) Root.FLAG_SUPPORTS_CREATE else 0) or Root.FLAG_SUPPORTS_IS_CHILD or Root.FLAG_LOCAL_ONLY)
            add(Root.COLUMN_ICON, R.mipmap.ic_launcher)
            add(Root.COLUMN_AVAILABLE_BYTES, v.fs.freeBytes)
            add(Root.COLUMN_CAPACITY_BYTES, v.fs.totalBytes)
        }
        c.setNotificationUri(context!!.contentResolver, DocumentsContract.buildRootsUri(AUTHORITY))
        return c
    }

    private class Ref(val vol: Volumes.Volume, val node: FsNode)

    private fun ref(docId: String): Ref {
        val i = docId.indexOf(':')
        val v = (if (i > 0) Volumes.get(docId.substring(0, i)) else null) ?: throw FileNotFoundException("Volume is locked")
        val n = v.fs.lookup(docId.substring(i + 1)) ?: throw FileNotFoundException(docId)
        return Ref(v, n)
    }

    private fun docId(v: Volumes.Volume, n: FsNode) = "${v.id}:${n.path}"

    private fun mime(n: FsNode): String = if (n.isDir) Document.MIME_TYPE_DIR else
        MimeTypeMap.getSingleton().getMimeTypeFromExtension(n.name.substringAfterLast('.', "").lowercase()) ?: "application/octet-stream"

    private fun row(c: MatrixCursor, v: Volumes.Volume, n: FsNode) = c.newRow().apply {
        val ro = v.fs.readOnlyReason != null
        add(Document.COLUMN_DOCUMENT_ID, docId(v, n))
        add(Document.COLUMN_DISPLAY_NAME, if (n.isRoot) v.title else n.name)
        add(Document.COLUMN_MIME_TYPE, mime(n))
        add(Document.COLUMN_SIZE, if (n.isDir) null else n.length)
        add(Document.COLUMN_LAST_MODIFIED, if (n.mtime > 0) n.mtime else null)
        add(Document.COLUMN_FLAGS, when {
            ro -> 0
            n.isDir -> Document.FLAG_DIR_SUPPORTS_CREATE or (if (n.isRoot) 0 else EDIT)
            else -> Document.FLAG_SUPPORTS_WRITE or EDIT
        })
    }

    override fun queryDocument(documentId: String, projection: Array<String>?): Cursor {
        val r = ref(documentId)
        return MatrixCursor(projection ?: docCols).also { row(it, r.vol, r.node) }
    }

    override fun queryChildDocuments(parentDocumentId: String, projection: Array<String>?, sortOrder: String?): Cursor {
        val r = ref(parentDocumentId)
        val c = MatrixCursor(projection ?: docCols)
        for (n in r.vol.fs.list(r.node)) row(c, r.vol, n)
        c.setNotificationUri(context!!.contentResolver, DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId))
        return c
    }

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        val p = parentDocumentId.trimEnd('/')
        return documentId.startsWith("$p/") || (parentDocumentId.endsWith(":/") && documentId.startsWith(parentDocumentId))
    }

    override fun getDocumentType(documentId: String): String = mime(ref(documentId).node)

    private fun notifyParent(docId: String) {
        val parent = docId.substringBeforeLast('/').let { if (it.endsWith(':')) "$it/" else it }
        context!!.contentResolver.notifyChange(DocumentsContract.buildChildDocumentsUri(AUTHORITY, parent), null)
    }

    private fun <T> fsOp(v: Volumes.Volume, what: String, f: () -> T): T = try {
        AppLog.i("$what (${v.fs.type})")
        timed(what) { f().also { v.fs.flush() } }
    } catch (e: Exception) {
        AppLog.e("$what failed", e)
        throw if (e is FileNotFoundException || e is IllegalStateException) e else IllegalStateException(e.message, e)
    }

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String {
        val r = ref(parentDocumentId)
        val fs = r.vol.fs
        val isDir = mimeType == Document.MIME_TYPE_DIR
        // the Files app asks for "name" and expects "name (1)" when it exists
        val dot = displayName.lastIndexOf('.').takeIf { it > 0 && !isDir } ?: displayName.length
        var name = displayName; var k = 1
        while (fs.lookup(r.node.path.trimEnd('/') + "/" + name) != null) name = displayName.substring(0, dot) + " (${k++})" + displayName.substring(dot)
        val n = fsOp(r.vol, "create $name") { fs.create(r.node, name, isDir) }
        return docId(r.vol, n).also { notifyParent(it) }
    }

    override fun deleteDocument(documentId: String) {
        val r = ref(documentId)
        fsOp(r.vol, "delete ${r.node.path}") { deleteTree(r.vol.fs, r.node) }
        notifyParent(documentId)
    }

    private fun deleteTree(fs: FileSystem, n: FsNode) {
        if (n.isDir) for (c in fs.list(n)) deleteTree(fs, c)
        fs.delete(n)
    }

    override fun renameDocument(documentId: String, displayName: String): String {
        val r = ref(documentId)
        fsOp(r.vol, "rename ${r.node.path}") { r.vol.fs.rename(r.node, r.vol.fs.parentOf(r.node) ?: throw FileNotFoundException("root"), displayName) }
        notifyParent(documentId)
        return docId(r.vol, r.node)
    }

    override fun moveDocument(sourceDocumentId: String, sourceParentDocumentId: String, targetParentDocumentId: String): String {
        val r = ref(sourceDocumentId); val t = ref(targetParentDocumentId)
        if (t.vol !== r.vol) throw UnsupportedOperationException("Move between volumes")
        fsOp(r.vol, "move ${r.node.path}") { r.vol.fs.rename(r.node, t.node, r.node.name) }
        notifyParent(sourceDocumentId); notifyParent(docId(r.vol, r.node))
        return docId(r.vol, r.node)
    }

    override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor {
        val r = ref(documentId)
        if (r.node.isDir) throw FileNotFoundException("Is a directory")
        val fs = r.vol.fs; val n = r.node
        if (fs.readOnlyReason != null && mode != "r") throw UnsupportedOperationException("Read-only volume: ${fs.readOnlyReason}")
        if ("t" in mode) fsOp(r.vol, "truncate ${n.path}") { fs.truncate(n, 0) }
        AppLog.i("open ${n.path} mode $mode (${fs.type}, ${n.length} bytes)")
        val sm = context!!.getSystemService(StorageManager::class.java)
        return sm.openProxyFileDescriptor(ParcelFileDescriptor.parseMode(mode), object : ProxyFileDescriptorCallback() {
            override fun onGetSize() = n.length
            override fun onRead(offset: Long, size: Int, data: ByteArray): Int = io("read ${n.path} @$offset+$size") { r.vol.touch(); fs.read(n, offset, data, 0, size).coerceAtLeast(0) }
            override fun onWrite(offset: Long, size: Int, data: ByteArray): Int = io("write ${n.path} @$offset+$size") { r.vol.touch(); fs.write(n, offset, data, 0, size); size }
            override fun onFsync() = io("fsync ${n.path}") { fs.flush() }
            override fun onRelease() {
                runCatching { fs.flush() }.onFailure { AppLog.e("flush on close of ${n.path}", it) }
                notifyParent(documentId)
            }
        }, io)
    }

    private fun <T> timed(what: String, f: () -> T): T {
        val t0 = System.nanoTime()
        return f().also { val s = (System.nanoTime() - t0) / 1e9; if (s > 2) AppLog.i("slow: $what took %.1fs".format(s)) }
    }

    private fun <T> io(what: String, f: () -> T): T = try { timed(what, f) } catch (e: Exception) {
        AppLog.e("$what failed", e)
        throw ErrnoException("io", OsConstants.EIO)
    }

    companion object {
        const val AUTHORITY = "me.nocke.cryptic.vaults.documents"
        private const val EDIT = Document.FLAG_SUPPORTS_DELETE or Document.FLAG_SUPPORTS_RENAME or Document.FLAG_SUPPORTS_MOVE
    }
}
