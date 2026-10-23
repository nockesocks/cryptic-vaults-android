package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.ChannelBlockDevice
import java.io.File

/** Reference images from test-vectors/vectors.sh make (passphrase test-pass). Tests copy them before writing. */
object Vectors {
    val dir = File(System.getProperty("vectors.dir") ?: "../test-vectors/out")
    const val PASS = "test-pass"
    val LUKS = listOf("luks2-argon2id.img", "luks2-argon2i.img", "luks2-pbkdf2.img", "luks2-4k.img")

    fun file(name: String): File = File(dir, name).also {
        check(it.isFile) { "missing $it: run test-vectors/vectors.sh make" }
    }

    fun copy(name: String): File {
        val f = File.createTempFile("vec", ".img"); f.deleteOnExit()
        file(name).copyTo(f, overwrite = true); return f
    }

    fun open(name: String, writable: Boolean = false) = ChannelBlockDevice.open(file(name), writable)

    /** "type size sha256 path" lines, as inside.sh writes them. */
    fun manifest(name: String): List<String> = File(dir, "$name.manifest").readLines()
}
