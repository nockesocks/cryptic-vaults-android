package me.nocke.cryptic.vaults.luks

/** Native Argon2 (app/src/main/cpp); absent on the JVM in unit tests, where BouncyCastle is used instead. */
object NativeArgon2 {
    val available: Boolean = runCatching { System.loadLibrary("argon2jni") }.isSuccess

    /** type: 1 = argon2i, 2 = argon2id. Returns the reference library's error code, 0 = ok. */
    @JvmStatic external fun hash(type: Int, time: Int, memoryKib: Int, lanes: Int, pass: ByteArray, salt: ByteArray, out: ByteArray): Int
}
