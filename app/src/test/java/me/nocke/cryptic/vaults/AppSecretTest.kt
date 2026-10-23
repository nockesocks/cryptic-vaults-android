package me.nocke.cryptic.vaults

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AppSecretTest {
    @Test fun verifierAndKey() {
        val (record, key) = AppSecret.create("correct horse 9", memoryKib = 1024)
        assertFalse("the record must not hold the secret", "correct horse" in record)
        assertArrayEquals(key, AppSecret.key(record, "correct horse 9"))
        assertNull(AppSecret.key(record, "correct horse 8"))
    }

    @Test fun strengthFloorForSavedPassphrases() {
        assertFalse("a PIN of any length", AppSecret.acceptable("12345678901234567890123456789012"))
        assertFalse("too short", AppSecret.acceptable("Ab3!xyz"))
        assertTrue("eight characters is the floor", AppSecret.acceptable("password"))
        assertTrue("an eight-letter lowercase word needs the warning", AppSecret.weak("password"))
        assertTrue("eight mixed characters still need it", AppSecret.weak("Ab3!xyzQ"))
        assertFalse(AppSecret.weak("correct horse battery"))
        assertTrue(AppSecret.strong(AppSecret.create("password", memoryKib = 1024).first))
        assertFalse(AppSecret.strong(AppSecret.create("24681012", memoryKib = 1024).first))
    }

    @Test fun sealOpen() {
        val key = AppSecret.create("a passphrase", memoryKib = 1024).second
        val blob = AppSecret.seal(key, "vault pass".toByteArray())
        assertArrayEquals("vault pass".toByteArray(), AppSecret.open(key, blob))
        assertNotNull(blob); assertFalse(blob.contentEquals(AppSecret.seal(key, "vault pass".toByteArray())))   // fresh nonce each time
        val other = AppSecret.create("another one", memoryKib = 1024).second
        assertThrows(Exception::class.java) { AppSecret.open(other, blob) }
        blob[blob.size - 1] = (blob[blob.size - 1] + 1).toByte()
        assertThrows(Exception::class.java) { AppSecret.open(key, blob) }
    }
}
