package me.nocke.cryptic.vaults

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class YubiKeyTest {
    /** The verifier and key halves come from the key's secret alone, differ from each other, and the secret is wiped. */
    @Test fun derive() {
        val secret = ByteArray(32) { it.toByte() }
        val a = YubiKey.derive(secret.copyOf()); val b = YubiKey.derive(secret.copyOf())
        assertEquals(64, a.size)
        assertEquals(a.toList(), b.toList())
        assertFalse(a.copyOf(32).contentEquals(a.copyOfRange(32, 64)))
        assertFalse(a.contentEquals(YubiKey.derive(ByteArray(32) { (it + 1).toByte() })))
        val wiped = secret.copyOf(); YubiKey.derive(wiped)
        assertEquals(List(32) { 0.toByte() }, wiped.toList())
    }
}
