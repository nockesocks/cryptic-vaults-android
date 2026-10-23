package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.ChannelBlockDevice
import me.nocke.cryptic.vaults.luks.Af
import me.nocke.cryptic.vaults.luks.Luks2
import me.nocke.cryptic.vaults.luks.WrongPassphraseException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class Luks2Test {
    private fun exfatSignature(b: ByteArray) = String(b, 3, 8, Charsets.US_ASCII)

    @Test fun unlocksEveryVectorToAnExfatVolume() {
        for (name in Vectors.LUKS) Vectors.open(name).use { dev ->
            assertTrue(name, Luks2.isLuks(dev))
            val vol = Luks2.open(dev, Vectors.PASS.toByteArray())
            val boot = ByteArray(vol.sectorSize); vol.read(0, boot)
            assertEquals(name, "EXFAT   ", exfatSignature(boot))
            assertEquals(name, dev.size - 16L * 1024 * 1024, vol.size)
        }
    }

    @Test(expected = WrongPassphraseException::class) fun rejectsWrongPassphrase() {
        Vectors.open("luks2-pbkdf2.img").use { Luks2.open(it, "nope".toByteArray()) }
    }

    @Test fun plainImageIsNotLuks() {
        Vectors.open("plain.exfat.img").use { assertTrue(!Luks2.isLuks(it)) }
    }

    @Test fun writeThenReadRoundTrips() {
        ChannelBlockDevice.open(Vectors.copy("luks2-argon2id.img")).use { dev ->
            val vol = Luks2.open(dev, Vectors.PASS.toByteArray())
            val data = ByteArray(vol.sectorSize * 3).also { SecureRandom().nextBytes(it) }
            vol.write(vol.size - data.size, data)
            val back = ByteArray(data.size); vol.read(vol.size - data.size, back)
            assertArrayEquals(data, back)
        }
    }

    @Test fun afSplitMergeRoundTrips() {
        val key = ByteArray(64).also { SecureRandom().nextBytes(it) }
        assertArrayEquals(key, Af.merge(Af.split(key, 4000, "sha256", SecureRandom()), 64, 4000, "sha256"))
    }
}
