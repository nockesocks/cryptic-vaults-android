package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.FsChecks.content
import me.nocke.cryptic.vaults.FsChecks.manifest
import me.nocke.cryptic.vaults.FsChecks.writeAndVerify
import me.nocke.cryptic.vaults.exfat.ExFat
import me.nocke.cryptic.vaults.luks.Luks2
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

class ExFatTest {
    @Test fun readsPlainImageLikeLinux() {
        ExFat.mount(Vectors.open("plain.exfat.img")).use { fs ->
            assertEquals(Vectors.manifest("plain.exfat.img").toSet(), manifest(fs))
            assertEquals("hello exfat\n", String(content(fs, "/HELLO.TXT")))  // case-insensitive lookup
        }
    }

    @Test fun readsEveryLuksImageLikeLinux() {
        for (name in Vectors.LUKS) ExFat.mount(Luks2.open(Vectors.open(name), Vectors.PASS.toByteArray())).use { fs ->
            assertEquals(name, Vectors.manifest(name).toSet(), manifest(fs))
        }
    }

    @Test fun writesPlainImageThatLinuxAccepts() = writeAndVerify("plain.exfat.img", "w-plain.img", { ExFat.mount(it) }, null)

    @Test fun writesLuksImageThatLinuxAccepts() = writeAndVerify("luks2-argon2id.img", "w-luks.img",
        { ExFat.mount(Luks2.open(it, Vectors.PASS.toByteArray())) }, Vectors.PASS)

    @Test fun writesLuks512ImageThatLinuxAccepts() = writeAndVerify("luks2-pbkdf2.img", "w-luks512.img",
        { ExFat.mount(Luks2.open(it, Vectors.PASS.toByteArray())) }, Vectors.PASS)

    @Test fun randomWorkload() = writeAndVerify("plain.exfat.img", "w-exfat-fuzz.img", { ExFat.mount(it) }, null) { FsChecks.randomWorkload(it, 3) }

    init { assumeTrue(Vectors.dir.isDirectory) }
}
