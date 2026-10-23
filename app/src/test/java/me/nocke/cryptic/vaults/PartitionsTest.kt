package me.nocke.cryptic.vaults

import me.nocke.cryptic.vaults.block.Partitions
import me.nocke.cryptic.vaults.block.SliceBlockDevice
import me.nocke.cryptic.vaults.exfat.ExFat
import me.nocke.cryptic.vaults.luks.Luks2
import org.junit.Assert.assertEquals
import org.junit.Test

class PartitionsTest {
    @Test fun findsLuksPartitionOnGptAndMbrDisks() {
        for (disk in listOf("gpt-disk.img", "dos-disk.img")) Vectors.open(disk).use { dev ->
            val found = Partitions.findLuks(dev)
            assertEquals(disk, 1, found.size)
            assertEquals(disk, 1024L * 1024, found[0].start)
            val fs = ExFat.mount(Luks2.open(SliceBlockDevice(dev, found[0].start, found[0].size), Vectors.PASS.toByteArray()))
            assertEquals(disk, 4 + 42, fs.list(fs.root).size + fs.list(fs.lookup("/dir")!!).size)
        }
    }

    @Test fun wholeDiskLuksIsFoundAsIs() {
        Vectors.open("luks2-pbkdf2.img").use { assertEquals("whole drive", Partitions.findLuks(it).single().name) }
    }
}
