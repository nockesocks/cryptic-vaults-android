package me.nocke.cryptic.vaults.fs

import me.nocke.cryptic.vaults.block.BlockDevice
import me.nocke.cryptic.vaults.block.Gpt
import me.nocke.cryptic.vaults.exfat.ExFatFormat
import me.nocke.cryptic.vaults.ext4.ExtFormat
import me.nocke.cryptic.vaults.luks.CryptBlockDevice
import me.nocke.cryptic.vaults.luks.LuksFormat

/** Encrypt a drive / new container: [GPT with one partition] → LUKS2 (aes-xts-512, argon2id, sha512) → mkfs. */
object Create {
    enum class Fs(val title: String, val maxLabel: Int) { EXFAT("exFAT", 11), EXT4("ext4", 16) }

    /** Label rules for [fs]: what's wrong with [label], or null. */
    fun labelProblem(fs: Fs, label: String): String? = when {
        label.toByteArray().size > fs.maxLabel -> "${fs.title} labels are at most ${fs.maxLabel} characters"
        label.any { it.code < 0x20 } -> "The label has control characters"
        else -> null
    }

    /**
     * Erases [dev] and builds an encrypted volume on it. A whole drive ([wholeDrive]) gets a GPT with one Linux
     * partition named [label]; a container file is encrypted directly. The label also names the LUKS2 header and the
     * filesystem. Returns the unlocked data segment.
     */
    fun encrypted(dev: BlockDevice, wholeDrive: Boolean, passphrase: ByteArray, fs: Fs, label: String,
                  kdf: LuksFormat.Kdf, digestIterations: Int = 100_000, linuxUid: Int = 1000): CryptBlockDevice {
        labelProblem(fs, label)?.let { throw IllegalArgumentException(it) }
        val target = if (wholeDrive) Gpt.singlePartition(dev, label) else dev
        val crypt = LuksFormat.format(target, passphrase, kdf, digestIterations = digestIterations, label = label)
        when (fs) {
            Fs.EXFAT -> ExFatFormat.format(crypt, label)
            Fs.EXT4 -> ExtFormat.format(crypt, label, linuxUid, linuxUid)
        }
        return crypt
    }
}
