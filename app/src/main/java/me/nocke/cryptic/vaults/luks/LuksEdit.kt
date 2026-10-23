package me.nocke.cryptic.vaults.luks

import me.nocke.cryptic.vaults.block.BlockDevice
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

/** Changes to an existing LUKS2 header: passphrase (cryptsetup luksChangeKey) and label (cryptsetup config --label). */
object LuksEdit {
    /**
     * Re-wraps the volume key under [newPass] in a fresh key slot area, swaps it for the old slot in one header write,
     * then zeroes the old area — so a crash at any point leaves either the old or the new passphrase working.
     * Throws WrongPassphraseException when [oldPass] opens no slot.
     */
    fun changePassphrase(dev: BlockDevice, oldPass: ByteArray, newPass: ByteArray, kdf: LuksFormat.Kdf) {
        val hdr = Luks2.readHeader(dev)
        val (oldId, volumeKey) = Luks2.unlockSlot(dev, hdr, oldPass)
        try {
            val json = JSONObject(hdr.json.toString())
            val slots = json.getJSONObject("keyslots")
            val old = slots.getJSONObject(oldId)
            val area = old.getJSONObject("area")
            val af = old.getJSONObject("af")
            val keySize = old.getInt("key_size")
            val areaKey = area.getInt("key_size")
            val stripes = af.getInt("stripes")
            val len = ((keySize * stripes + 511) / 512 * 512).toLong()
            val areaSize = (len + 4095) / 4096 * 4096
            val newOffset = freeArea(json, areaSize)
            val rnd = SecureRandom()

            val salt = ByteArray(32).also { rnd.nextBytes(it) }
            val kdfJson = JSONObject().put("type", "argon2id").put("time", kdf.time).put("memory", kdf.memoryKib)
                .put("cpus", kdf.lanes).put("salt", Base64.getEncoder().encodeToString(salt))
            val kek = Luks2.kdf(kdfJson, newPass, areaKey)
            val data = Af.split(volumeKey, stripes, af.getString("hash"), rnd).copyOf(len.toInt())
            Xts(kek).encrypt(data, 0, data.size, 512, 0)
            kek.fill(0)
            dev.write(newOffset, data.copyOf(((data.size + dev.sectorSize - 1) / dev.sectorSize) * dev.sectorSize))
            dev.flush()

            val newId = (0..31).first { !slots.has(it.toString()) }.toString()
            val slot = JSONObject(old.toString())
            slot.getJSONObject("area").put("offset", newOffset.toString()).put("size", areaSize.toString())
            slot.put("kdf", kdfJson)
            slots.remove(oldId)
            slots.put(newId, slot)
            val digests = json.getJSONObject("digests")
            for (d in digests.keys()) {
                val ks = digests.getJSONObject(d).getJSONArray("keyslots")
                val updated = JSONArray()
                for (i in 0 until ks.length()) updated.put(if (ks.getString(i) == oldId) newId else ks.getString(i))
                digests.getJSONObject(d).put("keyslots", updated)
            }
            LuksFormat.writeHeaders(dev, hdr.uuid, hdr.label, hdr.seqId + 1, json.toString().toByteArray(Charsets.UTF_8), hdr.subsystem)

            // the old slot's key material is now unreferenced: destroy it
            val oldOffset = area.getString("offset").toLong(); val oldSize = area.getString("size").toLong()
            dev.write(oldOffset, ByteArray(oldSize.toInt()))
            dev.flush()
        } finally {
            volumeKey.fill(0)
        }
    }

    fun setLabel(dev: BlockDevice, label: String) {
        require(label.toByteArray().size < 48) { "LUKS label is at most 47 bytes" }
        val hdr = Luks2.readHeader(dev)
        LuksFormat.writeHeaders(dev, hdr.uuid, label, hdr.seqId + 1, hdr.json.toString().toByteArray(Charsets.UTF_8), hdr.subsystem)
    }

    /** First 4 KiB-aligned gap in the key slot region that no slot uses. */
    private fun freeArea(json: JSONObject, size: Long): Long {
        val slots = json.getJSONObject("keyslots")
        val used = slots.keys().asSequence().map { slots.getJSONObject(it).getJSONObject("area") }
            .map { it.getString("offset").toLong() to it.getString("offset").toLong() + it.getString("size").toLong() }
            .sortedBy { it.first }.toList()
        val hdrSize = json.getJSONObject("config").getString("json_size").toLong() + Luks2.BIN_SIZE
        val end = 2 * hdrSize + json.getJSONObject("config").getString("keyslots_size").toLong()
        var at = 2 * hdrSize
        for ((s, e) in used) { if (s - at >= size) return at; at = maxOf(at, (e + 4095) / 4096 * 4096) }
        if (end - at >= size) return at
        throw UnsupportedLuksException("No room for another key slot")
    }
}
