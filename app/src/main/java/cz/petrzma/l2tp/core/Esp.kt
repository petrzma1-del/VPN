package cz.petrzma.l2tp.core

/** ESP (RFC 4303) v transportním režimu, bez vnější IP hlavičky (ta je UDP/4500 z NAT-T). */
class Esp(private val k: IpsecKeys) {
    private var seq = 0L
    private val bs = if (k.aes) 16 else 8
    private var replayTop = 0L
    private var replayMask = 0L          // posledních 64 sekvenčních čísel

    @Synchronized
    fun encap(payload: ByteArray, nextHdr: Int): ByteArray {
        val padLen = (bs - (payload.size + 2) % bs) % bs
        val tr = ByteArray(padLen + 2)
        for (i in 0 until padLen) tr[i] = (i + 1).toByte()
        tr[padLen] = padLen.toByte(); tr[padLen + 1] = nextHdr.toByte()
        val iv = rnd(bs)
        val ct = Cbc.encrypt(k.aes, k.encKeyOut, iv, cat(payload, tr))
        seq++
        val body = cat(Bb().u32(k.spiOut.toLong() and 0xFFFFFFFFL).u32(seq).toByteArray(), iv, ct)
        return cat(body, hmac(k.hmacAlg, k.authKeyOut, body).copyOf(k.icvLen))
    }

    /** Vrátí (obsah, další hlavička) nebo null, když paket není pro nás / je poškozený / opakovaný. */
    @Synchronized
    fun decap(p: ByteArray): Pair<ByteArray, Int>? {
        if (p.size < 8 + bs + bs + k.icvLen) return null
        if (p.u32(0).toInt() != k.spiIn) return null
        val bodyLen = p.size - k.icvLen
        val icv = hmac(k.hmacAlg, k.authKeyIn, p.copyOfRange(0, bodyLen)).copyOf(k.icvLen)
        if (!sameBytes(icv, p.copyOfRange(bodyLen, p.size))) return null
        val sn = p.u32(4)
        if (!replayOk(sn)) return null
        val iv = p.copyOfRange(8, 8 + bs)
        val ct = p.copyOfRange(8 + bs, bodyLen)
        if (ct.isEmpty() || ct.size % bs != 0) return null
        val pt = Cbc.decrypt(k.aes, k.encKeyIn, iv, ct)
        val padLen = pt.u8(pt.size - 2); val next = pt.u8(pt.size - 1)
        if (padLen + 2 > pt.size) return null
        return Pair(pt.copyOf(pt.size - 2 - padLen), next)
    }

    private fun replayOk(sn: Long): Boolean {
        if (sn == 0L) return false
        if (sn > replayTop) {
            val shift = sn - replayTop
            replayMask = if (shift >= 64) 1L else (replayMask shl shift.toInt()) or 1L
            replayTop = sn; return true
        }
        val d = replayTop - sn
        if (d >= 64) return false
        if (replayMask and (1L shl d.toInt()) != 0L) return false
        replayMask = replayMask or (1L shl d.toInt()); return true
    }
}
