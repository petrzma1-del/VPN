package cz.petrzma.l2tp.core

import java.math.BigInteger

class IkeException(msg: String) : Exception(msg)

/** Přenos IKE zpráv. float=false: UDP 500 bez značky; float=true: UDP 4500 se značkou 0x00000000. */
interface IkeIo {
    fun send(msg: ByteArray, float: Boolean)
    fun recv(timeoutMs: Int): ByteArray?       // surová IKE zpráva (značka odstraněna), null = vypršel čas
}

/** Výsledek vyjednávání: klíče a SPI pro ESP (UDP-encapsulated transport mode). */
class IpsecKeys(
    val spiIn: Int, val spiOut: Int,
    val aes: Boolean,
    val encKeyIn: ByteArray, val encKeyOut: ByteArray,
    val hmacAlg: String, val icvLen: Int,
    val authKeyIn: ByteArray, val authKeyOut: ByteArray,
    val info: String
)

/**
 * IKEv1 (RFC 2409) – Main Mode s předsdíleným klíčem + Quick Mode pro L2TP (UDP 1701), NAT-T (RFC 3947).
 * Provozní režim: vždy přepne na UDP 4500 a vynutí UDP-zapouzdření ESP, protože Android nedovolí surové ESP.
 */
class Ike(
    private val io: IkeIo,
    private val psk: ByteArray,
    private val localIp: ByteArray,
    private val serverIp: ByteArray,
    private val log: (String) -> Unit,
    private val lifeP1: Int = 28800,
    private val lifeP2: Int = 3600
) {
    private class Pl(val type: Int, val body: ByteArray)
    private class Hdr(val cki: ByteArray, val ckr: ByteArray, val next: Int, val exch: Int, val flags: Int, val mid: ByteArray, val len: Int)
    private class P1T(val enc: Int, val keyBits: Int, val hash: Int, val group: Int)
    private class P2T(val enc: Int, val keyBits: Int, val auth: Int)

    companion object {
        const val SA = 1; const val KE = 4; const val ID = 5; const val HASH = 8; const val NONCE = 10
        const val NOTIFY = 11; const val DELETE = 12; const val VID = 13
        const val EX_MAIN = 2; const val EX_INFO = 5; const val EX_QUICK = 32

        fun md5(s: String) = digest("MD5", s.toByteArray(Charsets.US_ASCII))
        val VID_RFC3947 = md5("RFC 3947")
        val VID_DRAFT03 = md5("draft-ietf-ipsec-nat-t-ike-03")
        val VID_DRAFT02 = md5("draft-ietf-ipsec-nat-t-ike-02\n")
        val VID_DRAFT02b = md5("draft-ietf-ipsec-nat-t-ike-02")

        fun hashName(h: Int) = when (h) { 1 -> "MD5"; 2 -> "SHA-1"; 4 -> "SHA-256"; else -> throw IkeException("neznámý hash $h") }
        fun hmacName(h: Int) = when (h) { 1 -> "HmacMD5"; 2 -> "HmacSHA1"; 4 -> "HmacSHA256"; else -> throw IkeException("neznámý hash $h") }
        fun notifyName(c: Int) = when (c) {
            7 -> "INVALID-EXCHANGE-TYPE"; 14 -> "NO-PROPOSAL-CHOSEN"; 15 -> "BAD-PROPOSAL-SYNTAX"; 16 -> "PAYLOAD-MALFORMED"
            17 -> "INVALID-KEY-INFORMATION"; 18 -> "INVALID-ID-INFORMATION"; 24 -> "AUTHENTICATION-FAILED"
            else -> "kód $c"
        }
    }

    private val p1Transforms: List<P1T> = buildList {
        for (g in listOf(14, 5, 2)) for ((e, k) in listOf(7 to 256, 7 to 128, 5 to 0)) for (h in listOf(2, 1)) add(P1T(e, k, h, g))
    }
    private val p2Transforms: List<P2T> = buildList {
        for ((e, k) in listOf(12 to 256, 12 to 128, 3 to 0)) for (a in listOf(2, 1, 5)) add(P2T(e, k, a))
    }

    private val cki: ByteArray = rnd(8).also { if (it[0] == 0.toByte()) it[0] = 1 }
    private var ckr = ByteArray(8)

    // stav fáze 1
    private lateinit var hashAlg: String
    private lateinit var hmacAlg: String
    private var aes = true
    private var encKey = ByteArray(0)
    private var skeyidA = ByteArray(0)
    private var skeyidD = ByteArray(0)
    private var p1Iv = ByteArray(0)           // poslední blok šifrotextu ve fázi 1
    private var bs = 16
    private var natRfc = true

    private fun prf(key: ByteArray, vararg d: ByteArray) = hmac(hmacAlg, key, *d)

    // ---------- stavba a rozbor zpráv ----------
    private fun chain(pls: List<Pl>): ByteArray {
        val b = Bb()
        for ((i, p) in pls.withIndex()) {
            val next = if (i + 1 < pls.size) pls[i + 1].type else 0
            b.u8(next).u8(0).u16(p.body.size + 4).bytes(p.body)
        }
        return b.toByteArray()
    }

    private fun message(ckrV: ByteArray, firstType: Int, exch: Int, flags: Int, mid: ByteArray, payload: ByteArray): ByteArray =
        Bb().bytes(cki).bytes(ckrV).u8(firstType).u8(0x10).u8(exch).u8(flags).bytes(mid).u32((28 + payload.size).toLong()).bytes(payload).toByteArray()

    private fun parseHdr(m: ByteArray): Hdr {
        if (m.size < 28) throw IkeException("příliš krátká zpráva IKE")
        return Hdr(m.copyOfRange(0, 8), m.copyOfRange(8, 16), m.u8(16), m.u8(18), m.u8(19), m.copyOfRange(20, 24), m.u32(24).toInt())
    }

    private fun parse(d: ByteArray, off: Int, first: Int): Pair<List<Pl>, Int> {
        val out = ArrayList<Pl>()
        var o = off; var t = first
        while (t != 0) {
            if (o + 4 > d.size) throw IkeException("poškozený řetězec payloadů")
            val next = d.u8(o); val len = d.u16(o + 2)
            if (len < 4 || o + len > d.size) throw IkeException("neplatná délka payloadu")
            out.add(Pl(t, d.copyOfRange(o + 4, o + len)))
            o += len; t = next
        }
        return Pair(out, o)
    }

    private fun attrs(d: ByteArray, off: Int, end: Int): Map<Int, Int> {
        val m = HashMap<Int, Int>(); var o = off
        while (o + 4 <= end) {
            val t = d.u16(o)
            if (t and 0x8000 != 0) { m[t and 0x7FFF] = d.u16(o + 2); o += 4 }
            else {
                val l = d.u16(o + 2); var v = 0
                for (i in 0 until minOf(l, 4)) v = (v shl 8) or d.u8(o + 4 + i)
                m[t] = v; o += 4 + l
            }
        }
        return m
    }
    private fun tv(b: Bb, type: Int, v: Int) = b.u16(0x8000 or type).u16(v)

    private fun checkNotify(m: ByteArray, h: Hdr) {
        if (h.exch != EX_INFO || h.flags and 1 != 0) return
        try {
            val (pls, _) = parse(m, 28, h.next)
            for (p in pls) if (p.type == NOTIFY && p.body.size >= 8) {
                val code = p.body.u16(6)
                if (code < 16384) throw IkeException("server odmítl: ${notifyName(code)}")
            }
        } catch (e: IkeException) { if (e.message?.startsWith("server odmítl") == true) throw e }
    }

    /** Pošle zprávu a čeká na odpověď, kterou přijme [accept] (vrací true). Opakuje po 3 s, nejvýš 4×. */
    private fun transact(msg: ByteArray, float: Boolean, what: String, accept: (ByteArray) -> Boolean): ByteArray {
        for (attempt in 1..4) {
            io.send(msg, float)
            val deadline = System.currentTimeMillis() + 3000
            while (true) {
                val left = (deadline - System.currentTimeMillis()).toInt()
                if (left <= 0) break
                val r = io.recv(left) ?: break
                try {
                    val h = parseHdr(r)
                    if (!sameBytes(h.cki, cki)) continue
                    checkNotify(r, h)
                    if (accept(r)) return r
                } catch (e: IkeException) {
                    if (e.message?.startsWith("server odmítl") == true) throw e
                    log("IKE: zahazuji nepoužitelnou zprávu ($what): ${e.message}")
                }
            }
            if (attempt < 4) log("IKE: $what – bez odpovědi, opakuji ($attempt)")
        }
        throw IkeException("server neodpovídá ($what)")
    }

    // ---------- fáze 1: Main Mode ----------
    private fun saP1Body(): ByteArray {
        val props = Bb()
        val n = p1Transforms.size
        for ((i, t) in p1Transforms.withIndex()) {
            val a = Bb()
            tv(a, 1, t.enc); tv(a, 2, t.hash); tv(a, 3, 1); tv(a, 4, t.group); tv(a, 11, 1); tv(a, 12, lifeP1)
            if (t.keyBits != 0) tv(a, 14, t.keyBits)
            val ab = a.toByteArray()
            props.u8(if (i + 1 < n) 3 else 0).u8(0).u16(8 + ab.size).u8(i + 1).u8(1).u16(0).bytes(ab)
        }
        val pb = props.toByteArray()
        val prop = Bb().u8(0).u8(0).u16(8 + pb.size).u8(1).u8(1).u8(0).u8(n).bytes(pb).toByteArray()
        return Bb().u32(1).u32(1).bytes(prop).toByteArray()
    }

    private fun natd(hash: String, ip: ByteArray, port: Int, ckrV: ByteArray) = digest(hash, cki, ckrV, ip, Bb().u16(port).toByteArray())

    private fun expandKey(k: ByteArray, need: Int): ByteArray {
        if (k.size >= need) return k.copyOf(need)
        var out = ByteArray(0); var prev = byteArrayOf(0)
        while (out.size < need) { prev = prf(k, prev); out += prev }
        return out.copyOf(need)
    }

    fun negotiate(): IpsecKeys {
        // MM1 / MM2
        val saBody = saP1Body()
        val mm1 = message(ByteArray(8), SA, EX_MAIN, 0, ByteArray(4),
            chain(listOf(Pl(SA, saBody), Pl(VID, VID_RFC3947), Pl(VID, VID_DRAFT03), Pl(VID, VID_DRAFT02), Pl(VID, VID_DRAFT02b))))
        var chosen: P1T? = null; var chosenAttrs = emptyMap<Int, Int>()
        var vids = emptyList<ByteArray>()
        val mm2 = transact(mm1, false, "MM1") { r ->
            val h = parseHdr(r)
            if (h.exch != EX_MAIN || h.flags and 1 != 0) return@transact false
            val (pls, _) = parse(r, 28, h.next)
            val sa = pls.firstOrNull { it.type == SA } ?: return@transact false
            ckr = h.ckr
            // SA: DOI(4) situation(4) proposal(...)
            val b = sa.body
            val ntr = b.u8(8 + 7)
            val spiLen = b.u8(8 + 6)
            val tOff = 8 + 8 + spiLen
            if (ntr < 1 || tOff + 8 > b.size) throw IkeException("neplatný SA v odpovědi")
            val tLen = b.u16(tOff + 2)
            val at = attrs(b, tOff + 8, minOf(b.size, tOff + tLen))
            chosenAttrs = at
            val enc = at[1] ?: 0; val hash = at[2] ?: 0; val grp = at[4] ?: 0; val kb = at[14] ?: 0
            chosen = P1T(enc, kb, hash, grp)
            vids = pls.filter { it.type == VID }.map { it.body }
            true
        }
        val ch = chosen!!
        val dh = DhGroup.byId(ch.group) ?: throw IkeException("server vybral nepodporovanou DH skupinu ${ch.group}")
        if (ch.enc != 7 && ch.enc != 5) throw IkeException("server vybral nepodporované šifrování ${ch.enc}")
        hashAlg = hashName(ch.hash); hmacAlg = hmacName(ch.hash)
        aes = ch.enc == 7; bs = Cbc.blockSize(aes)
        val keyBytes = if (aes) (if (ch.keyBits == 0) 16 else ch.keyBits / 8) else 24
        val rfc = vids.any { sameBytes(it, VID_RFC3947) }
        val d03 = vids.any { sameBytes(it, VID_DRAFT03) }
        val d02 = vids.any { sameBytes(it, VID_DRAFT02) || sameBytes(it, VID_DRAFT02b) }
        natRfc = rfc || d03 || !d02
        if (!rfc && !d03 && !d02) log("IKE: server NEOZNAČIL podporu NAT-T (VID) – zkusím přesto")
        log("IKE: server vybral ${if (aes) "AES-${keyBytes * 8}" else "3DES"}, ${hashAlg}, DH skupina ${ch.group}; NAT-T ${if (rfc) "RFC 3947" else if (d03) "draft-03" else if (d02) "draft-02" else "?"}")

        // MM3 / MM4
        val dhk = dh.generate()
        val ni = rnd(20)
        val natdType = if (natRfc) 20 else 130
        val mm3 = message(ckr, KE, EX_MAIN, 0, ByteArray(4), chain(listOf(
            Pl(KE, dhk.pub), Pl(NONCE, ni),
            Pl(natdType, natd(hashAlg, serverIp, 500, ckr)),
            Pl(natdType, natd(hashAlg, localIp, 0, ckr))          // záměrně nesedí → server si myslí, že jsme za NAT, a zapouzdří ESP do UDP
        )))
        var gxr = ByteArray(0); var nr = ByteArray(0)
        transact(mm3, false, "MM3") { r ->
            val h = parseHdr(r)
            if (h.exch != EX_MAIN || h.flags and 1 != 0) return@transact false
            val (pls, _) = parse(r, 28, h.next)
            val ke = pls.firstOrNull { it.type == KE } ?: return@transact false
            val no = pls.firstOrNull { it.type == NONCE } ?: return@transact false
            gxr = ke.body; nr = no.body
            true
        }
        if (gxr.size != dh.len) throw IkeException("neplatná délka DH hodnoty serveru (${gxr.size})")
        val gxy = dh.shared(dhk.priv, gxr)

        val skeyid = prf(psk, ni, nr)
        skeyidD = prf(skeyid, gxy, cki, ckr, byteArrayOf(0))
        skeyidA = prf(skeyid, skeyidD, gxy, cki, ckr, byteArrayOf(1))
        val skeyidE = prf(skeyid, skeyidA, gxy, cki, ckr, byteArrayOf(2))
        encKey = expandKey(skeyidE, keyBytes)
        p1Iv = digest(hashAlg, dhk.pub, gxr).copyOf(bs)

        // MM5 / MM6 (šifrované): ID + HASH_I
        val idBody = Bb().u8(1).u8(0).u16(0).bytes(localIp).toByteArray()
        val hashI = prf(skeyid, dhk.pub, gxr, cki, ckr, saBody, idBody)
        val mm5 = encryptP1(chain(listOf(Pl(ID, idBody), Pl(HASH, hashI))), ID, EX_MAIN)
        var peerIdBody = ByteArray(0)
        val mm6 = try { transact(mm5, true, "MM5") { r ->
            val h = parseHdr(r)
            if (h.exch != EX_MAIN || h.flags and 1 == 0) return@transact false
            val plain = decrypt(r, p1Iv)
            val (pls, _) = parse(plain, 0, h.next)
            val idp = pls.firstOrNull { it.type == ID } ?: return@transact false
            val hp = pls.firstOrNull { it.type == HASH } ?: return@transact false
            val exp = prf(skeyid, gxr, dhk.pub, ckr, cki, saBody, idp.body)
            if (!sameBytes(exp, hp.body)) throw IkeException("HASH_R nesedí – špatný předsdílený klíč (PSK)?")
            peerIdBody = idp.body
            true
        } } catch (e: IkeException) {
            if (e.message?.startsWith("server neodpovídá") == true) throw IkeException("server neodpovídá na ověření – nejspíš špatný předsdílený klíč (PSK) nebo server PSK s tímto ID nezná")
            throw e
        }
        p1Iv = lastBlock(mm6, 28)
        log("IKE: fáze 1 hotova (server se prokázal, jeho ID typ ${peerIdBody.u8(0)})")
        return quickMode()
    }

    private fun lastBlock(m: ByteArray, off: Int) = m.copyOfRange(m.size - bs, m.size)

    private fun pad(d: ByteArray): ByteArray {
        val r = d.size % bs
        return if (r == 0) d else d + ByteArray(bs - r)
    }

    /** Zašifruje obsah (řetěz payloadů) fáze 1 a zabalí do zprávy; posune p1Iv. */
    private fun encryptP1(payloads: ByteArray, firstType: Int, exch: Int): ByteArray {
        val ct = Cbc.encrypt(aes, encKey, p1Iv, pad(payloads))
        p1Iv = ct.copyOfRange(ct.size - bs, ct.size)
        return message(ckr, firstType, exch, 1, ByteArray(4), ct)
    }

    private fun decrypt(m: ByteArray, iv: ByteArray): ByteArray {
        val body = m.copyOfRange(28, m.size)
        if (body.isEmpty() || body.size % bs != 0) throw IkeException("šifrovaná část nemá násobek bloku")
        return Cbc.decrypt(aes, encKey, iv, body)
    }

    // ---------- fáze 2: Quick Mode ----------
    private fun keymat(proto: Int, spi: ByteArray, ni: ByteArray, nr: ByteArray, need: Int): ByteArray {
        var out = ByteArray(0); var prev = ByteArray(0)
        while (out.size < need) { prev = prf(skeyidD, prev, byteArrayOf(proto.toByte()), spi, ni, nr); out += prev }
        return out.copyOf(need)
    }

    private fun quickMode(): IpsecKeys {
        val mid = rnd(4)
        var qIv = digest(hashAlg, p1Iv, mid).copyOf(bs)
        val spiIn = (RNG.nextInt() and 0x7FFFFFFF).let { if (it < 4096) it + 4096 else it }
        val ni = rnd(20)

        val props = Bb(); val n = p2Transforms.size
        for ((i, t) in p2Transforms.withIndex()) {
            val a = Bb()
            tv(a, 1, 1); tv(a, 2, lifeP2); tv(a, 4, 4); tv(a, 5, t.auth)      // 4 = UDP-Encapsulated-Transport
            if (t.keyBits != 0) tv(a, 6, t.keyBits)
            val ab = a.toByteArray()
            props.u8(if (i + 1 < n) 3 else 0).u8(0).u16(8 + ab.size).u8(i + 1).u8(t.enc).u16(0).bytes(ab)
        }
        val pb = props.toByteArray()
        val spiB = Bb().u32(spiIn.toLong()).toByteArray()
        val prop = Bb().u8(0).u8(0).u16(12 + pb.size).u8(1).u8(3).u8(4).u8(n).bytes(spiB).bytes(pb).toByteArray()
        val sa = Bb().u32(1).u32(1).bytes(prop).toByteArray()

        val idci = Bb().u8(1).u8(17).u16(1701).bytes(localIp).toByteArray()
        val idcr = Bb().u8(1).u8(17).u16(1701).bytes(serverIp).toByteArray()
        val oaType = if (natRfc) 21 else 131
        val oai = Bb().u8(1).u8(0).u16(0).bytes(localIp).toByteArray()     // typ, 3 B rezerva, adresa
        val oar = Bb().u8(1).u8(0).u16(0).bytes(serverIp).toByteArray()
        val rest = chain(listOf(Pl(SA, sa), Pl(NONCE, ni), Pl(ID, idci), Pl(ID, idcr), Pl(oaType, oai), Pl(oaType, oar)))
        val h1 = prf(skeyidA, mid, rest)
        val full = Bb().u8(SA).u8(0).u16(4 + h1.size).bytes(h1).bytes(rest).toByteArray()
        val ct1 = Cbc.encrypt(aes, encKey, qIv, pad(full))
        val qm1 = message(ckr, HASH, EX_QUICK, 1, mid, ct1)
        qIv = ct1.copyOfRange(ct1.size - bs, ct1.size)

        var nr = ByteArray(0); var spiOut = 0; var enc = 0; var kb = 0; var auth = 0; var encap = 0
        val qm2 = transact(qm1, true, "QM1") { r ->
            val h = parseHdr(r)
            if (h.exch != EX_QUICK || h.flags and 1 == 0 || !sameBytes(h.mid, mid)) return@transact false
            val plain = decrypt(r, qIv)
            val (pls, end) = parse(plain, 0, h.next)
            val hp = pls.firstOrNull() ?: return@transact false
            if (hp.type != HASH) return@transact false
            val body = plain.copyOfRange(4 + hp.body.size, end)
            val exp = prf(skeyidA, mid, ni, body)
            if (!sameBytes(exp, hp.body)) throw IkeException("HASH(2) nesedí")
            val sp = pls.firstOrNull { it.type == SA } ?: throw IkeException("QM odpověď bez SA")
            val no = pls.firstOrNull { it.type == NONCE } ?: throw IkeException("QM odpověď bez nonce")
            val b = sp.body
            if (b.u8(13) != 3) throw IkeException("server vybral jiný protokol než ESP")
            if (b.u8(14) != 4) throw IkeException("neočekávaná délka SPI")
            spiOut = b.u32(16).toInt()
            val tOff = 16 + 4
            enc = b.u8(tOff + 5)
            val at = attrs(b, tOff + 8, minOf(b.size, tOff + b.u16(tOff + 2)))
            kb = at[6] ?: 0; auth = at[5] ?: 0; encap = at[4] ?: 0
            nr = no.body
            true
        }
        qIv = qm2.copyOfRange(qm2.size - bs, qm2.size)
        if (encap != 4 && encap != 61444) log("IKE: server nevybral UDP-Encapsulated-Transport (encap=$encap) – ESP v UDP nebude fungovat")
        val useAes = enc == 12
        if (!useAes && enc != 3) throw IkeException("server vybral nepodporované ESP šifrování $enc")
        val encLen = if (useAes) (if (kb == 0) 16 else kb / 8) else 24
        val (hmacN, authLen, icv) = when (auth) {
            1 -> Triple("HmacMD5", 16, 12); 2 -> Triple("HmacSHA1", 20, 12); 5 -> Triple("HmacSHA256", 32, 16)
            else -> throw IkeException("server vybral nepodporovaný ESP autentizační algoritmus $auth")
        }
        // QM3
        val h3 = prf(skeyidA, byteArrayOf(0), mid, ni, nr)
        val ct3 = Cbc.encrypt(aes, encKey, qIv, pad(chain(listOf(Pl(HASH, h3)))))
        io.send(message(ckr, HASH, EX_QUICK, 1, mid, ct3), true)

        val spiOutB = Bb().u32(spiOut.toLong() and 0xFFFFFFFFL).toByteArray()
        val kIn = keymat(3, spiB, ni, nr, encLen + authLen)
        val kOut = keymat(3, spiOutB, ni, nr, encLen + authLen)
        val info = "ESP ${if (useAes) "AES-${encLen * 8}" else "3DES"}-$hmacN, SPI in=${"%08x".format(spiIn)} out=${"%08x".format(spiOut)}"
        log("IKE: fáze 2 hotova ($info)")
        return IpsecKeys(spiIn, spiOut, useAes, kIn.copyOfRange(0, encLen), kOut.copyOfRange(0, encLen), hmacN, icv,
            kIn.copyOfRange(encLen, encLen + authLen), kOut.copyOfRange(encLen, encLen + authLen), info)
    }

    /** Zdvořile smaže ISAKMP SA na serveru (Informational + DELETE). */
    fun sendDelete() {
        try {
            val mid = rnd(4)
            val iv = digest(hashAlg, p1Iv, mid).copyOf(bs)
            val body = Bb().u32(1).u8(1).u8(16).u16(1).bytes(cki).bytes(ckr).toByteArray()
            val del = chain(listOf(Pl(DELETE, body)))
            val h = prf(skeyidA, mid, del)
            val full = chain(listOf(Pl(HASH, h), Pl(DELETE, body)))
            val ct = Cbc.encrypt(aes, encKey, iv, pad(full))
            io.send(message(ckr, HASH, EX_INFO, 1, mid, ct), true)
        } catch (e: Exception) { /* nevadí */ }
    }
}
