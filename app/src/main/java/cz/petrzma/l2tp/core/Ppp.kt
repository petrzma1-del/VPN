package cz.petrzma.l2tp.core

/** PPP klient: LCP, ověření (MS-CHAPv2 / CHAP-MD5 / PAP), IPCP (IP + DNS). Odmítá CCP/IPv6CP. */
class Ppp(
    private val user: String,
    private val pass: String,
    private val send: (ByteArray) -> Unit,                  // kompletní PPP rámec (FF 03 + protokol + data)
    private val log: (String) -> Unit,
    private val onIpUp: (ByteArray, List<ByteArray>) -> Unit,
    private val onIp: (ByteArray) -> Unit,
    private val onFail: (String) -> Unit
) {
    private class Opt(val type: Int, val data: ByteArray)

    private inner class Neg(val proto: Int, val name: String, var ours: MutableList<Opt>) {
        var reqId = 0; var gotAck = false; var sentAck = false
        var sentAt = 0L; var tries = 0
        val opened get() = gotAck && sentAck
    }

    private val PROTO_LCP = 0xC021; private val PROTO_PAP = 0xC023; private val PROTO_CHAP = 0xC223
    private val PROTO_IPCP = 0x8021; private val PROTO_IP = 0x0021; private val PROTO_CCP = 0x80FD

    private var magic = rnd(4)
    private val lcp = Neg(PROTO_LCP, "LCP", mutableListOf(Opt(1, Bb().u16(1400).toByteArray()), Opt(5, magic)))
    private val ipcp = Neg(PROTO_IPCP, "IPCP", mutableListOf(Opt(3, ByteArray(4)), Opt(129, ByteArray(4)), Opt(131, ByteArray(4))))
    private var nextId = 1
    private var authProto = 0            // 0 = server ověření nechce
    private var chapAlgo = 0
    private var authDone = false
    private var ipcpStarted = false
    private var ipUp = false
    private var failed = false
    private var authChallenge = ByteArray(0); private var peerChallenge = ByteArray(0); private var ntResp = ByteArray(0)
    private var papId = 0
    private var papSentAt = 0L

    private fun frame(proto: Int, data: ByteArray) = Bb().u8(0xFF).u8(0x03).u16(proto).bytes(data).toByteArray()
    private fun pkt(code: Int, id: Int, data: ByteArray) = Bb().u8(code).u8(id).u16(4 + data.size).bytes(data).toByteArray()
    private fun encOpts(l: List<Opt>): ByteArray { val b = Bb(); for (o in l) b.u8(o.type).u8(2 + o.data.size).bytes(o.data); return b.toByteArray() }
    private fun parseOpts(d: ByteArray): List<Opt>? {
        val r = ArrayList<Opt>(); var o = 0
        while (o < d.size) {
            if (o + 2 > d.size) return null
            val l = d.u8(o + 1); if (l < 2 || o + l > d.size) return null
            r.add(Opt(d.u8(o), d.copyOfRange(o + 2, o + l))); o += l
        }
        return r
    }

    fun start() { sendReq(lcp) }

    fun terminate() {
        try { send(frame(PROTO_LCP, pkt(5, nextId++, "bye".toByteArray()))) } catch (e: Exception) { }
    }

    fun sendIp(ip: ByteArray) { if (ipUp) send(frame(PROTO_IP, ip)) }

    private fun sendReq(n: Neg) {
        n.reqId = nextId++ and 0xFF; n.gotAck = false
        n.sentAt = System.currentTimeMillis(); n.tries++
        send(frame(n.proto, pkt(1, n.reqId, encOpts(n.ours))))
    }

    fun tick() {
        if (failed) return
        val now = System.currentTimeMillis()
        for (n in listOf(lcp, ipcp)) {
            if (n === ipcp && !ipcpStarted) continue
            if (!n.gotAck && now - n.sentAt > 3000) {
                if (n.tries >= 8) { fail("${n.name}: server neodpovídá"); return }
                sendReq(n)
            }
        }
        if (authProto == PROTO_PAP && !authDone && papSentAt != 0L && now - papSentAt > 3000) sendPap()
    }

    private fun fail(why: String) { if (!failed) { failed = true; onFail(why) } }

    fun onFrame(f: ByteArray) {
        if (failed || f.size < 2) return
        var i = 0
        if (f.u8(0) == 0xFF && f.u8(1) == 0x03) i = 2
        if (i >= f.size) return
        val proto: Int
        if (f.u8(i) and 1 == 1) { proto = f.u8(i); i += 1 } else { if (i + 2 > f.size) return; proto = f.u16(i); i += 2 }
        val d = f.copyOfRange(i, f.size)
        when (proto) {
            PROTO_IP -> onIp(d)
            PROTO_LCP -> negotiation(lcp, d)
            PROTO_IPCP -> if (lcp.opened) negotiation(ipcp, d)
            PROTO_CHAP -> chap(d)
            PROTO_PAP -> pap(d)
            PROTO_CCP -> ccp(d)
            0x0057, 0x8057, 0x80FB, 0x00FD -> protoReject(proto, d, f)
            else -> protoReject(proto, d, f)
        }
    }

    private var rejCount = 0
    private fun protoReject(proto: Int, d: ByteArray, raw: ByteArray) {
        if (!lcp.opened) return
        rejCount++
        // Jen skutečné PPP protokoly (první bajt 0x00/0x80/0xC0/0xC2 apod. a lichý spodní bajt) mají smysl odmítat.
        val plausible = (proto and 0x0001) == 1 && (proto and 0x8000 != 0 || proto < 0x4000)
        if (rejCount <= 6) {
            val hex = raw.take(32).joinToString("") { "%02x".format(it) }
            log("PPP: neznámý rámec, proto 0x${"%04x".format(proto)}, ${raw.size} B: $hex")
        } else if (rejCount % 200 == 0) log("PPP: dalších neznámých rámců: $rejCount")
        if (plausible && rejCount <= 20)
            send(frame(PROTO_LCP, pkt(8, nextId++ and 0xFF, Bb().u16(proto).bytes(d.copyOf(minOf(d.size, 64))).toByteArray())))
    }

    private fun ccp(d: ByteArray) {
        if (d.size < 4 || !lcp.opened) return
        val code = d.u8(0); val id = d.u8(1)
        if (code == 1) {
            val opts = d.copyOfRange(4, minOf(d.size, d.u16(2)))
            if (opts.isEmpty()) send(frame(PROTO_CCP, pkt(2, id, opts)))
            else send(frame(PROTO_CCP, pkt(4, id, opts)))        // odmítnout všechny volby (MPPE ani komprese nechceme)
        }
    }

    // ---------- společná část LCP/IPCP ----------
    private fun negotiation(n: Neg, d: ByteArray) {
        if (d.size < 4) return
        val code = d.u8(0); val id = d.u8(1); val len = minOf(d.u16(2), d.size)
        val body = d.copyOfRange(4, len)
        when (code) {
            1 -> onConfReq(n, id, body)
            2 -> if (id == n.reqId) { n.gotAck = true; afterChange(n) }
            3 -> if (id == n.reqId) {                                     // Conf-Nak: převezmi navržené hodnoty
                val l = parseOpts(body) ?: return
                for (o in l) {
                    val k = n.ours.indexOfFirst { it.type == o.type }
                    if (k >= 0) n.ours[k] = o else if (n === ipcp || o.type == 1) n.ours.add(o)
                }
                if (n === lcp) { val m = n.ours.firstOrNull { it.type == 5 }; if (m != null) magic = m.data }
                sendReq(n)
            }
            4 -> if (id == n.reqId) {                                     // Conf-Rej: tyto volby nechceme
                val l = parseOpts(body) ?: return
                n.ours.removeAll { o -> l.any { it.type == o.type } }
                sendReq(n)
            }
            5 -> { send(frame(n.proto, pkt(6, id, ByteArray(0)))); fail("server ukončil spojení (${n.name} Terminate)") }
            9 -> if (n === lcp) send(frame(PROTO_LCP, pkt(10, id, cat(magic, if (body.size > 4) body.copyOfRange(4, body.size) else ByteArray(0)))))
            8 -> log("${n.name}: server odmítl protokol ${if (body.size >= 2) "0x%04x".format(body.u16(0)) else "?"}")
            7 -> log("${n.name}: server odmítl kód")
            else -> {}
        }
    }

    private fun onConfReq(n: Neg, id: Int, body: ByteArray) {
        val opts = parseOpts(body)
        if (opts == null) { fail("${n.name}: poškozená Configure-Request"); return }
        val ok = if (n === lcp) setOf(1, 2, 3, 5, 7, 8) else setOf(3)
        val rej = opts.filter { it.type !in ok }
        if (rej.isNotEmpty()) { send(frame(n.proto, pkt(4, id, encOpts(rej)))); n.sentAck = false; return }
        if (n === lcp) {
            val a = opts.firstOrNull { it.type == 3 }
            if (a != null) {
                val p = if (a.data.size >= 2) a.data.u16(0) else 0
                val good = (p == PROTO_CHAP && a.data.size >= 3 && (a.data.u8(2) == 0x81 || a.data.u8(2) == 0x05)) || p == PROTO_PAP
                if (!good) { send(frame(n.proto, pkt(3, id, encOpts(listOf(Opt(3, byteArrayOf(0xC2.toByte(), 0x23, 0x81.toByte()))))))); n.sentAck = false; return }
                authProto = p; chapAlgo = if (p == PROTO_CHAP) a.data.u8(2) else 0
            } else authProto = 0
        }
        send(frame(n.proto, pkt(2, id, body)))
        n.sentAck = true
        afterChange(n)
    }

    private fun afterChange(n: Neg) {
        if (n === lcp && lcp.opened && !ipcpStarted) {
            log("PPP: LCP otevřeno (ověření: ${when (authProto) { PROTO_CHAP -> if (chapAlgo == 0x81) "MS-CHAPv2" else "CHAP-MD5"; PROTO_PAP -> "PAP"; else -> "žádné" }})")
            if (authProto == 0) { authDone = true; startIpcp() } else if (authProto == PROTO_PAP) sendPap()
        }
        if (n === ipcp && ipcp.opened && !ipUp) {
            val ip = ipcp.ours.first { it.type == 3 }.data
            if (ip.all { it == 0.toByte() }) return
            val dns = listOf(129, 131).mapNotNull { t -> ipcp.ours.firstOrNull { it.type == t }?.data?.takeIf { d -> d.any { it != 0.toByte() } } }
            ipUp = true
            log("PPP: IPCP hotovo, adresa ${ipStr(ip)}, DNS ${dns.joinToString { ipStr(it) }}")
            onIpUp(ip, dns)
        }
    }

    private fun startIpcp() { if (!ipcpStarted) { ipcpStarted = true; sendReq(ipcp) } }

    // ---------- ověření ----------
    private fun chap(d: ByteArray) {
        if (d.size < 4) return
        val code = d.u8(0); val id = d.u8(1); val len = minOf(d.u16(2), d.size)
        when (code) {
            1 -> {                                                         // Challenge
                val vs = d.u8(4); val value = d.copyOfRange(5, 5 + vs)
                if (chapAlgo == 0x81) {
                    authChallenge = value; peerChallenge = rnd(16)
                    val hashUser = user.substringAfter('\\')
                    ntResp = MsChapV2.ntResponse(authChallenge, peerChallenge, hashUser, pass)
                    val v = cat(peerChallenge, ByteArray(8), ntResp, byteArrayOf(0))
                    send(frame(PROTO_CHAP, pkt(2, id, cat(byteArrayOf(49), v, user.toByteArray()))))
                } else {
                    val resp = digest("MD5", byteArrayOf(id.toByte()), pass.toByteArray(), value)
                    send(frame(PROTO_CHAP, pkt(2, id, cat(byteArrayOf(16), resp, user.toByteArray()))))
                }
            }
            3 -> {                                                         // Success
                val msg = String(d, 4, len - 4, Charsets.ISO_8859_1)
                if (chapAlgo == 0x81 && msg.startsWith("S=")) {
                    val exp = MsChapV2.authenticatorResponse(pass, ntResp, peerChallenge, authChallenge, user.substringAfter('\\'))
                    if (!msg.uppercase().startsWith(exp)) log("PPP: VAROVÁNÍ – server neprokázal znalost hesla (S= nesedí)")
                }
                authDone = true; log("PPP: přihlášení přijato"); startIpcp()
            }
            4 -> fail("přihlášení odmítnuto serverem: " + String(d, 4, len - 4, Charsets.ISO_8859_1))
        }
    }

    private fun sendPap() {
        papSentAt = System.currentTimeMillis(); papId = nextId++ and 0xFF
        val u = user.toByteArray(); val p = pass.toByteArray()
        send(frame(PROTO_PAP, pkt(1, papId, cat(byteArrayOf(u.size.toByte()), u, byteArrayOf(p.size.toByte()), p))))
    }

    private fun pap(d: ByteArray) {
        if (d.size < 4) return
        when (d.u8(0)) {
            2 -> { authDone = true; log("PPP: přihlášení (PAP) přijato"); startIpcp() }
            3 -> fail("přihlášení (PAP) odmítnuto")
        }
    }
}
