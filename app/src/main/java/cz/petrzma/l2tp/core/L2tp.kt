package cz.petrzma.l2tp.core

/** L2TPv2 (RFC 2661): řídicí kanál se spolehlivým doručováním + datové zprávy s PPP rámci. */
class L2tp(
    private val out: (ByteArray) -> Unit,            // hotová L2TP zpráva k odeslání
    private val log: (String) -> Unit,
    private val onPppFrame: (ByteArray) -> Unit,
    private val onEstablished: () -> Unit,
    private val onClosed: (String) -> Unit
) {
    private class Ctl(val avps: ByteArray, val sessionLevel: Boolean)

    val myTid = 1 + RNG.nextInt(60000)
    private val mySid = 1 + RNG.nextInt(60000)
    private var peerTid = 0
    private var peerSid = 0
    private var ns = 0
    private var nr = 0
    private val queue = ArrayDeque<Ctl>()
    private var inflight: Ctl? = null
    private var inflightNs = 0
    private var sentAt = 0L
    private var retries = 0
    private var lastTx = System.currentTimeMillis()
    private var established = false
    @Volatile var closed = false

    private fun avp(type: Int, value: ByteArray, mandatory: Boolean = true) =
        Bb().u16((if (mandatory) 0x8000 else 0) or (6 + value.size)).u16(0).u16(type).bytes(value).toByteArray()
    private fun msgType(t: Int) = avp(0, Bb().u16(t).toByteArray())

    private fun header(avps: ByteArray, tid: Int, sid: Int, n: Int, r: Int) =
        Bb().u16(0xC802).u16(12 + avps.size).u16(tid).u16(sid).u16(n).u16(r).bytes(avps).toByteArray()

    @Synchronized fun start() {
        queue.add(Ctl(cat(
            msgType(1),
            avp(2, byteArrayOf(1, 0)),
            avp(3, Bb().u32(3).toByteArray()),
            avp(7, "android".toByteArray()),
            avp(9, Bb().u16(myTid).toByteArray()),
            avp(10, Bb().u16(8).toByteArray(), false)
        ), false))
        pump()
    }

    /** Pošle další zprávu z fronty, pokud žádná nečeká na potvrzení. Vrací true, když něco odeslala. */
    private fun pump(): Boolean {
        if (inflight != null || queue.isEmpty()) return false
        val c = queue.removeFirst()
        inflight = c; inflightNs = ns; retries = 0
        transmit(c)
        return true
    }

    private fun transmit(c: Ctl) {
        sentAt = System.currentTimeMillis(); lastTx = sentAt
        out(header(c.avps, peerTid, if (c.sessionLevel) peerSid else 0, inflightNs, nr))
    }

    private fun sendZlb() { lastTx = System.currentTimeMillis(); out(header(ByteArray(0), peerTid, 0, if (inflight != null) (ns + 1) and 0xFFFF else ns, nr)) }

    @Synchronized fun sendData(ppp: ByteArray) {
        if (!established) return
        out(Bb().u16(0x4002).u16(8 + ppp.size).u16(peerTid).u16(peerSid).bytes(ppp).toByteArray())
        lastTx = System.currentTimeMillis()
    }

    @Synchronized fun tick() {
        if (closed) return
        val now = System.currentTimeMillis()
        val c = inflight
        if (c != null && now - sentAt > 1000) {
            if (++retries > 6) { fail("L2TP: server nepotvrzuje zprávy"); return }
            transmit(c)
        }
        if (established && inflight == null && queue.isEmpty() && now - lastTx > 30000) {
            queue.add(Ctl(msgType(6), false)); pump()
        }
    }

    private fun fail(why: String) { if (!closed) { closed = true; onClosed(why) } }

    @Synchronized fun close() {
        if (closed || peerTid == 0) { closed = true; return }
        try {
            if (established) out(header(cat(msgType(14), avp(14, Bb().u16(mySid).toByteArray()), avp(1, Bb().u16(3).u16(0).toByteArray())), peerTid, peerSid, ns, nr))
            out(header(cat(msgType(4), avp(9, Bb().u16(myTid).toByteArray()), avp(1, Bb().u16(1).u16(0).toByteArray())), peerTid, 0, if (established) (ns + 1) and 0xFFFF else ns, nr))
        } catch (e: Exception) { }
        closed = true
    }

    @Synchronized fun onRx(m: ByteArray) {
        if (closed || m.size < 6) return
        val flags = m.u16(0)
        if (flags and 0xF != 2) { log("L2TP: verze ${flags and 0xF} nepodporována"); return }
        if (flags and 0x8000 != 0) {                               // řídicí zpráva
            if (flags and 0x4000 == 0 || flags and 0x0800 == 0 || m.size < 12) return
            val len = minOf(m.u16(2), m.size)
            val sn = m.u16(8); val peerNr = m.u16(10)
            if (inflight != null && peerNr == ((inflightNs + 1) and 0xFFFF)) {
                ns = (ns + 1) and 0xFFFF; inflight = null; retries = 0
            }
            if (len == 12) { pump(); return }                      // ZLB
            if (sn == nr) {
                nr = (nr + 1) and 0xFFFF
                process(m.copyOfRange(12, len))
                if (!closed && !pump()) sendZlb()
            } else {
                sendZlb()                                          // duplicita nebo mimo pořadí: znovu potvrdit
            }
        } else {                                                   // datová zpráva
            var pos = 2; var end = m.size
            if (flags and 0x4000 != 0) { end = minOf(m.u16(2), m.size); pos += 2 }
            pos += 4
            if (flags and 0x0800 != 0) pos += 4
            if (flags and 0x0200 != 0 && pos + 2 <= m.size) pos += 2 + m.u16(pos)
            if (pos < end) onPppFrame(m.copyOfRange(pos, end))
        }
    }

    private fun process(avps: ByteArray) {
        val v = HashMap<Int, ByteArray>()
        var o = 0
        while (o + 6 <= avps.size) {
            val len = avps.u16(o) and 0x3FF
            if (len < 6 || o + len > avps.size) break
            if (avps.u16(o + 2) == 0) v[avps.u16(o + 4)] = avps.copyOfRange(o + 6, o + len)
            o += len
        }
        val t = v[0]?.takeIf { it.size >= 2 }?.u16(0) ?: return
        when (t) {
            2 -> {                                                 // SCCRP
                peerTid = v[9]?.u16(0) ?: 0
                log("L2TP: tunel navázán (server tunnel id $peerTid)")
                queue.add(Ctl(msgType(3), false))
                queue.add(Ctl(cat(msgType(10), avp(14, Bb().u16(mySid).toByteArray()), avp(15, rnd(4))), false))
            }
            11 -> {                                                // ICRP
                peerSid = v[14]?.u16(0) ?: 0
                queue.add(Ctl(cat(msgType(12), avp(24, Bb().u32(100000000).toByteArray()), avp(19, Bb().u32(1).toByteArray())), true))
                established = true
                log("L2TP: sezení navázáno (server session id $peerSid)")
                onEstablished()
            }
            4 -> fail("server ukončil tunel L2TP (StopCCN)")
            14 -> fail("server ukončil sezení L2TP (CDN)")
            6 -> {}
            else -> log("L2TP: neznámá zpráva typu $t")
        }
    }
}
