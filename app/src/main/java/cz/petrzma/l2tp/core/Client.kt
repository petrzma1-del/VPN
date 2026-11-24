package cz.petrzma.l2tp.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException

class VpnConfig(
    val server: String, val psk: String, val user: String, val pass: String,
    val ikePort: Int = 500, val natPort: Int = 4500
)

interface VpnHost {
    fun log(msg: String)
    fun protect(s: DatagramSocket)
    fun onUp(ip: ByteArray, dns: List<ByteArray>)        // PPP přidělilo adresu; tady se vytvoří TUN
    fun onIp(packet: ByteArray)                           // IP paket z tunelu pro telefon
    fun onDown(reason: String)
}

/** Celý klient L2TP/IPsec: IKEv1 → ESP v UDP/4500 → L2TP → PPP. Vše v jednom vlákně + přijímací smyčka. */
class VpnClient(private val cfg: VpnConfig, private val host: VpnHost,
                private val negotiatorOverride: ((IkeIo, ByteArray, ByteArray) -> IpsecKeys)? = null) {   // override jen pro testy
    @Volatile private var stopFlag = false
    private var thread: Thread? = null
    @Volatile private var ppp: Ppp? = null
    private var socket: DatagramSocket? = null

    fun start() {
        thread = Thread({ run() }, "l2tp-ipsec").also { it.isDaemon = true; it.start() }
    }

    fun stop() { stopFlag = true }          // smyčka skončí do ~0,5 s, odešle odpojení a sama zavře socket

    fun sendIp(p: ByteArray) { ppp?.sendIp(p) }

    private fun localAddressFor(srv: InetAddress): InetAddress {
        try {
            DatagramSocket().use { t ->
                host.protect(t)
                t.connect(InetSocketAddress(srv, cfg.ikePort))
                val a = t.localAddress
                if (a != null && !a.isAnyLocalAddress && a is Inet4Address) return a
            }
        } catch (e: Exception) { }
        for (ni in NetworkInterface.getNetworkInterfaces()) {
            if (ni.isLoopback || !ni.isUp) continue
            for (a in ni.inetAddresses) if (a is Inet4Address && !a.isLoopbackAddress) return a
        }
        throw IkeException("nelze zjistit místní IP adresu")
    }

    private fun run() {
        var reason = "ukončeno"
        var ike: Ike? = null
        var l2tp: L2tp? = null
        try {
            val srv = InetAddress.getAllByName(cfg.server).firstOrNull { it is Inet4Address }
                ?: throw IkeException("server ${cfg.server} nemá IPv4 adresu")
            val local = localAddressFor(srv)
            host.log("Server ${srv.hostHostAddr()}, místní adresa ${local.hostAddress}")
            val sock = DatagramSocket()
            socket = sock
            host.protect(sock)
            val buf = ByteArray(4096)

            fun sendTo(port: Int, data: ByteArray) { sock.send(DatagramPacket(data, data.size, srv, port)) }
            fun rawRecv(timeoutMs: Int): ByteArray? {
                sock.soTimeout = maxOf(timeoutMs, 1)
                val pk = DatagramPacket(buf, buf.size)
                try { sock.receive(pk) } catch (e: SocketTimeoutException) { return null }
                if (pk.address != srv) return ByteArray(0)
                lastRx = System.currentTimeMillis()
                return buf.copyOf(pk.length)
            }

            val io = object : IkeIo {
                override fun send(msg: ByteArray, float: Boolean) {
                    if (float) sendTo(cfg.natPort, cat(ByteArray(4), msg)) else sendTo(cfg.ikePort, msg)
                }
                override fun recv(timeoutMs: Int): ByteArray? {
                    val end = System.currentTimeMillis() + timeoutMs
                    while (!stopFlag) {
                        val left = (end - System.currentTimeMillis()).toInt()
                        if (left <= 0) return null
                        val r = rawRecv(left) ?: return null
                        if (r.size <= 1) continue
                        if (r.size > 4 && r.u32(0) == 0L) return r.copyOfRange(4, r.size)
                        if (r.u32(0) == 0L) continue
                        if (r.size >= 28 && r.u8(17) == 0x10) return r
                        // jiný (ESP) paket během vyjednávání – zahodit
                    }
                    return null
                }
            }
            lastRx = System.currentTimeMillis()
            val keys: IpsecKeys
            if (negotiatorOverride != null) keys = negotiatorOverride.invoke(io, local.address, srv.address)
            else {
                val ik = Ike(io, cfg.psk.toByteArray(), local.address, srv.address, host::log)
                ike = ik
                keys = ik.negotiate()
            }
            val esp = Esp(keys)

            var l2tpUpAt = 0L
            var pppRef: Ppp? = null
            val l2 = L2tp(
                out = { msg ->
                    val udp = Bb().u16(1701).u16(1701).u16(8 + msg.size).u16(0).bytes(msg).toByteArray()      // kontrolní součet 0 = nepoužit
                    sendTo(cfg.natPort, esp.encap(udp, 17))
                },
                log = host::log,
                onPppFrame = { f -> pppRef?.onFrame(f) },
                onEstablished = { l2tpUpAt = System.currentTimeMillis(); pppRef?.start() },
                onClosed = { why -> reason = why; stopFlag = true }
            )
            l2tp = l2
            val p = Ppp(cfg.user, cfg.pass,
                send = { f -> l2.sendData(f) }, log = host::log,
                onIpUp = { ip, dns -> pppUp = true; host.onUp(ip, dns) },
                onIp = { pk -> host.onIp(pk) },
                onFail = { why -> reason = why; stopFlag = true })
            pppRef = p; ppp = p
            l2.start()

            var lastKeep = System.currentTimeMillis()
            while (!stopFlag) {
                val r = rawRecv(500)
                if (r != null && r.isNotEmpty()) handle(r, esp, l2)
                val now = System.currentTimeMillis()
                l2.tick(); p.tick()
                if (now - lastKeep > 20000) { sendTo(cfg.natPort, byteArrayOf(0xFF.toByte())); lastKeep = now }
                if (now - lastRx > 120000) { reason = "server 2 minuty neodpovídá"; break }
                if (l2tpUpAt != 0L && now - l2tpUpAt > 30000 && !pppUp) { reason = "PPP: vyjednávání vypršelo"; break }
            }
        } catch (e: IkeException) {
            reason = e.message ?: "chyba IKE"
        } catch (e: Exception) {
            if (!stopFlag) reason = "chyba: ${e.javaClass.simpleName}: ${e.message}"
        } finally {
            try { ppp?.terminate(); l2tp?.close(); ike?.sendDelete() } catch (e: Exception) { }
            try { socket?.close() } catch (e: Exception) { }
            ppp = null
            host.onDown(reason)
        }
    }

    private fun InetAddress.hostHostAddr() = hostAddress
    @Volatile private var lastRx = 0L
    @Volatile private var pppUp = false

    private fun handle(r: ByteArray, esp: Esp, l2tp: L2tp) {
        if (r.size == 1) return                                    // NAT keepalive
        if (r.size > 4 && r.u32(0) == 0L) return                   // IKE zprávy za provozu (Informational) zatím jen ignorujeme
        val d = esp.decap(r) ?: return
        if (d.second != 17 || d.first.size < 8) return
        val sp = d.first.u16(0); val dp = d.first.u16(2)
        if (sp != 1701 && dp != 1701) return
        l2tp.onRx(d.first.copyOfRange(8, d.first.size))
    }
}
