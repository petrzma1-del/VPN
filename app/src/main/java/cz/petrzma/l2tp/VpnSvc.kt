package cz.petrzma.l2tp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import cz.petrzma.l2tp.core.VpnClient
import cz.petrzma.l2tp.core.VpnConfig
import cz.petrzma.l2tp.core.VpnHost
import cz.petrzma.l2tp.core.ipStr
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket

class VpnSvc : VpnService() {
    companion object {
        const val ACT_CONNECT = "cz.petrzma.l2tp.CONNECT"
        const val ACT_DISCONNECT = "cz.petrzma.l2tp.DISCONNECT"
        private const val CHANNEL = "vpn"
        private const val NOTIF_ID = 1
    }

    private val handler = Handler(Looper.getMainLooper())
    private var client: VpnClient? = null
    private var tun: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    private var userStop = false
    private var attempts = 0
    private var cfg: Cfg? = null

    private class Cfg(val server: String, val psk: String, val user: String, val pass: String,
                      val routes: List<String>, val dns: List<String>, val apps: List<String>, val reconnect: Boolean)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACT_DISCONNECT) {
            userStop = true
            VpnState.log("Odpojuji…")
            val c = client
            if (c != null) c.stop() else { finishService() }
            return START_NOT_STICKY
        }
        startFg("Připojování…")
        userStop = false; attempts = 0
        connect()
        return START_STICKY
    }

    private fun split(s: String) = s.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }

    private fun loadCfg(): Cfg? {
        val server = Store.str(this, "server").trim()
        val user = Store.str(this, "user").trim()
        val psk = Store.secret(this, "psk"); val pass = Store.secret(this, "pass")
        if (server.isEmpty() || user.isEmpty() || psk.isEmpty() || pass.isEmpty()) return null
        return Cfg(server, psk, user, pass, split(Store.str(this, "routes")), split(Store.str(this, "dns")),
            split(Store.str(this, "apps")), Store.flag(this, "reconnect", true))
    }

    private fun connect() {
        val c = loadCfg()
        if (c == null) {
            VpnState.status = "Chybí nastavení (server, uživatel, heslo, PSK)"
            VpnState.log(VpnState.status); finishService(); return
        }
        cfg = c
        VpnState.running = true; VpnState.up = false
        VpnState.status = "Připojuji k ${c.server}…"
        VpnState.log("Připojuji k ${c.server} jako ${c.user}")
        val cl = VpnClient(VpnConfig(c.server, c.psk, c.user, c.pass), host)
        client = cl
        cl.start()
    }

    private val host = object : VpnHost {
        override fun log(msg: String) { VpnState.log(msg) }
        override fun protect(s: DatagramSocket) { if (!this@VpnSvc.protect(s)) VpnState.log("VAROVÁNÍ: protect() selhalo") }

        override fun onUp(ip: ByteArray, dns: List<ByteArray>) {
            val c = cfg ?: return
            try {
                val b = Builder().setSession("L2TP/IPsec").setMtu(1280).addAddress(ipStr(ip), 32)
                if (c.routes.isEmpty()) b.addRoute("0.0.0.0", 0)
                else for (r in c.routes) {
                    val p = r.split('/')
                    b.addRoute(p[0], if (p.size > 1) p[1].toInt() else 32)
                }
                val dnsList = if (c.dns.isNotEmpty()) c.dns else if (c.routes.isEmpty()) dns.map { ipStr(it) } else emptyList()
                for (d in dnsList) b.addDnsServer(d)
                for (a in c.apps) try { b.addAllowedApplication(a) } catch (e: PackageManager.NameNotFoundException) { VpnState.log("Aplikace $a není nainstalovaná") }
                val t = b.establish()
                if (t == null) { VpnState.log("establish() selhalo – oprávnění VPN odebráno?"); client?.stop(); return }
                tun = t; tunOut = FileOutputStream(t.fileDescriptor)
                attempts = 0
                VpnState.up = true
                VpnState.status = "Připojeno, adresa ${ipStr(ip)}"
                VpnState.log("Tunel nahoře: ${ipStr(ip)}, trasy: ${if (c.routes.isEmpty()) "vše" else c.routes.joinToString()}, DNS: ${dnsList.joinToString().ifEmpty { "beze změny" }}")
                handler.post { updateNotif("Připojeno (${ipStr(ip)})") }
                val input = FileInputStream(t.fileDescriptor)
                Thread({
                    val buf = ByteArray(32767)
                    try {
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            if (n > 0) client?.sendIp(buf.copyOf(n))
                        }
                    } catch (e: Exception) { }
                }, "tun-reader").also { it.isDaemon = true }.start()
            } catch (e: Exception) {
                VpnState.log("Chyba při vytváření tunelu: ${e.message}"); client?.stop()
            }
        }

        override fun onIp(packet: ByteArray) {
            try { tunOut?.write(packet) } catch (e: Exception) { }
        }

        override fun onDown(reason: String) { handler.post { handleDown(reason) } }
    }

    private fun handleDown(reason: String) {
        try { tun?.close() } catch (e: Exception) { }
        tun = null; tunOut = null; client = null
        VpnState.up = false
        VpnState.log("Odpojeno: $reason")
        val fatal = listOf("přihlášení", "předsdílený", "NO-PROPOSAL", "AUTHENTICATION", "IPv4 adresu").any { reason.contains(it) }
        val c = cfg
        if (!userStop && c != null && c.reconnect && !fatal && attempts < 5) {
            attempts++
            VpnState.status = "Spojení padlo ($reason), opakuji za 10 s ($attempts/5)"
            handler.postDelayed({ if (!userStop && client == null) connect() }, 10000)
        } else {
            VpnState.status = if (userStop) "Odpojeno" else "Odpojeno: $reason"
            finishService()
        }
    }

    private fun finishService() {
        VpnState.running = false; VpnState.up = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() { userStop = true; client?.stop(); super.onRevoke() }

    override fun onDestroy() { userStop = true; client?.stop(); try { tun?.close() } catch (e: Exception) { }; super.onDestroy() }

    // ---------- oznámení (služba popředí je u VPN povinná) ----------
    private fun notif(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW))
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("L2TP/IPsec VPN").setContentText(text).setOngoing(true).setContentIntent(pi).build()
    }

    private fun startFg(text: String) {
        val n = notif(text)
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(NOTIF_ID, n)
    }

    private fun updateNotif(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notif(text))
    }
}
