package cz.petrzma.l2tp

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var eServer: EditText
    private lateinit var eUser: EditText
    private lateinit var ePass: EditText
    private lateinit var ePsk: EditText
    private lateinit var eRoutes: EditText
    private lateinit var eDns: EditText
    private lateinit var eApps: EditText
    private lateinit var cReconnect: CheckBox
    private lateinit var tStatus: TextView
    private lateinit var tLog: TextView
    private lateinit var scroll: ScrollView
    private lateinit var bConnect: Button
    private var lastLog = ""

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun label(parent: LinearLayout, text: String) {
        parent.addView(TextView(this).apply { this.text = text; textSize = 13f; setPadding(0, dp(10), 0, 0) })
    }

    private fun field(parent: LinearLayout, label: String, hint: String, type: Int, secret: Boolean = false): EditText {
        label(parent, label)
        val e = EditText(this).apply {
            this.hint = hint; inputType = type; setSingleLine(true)
            if (secret) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        parent.addView(e, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        return e
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "L2TP/IPsec VPN"
        scroll = ScrollView(this)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(16), dp(16), dp(24)) }
        scroll.addView(root)
        setContentView(scroll)

        val uri = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        val txt = InputType.TYPE_CLASS_TEXT
        eServer = field(root, "Server (adresa nebo název)", "vpn.example.cz", uri)
        eUser = field(root, "Uživatel", "", txt)
        ePass = field(root, "Heslo", "", txt, true)
        ePsk = field(root, "Předsdílený klíč (PSK)", "", txt, true)
        eRoutes = field(root, "Trasy přes VPN (prázdné = veškerý provoz)", "např. 10.1.1.0/24, 192.168.0.0/16", txt)
        eDns = field(root, "DNS servery (prázdné = ze serveru, jen při plném tunelu)", "např. 10.1.1.1", txt)
        eApps = field(root, "Jen pro aplikace (balíčky, prázdné = všechny)", "např. com.android.chrome", txt)
        cReconnect = CheckBox(this).apply { text = "Automaticky se znovu připojit"; isChecked = true }
        root.addView(cReconnect)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(12), 0, 0) }
        bConnect = Button(this).apply { text = "Připojit"; setOnClickListener { onConnect() } }
        val bDisc = Button(this).apply { text = "Odpojit"; setOnClickListener { onDisconnect() } }
        row.addView(bConnect, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(bDisc, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(row)

        tStatus = TextView(this).apply { textSize = 16f; setPadding(0, dp(12), 0, dp(4)) }
        root.addView(tStatus)
        tLog = TextView(this).apply { typeface = android.graphics.Typeface.MONOSPACE; textSize = 11f; setTextIsSelectable(true) }
        root.addView(tLog)
        val bShare = Button(this).apply { text = "Sdílet log"; setOnClickListener { shareLog() } }
        root.addView(bShare)

        load()
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
    }

    private fun load() {
        eServer.setText(Store.str(this, "server")); eUser.setText(Store.str(this, "user"))
        ePass.setText(Store.secret(this, "pass")); ePsk.setText(Store.secret(this, "psk"))
        eRoutes.setText(Store.str(this, "routes")); eDns.setText(Store.str(this, "dns")); eApps.setText(Store.str(this, "apps"))
        cReconnect.isChecked = Store.flag(this, "reconnect", true)
    }

    private fun save() {
        Store.put(this, "server", eServer.text.toString().trim()); Store.put(this, "user", eUser.text.toString().trim())
        Store.putSecret(this, "pass", ePass.text.toString()); Store.putSecret(this, "psk", ePsk.text.toString())
        Store.put(this, "routes", eRoutes.text.toString().trim()); Store.put(this, "dns", eDns.text.toString().trim())
        Store.put(this, "apps", eApps.text.toString().trim()); Store.putFlag(this, "reconnect", cReconnect.isChecked)
    }

    private fun onConnect() {
        save()
        val i = VpnService.prepare(this)                 // jednorázové systémové povolení VPN
        if (i != null) startActivityForResult(i, 1) else startVpn()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 1) { if (resultCode == RESULT_OK) startVpn() else VpnState.log("Povolení VPN zamítnuto") }
        else super.onActivityResult(requestCode, resultCode, data)
    }

    private fun startVpn() {
        VpnState.clear()
        val it = Intent(this, VpnSvc::class.java).setAction(VpnSvc.ACT_CONNECT)
        startForegroundService(it)
    }

    private fun onDisconnect() {
        startService(Intent(this, VpnSvc::class.java).setAction(VpnSvc.ACT_DISCONNECT))
    }

    private fun shareLog() {
        val i = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, VpnState.text())
        startActivity(Intent.createChooser(i, "Sdílet log"))
    }

    private val tick = object : Runnable {
        override fun run() {
            tStatus.text = VpnState.status
            val t = VpnState.text()
            if (t != lastLog) {
                lastLog = t; tLog.text = t
                scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
            }
            bConnect.isEnabled = !VpnState.running
            handler.postDelayed(this, 500)
        }
    }

    override fun onResume() { super.onResume(); handler.post(tick) }
    override fun onPause() { super.onPause(); handler.removeCallbacks(tick) }
}
