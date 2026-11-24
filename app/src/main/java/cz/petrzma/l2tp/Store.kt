package cz.petrzma.l2tp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Nastavení. Heslo a PSK jsou uložené zašifrované klíčem z Android Keystore (nejdou vyčíst ze zálohy ani z jiné aplikace). */
object Store {
    private const val ALIAS = "l2tp_secrets"

    fun prefs(c: Context): SharedPreferences = c.getSharedPreferences("cfg", Context.MODE_PRIVATE)

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null)
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return g.generateKey()
    }

    fun seal(s: String): String {
        if (s.isEmpty()) return ""
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        return Base64.encodeToString(c.iv + c.doFinal(s.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    fun open(s: String): String {
        if (s.isEmpty()) return ""
        return try {
            val b = Base64.decode(s, Base64.NO_WRAP)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, 12))
            String(c.doFinal(b, 12, b.size - 12), Charsets.UTF_8)
        } catch (e: Exception) { "" }
    }

    fun str(c: Context, k: String) = prefs(c).getString(k, "") ?: ""
    fun secret(c: Context, k: String) = open(str(c, k))
    fun put(c: Context, k: String, v: String) { prefs(c).edit().putString(k, v).apply() }
    fun putSecret(c: Context, k: String, v: String) { prefs(c).edit().putString(k, seal(v)).apply() }
    fun flag(c: Context, k: String, def: Boolean) = prefs(c).getBoolean(k, def)
    fun putFlag(c: Context, k: String, v: Boolean) { prefs(c).edit().putBoolean(k, v).apply() }
}

/** Společný stav pro obrazovku a službu (běží ve stejném procesu). */
object VpnState {
    @Volatile var status = "Odpojeno"
    @Volatile var up = false
    @Volatile var running = false
    private val lines = ArrayDeque<String>()
    private val fmt = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)

    @Synchronized fun log(s: String) {
        lines.addLast(fmt.format(java.util.Date()) + "  " + s)
        while (lines.size > 400) lines.removeFirst()
    }
    @Synchronized fun text(): String = lines.joinToString("\n")
    @Synchronized fun clear() { lines.clear() }
}
