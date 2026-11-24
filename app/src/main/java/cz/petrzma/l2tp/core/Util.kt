package cz.petrzma.l2tp.core

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal val RNG = SecureRandom()

/** Jednoduchý skladač bajtů (big-endian). */
class Bb {
    private val o = ByteArrayOutputStream()
    fun u8(v: Int) = apply { o.write(v and 0xFF) }
    fun u16(v: Int) = apply { o.write((v shr 8) and 0xFF); o.write(v and 0xFF) }
    fun u32(v: Long) = apply { u16(((v shr 16) and 0xFFFF).toInt()); u16((v and 0xFFFF).toInt()) }
    fun bytes(b: ByteArray) = apply { o.write(b, 0, b.size) }
    fun toByteArray(): ByteArray = o.toByteArray()
    val size: Int get() = o.size()
}

fun ByteArray.u8(i: Int): Int = this[i].toInt() and 0xFF
fun ByteArray.u16(i: Int): Int = (u8(i) shl 8) or u8(i + 1)
fun ByteArray.u32(i: Int): Long = (u16(i).toLong() shl 16) or u16(i + 2).toLong()
fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
fun hexToBytes(s: String): ByteArray {
    val t = s.replace(" ", "")
    return ByteArray(t.length / 2) { t.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
fun cat(vararg parts: ByteArray): ByteArray {
    val o = ByteArrayOutputStream()
    for (p in parts) o.write(p, 0, p.size)
    return o.toByteArray()
}
fun rnd(n: Int): ByteArray = ByteArray(n).also { RNG.nextBytes(it) }
fun ipBytes(a: java.net.InetAddress): ByteArray = a.address
fun ipStr(b: ByteArray, off: Int = 0): String = "${b.u8(off)}.${b.u8(off + 1)}.${b.u8(off + 2)}.${b.u8(off + 3)}"
fun sameBytes(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)   // konstantní čas

/** HMAC: alg = "HmacSHA1" | "HmacMD5" | "HmacSHA256" */
fun hmac(alg: String, key: ByteArray, vararg data: ByteArray): ByteArray {
    val m = Mac.getInstance(alg)
    m.init(SecretKeySpec(if (key.isEmpty()) ByteArray(1) else key, alg))   // prázdný klíč Java neumí
    for (d in data) m.update(d)
    return m.doFinal()
}

fun digest(alg: String, vararg data: ByteArray): ByteArray {
    val m = MessageDigest.getInstance(alg)
    for (d in data) m.update(d)
    return m.digest()
}

/** CBC bez paddingu (padding řeší volající). enc: 12 = AES, 3 = 3DES */
object Cbc {
    fun blockSize(aes: Boolean) = if (aes) 16 else 8
    private fun mk(aes: Boolean, mode: Int, key: ByteArray, iv: ByteArray): Cipher {
        val c = if (aes) Cipher.getInstance("AES/CBC/NoPadding") else Cipher.getInstance("DESede/CBC/NoPadding")
        c.init(mode, SecretKeySpec(key, if (aes) "AES" else "DESede"), IvParameterSpec(iv))
        return c
    }
    fun encrypt(aes: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray = mk(aes, Cipher.ENCRYPT_MODE, key, iv).doFinal(data)
    fun decrypt(aes: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray = mk(aes, Cipher.DECRYPT_MODE, key, iv).doFinal(data)
}

/** MD4 (Android ho v MessageDigest nemá spolehlivě). */
object Md4 {
    private fun rol(x: Int, s: Int) = (x shl s) or (x ushr (32 - s))
    fun hash(msg: ByteArray): ByteArray {
        val len = msg.size
        val padLen = ((55 - len) % 64 + 64) % 64 + 1
        val total = len + padLen + 8
        val m = ByteArray(total)
        System.arraycopy(msg, 0, m, 0, len)
        m[len] = 0x80.toByte()
        val bits = len.toLong() * 8
        for (i in 0 until 8) m[total - 8 + i] = ((bits ushr (8 * i)) and 0xFF).toByte()
        var a = 0x67452301; var b = 0xefcdab89.toInt(); var c = 0x98badcfe.toInt(); var d = 0x10325476
        val x = IntArray(16)
        var off = 0
        while (off < total) {
            for (i in 0 until 16) {
                x[i] = (m[off + i * 4].toInt() and 0xFF) or ((m[off + i * 4 + 1].toInt() and 0xFF) shl 8) or
                        ((m[off + i * 4 + 2].toInt() and 0xFF) shl 16) or ((m[off + i * 4 + 3].toInt() and 0xFF) shl 24)
            }
            val aa = a; val bb = b; val cc = c; val dd = d
            fun f(x_: Int, y: Int, z: Int) = (x_ and y) or (x_.inv() and z)
            fun g(x_: Int, y: Int, z: Int) = (x_ and y) or (x_ and z) or (y and z)
            fun h(x_: Int, y: Int, z: Int) = x_ xor y xor z
            val s1 = intArrayOf(3, 7, 11, 19)
            for (i in 0 until 16) {
                val t = rol(a + f(b, c, d) + x[i], s1[i % 4]); a = d; d = c; c = b; b = t
            }
            val s2 = intArrayOf(3, 5, 9, 13)
            val o2 = intArrayOf(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
            for (i in 0 until 16) {
                val t = rol(a + g(b, c, d) + x[o2[i]] + 0x5a827999, s2[i % 4]); a = d; d = c; c = b; b = t
            }
            val s3 = intArrayOf(3, 9, 11, 15)
            val o3 = intArrayOf(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
            for (i in 0 until 16) {
                val t = rol(a + h(b, c, d) + x[o3[i]] + 0x6ed9eba1, s3[i % 4]); a = d; d = c; c = b; b = t
            }
            a += aa; b += bb; c += cc; d += dd
            off += 64
        }
        val out = ByteArray(16)
        val r = intArrayOf(a, b, c, d)
        for (i in 0 until 4) for (j in 0 until 4) out[i * 4 + j] = ((r[i] ushr (8 * j)) and 0xFF).toByte()
        return out
    }
}

/** MS-CHAPv2 podle RFC 2759. */
object MsChapV2 {
    private val MAGIC1 = "Magic server to client signing constant".toByteArray(Charsets.US_ASCII)
    private val MAGIC2 = "Pad to make it do more than one iteration".toByteArray(Charsets.US_ASCII)

    fun ntPasswordHash(password: String): ByteArray = Md4.hash(password.toByteArray(Charsets.UTF_16LE))

    fun challengeHash(peerChallenge: ByteArray, authChallenge: ByteArray, userName: String): ByteArray =
        digest("SHA-1", peerChallenge, authChallenge, userName.toByteArray(Charsets.UTF_8)).copyOf(8)

    private fun desKey(k7: ByteArray): ByteArray {
        val k = ByteArray(8)
        k[0] = (k7.u8(0) and 0xFE).toByte()
        k[1] = (((k7.u8(0) shl 7) or (k7.u8(1) ushr 1)) and 0xFE).toByte()
        k[2] = (((k7.u8(1) shl 6) or (k7.u8(2) ushr 2)) and 0xFE).toByte()
        k[3] = (((k7.u8(2) shl 5) or (k7.u8(3) ushr 3)) and 0xFE).toByte()
        k[4] = (((k7.u8(3) shl 4) or (k7.u8(4) ushr 4)) and 0xFE).toByte()
        k[5] = (((k7.u8(4) shl 3) or (k7.u8(5) ushr 5)) and 0xFE).toByte()
        k[6] = (((k7.u8(5) shl 2) or (k7.u8(6) ushr 6)) and 0xFE).toByte()
        k[7] = ((k7.u8(6) shl 1) and 0xFE).toByte()
        for (i in 0 until 8) {                      // lichá parita
            val v = k[i].toInt() and 0xFE
            k[i] = (if (Integer.bitCount(v) % 2 == 0) v or 1 else v).toByte()
        }
        return k
    }

    fun challengeResponse(challenge8: ByteArray, passwordHash: ByteArray): ByteArray {
        val z = passwordHash.copyOf(21)
        val out = Bb()
        for (i in 0 until 3) {
            val c = Cipher.getInstance("DES/ECB/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(desKey(z.copyOfRange(i * 7, i * 7 + 7)), "DES"))
            out.bytes(c.doFinal(challenge8))
        }
        return out.toByteArray()
    }

    fun ntResponse(authChallenge: ByteArray, peerChallenge: ByteArray, userName: String, password: String): ByteArray =
        challengeResponse(challengeHash(peerChallenge, authChallenge, userName), ntPasswordHash(password))

    /** "S=…" – odpověď serveru, kterou ověřujeme, že zná heslo i on. */
    fun authenticatorResponse(password: String, ntResp: ByteArray, peerChallenge: ByteArray, authChallenge: ByteArray, userName: String): String {
        val pwHashHash = Md4.hash(ntPasswordHash(password))
        val d1 = digest("SHA-1", pwHashHash, ntResp, MAGIC1)
        val ch = challengeHash(peerChallenge, authChallenge, userName)
        val d2 = digest("SHA-1", d1, ch, MAGIC2)
        return "S=" + d2.hex().uppercase()
    }
}
