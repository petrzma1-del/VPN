package cz.petrzma.l2tp.core

import java.math.BigInteger

/** Diffie-Hellman skupiny pro IKE (RFC 2409 a RFC 3526). Generátor je vždy 2. */
class DhGroup(val id: Int, private val primeHex: String) {
    val p: BigInteger = BigInteger(primeHex, 16)
    val len: Int = (p.bitLength() + 7) / 8
    private val g = BigInteger.valueOf(2)

    class Pair(val priv: BigInteger, val pub: ByteArray)

    fun generate(): Pair {
        var x: BigInteger
        do { x = BigInteger(p.bitLength() - 1, RNG) } while (x.bitLength() < 128)
        return Pair(x, fixed(g.modPow(x, p)))
    }

    fun shared(priv: BigInteger, peerPub: ByteArray): ByteArray {
        val y = BigInteger(1, peerPub)
        require(y > BigInteger.ONE && y < p.subtract(BigInteger.ONE)) { "neplatná veřejná hodnota DH" }
        return fixed(y.modPow(priv, p))
    }

    private fun fixed(v: BigInteger): ByteArray {
        val raw = v.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        return ByteArray(len - raw.size) + raw
    }

    companion object {
        fun byId(id: Int): DhGroup? = when (id) { 2 -> G2; 5 -> G5; 14 -> G14; else -> null }
        private val G2 = DhGroup(2,
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF" +
        "")
        private val G5 = DhGroup(5,
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF" +
        "")
        private val G14 = DhGroup(14,
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF" +
        "")
    }
}
