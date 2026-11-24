import cz.petrzma.l2tp.core.*
import java.net.DatagramSocket
fun icmpEcho(src: IntArray, dst: IntArray): ByteArray {
  val b = ByteArray(28)
  b[0] = 0x45; b[2] = 0; b[3] = 28; b[8] = 64; b[9] = 1
  for (i in 0..3) { b[12 + i] = src[i].toByte(); b[16 + i] = dst[i].toByte() }
  b[20] = 8; b[24] = 0x12; b[25] = 0x34; b[26] = 0; b[27] = 1
  fun cs(from: Int, to: Int): Int { var s = 0; var i = from; while (i < to) { s += ((b[i].toInt() and 255) shl 8) or (b[i + 1].toInt() and 255); i += 2 }; while (s shr 16 != 0) s = (s and 0xffff) + (s shr 16); return s.inv() and 0xffff }
  val hc = cs(0, 20); b[10] = (hc shr 8).toByte(); b[11] = hc.toByte()
  val ic = cs(20, 28); b[22] = (ic shr 8).toByte(); b[23] = ic.toByte()
  return b
}
fun main(args: Array<String>) {
  val port = args[0].toInt(); val user = args[1]; val pass = args[2]
  val k = IpsecKeys(0xAAAA0001.toInt(), 0xBBBB0002.toInt(), true, ByteArray(32) { (100 + it).toByte() }, ByteArray(32) { it.toByte() },
      "HmacSHA1", 12, ByteArray(20) { (50 + it).toByte() }, ByteArray(20) { it.toByte() }, "test")
  var up: String? = null; var down: String? = null; var replies = 0
  lateinit var c: VpnClient
  val host = object : VpnHost {
    override fun log(msg: String) = println("  [klient] $msg")
    override fun protect(s: DatagramSocket) {}
    override fun onUp(ip: ByteArray, dns: List<ByteArray>) { up = "IP=${ipStr(ip)} DNS=${dns.map { ipStr(it) }}"
      Thread { Thread.sleep(300); repeat(3) { c.sendIp(icmpEcho(intArrayOf(ip.u8(0), ip.u8(1), ip.u8(2), ip.u8(3)), intArrayOf(10, 99, 0, 1))); Thread.sleep(200) } }.start() }
    override fun onIp(packet: ByteArray) { if (packet.size >= 21 && packet.u8(9) == 1 && packet.u8(20) == 0) replies++ }
    override fun onDown(reason: String) { down = reason }
  }
  c = VpnClient(VpnConfig("127.0.0.1", "psk", user, pass, ikePort = port, natPort = port), host) { _, _, _ -> k }
  c.start()
  val t0 = System.currentTimeMillis()
  while (System.currentTimeMillis() - t0 < 6000 && down == null) Thread.sleep(100)
  println("VÝSLEDEK: up=$up, ping odpovědí=$replies, down=$down")
  val t1 = System.currentTimeMillis(); c.stop(); while (down == null && System.currentTimeMillis() - t1 < 3000) Thread.sleep(50)
  println("po stop: down=$down")
}
