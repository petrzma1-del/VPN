import cz.petrzma.l2tp.core.*
import java.net.*
fun main(args: Array<String>) {
  val srv = InetAddress.getByName("10.9.0.2"); val local = InetAddress.getByName("10.9.0.1")
  val psk = if (args.isNotEmpty()) args[0] else "testpsk"
  val s = DatagramSocket(InetSocketAddress(local, 0))
  val io = object : IkeIo {
    override fun send(msg: ByteArray, float: Boolean) {
      val d = if (float) cat(ByteArray(4), msg) else msg
      s.send(DatagramPacket(d, d.size, srv, if (float) 4500 else 500))
    }
    override fun recv(timeoutMs: Int): ByteArray? {
      s.soTimeout = timeoutMs; val b = ByteArray(2048); val p = DatagramPacket(b, b.size)
      return try { s.receive(p); val r = b.copyOf(p.length); if (r.size > 4 && r.u32(0) == 0L) r.copyOfRange(4, r.size) else r } catch (e: SocketTimeoutException) { null }
    }
  }
  try {
    val k = Ike(io, psk.toByteArray(), local.address, srv.address, { println("  [log] $it") }).negotiate()
    println("USPĚCH: ${k.info}"); println("KEY_IN ${k.encKeyIn.hex()} ${k.authKeyIn.hex()}"); println("KEY_OUT ${k.encKeyOut.hex()} ${k.authKeyOut.hex()}")
  } catch (e: IkeException) { println("SELHÁNÍ: ${e.message}") }
}
