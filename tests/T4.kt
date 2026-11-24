import cz.petrzma.l2tp.core.*
import java.net.*
fun main(args: Array<String>) {
  val srv = InetAddress.getByName(args.getOrElse(0) { "10.9.0.2" }); val port = args.getOrElse(1) { "1701" }.toInt()
  val s = DatagramSocket(InetSocketAddress(InetAddress.getByName(args.getOrElse(4) { "10.9.0.1" }), 0))
  var done = false; var result = "?"
  val t0 = System.currentTimeMillis()
  fun lg(x: String) = println("  [%5d ms] %s".format(System.currentTimeMillis() - t0, x))
  lateinit var ppp: Ppp
  val l2 = L2tp(out = { m -> s.send(DatagramPacket(m, m.size, srv, port)) }, log = ::lg,
    onPppFrame = { f -> ppp.onFrame(f) }, onEstablished = { ppp.start() }, onClosed = { w -> result = "ZAVŘENO: $w"; done = true })
  ppp = Ppp(args.getOrElse(2) { "tester" }, args.getOrElse(3) { "testpass" }, send = { f -> l2.sendData(f) }, log = ::lg,
    onIpUp = { ip, dns -> result = "IP NAHORU ${ipStr(ip)} DNS ${dns.map { ipStr(it) }}"; done = true }, onIp = { }, onFail = { w -> result = "PPP SELHÁNÍ: $w"; done = true })
  l2.start()
  val buf = ByteArray(4096)
  while (!done && System.currentTimeMillis() - t0 < 20000) {
    s.soTimeout = 300
    try { val p = DatagramPacket(buf, buf.size); s.receive(p); l2.onRx(buf.copyOf(p.length)) } catch (e: SocketTimeoutException) { }
    l2.tick(); ppp.tick()
  }
  println("VÝSLEDEK: $result")
  ppp.terminate(); l2.close()
}
