import cz.petrzma.l2tp.core.*
fun main(args: Array<String>) {
  val aes = args[0] == "1"; val hm = args[1]; val ek = hexToBytes(args[2]); val ak = hexToBytes(args[3]); val spi = args[4].toLong(16).toInt()
  val icv = if (hm == "HmacSHA256") 16 else 12
  val esp = Esp(IpsecKeys(spi, spi, aes, ek, ek, hm, icv, ak, ak, ""))
  while (true) {
    val line = readLine() ?: break
    val (m, h) = line.split(" ")
    if (m == "E") println(esp.encap(hexToBytes(h), 17).hex())
    else { val r = esp.decap(hexToBytes(h)); println(if (r == null) "NULL" else r.second.toString() + ":" + r.first.hex()) }
  }
}
