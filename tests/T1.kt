import cz.petrzma.l2tp.core.*
fun check(name:String, got:String, exp:String){ println((if(got.equals(exp,true)) "OK   " else "CHYBA")+" $name"+(if(got.equals(exp,true)) "" else "\n   got=$got\n   exp=$exp")) }
fun main(){
  check("MD4('')", Md4.hash(ByteArray(0)).hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
  check("MD4('abc')", Md4.hash("abc".toByteArray()).hex(), "a448017aaf21d8525fc10ae87aa6729d")
  check("MD4(message digest)", Md4.hash("message digest".toByteArray()).hex(), "d9130a8164549fe818874806e1c7014b")
  check("MD4(80 znaků)", Md4.hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890".toByteArray()).hex(), "e33b4ddc9c38f2199c3e7b164fcc0536")
  // RFC 2759 příloha 9.2
  val authCh = hexToBytes("5B5D7C7D7B3F2F3E3C2C602132262628")
  val peerCh = hexToBytes("21402324255E262A28295F2B3A337C7E")
  check("NT hash", MsChapV2.ntPasswordHash("clientPass").hex(), "44ebba8d5312b8d611474411f56989ae")
  check("ChallengeHash", MsChapV2.challengeHash(peerCh, authCh, "User").hex(), "d02e4386bce91226")
  val nt = MsChapV2.ntResponse(authCh, peerCh, "User", "clientPass")
  check("NT-Response", nt.hex(), "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")
  check("Authenticator", MsChapV2.authenticatorResponse("clientPass", nt, peerCh, authCh, "User"), "S=407A5589115FD0D6209F510FE9C04566932CDA56")
  // DH
  for (g in listOf(2,5,14)) { val d = DhGroup.byId(g)!!; val a = d.generate(); val b = d.generate()
    check("DH skupina $g", d.shared(a.priv, b.pub).hex(), d.shared(b.priv, a.pub).hex()) }
  // ESP round trip
  val ek=rnd(32); val ak=rnd(20); val k = IpsecKeys(0x1234, 0x1234, true, ek, ek, "HmacSHA1", 12, ak, ak, "")
  val e = Esp(k); val data = rnd(77); val p = e.encap(data, 17); val d = e.decap(p)
  check("ESP round-trip", if (d != null && d.first.contentEquals(data) && d.second == 17) "ok" else "bad", "ok")
  check("ESP replay", if (e.decap(p) == null) "ok" else "bad", "ok")
  val bad = p.copyOf(); bad[20] = (bad[20].toInt() xor 1).toByte()
  check("ESP poškozený paket", if (Esp(k).decap(bad) == null) "ok" else "bad", "ok")
}
