import subprocess, os, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, UDP, Raw, ESP
from scapy.layers.ipsec import SecurityAssociation
KL='/tmp/claude-0/kt/kotlinc/lib'
CP="/tmp/claude-0/vpn/build/core.jar:/tmp/claude-0/vpn/build/t2.jar:%s/kotlin-stdlib.jar"%KL
def run(aes,hm,ek,ak,spi):
    return subprocess.Popen(['java','-cp',CP,'T2Kt','1' if aes else '0',hm,ek.hex(),ak.hex(),'%08x'%spi],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env={**os.environ,'JAVA_TOOL_OPTIONS':''})
def ask(p,line):
    p.stdin.write(line+"\n"); p.stdin.flush(); return p.stdout.readline().strip()
cases=[('AES-CBC',16,'HmacSHA1','HMAC-SHA1-96',20,True),('AES-CBC',32,'HmacSHA1','HMAC-SHA1-96',20,True),('3DES',24,'HmacMD5','HMAC-MD5-96',16,False),('AES-CBC',16,'HmacSHA256','SHA2-256-128',32,True)]
src,dst='10.9.0.1','10.9.0.2'
ok=True
for crypt,kl,hm,sc_auth,al,aes in cases:
    ek=os.urandom(kl); ak=os.urandom(al); spi=0x11223344
    p=run(aes,hm,ek,ak,spi)
    sa=SecurityAssociation(ESP,spi=spi,crypt_algo=crypt,crypt_key=ek,auth_algo=sc_auth,auth_key=ak)
    for n in (1,20,61,100):
        inner=bytes(UDP(sport=1701,dport=1701)/Raw(os.urandom(n)))
        # scapy -> kotlin
        enc=sa.encrypt(IP(src=src,dst=dst)/Raw(inner) if False else IP(src=src,dst=dst)/UDP(sport=1701,dport=1701)/Raw(inner[8:]))
        espb=bytes(enc)[20:]
        r=ask(p,'D '+espb.hex()); exp='17:'+inner.hex()
        parts=r.split(':'); got=bytes.fromhex(parts[1]) if parts[0]=='17' else b''; good=(len(got)==len(inner) and got[:4]==inner[:4] and got[8:]==inner[8:])
        # kotlin -> scapy
        k=ask(p,'E '+inner.hex()); kb=bytes.fromhex(k)
        pk=IP(bytes(IP(src=src,dst=dst,proto=50)/Raw(kb)))
        try:
            dec=sa.decrypt(pk); out=bytes(dec)[20:]
            good2=(out==inner)
        except Exception as e:
            good2=False; out=str(e).encode()
        print(crypt,kl*8,hm,'payload',n,'scapy→kotlin',good,'kotlin→scapy',good2)
        ok&=good and good2
    p.stdin.close(); p.wait()
print('VŠE OK' if ok else 'CHYBA')
