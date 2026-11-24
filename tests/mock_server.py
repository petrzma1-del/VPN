#!/usr/bin/env python3
"""Nezávislý testovací server: ESP v UDP -> L2TP (LNS) -> PPP (LCP, MS-CHAPv2, IPCP, CCP) -> ICMP echo."""
import socket, struct, os, sys, hmac, hashlib, time, threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Hash import MD4
from Crypto.Cipher import DES

PORT=int(sys.argv[1]); USER=sys.argv[2]; PASSW=sys.argv[3]
SPI_C, SPI_S = 0xAAAA0001, 0xBBBB0002          # SPI, které používá klient pro vysílání / příjem
K_C2S=bytes(range(32)); K_S2C=bytes(range(100,132)); A_C2S=bytes(range(20)); A_S2C=bytes(range(50,70))
seq=0

def esp_enc(payload, nh=17):
    global seq
    seq+=1; iv=os.urandom(16)
    pl=(16-(len(payload)+2)%16)%16
    data=payload+bytes(range(1,pl+1))+bytes([pl,nh])
    e=Cipher(algorithms.AES(K_S2C),modes.CBC(iv)).encryptor(); ct=e.update(data)+e.finalize()
    body=struct.pack('>II',SPI_C,seq)+iv+ct          # klient přijímá na SPI_C
    return body+hmac.new(A_S2C,body,hashlib.sha1).digest()[:12]
def esp_dec(p):
    if len(p)<8+16+16+12: return None
    spi,sn=struct.unpack('>II',p[:8])
    if spi!=SPI_S: return None
    if not hmac.compare_digest(hmac.new(A_C2S,p[:-12],hashlib.sha1).digest()[:12],p[-12:]): print('MOCK: špatné ICV'); return None
    iv=p[8:24]; d=Cipher(algorithms.AES(K_C2S),modes.CBC(iv)).decryptor(); pt=d.update(p[24:-12])+d.finalize()
    return pt[:len(pt)-2-pt[-2]], pt[-1]

# --- MS-CHAPv2 nezávisle (pycryptodome)
def nthash(pw): return MD4.new(pw.encode('utf-16-le')).digest()
def desk(k7):
    b=int.from_bytes(k7,'big'); out=bytearray()
    for i in range(8):
        v=(b>>(49-7*i))&0x7f; v<<=1
        out.append(v|(0 if bin(v).count('1')%2 else 1))
    return bytes(out)
def chresp(ch,h):
    h=h+b'\0'*(21-len(h)); return b''.join(DES.new(desk(h[i*7:i*7+7]),DES.MODE_ECB).encrypt(ch) for i in range(3))
def ntresp(auth,peer,user,pw):
    c=hashlib.sha1(peer+auth+user.encode()).digest()[:8]; return chresp(c,nthash(pw))
def authresp(pw,nt,peer,auth,user):
    M1=b"Magic server to client signing constant"; M2=b"Pad to make it do more than one iteration"
    d1=hashlib.sha1(MD4.new(nthash(pw)).digest()+nt+M1).digest()
    c=hashlib.sha1(peer+auth+user.encode()).digest()[:8]
    return 'S='+hashlib.sha1(d1+c+M2).hexdigest().upper()

sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind(('127.0.0.1',PORT)); sock.settimeout(0.3)
peer=None
# --- L2TP
my_tid=777; my_sid=888; c_tid=0; c_sid=0; ns=0; nr=0
def l2out(inner): sock.sendto(esp_enc(struct.pack('>HHHH',1701,1701,8+len(inner),0)+inner),peer)
def avp(t,v,m=True): return struct.pack('>HHH',(0x8000 if m else 0)|(6+len(v)),0,t)+v
def ctl(avps,sid):
    global ns
    m=struct.pack('>HHHHHH',0xC802,12+len(avps),c_tid,sid,ns,nr)+avps; ns=(ns+1)&0xFFFF; l2out(m)
def zlb(): l2out(struct.pack('>HHHHHH',0xC802,12,c_tid,0,ns,nr))
def l2data(ppp): l2out(struct.pack('>HHHH',0x4002,8+len(ppp),c_tid,c_sid)+ppp)
# --- PPP
state={'lcp_ack_ours':False,'lcp_ack_theirs':False,'chap':False,'ipcp_ack_ours':False,'ipcp_ack_theirs':False,'ccp_rej':False,'echo':False,'ping':0,'ip_assigned':None}
def pppf(proto,code,i,data=b''): l2data(b'\xff\x03'+struct.pack('>H',proto)+struct.pack('>BBH',code,i,4+len(data))+data)
MAGIC=os.urandom(4); CH=os.urandom(16)
def lcp_req(): pppf(0xC021,1,1,b'\x01\x04'+struct.pack('>H',1280)+b'\x03\x05\xc2\x23\x81'+b'\x05\x06'+MAGIC)
def opts(d):
    r=[];o=0
    while o<len(d): r.append((d[o],d[o+2:o+d[o+1]])); o+=d[o+1]
    return r
def on_ppp(f):
    i=2 if f[:2]==b'\xff\x03' else 0
    proto=struct.unpack('>H',f[i:i+2])[0]; d=f[i+2:]
    if proto==0x0021:
        if d[9]==1 and d[20]==8:                         # ICMP echo request -> odpověď
            r=bytearray(d); r[12:16],r[16:20]=d[16:20],d[12:16]; r[20]=0; r[22:24]=b'\0\0'
            r[10:12]=b'\0\0'; hs=sum(struct.unpack('>10H',bytes(r[:20]))); hs=(hs&0xffff)+(hs>>16); hs=(hs&0xffff)+(hs>>16); r[10:12]=struct.pack('>H',~hs&0xffff)
            cs=sum(struct.unpack('>%dH'%((len(r)-20+1)//2),bytes(r[20:])+(b'\0' if (len(r)-20)%2 else b''))); cs=(cs&0xffff)+(cs>>16); cs=(cs&0xffff)+(cs>>16); r[22:24]=struct.pack('>H',~cs&0xffff)
            l2data(b'\xff\x03\x00\x21'+bytes(r)); state['ping']+=1; print('MOCK: ping #%d zodpovězen'%state['ping'],flush=True)
        return
    code,idn,ln=struct.unpack('>BBH',d[:4]); body=d[4:ln]
    if proto==0xC021:
        if code==1:
            pppf(0xC021,2,idn,body); state['lcp_ack_theirs']=True; print('MOCK: LCP req klienta přijat, opts',[o[0] for o in opts(body)],flush=True)
        elif code==2: state['lcp_ack_ours']=True
        elif code==10: state['echo']=True; print('MOCK: Echo-Reply od klienta',flush=True)
        elif code==5: print('MOCK: klient poslal Terminate',flush=True); pppf(0xC021,6,idn)
        if state['lcp_ack_ours'] and state['lcp_ack_theirs'] and not state['chap']:
            state['chap']=True; pppf(0xC223,1,1,bytes([16])+CH+b'lns')
    elif proto==0xC223:
        if code==2:
            vs=body[0]; v=body[1:1+vs]; name=body[1+vs:].decode()
            peerc,nt=v[:16],v[24:48]
            ok=(name==USER and nt==ntresp(CH,peerc,name,PASSW))
            print('MOCK: CHAP odpověď od "%s": %s'%(name,'OK' if ok else 'ŠPATNĚ'),flush=True)
            if ok:
                pppf(0xC223,3,idn,(authresp(PASSW,nt,peerc,CH,name)+' M=ok').encode())
                pppf(0x8021,1,1,b'\x03\x06'+bytes([10,99,0,1]))                     # IPCP: naše adresa
                pppf(0x80FD,1,1,b'\x12\x06\x00\x00\x00\x01')                         # CCP s MPPE – klient má odmítnout
                pppf(0xC021,9,7,MAGIC+b'ping')                                       # LCP echo
            else: pppf(0xC223,4,idn,b'E=691 R=0 V=3')
    elif proto==0x8021:
        if code==1:
            o=dict(opts(body))
            if o.get(3)==b'\0\0\0\0' :
                pppf(0x8021,3,idn,b'\x03\x06'+bytes([10,99,0,10])+b'\x81\x06'+bytes([10,99,0,1])+b'\x83\x06'+bytes([8,8,8,8]))
            else:
                pppf(0x8021,2,idn,body); state['ip_assigned']=o.get(3); state['ipcp_ack_theirs']=True; print('MOCK: IPCP schváleno, IP',o.get(3).hex(),flush=True)
        elif code==2: state['ipcp_ack_ours']=True
    elif proto==0x80FD:
        if code==4: state['ccp_rej']=True; print('MOCK: CCP odmítnuto klientem ✔',flush=True)
        elif code==2: print('MOCK: CCP přijato?! (nemělo by)',flush=True)

def on_l2(m):
    global peer,c_tid,c_sid,nr
    fl=struct.unpack('>H',m[:2])[0]
    if fl&0x8000:
        ln,tid,sid,sn,rn=struct.unpack('>HHHHH',m[2:12]); av=m[12:ln]
        if ln==12: return
        if sn!=nr: zlb(); return
        nr=(nr+1)&0xFFFF
        a={};o=0
        while o<len(av):
            l=struct.unpack('>H',av[o:o+2])[0]&0x3ff; a[struct.unpack('>H',av[o+4:o+6])[0]]=av[o+6:o+l]; o+=l
        t=struct.unpack('>H',a[0])[0]
        if t==1:
            c_tid=struct.unpack('>H',a[9])[0]; print('MOCK: SCCRQ, host',a.get(7),flush=True)
            ctl(avp(0,b'\0\2')+avp(2,b'\1\0')+avp(3,struct.pack('>I',3))+avp(7,b'lns')+avp(9,struct.pack('>H',my_tid)),0)
        elif t==3: print('MOCK: SCCCN',flush=True); 
        elif t==10:
            c_sid=struct.unpack('>H',a[14])[0]; print('MOCK: ICRQ',flush=True)
            ctl(avp(0,b'\0\x0b')+avp(14,struct.pack('>H',my_sid)),c_sid)
        elif t==12:
            print('MOCK: ICCN, PPP start',flush=True); zlb(); lcp_req()
        elif t in (4,14): print('MOCK: klient ukončuje (%d)'%t,flush=True)
        if t not in (1,10,12): zlb()
    else:
        pos=2; end=len(m)
        if fl&0x4000: end=struct.unpack('>H',m[2:4])[0]; pos+=2
        pos+=4
        if fl&0x800: pos+=4
        on_ppp(m[pos:end])
t0=time.time()
print('MOCK: poslouchám na',PORT,flush=True)
last_echo=0
while time.time()-t0<int(sys.argv[4]) if len(sys.argv)>4 else 40:
    try: p,a=sock.recvfrom(4096)
    except socket.timeout: continue
    peer=a
    if len(p)==1: continue
    r=esp_dec(p)
    if r is None: continue
    inner,nh=r
    if nh!=17: continue
    on_l2(inner[8:])
print('MOCK stav:',state,flush=True)
