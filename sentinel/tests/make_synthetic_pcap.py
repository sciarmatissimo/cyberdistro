import random, string
from scapy.all import *
random.seed(1); pk=[]; t=1_700_000_000.0
GW='192.168.1.1'; GWMAC='aa:aa:aa:00:00:01'; ME='192.168.1.10'; MEMAC='bb:bb:bb:00:00:10'
ATK='192.168.1.57'; ATKMAC='dc:a6:32:00:00:57'
def add(p):
    global t; t+=0.002; p.time=t; pk.append(p)
def tcp_sess(src,smac,dst,dmac,sport,dport,payload_c=b'',payload_s=b''):
    s=random.randint(1,2**31); d=random.randint(1,2**31)
    E=lambda a,b: Ether(src=a,dst=b)
    add(E(smac,dmac)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='S',seq=s))
    add(E(dmac,smac)/IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags='SA',seq=d,ack=s+1))
    add(E(smac,dmac)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='A',seq=s+1,ack=d+1))
    if payload_s: add(E(dmac,smac)/IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags='PA',seq=d+1,ack=s+1)/payload_s); d+=len(payload_s)
    if payload_c: add(E(smac,dmac)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='PA',seq=s+1,ack=d+1)/payload_c); s+=len(payload_c)
    add(E(smac,dmac)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='FA',seq=s+1,ack=d+1))
    add(E(dmac,smac)/IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags='FA',seq=d+1,ack=s+2))
# normal background: DNS + HTTP to many hosts
for i in range(3000):
    dom=random.choice(['example.com','debian.org','wikipedia.org','repubblica.it','github.com'])
    add(Ether(src=MEMAC,dst=GWMAC)/IP(src=ME,dst=GW)/UDP(sport=random.randint(1025,65000),dport=53)/DNS(rd=1,qd=DNSQR(qname=dom)))
    tcp_sess(ME,MEMAC,'93.184.%d.%d'%(i%250,i%200+1),GWMAC,random.randint(1025,65000),80,payload_c=b'GET / HTTP/1.1\r\nHost: '+dom.encode()+b'\r\nUser-Agent: Mozilla/5.0\r\n\r\n',payload_s=b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
# 1 port scan: SYN to 1000 ports, RST replies
for p in range(1,1001):
    add(Ether(src=ATKMAC,dst=MEMAC)/IP(src=ATK,dst=ME)/TCP(sport=40000,dport=p,flags='S'))
    add(Ether(src=MEMAC,dst=ATKMAC)/IP(src=ME,dst=ATK)/TCP(sport=p,dport=40000,flags='RA'))
# 2 SSH brute force: 60 sessions
for i in range(60):
    tcp_sess(ATK,ATKMAC,ME,MEMAC,41000+i,22,payload_c=b'SSH-2.0-libssh_0.9.6\r\n',payload_s=b'SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n')
# 3 DGA-like DNS
for i in range(200):
    q=''.join(random.choice(string.ascii_lowercase) for _ in range(18))+'.xyz'
    add(Ether(src=MEMAC,dst=GWMAC)/IP(src=ME,dst=GW)/UDP(sport=50000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=q)))
    add(Ether(src=GWMAC,dst=MEMAC)/IP(src=GW,dst=ME)/UDP(sport=53,dport=50000+i)/DNS(id=0,qr=1,rcode=3,qd=DNSQR(qname=q)))
# 4 DNS tunnel-like long labels TXT
for i in range(100):
    q=''.join(random.choice('abcdef0123456789') for _ in range(60))+'.t.evil-tunnel.net'
    add(Ether(src=MEMAC,dst=GWMAC)/IP(src=ME,dst=GW)/UDP(sport=52000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=q,qtype='TXT')))
# 5 ARP spoof: attacker claims gateway IP
for i in range(20):
    add(Ether(src=ATKMAC,dst='ff:ff:ff:ff:ff:ff')/ARP(op=2,psrc=GW,hwsrc=ATKMAC,pdst=ME,hwdst=MEMAC))
# 6 beacon: same host every 60s, curl UA
for i in range(30):
    t+=60; tcp_sess(ME,MEMAC,'185.220.10.10',GWMAC,45000+i,8080,payload_c=b'GET /gate.php?id=4f2a HTTP/1.1\r\nHost: 185.220.10.10:8080\r\nUser-Agent: curl/7.88\r\n\r\n')
wrpcap('/root/lab/test.pcap',pk); print(len(pk),'packets')
