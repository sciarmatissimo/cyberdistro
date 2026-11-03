"""Benign LAN background traffic (IPv6 MLD/NDP/RA, DHCP, mDNS, SSDP, LLMNR, NTP, DNS, IGMP).
Used to look for Suricata false positives: run Suricata with the Sentinel rule set on
the output and expect zero alerts."""
import sys
from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.dhcp import *
from scapy.contrib.igmpv3 import *
pk=[]; t=1700000000.0
def add(p):
    global t; t+=0.01; p.time=t; pk.append(p)
ME='52:54:00:12:34:56'; LL='fe80::5054:ff:fe12:3456'; GW='52:55:0a:00:02:02'
for i in range(20):
    # MLDv2 report, MLD v1, NDP NS/NA, RS/RA (router)
    add(Ether(src=ME,dst='33:33:00:00:00:16')/IPv6(src=LL,dst='ff02::16',hlim=1)/IPv6ExtHdrHopByHop(options=[RouterAlert()])/ICMPv6MLReport2(records=[ICMPv6MLDMultAddrRec(dst='ff02::fb')]))
    add(Ether(src=ME,dst='33:33:00:00:00:02')/IPv6(src=LL,dst='ff02::2')/ICMPv6ND_RS())
    add(Ether(src=GW,dst='33:33:00:00:00:01')/IPv6(src='fe80::2',dst='ff02::1')/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix='fec0::',prefixlen=64))
    add(Ether(src=GW,dst='33:33:00:00:00:01')/IPv6(src='fe80::2',dst='ff02::1',hlim=1)/IPv6ExtHdrHopByHop(options=[RouterAlert()])/ICMPv6MLQuery())
    add(Ether(src=ME,dst='33:33:ff:00:00:02')/IPv6(src=LL,dst='ff02::1:ff00:2')/ICMPv6ND_NS(tgt='fe80::2'))
    add(Ether(src=ME,dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=bytes.fromhex('525400123456'))/DHCP(options=[('message-type','request'),('hostname','sentinel'),'end']))
    add(Ether(src=ME,dst='01:00:5e:00:00:fb')/IP(src='10.0.2.15',dst='224.0.0.251')/UDP(sport=5353,dport=5353)/DNS(qd=DNSQR(qname='_googlecast._tcp.local',qtype='PTR')))
    add(Ether(src=ME,dst='01:00:5e:7f:ff:fa')/IP(src='10.0.2.15',dst='239.255.255.250')/UDP(sport=50000,dport=1900)/Raw(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'))
    add(Ether(src=ME,dst=GW)/IP(src='10.0.2.15',dst='162.159.200.1')/UDP(sport=123,dport=123)/NTP())
    add(Ether(src=ME,dst='01:00:5e:00:00:fc')/IP(src='10.0.2.15',dst='224.0.0.252')/UDP(sport=5355,dport=5355)/Raw(b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07printer\x00\x00\x01\x00\x01'))
    add(Ether(src=ME,dst=GW)/IP(src='10.0.2.15',dst='10.0.2.3')/UDP(sport=40000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname='deb.debian.org')))
    add(Ether(src=ME,dst='01:00:5e:00:00:16')/IP(src='10.0.2.15',dst='224.0.0.22',ttl=1,options=[IPOption_Router_Alert()])/IGMPv3()/IGMPv3mr(records=[IGMPv3gr(maddr='224.0.0.251')]))
wrpcap('sys.argv[1] if len(sys.argv) > 1 else 'benign.pcap'',pk); print(len(pk))
