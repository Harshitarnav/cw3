import pytest
from l4lb import L4Lb
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_4, ofproto_v1_4_parser, ether
from ryu.ofproto.ofproto_v1_4_parser import OFPPacketIn, OFPMatch
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp_ip
from ryu.lib.packet import arp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.tcp import TCP_SYN
from ryu.lib.packet.tcp import TCP_FIN
from ryu.lib.packet.tcp import TCP_RST
from ryu.lib.packet.tcp import TCP_ACK
from ryu.lib.packet.udp import udp
from ryu.lib.packet.in_proto import IPPROTO_TCP
import random
from ipaddress import ip_address

class _Datapath(object):
    ofproto = ofproto_v1_4
    ofproto_parser = ofproto_v1_4_parser
    def __init__(self):
        self.id = 1
    def send_msg(self, msg):
        self.out = msg

def genports(n):
    return tuple(random.sample([i for i in range(20000, 0xffff)], n))

def genpktin(smac, dmac, sip, dip, sport, dport, dp, pi, bits=0):
    eh = ethernet(dmac, smac, ether.ETH_TYPE_IP)
    iph = ipv4(total_length=64, proto=IPPROTO_TCP, src=sip, dst=dip)
    tcph = tcp(src_port=sport, dst_port=dport, bits=bits)
    p = Packet()
    for h in (eh, iph, tcph):
        p.add_protocol(h)
    p.serialize()
    packetIn = OFPPacketIn(dp, match=OFPMatch(in_port=pi), data=p.data)
    return packetIn

def genarpin(smac, sip, dip, dp, pi):
    eh = ethernet('ff:ff:ff:ff:ff:ff', smac, ether.ETH_TYPE_ARP)
    ah = arp_ip(arp.ARP_REQUEST, smac, sip, '00:00:00:00:00:00', dip)
    p = Packet()
    for h in (eh, ah):
        p.add_protocol(h)
    p.serialize()
    packetIn = OFPPacketIn(dp, match=OFPMatch(in_port=pi), data=p.data)
    return packetIn

macs = ('00:00:00:00:00:02', '00:00:00:00:00:03')
cmac = '00:00:00:00:00:01'
cip = '10.0.0.1'
ips = ('10.0.0.2', '10.0.0.3')
vip = '10.0.0.10'
dport = 50000
ports = genports(100)

# 3WHS
def test_l4lb1():

    ctlr = L4Lb()
    dp = _Datapath()

    n1n2 = genpktin(cmac, macs[0], cip, vip, ports[0], dport, dp, 1,
            bits=TCP_SYN)
    n2n1 = genpktin(macs[0], cmac, ips[0], cip, dport, ports[0], dp, 2,
            bits=TCP_SYN | TCP_ACK)

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2))
    dip_mod = False
    dport_mod = False
    for a in dp.out.instructions[0].actions:
        d = a.to_jsondict()
        if 'OFPActionSetField' in d:
            f = d['OFPActionSetField']['field']['OXMTlv']
            if f['field'] == 'ipv4_dst':
                dip_mod = f['value'] == ips[0]
        elif 'OFPActionOutput' in d:
            f = d['OFPActionOutput']
            dport_mod = f['port'] == 2

    assert dip_mod
    assert dport_mod

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    sip_mod = False
    dport_mod = False
    for a in dp.out.instructions[0].actions:
        d = a.to_jsondict()
        if 'OFPActionSetField' in d:
            f = d['OFPActionSetField']['field']['OXMTlv']
            if f['field'] == 'ipv4_src':
                sip_mod = f['value'] == vip
        elif 'OFPActionOutput' in d:
            f = d['OFPActionOutput']
            dport_mod = f['port'] == 1

    assert sip_mod
    assert dport_mod

def test_l4lb2():

    ctlr = L4Lb()
    dp = _Datapath()

    n1n2 = genpktin(cmac, macs[0], cip, vip, ports[0], dport, dp, 1,
            bits=TCP_SYN)
    n2n1 = genpktin(macs[0], cmac, ips[0], cip, dport, ports[0], dp, 2,
            bits=TCP_SYN | TCP_ACK)

    n1n2_2 = genpktin(cmac, macs[0], cip, vip, ports[1], dport, dp, 1,
            bits=TCP_SYN)
    n2n1_2 = genpktin(macs[0], cmac, ips[1], cip, dport, ports[1], dp, 3,
            bits=TCP_SYN | TCP_ACK)

    n1n2_3 = genpktin(cmac, macs[0], cip, vip, ports[2], dport, dp, 1,
            bits=TCP_SYN)
    n2n1_3 = genpktin(macs[0], cmac, ips[0], cip, dport, ports[2], dp, 2,
            bits=TCP_SYN | TCP_ACK)

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2))
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2_2))

    dip_mod = False
    dport_mod = False
    dmac_mod = False
    for a in dp.out.instructions[0].actions:
        d = a.to_jsondict()
        if 'OFPActionSetField' in d:
            f = d['OFPActionSetField']['field']['OXMTlv']
            if f['field'] == 'ipv4_dst':
                dip_mod = f['value'] == ips[1]
            elif f['field'] == 'eth_dst':
                dmac_mod = f['value'] == macs[1]
        elif 'OFPActionOutput' in d:
            f = d['OFPActionOutput']
            dport_mod = f['port'] == 3
    assert dip_mod
    assert dport_mod
    assert dmac_mod

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1_2))
    sip_mod = False
    dport_mod = False

    for a in dp.out.instructions[0].actions:
        d = a.to_jsondict()
        if 'OFPActionSetField' in d:
            f = d['OFPActionSetField']['field']['OXMTlv']
            if f['field'] == 'ipv4_src':
                sip_mod = f['value'] == vip
        elif 'OFPActionOutput' in d:
            f = d['OFPActionOutput']
            dport_mod = f['port'] == 1
    assert sip_mod
    assert dport_mod

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2_3))

    dip_mod = False
    dport_mod = False
    for a in dp.out.instructions[0].actions:
        d = a.to_jsondict()
        if 'OFPActionSetField' in d:
            f = d['OFPActionSetField']['field']['OXMTlv']
            if f['field'] == 'ipv4_dst':
                dip_mod = f['value'] == ips[0]
        elif 'OFPActionOutput' in d:
            f = d['OFPActionOutput']
            dport_mod = f['port'] == 2
    assert dip_mod
    assert dport_mod

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1_3))

    sip_mod = False
    dport_mod = False

    for a in dp.out.instructions[0].actions:
        d = a.to_jsondict()
        if 'OFPActionSetField' in d:
            f = d['OFPActionSetField']['field']['OXMTlv']
            if f['field'] == 'ipv4_src':
                sip_mod = f['value'] == vip
        elif 'OFPActionOutput' in d:
            f = d['OFPActionOutput']
            dport_mod = f['port'] == 1
    assert sip_mod

def test_l4lb3():

    ctlr = L4Lb()
    dp = _Datapath()

    n1n2arp = genarpin(cmac, cip, vip, dp, 1)
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2arp))
    ap = arp.arp.parser(dp.out.to_jsondict()['OFPPacketOut']['data'][14:])[0]
    assert (ap.dst_ip == cip and ap.dst_mac == cmac and
            ap.src_ip == vip and ap.src_mac == macs[0])

    n2n1arp = genarpin(macs[0], ips[0], cip, dp, 2)
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1arp))
    ap = arp.arp.parser(dp.out.to_jsondict()['OFPPacketOut']['data'][14:])[0]

    assert (ap.dst_ip == ips[0] and ap.dst_mac == macs[0] and
            ap.src_ip == cip and ap.src_mac == cmac)

    n3n1arp = genarpin(macs[1], ips[1], cip, dp, 3)
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n3n1arp))
    ap = arp.arp.parser(dp.out.to_jsondict()['OFPPacketOut']['data'][14:])[0]

    assert (ap.dst_ip == ips[1] and ap.dst_mac == macs[1] and
            ap.src_ip == cip and ap.src_mac == cmac)
