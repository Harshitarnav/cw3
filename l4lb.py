from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.tcp import TCP_SYN
from ryu.lib.packet.tcp import TCP_FIN
from ryu.lib.packet.tcp import TCP_RST
from ryu.lib.packet.tcp import TCP_ACK
from ryu.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP

class L4Lb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Lb, self).__init__(*args, **kwargs)
        self.ht = {} # {(<sip><vip><sport><dport>): out_port, ...}
        self.vip = '10.0.0.10'
        self.dips = ('10.0.0.2', '10.0.0.3')
        self.dmacs = ('00:00:00:00:00:02', '00:00:00:00:00:03')
        #
        self.flag = 0
        # write your code here, if needed
        #

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        return out

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        #
        # write your code here, if needed
        #
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)

        arph = pkt.get_protocols(arp.arp)
        
        if arph:
            if arph[0].opcode == arp.ARP_REQUEST:
                if in_port == 1:
                    eh = ethernet.ethernet(dst="00:00:00:00:00:01", src="00:00:00:00:00:02", ethertype=ETH_TYPE_ARP)
                    ah = arp.arp(opcode=arp.ARP_REPLY, src_mac="00:00:00:00:00:02", src_ip="10.0.0.10",
                                dst_mac='00:00:00:00:00:01', dst_ip="10.0.0.1")
                    p = packet.Packet()
                    p.add_protocol(eh)
                    p.add_protocol(ah)
                    out = self._send_packet(dp, 1, p)
                    dp.send_msg(out)
                    return

                elif in_port == 2:
                    eh = ethernet.ethernet(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", ethertype=ETH_TYPE_ARP)
                    ah = arp.arp(opcode=arp.ARP_REPLY, src_mac="00:00:00:00:00:01", src_ip="10.0.0.1",
                                dst_mac="00:00:00:00:00:02", dst_ip="10.0.0.2")
                    p = packet.Packet()
                    p.add_protocol(eh)
                    p.add_protocol(ah)
                    out = self._send_packet(dp, 2, p)
                    dp.send_msg(out)
                    return

                elif in_port == 3:
                    eh = ethernet.ethernet(dst="00:00:00:00:00:03", src="00:00:00:00:00:01", ethertype=ETH_TYPE_ARP)
                    ah = arp.arp(opcode=arp.ARP_REPLY, src_mac="00:00:00:00:00:01", src_ip="10.0.0.1",
                                dst_mac="00:00:00:00:00:03", dst_ip="10.0.0.3")
                    p = packet.Packet()
                    p.add_protocol(eh)
                    p.add_protocol(ah)
                    out = self._send_packet(dp, 3, p)
                    dp.send_msg(out)
                    return

        elif eth.ethertype == ETH_TYPE_IP and len(tcph)>0 and len(iph)>0:
            srcip = iph[0].src
            dstip = iph[0].dst
            srcport = tcph[0].src_port
            dstport = tcph[0].dst_port
            
            if in_port == 1:

                match = (srcip, "10.0.0.10", srcport, dstport)
                if match in self.ht:
                    if self.ht[match] == 2:
                        acts = [psr.OFPActionSetField(eth_dst="00:00:00:00:00:02"), psr.OFPActionSetField(ipv4_dst="10.0.0.2"), 
                            psr.OFPActionOutput(2)]
                    elif self.ht[match] == 3:
                        acts = [psr.OFPActionSetField(eth_dst="00:00:00:00:00:03"), psr.OFPActionSetField(ipv4_dst="10.0.0.3"), 
                            psr.OFPActionOutput(3)]
                    mtc = psr.OFPMatch(in_port=in_port, eth_type = eth.ethertype, ipv4_src = srcip, ipv4_dst = dstip, tcp_src = srcport, tcp_dst = dstport)
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return

                elif self.flag % 2 == 0:
                    self.ht.update({match:2})
                    acts = [psr.OFPActionSetField(eth_dst="00:00:00:00:00:02"), psr.OFPActionSetField(ipv4_dst="10.0.0.2"), psr.OFPActionOutput(2)]
                    mtc = psr.OFPMatch(in_port=in_port, eth_type = eth.ethertype, ipv4_src = srcip, ipv4_dst = dstip, tcp_src = srcport, tcp_dst = dstport)
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    self.flag += 1
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return

                elif self.flag % 2 == 1:
                    self.ht.update({match:3})
                    acts = [psr.OFPActionSetField(eth_dst="00:00:00:00:00:03"), psr.OFPActionSetField(ipv4_dst="10.0.0.3"), psr.OFPActionOutput(3)]
                    mtc = psr.OFPMatch(in_port=in_port, eth_type = eth.ethertype, ipv4_src = srcip, ipv4_dst = dstip, tcp_src = srcport, tcp_dst = dstport)
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    self.flag += 1
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return
            
            elif in_port == 2 or in_port == 3:
                acts = [psr.OFPActionSetField(eth_src="00:00:00:00:00:02"), psr.OFPActionSetField(ipv4_src="10.0.0.10"), psr.OFPActionOutput(1)]
                mtc = psr.OFPMatch(in_port=in_port, eth_type = eth.ethertype,ipv4_src = srcip, ipv4_dst = dstip, tcp_src = srcport, tcp_dst = dstport)
                self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    return
            
        else:
            return

        #
        # write your code here
        #
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
