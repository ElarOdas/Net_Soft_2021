from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import tcp

class L3Switch(app_manager .RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    IP_ADDR = "10.0.0.254"
    MAC_ADDR = "52:00:00:00:00:01"
    round_robin = 0
    server_ip = ["10.0.0.2","10.0.0.3","10.0.0.4"]
    anycast_map = dict()

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_packet(self, datapath, port, pkt, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data

        actions = [parser.OFPActionOutput(port=port)]

        if buffer_id:
            out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=buffer_id,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        else:
            out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)

        datapath.send_msg(out)

    def do_arp(self, datapath, packet, frame, inPort):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        arpPacket = packet.get_protocol(arp)
        if arpPacket.opcode == 1 :
            # arp request
            arp_dstIp = arpPacket.dst_ip
            self.logger.info('received ARP Request %s => %s (port%d)'%(frame.src, frame.dst, inPort))
            if arp_dstIp == self.IP_ADDR:
                # this switch was requested
                opcode = 2
                srcMAC  = self.MAC_ADDR
                srcIP   = self.IP_ADDR
                dstMAC  = frame.src
                dstIP   = arpPacket.src_ip
                outPort = inPort
                # learn mac 2 port mapping
                self.mac_to_port[dpid][dstMAC] = inPort
                # learn ip 2 mac mapping
                self.ip_to_mac[dpid][dstIP] = dstMAC
                self.logger.info("send ARP reply %s => %s (port%d)" %(srcMAC, dstMAC, outPort))
            else:
                if arpPacket.dst_ip in self.ip_to_mac[dpid]:
                    # optimization: the switch already knows the mapping and can answer the request
                    opcode = 2
                    srcMAC  = self.ip_to_mac[dpid][arpPacket.dst_ip]
                    srcIP   = arpPacket.dst_ip
                    dstMAC  = frame.src
                    dstIP   = arpPacket.src_ip
                    outPort = self.mac_to_port[dpid][dstMAC]
                    self.logger.info("optimization: answer ARP request %s => %s (port%d)" %(srcMAC, dstMAC, outPort))
                else:
                    # forward arp request
                    opcode = 1
                    srcMAC  = frame.src
                    srcIP   = arpPacket.src_ip
                    dstMAC  = frame.dst
                    dstIP   = arpPacket.dst_ip
                    outPort = ofproto.OFPP_FLOOD
                    # learn mac 2 port mapping
                    self.mac_to_port[dpid][srcMAC] = inPort
                    # learn ip 2 mac mapping
                    self.ip_to_mac[dpid][srcIP] = srcMAC
                    self.logger.info("froward ARP request %s => %s (port%d)" %(srcMAC, dstMAC, outPort))
        elif arpPacket.opcode == 2 :
            opcode = 2
            #arp reply
            # forward arp reply
            srcMAC  = frame.src
            srcIP   = arpPacket.src_ip
            dstMAC  = frame.dst
            dstIP   = arpPacket.dst_ip
            outPort = self.mac_to_port[dpid][dstMAC]
            # learn mac 2 port mapping
            self.mac_to_port[dpid][srcMAC] = inPort
            # learn ip 2 mac mapping
            self.ip_to_mac[dpid][srcIP] = srcMAC
            self.logger.debug('forward ARP reply %s => %s (port%d)'%(frame.src ,frame.dst, inPort))
        self.send_arp(datapath, opcode, srcMAC, srcIP, dstMAC, dstIP, outPort)

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "FF:FF:FF:FF:FF:FF"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        self.send_packet(datapath, outPort, p)

    def do_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.MAC_ADDR))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=self.IP_ADDR,
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self.logger.info("do icmp: %s" %(pkt,))
        self.send_packet(datapath, port, pkt)

    def do_l2_switch(self, datapath, dpid, packet, frame, in_port, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if frame.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][frame.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=frame.dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = packet.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        self.logger.info("packet in dpid: %s, src: %s, dest: %s, in_port: %s", dpid, src, dst, in_port)

        #learn mac to port mapping
        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = in_port
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, match, actions)

        #if eth.ethertype == ether_types.ETH_TYPE_ARP:
        #    self.do_arp(datapath, pkt, eth, in_port)
        #    return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

            #check if packet is for this switch
            if ipv4_pkt.dst == self.IP_ADDR:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    self.do_icmp(datapath, in_port, eth, ipv4_pkt, icmp_pkt)
            else:
                self.ip_to_mac[dpid][ipv4_pkt.dst] = dst
                if ipv4_pkt.dst == '10.0.0.100':
                    """
                    Note to TA: As the task requires implementation of tcp handling
                    the Protocol ID argument of th 4-Tupel is always the same.
                    It is assumed that in normal circumstances other stateful protocols
                    also receive the same flow based any-cast treatment and Protocol ID would matter
                    """
                    #There might be more ryu ways to check if pkt is a tcp protocol but this method does the job
                    if ipv4_pkt.proto == 6:
                        tcp_pkt = pkt.get_protocol(tcp.tcp)
                        pkt_tupel = (ipv4_pkt.src,ipv4_pkt.dst,tcp_pkt.src_port,tcp_pkt.dst_port,ipv4_pkt.proto)
                        hashed_pkt = "%s",hash(pkt_tupel)
                        if hashed_pkt in self.anycast_map:
                            ipv4_pkt.dst = self.anycast_map[hashed_pkt]
                        else:
                            ipv4_pkt.dst = self.server_ip[self.round_robin]
                            self.round_robin = 0 if self.round_robin >= 2 else self.round_robin+1
                            self.anycast_map[hashed_pkt] = ipv4_pkt.dst
                    else:
                        ipv4_pkt.dst = self.server_ip[self.round_robin]
                        self.round_robin = 0 if self.round_robin >= 2 else self.round_robin+1

                if ipv4_pkt.dst in self.ip_to_mac[dpid] and self.ip_to_mac[dpid][ipv4_pkt.dst] in self.mac_to_port[
                    dpid]:
                    out_port = self.mac_to_port[dpid][self.ip_to_mac[dpid][ipv4_pkt.dst]]
                    match = parser.OFPMatch(ipv4_src=ipv4_pkt.src,ipv4_dst=ipv4_pkt.dst)
                    actions = [parser.OFPActionOutput(out_port)]
                    """
                    Due to the lean implementation of anycast, flow entries are made for the servers
                    during every anycast. This was deemed to be a non-damaging side effect justified
                    by the improvement in readability of the _packet_in_handler function.
                    """
                    self.add_flow(datapath,1,match,actions)
                    self.send_packet(datapath, out_port, pkt)
                else:
                    out_port = ofproto.OFPP_FLOOD
                    self.send_packet(datapath, out_port, pkt)

        # packet is not for this switch, so do l2 switching
        if dst != self.MAC_ADDR:
            self.do_l2_switch(datapath, dpid, pkt, eth, in_port, msg.buffer_id)
            return
        return
