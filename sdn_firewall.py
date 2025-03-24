from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp

class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        # MAC address table
        self.mac_to_port = {}
        # MAC whitelist
        self.allowed_macs = {
            '00:00:00:00:00:01',  # h1
            '00:00:00:00:00:02',  # h2
            '00:00:00:00:00:04'   # h4 permitted external users
        }
        
        # sort of ports
        self.internal_ports = {1, 2}  # internal ports
        self.external_ports = {3, 4}  # external ports

        # debug switch
        self.debug = True

    # debug logging function
    def _log(self, msg, *args):
        if self.debug:
            self.logger.info(msg, *args)

    def _check_mac(self, src_mac, in_port):
        # check if MAC address is allowed
        if in_port in self.external_ports:
            if src_mac not in self.allowed_macs:
                self._log("Blocked unauthorized MAC: %s from port %s", src_mac, in_port)
                return False
        return True
    
    # handle switch connection event
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install default flow entry (send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self._log("Switch connected: %s", datapath.id)

    # add flow table entry
    def add_flow(self, datapath, priority, match, actions, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                               match=match, instructions=inst,
                               hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    # handle incoming packets
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # print debug info
        self._log("\nPacket in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)

        # filter MAC addr
        if not self._check_mac(eth.src, in_port):
            return

        # learn MAC address
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # determine output port
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # create forwarding action
        actions = [parser.OFPActionOutput(out_port)]

        # install flow entry (if not broadcast)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            # add timeout
            self.add_flow(datapath, 1, match, actions, hard_timeout=30)

        # send packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)