from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from collections import defaultdict
import time

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

        # DDoS protection parameters
        self.ddos_window = 5  # Time window (seconds)
        self.ddos_threshold = 5  # Maximum allowed requests per IP
        self.total_ddos_threshold = 25  # Maximum allowed total requests
        self.ip_tracker = defaultdict(lambda: {
            'ip_counts': defaultdict(int),  # request count for each IP
            'time': time.time(),  # last request time
        })

        # debug switch
        self.debug = True

    # debug logging function
    def _log(self, msg, *args):
        if self.debug:
            self.logger.info(msg, *args)

    # check if MAC address is allowed
    def _check_mac(self, src_mac, in_port, dst_mac):
        if in_port not in self.internal_ports: # not in security zone
            if dst_mac not in self.internal_ports: # communication outside of security zone
                return True
            if src_mac not in self.allowed_macs: # not in allowed list (external users)
                self._log("Blocked unauthorized MAC: %s from port %s", src_mac, in_port)
                return False
        return True

    # detect DDoS attack
    def _is_ddos_attack(self, dst_ip, src_ip):
        current_time = time.time()
        tracker = self.ip_tracker[dst_ip]
        
        # reset expired statistics
        if current_time - tracker['time'] > self.ddos_window:
            self._log("Resetting DDoS counter for %s", dst_ip)
            tracker['ip_counts'].clear()
            tracker['time'] = current_time
        
        # record new request
        tracker['ip_counts'][src_ip] += 1
        
        # calculate total requests
        total_requests = sum(tracker['ip_counts'].values())
        
        # check if threshold is exceeded
        if total_requests > self.total_ddos_threshold:
            self._log("Total DDoS threshold exceeded for %s: %d total requests from %d different IPs", 
                     dst_ip, total_requests, len(tracker['ip_counts']))
            return True
        elif tracker['ip_counts'][src_ip] > self.ddos_threshold:
            self._log("Per-IP DDoS threshold exceeded for %s: %d requests from IP %s", 
                     dst_ip, tracker['ip_counts'][src_ip], src_ip)
            return True
        return False

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
        ip = pkt.get_protocol(ipv4.ipv4)

        # print debug info
        self._log("\nPacket in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)

        # filter MAC addr
        if not self._check_mac(eth.src, in_port, eth.dst):
            return

        # DDoS protection (only check IP packets from external to internal)
        if ip and in_port in self.external_ports:
            if ip.dst.startswith('10.0.'):  # target is internal IP
                if self._is_ddos_attack(ip.dst, ip.src):
                    self._log("Blocked DDoS attack from %s to %s", ip.src, ip.dst)
                    # add temporary drop rule
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip.src,
                        ipv4_dst=ip.dst
                    )
                    self.add_flow(datapath, 2, match, [], hard_timeout=10)  # empty actions == drop
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
            if ip:
                # use more precise matching for IP packets
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,  # IPv4
                    ipv4_src=ip.src,
                    ipv4_dst=ip.dst
                )
            else:
                # use MAC matching for non-IP packets
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=eth.dst,
                    eth_src=eth.src
                )
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