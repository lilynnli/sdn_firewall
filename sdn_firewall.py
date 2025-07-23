from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp
from collections import defaultdict, namedtuple
import time
import socket
import threading

class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        # MAC address table
        self.mac_to_port = {}
        # MAC whitelist
        self.whitelist_macs = set()  # Whitelisted MACs (external allowed)
        self.internal_macs = set()   # Internal network MACs
        self.internal_ports = set()  # Ports where internal MACs are observed

        # DDoS protection parameters
        self.ddos_window = 5  # 5 seconds window
        self.ddos_threshold = 5  # Single IP threshold
        self.total_ddos_threshold = 25  # Total request threshold
        self.ddos_tracker = defaultdict(lambda: {'ip_counts': defaultdict(int), 'time': time.time()})
        self.ddos_blacklist = {}  # (src_ip, dst_ip) -> unblock_time
        self.ddos_strikes = {}    # (src_ip, dst_ip) -> strike_count
        self.ddos_base_block = 60      # 60 seconds
        self.ddos_add_block = 600      # 10 minutes
        self.ddos_max_block = 3600     # 1 hour

        # debug switch
        self.debug = True
        threading.Thread(target=self.start_cli_server, args=(), daemon=True).start()

    # debug logging function
    def _log(self, msg, *args):
        if self.debug:
            self.logger.info(msg, *args)

    def add_whitelist_mac(self, mac):
        self.whitelist_macs.add(mac)
        self._log("Added MAC %s to whitelist", mac)

    def del_whitelist_mac(self, mac):
        if mac in self.whitelist_macs:
            self.whitelist_macs.remove(mac)
            self._log("Removed MAC %s from whitelist", mac)
            self._remove_flows_by_mac(mac)

    def add_internal_mac(self, mac):
        self.internal_macs.add(mac)
        self._log("Added MAC %s to internal_macs", mac)

    def del_internal_mac(self, mac):
        if mac in self.internal_macs:
            self.internal_macs.remove(mac)
            self._log("Removed MAC %s from internal_macs", mac)
            self._remove_flows_by_mac(mac)

    def _remove_flows_by_mac(self, mac):
        # Remove all flows related to this MAC on all datapaths
        for dp in getattr(self, 'datapaths', {}).values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            match = parser.OFPMatch(eth_src=mac)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            dp.send_msg(mod)

    def _is_valid_mac(self, src_mac, dst_mac, in_port):
        if src_mac in self.internal_macs:
            if in_port not in self.internal_ports:
                self.internal_ports.add(in_port)
            return True
        elif src_mac not in self.whitelist_macs:
            if dst_mac in self.internal_macs:
                return False        
        return True

    # detect DDoS attack
    def _is_ddos_attack(self, dst_ip, src_ip):
        now = time.time()
        tracker = self.ddos_tracker[dst_ip]
        # Reset window if expired
        if now - tracker['time'] > self.ddos_window:
            tracker['ip_counts'].clear()
            tracker['time'] = now
        tracker['ip_counts'][src_ip] += 1
        total = sum(tracker['ip_counts'].values())
        if tracker['ip_counts'][src_ip] > self.ddos_threshold or total > self.total_ddos_threshold:
            return True
        return False

    def _handle_ddos_block(self, src_ip, dst_ip):
        now = time.time()
        key = (src_ip, dst_ip)
        strikes = self.ddos_strikes.get(key, 0) + 1
        self.ddos_strikes[key] = strikes
        block_time = min(self.ddos_base_block + (strikes - 1) * self.ddos_add_block, self.ddos_max_block)
        self.ddos_blacklist[key] = now + block_time
        self._log("DDoS block: %s -> %s, strikes=%d, block_time=%ds", src_ip, dst_ip, strikes, block_time)
        return block_time

    def start_cli_server(self, host='127.0.0.1', port=9999):
        def handle_client(conn):
            data = conn.recv(1024).decode().strip()
            resp = self.handle_cli_cmd(data)
            conn.sendall(resp.encode())
            conn.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        self._log("CLI server listening on %s:%d", host, port)
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_client, args=(conn,)).start()

    def handle_cli_cmd(self, cmd):
        parts = cmd.strip().split()
        if not parts:
            return "Empty command"
        action = parts[0].lower()
        if action == "addmac":
            if len(parts) == 3 and parts[1] == "whitelist":
                self.add_whitelist_mac(parts[2])
                return f"Added {parts[2]} to whitelist"
            elif len(parts) == 3 and parts[1] == "internal":
                self.add_internal_mac(parts[2])
                return f"Added {parts[2]} to internal_macs"
            else:
                return "Usage: addmac whitelist|internal <mac>"
        elif action == "delmac":
            if len(parts) == 3 and parts[1] == "whitelist":
                self.del_whitelist_mac(parts[2])
                return f"Removed {parts[2]} from whitelist"
            elif len(parts) == 3 and parts[1] == "internal":
                self.del_internal_mac(parts[2])
                return f"Removed {parts[2]} from internal_macs"
            else:
                return "Usage: delmac whitelist|internal <mac>"
        elif action == "listmac":
            return f"Whitelist: {self.whitelist_macs}\nInternal: {self.internal_macs}"
        else:
            return

    def is_multicast_or_broadcast(self, mac):
        mac = mac.lower()
        return mac.startswith('33') or mac == 'ff:ff:ff:ff:ff:ff'

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

        # print debug info (suppress log for 33:33 multicast and broadcast)
        if not self.is_multicast_or_broadcast(eth.dst):
            self._log("\nPacket in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)

        # DDoS blacklist check
        if ip:
            key = (ip.src, ip.dst)
            now = time.time()
            # Clean expired blacklist
            expired = [k for k, t in self.ddos_blacklist.items() if t <= now]
            for k in expired:
                del self.ddos_blacklist[k]
                self._log("Unblocked DDoS IP pair: %s -> %s", k[0], k[1])
            # Check if in blacklist
            if key in self.ddos_blacklist:
                self._log("Blocked by DDoS blacklist: %s -> %s", ip.src, ip.dst)
                return
            # Only detect from outside to inside
            if in_port not in self.internal_ports and eth.dst in self.internal_macs:
                if self._is_ddos_attack(ip.dst, ip.src):
                    block_time = self._handle_ddos_block(ip.src, ip.dst)
                    # Install drop flow table
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=ip.src,
                        ipv4_dst=ip.dst
                    )
                    self.add_flow(datapath, 20, match, [], hard_timeout=int(block_time))
                    return

        # filter MAC addr
        if not self._is_valid_mac(eth.src, eth.dst, in_port):
            # Install drop flow before return
            if ip:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=eth.src,
                    eth_dst=eth.dst,
                    eth_type=0x0800,
                    ipv4_src=ip.src,
                    ipv4_dst=ip.dst
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=eth.src,
                    eth_dst=eth.dst
                )
            self.add_flow(datapath, 20, match, [], hard_timeout=30)
            self._log("Drop flow installed for non-whitelisted MAC %s from port %s", eth.src, in_port)
            return

        # ARP packet handling
        # Ensure that all hosts in the network topology can correctly learn and parse ARP to achieve IP communication.
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            # Install a flow to flood all ARP packets
            match = parser.OFPMatch(eth_type=0x0806)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, 5, match, actions, hard_timeout=60)
            # Immediately flood this ARP packet
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
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

        # Only send the allowed flow table for non-external to internal traffic
        if not (in_port not in self.internal_ports and eth.dst in self.internal_macs):
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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths = getattr(self, 'datapaths', {})
            self.datapaths[dp.id] = dp
        elif ev.state == 'DEAD':
            if hasattr(self, 'datapaths') and dp.id in self.datapaths:
                del self.datapaths[dp.id]