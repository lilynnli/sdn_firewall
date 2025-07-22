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

FirewallRule = namedtuple('FirewallRule', ['proto', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'action'])

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

        # Firewall rules list
        self.firewall_rules = []  # List of FirewallRule

        # DDoS protection parameters
        self.ddos_window = 5  # Time window (seconds)
        self.ddos_threshold = 5  # Maximum allowed requests per IP
        self.total_ddos_threshold = 25  # Maximum allowed total requests
        self.ip_tracker = defaultdict(lambda: {
            'ip_counts': defaultdict(int),  # request count for each IP
            'time': time.time(),  # last request time
        })
        # DDoS blacklist: (src_ip, dst_ip) -> unblock_time
        self.ddos_blacklist = {}  # key: (src_ip, dst_ip), value: unblock_time (timestamp)
        # Exponential backoff for DDoS
        self.ddos_strikes = {}  # key: (src_ip, dst_ip), value: (strike_count, last_strike_time)
        self.ddos_base_block = 60      # 60 seconds
        self.ddos_max_block = 3600     # 1 hour
        self.ddos_reset_window = 600   # 10 minutes

        # debug switch
        self.debug = True
        threading.Thread(target=self.start_cli_server, args=(), daemon=True).start()


    def match_rule(self, pkt, rule):
        # Only match IPv4 packets
        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip:
            return False
        # Protocol
        if rule.proto != '*' and rule.proto != 'ALL':
            if rule.proto == 'TCP':
                l4 = pkt.get_protocol(tcp.tcp)
                if not l4:
                    return False
            elif rule.proto == 'UDP':
                l4 = pkt.get_protocol(udp.udp)
                if not l4:
                    return False
            else:
                return False
        # Src IP
        if rule.src_ip != '*' and rule.src_ip != ip.src:
            return False
        # Dst IP
        if rule.dst_ip != '*' and rule.dst_ip != ip.dst:
            return False
        # Src Port
        l4 = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
        if rule.src_port != '*' and l4:
            if str(l4.src_port) != rule.src_port:
                return False
        # Dst Port
        if rule.dst_port != '*' and l4:
            if str(l4.dst_port) != rule.dst_port:
                return False
        return True

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

    def _handle_ddos_block(self, src_ip, dst_ip):
        now = time.time()
        key = (src_ip, dst_ip)
        count, last_time = self.ddos_strikes.get(key, (0, 0))
        # Reset strike count if last strike was long ago
        if now - last_time > self.ddos_reset_window:
            count = 0
        count += 1
        self.ddos_strikes[key] = (count, now)
        block_time = min(self.ddos_base_block * (2 ** (count - 1)), self.ddos_max_block)
        self.ddos_blacklist[key] = now + block_time
        self._log("DDoS block: %s -> %s, strikes=%d, block_time=%ds", src_ip, dst_ip, count, block_time)
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
            # return  # Completely skip further processing/logging for these packets
            self._log("\nPacket in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)

        # clean expired blacklist entries
        now = time.time()
        expired = [(s, d) for (s, d), t in self.ddos_blacklist.items() if t <= now]
        for key in expired:
            del self.ddos_blacklist[key]
            self._log("Unblocked DDoS IP pair: %s -> %s", key[0], key[1])

        # DDoS blacklist check
        if ip:
            if (ip.src, ip.dst) in self.ddos_blacklist:
                self._log("Blocked by DDoS blacklist: %s -> %s", ip.src, ip.dst)
                return

        # firewall rules check (highest priority)
        for rule in self.firewall_rules:
            if self.match_rule(pkt, rule):
                self._log("Firewall rule matched: %s", rule)
                if rule.action == 'DENY':
                    # drop packet and install drop flow
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=ip.src,
                        ipv4_dst=ip.dst
                    )
                    self.add_flow(datapath, 10, match, [], hard_timeout=30)
                    return
                elif rule.action == 'ALLOW':
                    break  # allow, continue normal processing

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

        # DDoS protection (only check IP packets from external to internal)
        if ip and in_port not in self.internal_ports:
            if ip.dst.startswith('10.0.'):  # target is internal IP
                if self._is_ddos_attack(ip.dst, ip.src):
                    self._log("Blocked DDoS attack from %s to %s", ip.src, ip.dst)
                    # exponential backoff block
                    block_time = self._handle_ddos_block(ip.src, ip.dst)
                    # add temporary drop rule
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip.src,
                        ipv4_dst=ip.dst
                    )
                    self.add_flow(datapath, 2, match, [], hard_timeout=int(block_time)) # empty actions == drop
                    return

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