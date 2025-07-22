from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import socket

class MyCLI(CLI):
    def do_addmac(self, line):
        """addmac <mac> : Add MAC address to Ryu whitelist"""
        resp = self.send_to_ryu(f"addmac {line.strip()}")
        print(resp)

    def do_delmac(self, line):
        """delmac <mac> : Remove MAC address from Ryu whitelist"""
        resp = self.send_to_ryu(f"delmac {line.strip()}")
        print(resp)

    def do_listmac(self, line):
        """listmac : Show Ryu whitelist"""
        resp = self.send_to_ryu("listmac")
        print(resp)

    def send_to_ryu(self, cmd):
        HOST = '127.0.0.1'
        PORT = 9999
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(cmd.encode())
                data = s.recv(1024)
                return data.decode()
        except Exception as e:
            return f"Failed to communicate with Ryu: {e}"

def simple_topology():
    net = Mininet(controller=RemoteController)
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.start()
    MyCLI(net)  # Use custom CLI instead of default CLI
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    simple_topology()