from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from cli_client import MyCLI


def simple_topology():
    net = Mininet(controller=RemoteController)
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1)
    net.start()
    MyCLI(net)  # Use custom CLI instead of default CLI
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    simple_topology()