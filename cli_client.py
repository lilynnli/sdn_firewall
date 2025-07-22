from mininet.cli import CLI
import socket

HOST = '127.0.0.1'
PORT = 9999

class MyCLI(CLI):
    def do_addmac(self, line):
        """addmac <whitelist|internal> <mac> : Add MAC address to Ryu via socket"""
        cmd = f"addmac {line.strip()}"
        self._send_cmd(cmd)

    def do_delmac(self, line):
        """delmac <whitelist|internal> <mac> : Remove MAC address from Ryu via socket"""
        cmd = f"delmac {line.strip()}"
        self._send_cmd(cmd)

    def do_listmac(self, line):
        """listmac : Show whitelist and internal MACs from Ryu"""
        cmd = "listmac"
        self._send_cmd(cmd)

    def _send_cmd(self, cmd):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(cmd.encode())
                data = s.recv(1024)
                print(data.decode())
        except Exception as e:
            print(f"Failed to communicate with Ryu: {e}")
