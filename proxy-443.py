#!/usr/bin/env python
import socket, sys
try:
    import socketserver
except:
    import SocketServer as socketserver
import struct, select
from datetime import datetime
import ipaddress

from config import *

# Interpretation of a local IPv6 address:
# service (1 byte int), ip (4 bytes), port (2 bytes int).
address_struct = struct.Struct('!B4sH')

def parse_from_ipv6_address(ip):
    """
    Parses an IPv6 address, splitting prefix::SS:AABB:CCDD:XXYY into a tuple
    (service_type, ipv4_addr, port_no) such as (0xSS, 0xAABBCCDD, 0xXXYY).

    :type ip: ipaddress.IPv6Address
    :rtype: (int, bytes, int)
    """
    parsed = address_struct.unpack(ip.packed[-address_struct.size:])
    return parsed

def get_local_address(sock):
    """
    Given an IP socket, returns its local IP address.
    """
    # For testing purposes:
    #return '::5db8:d822:01bb' # example.com (93.184.216.34, 443)
    return sock.getsockname()[0]

class ProxyRequestHandler(socketserver.BaseRequestHandler):
    def parse_local_address(self):
        ip = get_local_address(self.request)
        addr = ipaddress.IPv6Address(ip)
        # Is this within our range?
        if addr not in self.server.my_ipv6_network:
            self.log('Address', addr, 'not in net', self.server.my_ipv6_network)
            return None
        return parse_from_ipv6_address(addr)

    def handle(self):
        # Definition of the destination
        parsed = self.parse_local_address()
        # Closes the connection for unknown prefixes.
        if not parsed:
            return
        service_type, ipv4_addr, port_no = parsed

        # Connect to subject host
        ipv4_addr_str = socket.inet_ntoa(ipv4_addr)
        sock = socket.create_connection((ipv4_addr_str, port_no))
        try:
            if self.setup_socket(sock, service_type):
                self.handle_pipe(sock, self.request)
        finally:
            sock.close()

    def setup_socket(self, server, service_type):
        # TODO: see pacemaker.py for prepare_* functions
        return False

    def handle_pipe(self, server, client):
        fds = [server, client]
        timeout = 10
        written_bytes = { 'server': 0, 'client': 0 }
        try:
            while True:
                rl, _, _ = select.select(fds, [], [], timeout)
                if not rl:
                    # Timeout?
                    break
                for sock in rl:
                    data = sock.recv(64 * 1024)
                    if not data:
                        self.log("Detected EOF from", sock)
                        raise StopIteration
                    if sock == client:
                        what = 'client'
                        server.sendall(data)
                    elif sock == server:
                        what = 'server'
                        client.sendall(data)
                    else:
                        self.log("Unknown sock", sock, "; data:", repr(data))
                        continue
                    written_bytes[what] += len(data)
                    self.log('{}: wrote {} bytes'.format(what, len(data)))
        except StopIteration:
            pass
        except Exception as e:
            self.log("IO failure", e)
        self.log("Written bytes: {0} (client), {1} (server)"
            .format(written_bytes['client'], written_bytes['server']))

    def log(self, *args):
        timestamp = datetime.now().strftime('%H:%M:%S.%f:')
        prefix = '{} {}:'.format(timestamp, self.request.getsockname()[0:2])
        print(prefix, *args)

class ProxyServer(socketserver.TCPServer):
    def __init__(self, addr):
        self.address_family = socket.AF_INET6
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, addr, ProxyRequestHandler)
        self.my_ipv6_network = ipaddress.IPv6Network(ipv6_network)

if __name__ == '__main__':
    host = sys.argv[1]      if len(sys.argv) > 1 else '::'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4433
    server = ProxyServer((host, port))
    print('Listening on {} port {}...'.format(host, port))
    server.serve_forever()
