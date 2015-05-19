#!/usr/bin/env python
import socket, sys
try:
    import socketserver
except:
    import SocketServer as socketserver
import ipaddress
import struct, re

import dns.message, dns.rcode, dns.flags, dns.name
import dns.rrset, dns.rdata
import dns.rdtypes.IN.A, dns.rdtypes.IN.AAAA, dns.rdtypes.ANY.SOA
import dns.rdataclass, dns.rdatatype

from config import *

hostname_pattern = re.compile('^' + label_pattern + '$', re.IGNORECASE)

def int_from_bytes(bytes):
    """
    Converts bytes to an integer.
    """
    # TODO: python < 3.2 compat
    return int.from_bytes(bytes, byteorder='big')

class DnsRequestHandler(socketserver.BaseRequestHandler):
    def _make_response(self, query):
        response = dns.message.make_response(query)
        # Recursion is not supported. It should not be copied from the query.
        response.flags &= ~dns.flags.RD
        return response

    def handle(self):
        data, socket = self.request[0:2]
        query = dns.message.from_wire(data)
        try:
            response = self._make_response(query)
            rcode = self.handle_dns_query(query, response)
            response.set_rcode(rcode)
        except:
            response = self._make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            raise
        finally:
            #print('\n{}'.format(response))
            # Always send a response, otherwise the client retries again
            # since there is no connection concept in UDP.
            socket.sendto(response.to_wire(), self.client_address)

    def handle_dns_query(self, query, response):
        """Processes a DNS query.

        :type query: dns.message.Message
        :type response: dns.message.Message
        :return: the DNS response code (rcode).
        """
        # Assume one question, http://maradns.samiam.org/multiple.qdcount.html
        if len(query.question) != 1:
            return dns.rcode.FORMERR

        q = query.question[0]

        # Are we authoritative for this zone?
        if not self.server.my_zone_name.is_superdomain(q.name):
            return dns.rcode.REFUSED
        # This name server manages the zone, enable Authoritative Answer bit.
        response.flags |= dns.flags.AA

        # Only support Internet, not Chaosnet or something.
        if q.rdclass != dns.rdataclass.IN:
            return dns.rcode.NOTIMP

        # www.example.com -> www
        domain_prefix = str(q.name.relativize(self.server.my_zone_name)).lower()
        # Try to parse the special format
        parsed_address = self.parse_label(domain_prefix)
        if parsed_address:
            # Resolve name to IPv6 address.
            if q.rdtype in (dns.rdatatype.ANY, dns.rdatatype.AAAA):
                answer = dns.rrset.from_text(q.name, record_ip_ttl,
                    dns.rdataclass.IN, dns.rdatatype.AAAA, parsed_address)
                response.answer.append(answer)
        elif domain_prefix in zone_contents:
            # try to look up in the general zone.
            records = zone_contents[domain_prefix]
            for ttl, type_name, data in records:
                # Add record if the type matches (or ANY is requested).
                rdtype = dns.rdatatype.from_text(type_name)
                if q.rdtype in (dns.rdatatype.ANY, rdtype):
                    answer = dns.rrset.from_text(q.name, ttl,
                        dns.rdataclass.IN, rdtype, data)
                    response.answer.append(answer)
        else:
            # Name is invalid, but we are authoritative. Report Name Error.
            return dns.rcode.NXDOMAIN

        return dns.rcode.NOERROR

    def parse_label(self, label):
        """
        Parses a label into an IPv6 address.

        :type name: str
        :rtype: str
        """
        # Example pattern: ip-(127)-(0)-(0)-(1)-ssl-443
        match = hostname_pattern.match(label)
        if not match:
            return

        # Example output address: 2001:db8::00:7f00:0001:01bb
        # service (1 byte int), ip (4 bytes), port (2 bytes int).
        service_type_name = match.group('service').lower()
        service_type = service_types.index(service_type_name)
        octets = tuple(int(x) for x in match.groups()[0:4])
        port = int(match.group('port'))
        # ip-999-0-0-0-ssl-99999 is not valid. No response available.
        if any(x > 255 for x in octets) or port > 65535:
            return

        # Pack the suffix into bytes and then fill it in the network.
        suffix = struct.pack('!B4sH', service_type, bytes(octets), port)
        address = str(self.server.my_ipv6_network[int_from_bytes(suffix)])

        return address

class DnsServer(socketserver.UDPServer):
    def __init__(self, addr):
        # Support listening on IPv4/IPv6 addresses
        if ':' in addr[0]:
            self.address_family = socket.AF_INET6
        self.allow_reuse_address = True
        socketserver.UDPServer.__init__(self, addr, DnsRequestHandler)
        self.my_ipv6_network = ipaddress.IPv6Network(ipv6_network)
        self.my_zone_name = dns.name.from_text(served_zone)

if __name__ == '__main__':
    host = sys.argv[1]      if len(sys.argv) > 1 else '::'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353
    server = DnsServer((host, port))
    print('Listening on {} port {}...'.format(host, port))
    server.serve_forever()
