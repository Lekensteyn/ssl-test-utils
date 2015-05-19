## Configuration

# Order is important.
service_types = [
    'ssl',      # direct unwrapped SSL connection (https/smtps/...)
    'smtp',     # SMTP with STARTTLS
]


# Example valid pattern: ip-(127)-(0)-(0)-(1)-ssl-443
# matches "ip-(127)-(0)-(0)-(1)", groups 1-4 are the octets.
# 0.x.x.x is disallowed.
label_pattern = r'ip-([1-9]\d{0,2})' + (3 * r'-(0|[1-9]\d{0,2})')
# matches "-(ssl)" where "ssl" is a service from service_types.
label_pattern += '-(?P<service>' + '|'.join(service_types) + ')'
# matches "-(443)" where "443" is a port number
label_pattern += r'-(?P<port>[1-9]\d{0,4})'


# IPv6 network range as used for mapping ip+port+service requests.
ipv6_network = '2001:db8::/72'


# The FQDN of the zone which is served by the server, other suffixes are
# rejected by the nameserver.
served_zone = 'ssltest.lekensteyn.nl.'

# TTL for AAAA records which are specially interpreted.
record_ip_ttl = 60 * 5

# SOA record for served_zone.
# See https://tools.ietf.org/html/rfc1035#section-3.3.13
_soa_record = (
    # MNAME (name of the primary (master) server)
    'ns-' + served_zone,
    # RNAME (mailbox for person responsible for thiz zone)
    'peter.lekensteyn.nl.',
    # serial
    1,
    # slave refresh
    3600 * 24,
    # slave retry time in case of a problem
    3600 * 2,
    # slave expiration time
    3600 * 24 * 7 * 4,
    # minimum caching time in case of failed lookups
    3600,
)

# map from names to iterables of (ttl, type, data)
zone_contents = {
    '@': (
        (0,         'SOA',      ' '.join(str(x) for x in _soa_record)),
        (60 * 5,    'A',        '127.0.0.1'),
        (60 * 5,    'AAAA',     '::1'),
    ),
    'www': (
        (60 * 5,    'CNAME',    served_zone),
    ),
}
