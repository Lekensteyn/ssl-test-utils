# ssl-test-utils
Utilities for SSL server testing.

## proxy-443.py
Proxies TCP port 443 to any other port, possibly performing STARTTLS/STARTSSL
handshakes first for certain protocols.

This tool is designed to for use with Qualys SSL Server Test. That tool only
allows testing TCP port 443 which is unfortunate since the tests are also useful
for SMTP over STARTTLS, IMAPS, HTTPS on a custom port and so on.

## nameserver.py
A nameserver which resolves names such as `AABBCCDD-XXYY.SS.example.com` to an
AAAA record such as `2001:db8::SS:AABB:CCDD:XXYY`. This format applies the
following considerations:

 - Fits within a /72 block.
 - Different service types come first (up to 256 for 8-bit).
 - IPv4 address follows.
 - TCP port number follows.

Currently defined services:

 - 0: SSL/TLS (for HTTPS, IMAPS, etc.)
 - 1: SMTP STARTTLS.

## Testing
Set up a rfc4193 unique local IPv6 unicast address.

    ip route add local fd77:3528:d6ca:221d::/72 dev lo

## Links
[Any-IP support for IPv6 in
Linux](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ab79ad14a2d51e95f0ac3cef7cd116a57089ba82)

https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs.md

https://tools.ietf.org/html/rfc4193
