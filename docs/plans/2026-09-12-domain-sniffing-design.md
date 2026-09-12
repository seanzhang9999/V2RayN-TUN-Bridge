# Domain Sniffing Design

## Problem

Browsers can resolve a website through encrypted DNS before traffic reaches the
TUN adapter. Mihomo may then receive only a CDN IP address. Domain rules such as
`DOMAIN-SUFFIX,zhihu.com,DIRECT-BOUND` cannot match that connection, so it can
fall through to the default proxy route.

## Design

Every generated Mihomo configuration enables its built-in HTTP, TLS, and QUIC
sniffer. Pure-IP parsing and DNS-mapping sniffing are enabled, and a recovered
hostname replaces the IP destination for routing. Existing ordered v2rayN rules
remain authoritative; sniffing only restores the domain information required to
evaluate them. The feature is applied to all generated modes so switching
between mixed proxy and TUN does not silently change routing semantics.

## Verification

Unit tests assert the complete sniffer schema and the safe runtime summary.
Mihomo's offline configuration validation verifies that the bundled v1.19.29
core accepts the generated JSON. The full regression suite must pass before the
portable package is produced.
