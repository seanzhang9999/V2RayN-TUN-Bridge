# Direct DNS Design

## Problem

The default resolver intentionally uses Cloudflare through the proxy. That is
appropriate for proxied websites, but a Direct domain can receive an overseas
CDN answer and then fail or perform poorly when the selected address is reached
from the physical Chinese network.

## Design

Generated configurations set `direct-nameserver` to `system`. Mihomo therefore
re-resolves domains that match a Direct route using the DNS service associated
with the current physical network. `direct-nameserver-follow-policy` is disabled
so this dedicated resolver cannot be redirected back to the proxy resolver.
The default nameserver remains Cloudflare through PROXY, and proxy-node endpoint
resolution remains on the system resolver to avoid a bootstrap loop.

## Verification

Unit tests assert the separation between default, node, and Direct resolvers.
The bundled Mihomo core validates a synthetic generated configuration offline,
and the complete regression suite must pass before packaging v0.2.2.
