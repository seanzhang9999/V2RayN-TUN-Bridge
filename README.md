# V2RayN TUN Bridge

Windows x64 console for an IPv4 Mihomo TUN and independent Windows Filtering Platform (WFP) egress protection. Keep node selection and traffic policy in v2rayN. [中文说明及网络拓扑图](README.zh-CN.md)

## Packet paths

| Traffic | Path |
| --- | --- |
| Ordinary apps and OpenSSH | Windows route → Mihomo TUN → SOCKS at 127.0.0.1:1081 → v2rayN-managed Xray → selected outbound |
| System proxy clients | Directly to v2rayN on 1081 |
| Explicit Mihomo proxy clients | Mihomo mixed listener on 127.0.0.1:1082 → v2rayN on 1081 |
| Xray socket captured again by TUN | Exact executable-path match → authenticated loopback VLESS listener → auxiliary Xray freedom outbound bound to the physical interface → WFP |
| Windows DHCP client | Physical adapter → DHCP server using UDP 68 to 67 (IPv4) or 546 to 547 (IPv6). WFP checks the service token and executable path. |
| Captive portal | Dedicated Edge profile → PortalRelay → approved IP and port on the current physical link |

The VPN endpoint is exempted at the WFP layer for the Xray application, protocol and port. Its entire IP remains eligible for TUN capture, including ordinary SSH to that same host. Pure IP/CIDR direct rules and the China GeoIP set grant physical access only to the identified Xray executable. Domain rules remain part of Xray routing. Unknown apps have no general physical Internet exception. Approved on-link LAN destinations have separate interface-scoped exceptions.

TUN uses fake-IP DNS and proxied DoH. When the physical egress helper needs a real address it resolves through DoH via 1081. The primary Xray retains its own DNS policy. WFP covers IPv4 and IPv6 physical egress; the TUN forwarding configuration and node discovery in this release are IPv4.

## Run the release

1. Extract the Windows x64 ZIP and install 64-bit Python 3.11+ with Tk and `python` on PATH. Start v2rayN with its Xray mixed/SOCKS listener on 1081. Edge is needed only for captive portal login. For UDP through TUN, enable UDP on the **v2rayN local SOCKS/mixed inbound on 1081** and apply the setting. A successful TCP request to 1081 only checks TCP. A SOCKS5 UDP ASSOCIATE reply with status 7 means the listener rejected that command.
2. Run `python -X utf8 guard-console.pyw` and select the v2rayN installation folder on first use. Download the asset from [GitHub Releases](https://github.com/seanzhang9999/V2RayN-TUN-Bridge/releases).
3. Select **开启保护并启动 TUN** to enable WFP and start TUN. Network changes request Windows administrator approval. **停止 TUN** stops only the tunnel. **关闭保护** removes Bridge protection to restore normal physical egress. Closing the console can leave protection active.
4. Inspect recent TUN connections and command logs in the console. Runtime files are under `%LOCALAPPDATA%\v2rayn-tun-controller`. Wi-Fi LAN settings persist only when requested; captive-portal approvals are session-scoped.

## Verification

On a Windows laptop connected to a Wi-Fi hotspot, the DHCP server renewed the lease while WFP and TUN were both active. Two SSH hosts authenticated through the tunnel. An authenticated Codex request also completed. See the [RC2 validation notes](docs/release-v0.3.4-rc.2.md) for the observation interval and limits. Public IPv6 forwarding, sleep/wake recovery and a fresh Antigravity browser login remain unverified.

## Related

- [managed-tun](https://github.com/seanzhang9999/managed-tun) — the macOS counterpart: a standalone
  sing-box TUN beneath v2rayN with an explainable judgement layer (facts → evidence → diagnosis →
  action), so failures are named and repaired by conclusion instead of being inferred from status flags.
