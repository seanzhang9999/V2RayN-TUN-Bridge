# V2RayN TUN Bridge

[简体中文](README.zh-CN.md)

A small Windows companion that reuses your existing v2rayN profiles and
routing rules, then runs them through an independent system-wide TUN.

It is built for a frustrating failure mode: the normal local proxy works, but
TUN mode causes timeouts, DNS failures, or a routing loop. V2RayN TUN Bridge
keeps v2rayN as the configuration source and uses a separately managed core for
the actual TUN path.

## Highlights

- No subscription re-entry: reads the selected profile and active route from
  the local v2rayN database.
- Supports Hysteria2 and VLESS over TCP/raw, gRPC, or WebSocket.
- Full IPv4 TUN plus a local mixed SOCKS/HTTP endpoint on `127.0.0.1:1081`.
- Separates recent TUN and local mixed-proxy connections into two ten-entry
  views, with destinations, instantaneous speeds, and direct/proxy routing.
- Detects physical-interface changes and safely rebuilds the route.
- Website checks for Google, ChatGPT, and Baidu are diagnostics only.
- Portable Windows build: no Python installation required.

## Download and run

1. Open the [latest release](https://github.com/seanzhang9999/V2RayN-TUN-Bridge/releases/latest).
2. Download `V2RayN-TUN-Bridge-windows-x64.zip` and verify `SHA256SUMS.txt`.
3. Extract the entire folder and run `V2RayN-TUN-Bridge.exe`.
4. Select the folder containing `v2rayN.exe`, choose a supported profile, and
   click **Start TUN**. Approve the Windows administrator prompt used to create
   the adapter and routes.
5. Click **Stop TUN** before starting v2rayN again. The app releases port 1081
   but deliberately does not launch v2rayN for you.

The first release is unsigned, so Windows may identify the publisher as
unknown. Verify the SHA-256 checksum before running it.

## Connection visibility

The monitor has two views:

- **Recent TUN connections** shows the last ten connections captured through
  the virtual adapter.
- **Recent 1081 proxy connections** shows the last ten connections accepted by
  the local SOCKS/HTTP mixed endpoint.

Both views retain the existing time, target, input, route, process, and live
upload/download speed columns, including recently closed connections. A closed
connection remains visible with a zero rate instead of a misleading cumulative
byte count.

The app asks the core for strict process detection. Windows can still label
some service, kernel, UDP, or very short-lived traffic as unknown. Monitoring
data remains in memory and is not written to disk.

Failure diagnostics are different from connection history. The protected local
runtime directory keeps up to 20 credential-free failure summaries plus one
rotated copy of the previous status, watchdog report, core log, and supervisor
log. This evidence survives a restart so a later investigation can identify
the failed checkpoint and exit reason. Generated proxy configuration and
controller secrets are never added to the history.

## Requirements and limitations

- Windows 11 x64; Windows 10 may work but is not yet a release target.
- An existing v2rayN installation with a working profile and routing policy.
- Administrator rights for TUN and route changes.
- IPv4 TUN only in the current v0.1.x releases.
- XHTTP is not yet supported.
- The app currently understands the v2rayN 7.x storage layout used by the test
  machine; please report redacted compatibility failures.

## Development

```powershell
$env:PYTHONPATH = Join-Path $PWD 'src'
python -m unittest discover -s tests -v
python -m tun_bridge
```

To build a release locally:

```powershell
python -m pip install -r requirements-build.txt
./packaging/fetch-runtime.ps1
pyinstaller --noconfirm V2RayN-TUN-Bridge.spec
```

Runtime downloads are version-pinned and SHA-256 verified. Core binaries and
generated private configuration are excluded from Git.

## Independence and licenses

This project is not affiliated with v2rayN, MetaCubeX, or Clash Verge Rev. The
application source is MIT licensed. Bundled third-party runtime components keep
their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

Please do not use this project to violate local laws, network policies, or the
terms of any service.
