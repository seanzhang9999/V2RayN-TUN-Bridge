"""Read the generated Xray routing table, preserving order and compound conditions."""
from pathlib import Path
import ipaddress
import json
import os
import subprocess


def config_path():
    settings = Path(os.environ['LOCALAPPDATA']) / 'v2rayn-tun-controller/gui-settings.json'
    root = Path(json.loads(settings.read_text(encoding='utf-8-sig'))['app_root'])
    return root / 'binConfigs/config.json'


def direct_rules(path):
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    freedom = {o['tag'] for o in config['outbounds'] if o.get('protocol') == 'freedom'}
    rules = [(n, rule) for n, rule in enumerate(config['routing']['rules'], 1)
             if rule.get('outboundTag') in freedom]
    return rules


# Keys that constrain the destination only. Xray evaluates one field rule as OR
# inside an attribute and AND across attributes, so `{domain:[...], ip:[...]}`
# means "domain or ip": the ip half still sends those addresses out directly.
# Requiring the rule to consist of nothing but {type, outboundTag, ip} discarded
# every rule v2rayN actually ships, leaving the permit list empty while the
# default action kept blocking the physical egress.
DESTINATION_KEYS = frozenset({'type', 'outboundTag', 'ip', 'domain', 'port', 'network'})


def direct_items(rule):
    """Return the raw `ip` entries of a rule whose matches leave directly.

    Rules narrowed by anything other than the destination (`source`,
    `inboundTag`, `user`, `protocol`, `attributes`) are skipped: turning a
    conditional permit into a blanket one would trade a blocked connection for
    a silent leak.
    """
    if rule.get('type', 'field') != 'field':
        return ()
    if set(rule) - DESTINATION_KEYS:
        return ()
    items = rule.get('ip')
    return tuple(items) if isinstance(items, list) else ()


def literal_targets(rule):
    result = set()
    for item in direct_items(rule):
        try:
            result.add(ipaddress.ip_address(item))
        except (AttributeError, ValueError):
            continue
    return result


def verify_core(exe):
    # Both the base listener and the v2rayN installation must identify this executable.
    script = """
$ErrorActionPreference='Stop'
$owner=@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 1081 -State Listen)
if ($owner.Count -ne 1) {exit 1}
$core=(Get-Process -Id $owner[0].OwningProcess).Path
$match=@(Get-Process -Name v2rayN | Where-Object {
    $_.Path -and (Join-Path (Split-Path $_.Path) 'bin/Xray/xray.exe') -eq $core
})
if (!$core -or !$match.Count) {exit 1}
[Console]::OutputEncoding=[Text.Encoding]::UTF8
[Console]::Write($core)
"""
    shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    cmd = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                         capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if cmd.returncode or Path(cmd.stdout.decode('utf-8-sig').strip()).resolve() != exe.resolve():
        raise RuntimeError('无法确认 1081 监听进程属于当前 v2rayN 安装，已取消本次测试')

def _fields(data):
    """Decode the scalar and length-delimited fields used by Xray GeoIPList."""
    pos = 0
    def integer():
        nonlocal pos
        value = 0
        for shift in range(0, 70, 7):
            if pos == len(data):
                break
            byte = data[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError('Invalid GeoIP integer')
    while pos < len(data):
        tag = integer()
        if tag & 7 == 0:
            value = integer()
        elif tag & 7 == 2:
            size = integer()
            if size > len(data) - pos:
                raise ValueError('Truncated GeoIP field')
            value = data[pos:pos + size]
            pos += size
        else:
            raise ValueError('Unsupported GeoIP field')
        yield tag >> 3, value


from functools import lru_cache


@lru_cache(maxsize=2)
def _cn_networks(path, mtime, size):
    for field, entry in _fields(memoryview(path.read_bytes())):
        if field != 1:
            continue
        fields = iter(_fields(entry))
        first = next(fields, None)
        if not first or first[0] != 1 or bytes(first[1]).upper() != b'CN':
            continue
        networks = []
        for key, value in fields:
            if key == 3 and value:
                raise ValueError('Inverted CN record')
            if key == 2:
                cidr = dict(_fields(value))
                prefix = cidr.get(2, 0)
                if prefix == 0:
                    raise ValueError('Unexpected default route in CN record')
                networks.append(ipaddress.ip_network((ipaddress.ip_address(bytes(cidr[1])), prefix)))
        if not networks:
            break
        return frozenset(n for family in (4, 6) for n in
                         ipaddress.collapse_addresses(x for x in networks if x.version == family))
    raise ValueError('Missing CN record in v2rayN GeoIP database')


def direct_networks(path):
    networks = set()
    for _, rule in direct_rules(path):
        for item in direct_items(rule):
            if item.lower() == 'geoip:cn':
                db = path.parents[1] / 'bin' / 'geoip.dat'
                st = db.stat()
                networks.update(_cn_networks(db, st.st_mtime_ns, st.st_size))
            else:
                try:
                    network = ipaddress.ip_network(item)
                except (AttributeError, ValueError):
                    continue
                if network.prefixlen:
                    networks.add(network)
    return networks
