"""Windows x64 WFP trial. Filters exist only while the worker process lives."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import ctypes as c
from ctypes import wintypes as w
import ipaddress
import json
import os
import socket
import tempfile
from pathlib import Path
import subprocess
import sys
import time
import uuid
from urllib.parse import urlencode

DWORD = c.c_uint32
PTR = c.c_void_p
GUID = c.c_ubyte * 16


def guid(value):
    return GUID.from_buffer_copy(uuid.UUID(value).bytes_le)


class Display(c.Structure):
    _fields_ = [('name', w.LPWSTR), ('description', w.LPWSTR)]


class Blob(c.Structure):
    _fields_ = [('size', DWORD), ('data', PTR)]


class Session(c.Structure):
    _fields_ = [('key', GUID), ('display', Display), ('flags', DWORD),
                ('timeout', DWORD), ('pid', DWORD), ('sid', PTR),
                ('username', PTR), ('kernel', w.BOOL)]


class Sublayer(c.Structure):
    _fields_ = [('key', GUID), ('display', Display), ('flags', DWORD),
                ('provider', PTR), ('data', Blob), ('weight', c.c_uint16)]


class Data(c.Union):
    _fields_ = [('number', DWORD), ('pointer', PTR)]


class Value(c.Structure):
    _fields_ = [('type', DWORD), ('data', Data)]


class Condition(c.Structure):
    _fields_ = [('key', GUID), ('match', DWORD), ('value', Value)]


class Action(c.Structure):
    _fields_ = [('type', DWORD), ('key', GUID)]


class Context(c.Union):
    _fields_ = [('raw', c.c_uint64), ('key', GUID)]


class Filter(c.Structure):
    _fields_ = [('key', GUID), ('display', Display), ('flags', DWORD),
                ('provider', PTR), ('data', Blob), ('layer', GUID),
                ('sublayer', GUID), ('weight', Value), ('count', DWORD),
                ('conditions', c.POINTER(Condition)), ('action', Action),
                ('context', Context), ('reserved', PTR), ('id', c.c_uint64),
                ('effective', Value)]


LAYERS = ['c38d57d1-05a7-4c33-904f-7fbceee60e82', '4a72393b-319f-44bc-84c3-ba54dcb3b6b4']
FLAGS = '632ce23b-5167-435c-86d7-e903684aa80c'
APP = 'd78e1e87-8644-4ea5-9437-d809ecefc971'
REMOTE = 'b235ae9a-1d64-49b8-a44c-5ff3d9095045'
GUARD_KEY = '5a832ea6-392a-4fb8-8d65-40ec80392ab9'
PERMIT, BLOCK = 0x1002, 0x1001
api = c.WinDLL('fwpuclnt')


def call(name, *args):
    result = getattr(api, name)(*args)
    if result:
        raise OSError(f'{name}: 0x{result & 0xffffffff:08x}')


def add_filter(engine, sub, layer, label, action, weight, conditions, temporary=False):
    f = Filter()
    f.display.name = 'Bridge trial: ' + label
    f.layer, f.sublayer = guid(layer), sub.key
    if not temporary and bytes(sub.key) == bytes(guid(GUARD_KEY)):
        f.flags = 1  # FWPM_FILTER_FLAG_PERSISTENT
    f.weight = Value(1, Data(number=weight))
    f.action.type = action
    array = (Condition * len(conditions))(*conditions)
    f.conditions, f.count = array, len(array)
    ident = c.c_uint64()
    call('FwpmFilterAdd0', engine, c.byref(f), None, c.byref(ident))
    return ident


def permit_endpoint(engine, sub, app, ip, transport):
    port, protocol = transport
    return add_filter(engine, sub, LAYERS[0], 'VPN endpoint', PERMIT, 13, [
        Condition(guid(APP), 0, Value(12, Data(pointer=app.value))),
        Condition(guid(REMOTE), 0, Value(3, Data(number=int(ip)))),
        Condition(guid('c35a604d-d22b-4e1a-91b4-68f674ee674b'), 0, Value(2, Data(number=port))),
        Condition(guid('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7'), 0, Value(1, Data(number=protocol)))])


def replace_endpoints(engine, sub, app, previous, addresses, transport):
    call('FwpmTransactionBegin0', engine, 0)
    try:
        for ident in previous:
            call('FwpmFilterDeleteById0', engine, ident)
        updated = [permit_endpoint(engine, sub, app, ip, transport) for ip in addresses]
        call('FwpmTransactionCommit0', engine)
        return updated
    except BaseException:
        api.FwpmTransactionAbort0(engine)
        raise


class V4Mask(c.Structure):
    _fields_ = [('address', DWORD), ('mask', DWORD)]


class V6Mask(c.Structure):
    _fields_ = [('address', c.c_ubyte * 16), ('prefix', c.c_uint8)]


def permit_network(engine, sub, app, net):
    if net.version == 4:
        mask = V4Mask(int(net.network_address), int(net.netmask))
        kind = 0x100
    else:
        mask = V6Mask((c.c_ubyte * 16).from_buffer_copy(net.network_address.packed), net.prefixlen)
        kind = 0x101
    return add_filter(engine, sub, LAYERS[net.version == 6], 'Xray direct network', PERMIT, 13, [
        Condition(guid(APP), 0, Value(12, Data(pointer=app.value))),
        Condition(guid(REMOTE), 0, Value(kind, Data(pointer=c.addressof(mask))))])


def sync_direct_filters(engine, sub, app, previous, targets):
    updated = previous.copy()
    call('FwpmTransactionBegin0', engine, 0)
    try:
        for net in previous.keys() - targets:
            call('FwpmFilterDeleteById0', engine, updated.pop(net))
        for net in targets - previous.keys():
            updated[net] = permit_network(engine, sub, app, net)
        call('FwpmTransactionCommit0', engine)
        return updated
    except BaseException:
        api.FwpmTransactionAbort0(engine)
        raise


def worker(exe, endpoints, seconds, watch_host, prepared, tun_luid=None, direct=False):
    _, _, transport = read_node_details()
    direct_ids = {}
    applied = set()
    if direct:
        from xray_direct import config_path, direct_networks
        path = config_path()
    session = Session()
    session.flags = 1  # FWPM_SESSION_FLAG_DYNAMIC
    engine = PTR()
    call('FwpmEngineOpen0', None, 10, None, c.byref(session), c.byref(engine))
    app = PTR()
    try:
        call('FwpmGetAppIdFromFileName0', c.c_wchar_p(str(exe)), c.byref(app))
        sub = Sublayer()
        sub.key = guid(str(uuid.uuid4()))
        sub.display.name = 'Bridge temporary outbound guard'
        sub.weight = 0x8000
        call('FwpmTransactionBegin0', engine, 0)
        call('FwpmSubLayerAdd0', engine, c.byref(sub), None)
        for version, layer in enumerate(LAYERS, 4):
            rules = [('loopback', PERMIT, 14, [
                Condition(guid(FLAGS), 6, Value(3, Data(number=1)))])]
            if tun_luid:
                luid = c.c_uint64(tun_luid)
                rules.append(('trial TUN interface', PERMIT, 13, [
                    Condition(guid('4cd62a49-59c3-4969-b7f3-bda5d32890a4'), 0,
                              Value(4, Data(pointer=c.addressof(luid)))) ]))
            rules.append(('other connections', BLOCK, 1, []))
            for label, action, weight, conditions in rules:
                add_filter(engine, sub, layer, label, action, weight, conditions)
        if direct:
            applied = direct_networks(path)
            direct_ids = {net: permit_network(engine, sub, app, net) for net in applied}
        permits = [permit_endpoint(engine, sub, app, ip, transport) for ip in endpoints]
        call('FwpmTransactionCommit0', engine)
        print(f'Guard active for {seconds} seconds.', flush=True)
        if direct:
            print(f'已提交 {len(direct_ids)} 条 Xray 目标网段规则；节点端口 {transport[0]}，协议 {transport[1]}', file=sys.stderr, flush=True)
        deadline = time.monotonic() + seconds
        switch_pending = False
        switch_seen = False
        next_probe = 0.0
        while time.monotonic() < deadline:
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            if direct and time.monotonic() < deadline:
                try:
                    targets = direct_networks(path)
                except (OSError, KeyError, ValueError, TypeError):
                    targets = set()
                if targets != applied:
                    direct_ids = sync_direct_filters(engine, sub, app, direct_ids, targets)
                    applied = targets
                    print(f'Xray direct network filters active: {len(applied)}', file=sys.stderr, flush=True)
            if not watch_host or time.monotonic() >= deadline:
                continue
            try:
                core, host, next_transport = read_node_details()
                if host == watch_host and core == exe and next_transport == transport:
                    if switch_pending and next_probe <= time.monotonic() < deadline - 4:
                        ready = local_proxy_ready()
                        ok = ready and probe_proxy_targets(
                                             timeout=min(10, int(deadline - time.monotonic()) - 2))
                        try:
                            states = upstream_tcp_states(prepared.get(host, []))
                            print(f'1081 owner TCP to allowed IP: {states}', file=sys.stderr, flush=True)
                        except (OSError, subprocess.SubprocessError) as exc:
                            print(f'TCP observation unavailable: {type(exc).__name__}', file=sys.stderr)
                        print(f'After switch: {host}, 1081 proxy={ok}, listener={ready}, '
                              f'remaining={max(0, deadline-time.monotonic()):.1f}s',
                              file=sys.stderr, flush=True)
                        switch_pending = not ok
                        next_probe = time.monotonic() + 1
                    continue
                if core != exe:
                    raise ValueError('Core changed')
                addresses = prepared.get(host) or resolve_node(host)
                permits = replace_endpoints(engine, sub, app, permits, addresses, next_transport)
                transport = next_transport
                watch_host = host
                prepared[host] = addresses
                print(f'Updated WFP endpoint: {host} -> {addresses}', file=sys.stderr, flush=True)
                switch_pending = switch_seen = True
                next_probe = 0.0
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                if permits:
                    print('Node update failed. Old permit revoked.', file=sys.stderr, flush=True)
                    permits = replace_endpoints(engine, sub, app, permits, [], transport)
                switch_pending = switch_seen = True
                watch_host = '<retry>'
        if switch_pending:
            raise SystemExit('Neither HTTPS test target succeeded via 1081 after switch inside protection window.')
        if watch_host and not switch_seen:
            print('No endpoint switch observed.', file=sys.stderr)
    finally:
        if app:
            api.FwpmFreeMemory0(c.byref(app))
        call('FwpmEngineClose0', engine)


def upstream_tcp_states(addresses):
    # Match connections by the PID that owns 1081 and the permitted peer IP.
    cmd = Path(os.environ['SystemRoot']) / 'System32' / 'netstat.exe'
    rows = [line.split() for line in subprocess.check_output(
        [str(cmd), '-ano', '-p', 'TCP'], timeout=2
    ).decode(errors='replace').splitlines()]
    rows = [r for r in rows if len(r) == 5 and r[0] == 'TCP']
    owners = {r[4] for r in rows if r[1].endswith(':1081') and r[2].endswith(':0')}
    peers = {str(address) for address in addresses}
    return sorted({r[2] + '/' + r[3] for r in rows
                   if r[4] in owners and r[2].rsplit(':', 1)[0] in peers})


def local_proxy_ready():
    try:
        with socket.create_connection(('127.0.0.1', 1081), timeout=0.4):
            return True
    except OSError:
        return False


def probe_proxy_targets(timeout):
    urls = ['https://www.google.com/generate_204', 'https://www.cloudflare.com/cdn-cgi/trace']
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        jobs = [pool.submit(probe, None, True, True, timeout, url) for url in urls]
        results = [job.result() for job in jobs]
    return any(results)


def probe(ip, proxy=False, diagnostic=False, timeout=3, url='https://www.google.com/generate_204'):
    curl = Path(os.environ['SystemRoot']) / 'System32' / 'curl.exe'
    args = [str(curl), '--disable', '--silent', '--output', 'NUL', '--fail',
            '--max-time', str(timeout), '--noproxy', '' if proxy else '*']
    if proxy:
        args += ['--proxy', 'socks5h://127.0.0.1:1081', url]
    else:
        args += ['--resolve', f'www.baidu.com:443:{ip}', 'https://www.baidu.com/']
    if diagnostic:
        args[-1:-1] = ['--show-error', '--write-out',
                       'local TCP=%{time_connect} TLS=%{time_appconnect} HTTP=%{http_code}']
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 2)
        print(f'HTTPS probe {url if proxy else "Baidu direct"}: curl={result.returncode} {result.stdout.strip()} '
              f'{result.stderr.strip()}', file=sys.stderr, flush=True)
        return result.returncode == 0
    return subprocess.run(args, timeout=timeout + 2).returncode == 0


def dns_probe():
    # Send a fresh UDP query directly, independently of the Windows DNS cache.
    token = os.urandom(2)
    packet = token + bytes.fromhex(
        '01000001000000000000 0377777705626169647503636f6d00 00010001')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.5)
        try:
            sock.connect(('223.5.5.5', 53))
            sock.send(packet)
            reply = sock.recv(4096)
            return len(reply) >= 12 and reply[:2] == token and bool(reply[2] & 128)
        except OSError:
            return False


def trial(args):
    ip = socket.gethostbyname('www.baidu.com')
    for label, use_proxy in [('IPv4 direct to Baidu', False), ('1081 proxy to Google', True)]:
        for attempt in range(1, 4):
            print(f'Baseline {label}, attempt {attempt}', flush=True)
            if probe(ip, proxy=use_proxy, diagnostic=True, timeout=12 if use_proxy else 3):
                break
            if attempt < 3:
                time.sleep(1)
        else:
            raise RuntimeError(f'Baseline failed: {label}. No filters installed.')
    dns_baseline = dns_probe()
    with tempfile.TemporaryFile() as log:
        prepared = {}
        if args.watch_host:
            prepared[args.watch_host] = list(map(str, args.endpoint))
            for host in args.prepare_host:
                if host not in prepared:
                    prepared[host] = list(map(str, resolve_node(host, retries=1)))
            print('Prepared endpoints:', ', '.join(prepared), flush=True)
        process = subprocess.Popen([sys.executable, __file__, '--worker', '--core', str(args.core),
                                    '--seconds', str(args.seconds), '--prepared', json.dumps(prepared), *(['--watch-host', args.watch_host] if args.watch_host else []), *[part for ip in args.endpoint
                                    for part in ('--endpoint', str(ip))]],
                                   stdout=log)
        try:
            deadline = time.monotonic() + 5
            while not os.fstat(log.fileno()).st_size:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('WFP worker did not activate')
                time.sleep(0.05)
            print('Guard active. Switch in v2rayN now.', flush=True)
            blocked = not probe(ip)
            proxy_ok = probe(ip, proxy=True)
            dns_blocked = not dns_probe() if dns_baseline else None
            active = process.poll() is None
            process.wait(timeout=args.seconds + 2)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    recovered = probe(ip)
    print(f'Direct UDP DNS blocked={dns_blocked} (None means baseline unavailable)')
    print(f'Direct blocked={blocked}, initial 1081 proxy={proxy_ok}, '
          f'probes inside test window={active}, recovered={recovered}')
    if not (blocked and dns_blocked is True and proxy_ok and active and recovered and process.returncode == 0):
        raise RuntimeError('Trial incomplete or failed')


def read_node_details():
    settings = Path(os.environ['LOCALAPPDATA']) / 'v2rayn-tun-controller' / 'gui-settings.json'
    root = Path(json.loads(settings.read_text(encoding='utf-8-sig'))['app_root'])
    config = json.loads((root / 'binConfigs' / 'config.json').read_text(encoding='utf-8-sig'))
    proxy = next((item for item in config['outbounds'] if item.get('tag') == 'proxy'), {})
    if proxy.get('protocol') not in {'hysteria', 'vless', 'vmess', 'trojan', 'shadowsocks'}:
        raise ValueError('Unrecognized Xray outbound. Supply explicit core and endpoint.')
    if proxy.get('proxySettings') or proxy.get('streamSettings', {}).get('sockopt', {}).get('dialerProxy'):
        raise ValueError('Chained outbound requires explicit core and endpoint.')
    node = proxy['settings']
    servers = node.get('vnext') or node.get('servers') or [node]
    if len(servers) != 1 or not servers[0].get('address'):
        raise ValueError('Cannot identify a single upstream server.')
    host = servers[0]['address']
    port = int(servers[0]['port'])
    network = proxy.get('streamSettings', {}).get('network', 'tcp').lower()
    if proxy.get('protocol') == 'hysteria':
        protocol = 17
    elif network in {'tcp','raw','ws','grpc','http','httpupgrade','splithttp','xhttp','h2'}:
        protocol = 6
    elif network in {'quic','kcp','hysteria','hysteria2'}:
        protocol = 17
    else:
        raise ValueError(f'Unsupported node transport: {network}')
    if not 1 <= port <= 65535:
        raise ValueError('Invalid node port')
    return root / 'bin' / 'Xray' / 'xray.exe', host, (port, protocol)


def read_node():
    core, host, _ = read_node_details()
    return core, host


def resolve_node(host, retries=0):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        query = urlencode({'name': host, 'type': 'A'})
        curl = Path(os.environ['SystemRoot']) / 'System32' / 'curl.exe'
        for attempt in range(retries + 1):
            try:
                result = subprocess.run([str(curl), '--disable', '--fail', '--silent',
                                         '--max-time', '3', '--noproxy', '', '--proxy',
                                         'socks5h://127.0.0.1:1081',
                                         'https://dns.google/resolve?' + query],
                                        capture_output=True, check=True, timeout=4)
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                transient = isinstance(exc, subprocess.TimeoutExpired) or exc.returncode == 28
                if attempt == retries or not transient:
                    raise ValueError(f'通过 1081 查询 {host} 失败，请检查代理连接') from None
        reply = json.loads(result.stdout)
        if reply.get('Status') != 0:
            raise ValueError('Protected DNS lookup failed')
        addresses = sorted({ipaddress.IPv4Address(a['data']) for a in
                            reply.get('Answer', []) if a['type'] == 1})
    else:
        addresses = [ipaddress.IPv4Address(address)]
    if not addresses or any(not ip.is_global for ip in addresses):
        raise ValueError('VPN endpoint did not resolve exclusively to public IPv4.')
    return addresses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path)
    parser.add_argument('--endpoint', action='append', type=ipaddress.IPv4Address)
    parser.add_argument('--seconds', type=int, choices=range(5, 31), default=15, metavar='5..30')
    parser.add_argument('--prepare-host', action='append', default=[])
    parser.add_argument('--prepared', default='{}', help=argparse.SUPPRESS)
    parser.add_argument('--watch-host', help=argparse.SUPPRESS)
    parser.add_argument('--xray-direct', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--tun-luid', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if c.sizeof(PTR) != 8 or Filter.effective.offset != 184:
        raise RuntimeError('Unsupported WFP structure layout')
    if not args.core or not args.endpoint:
        core, host = read_node()
        endpoints = args.endpoint or resolve_node(host, retries=1)
        if not args.endpoint and not args.core:
            args.watch_host = host
        print(f"v2rayN endpoint: {host} -> {endpoints}")
        args.core = args.core or core
        args.endpoint = args.endpoint or endpoints
    if not args.core.is_absolute() or not args.core.is_file():
        parser.error('Specify the absolute path of the active v2rayN core')
    if args.check:
        print('Arguments and Windows x64 ABI checked. No filters installed.')
        return
    if not c.windll.shell32.IsUserAnAdmin():
        parser.error('Administrator privileges required')
    if args.worker:
        if args.xray_direct:
            from xray_direct import verify_core
            verify_core(args.core)
        worker(args.core, args.endpoint, args.seconds, args.watch_host,
               {h: [ipaddress.IPv4Address(ip) for ip in ips] for h, ips in json.loads(args.prepared).items()}, args.tun_luid, args.xray_direct)
    else:
        trial(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
