"""Bounded IPv4 TUN acceptance trial on Windows x64."""
import argparse
import ctypes as c
import ipaddress
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
GUARD = HERE / '限时出站保护.py'
if not GUARD.is_file():
    GUARD = HERE / 'outbound-guard-trial.py'
g = runpy.run_path(str(GUARD))
iphlp = c.WinDLL('iphlpapi')
HOST = 'www.cloudflare.com'


def iface(name):
    luid = c.c_uint64()
    index = c.c_uint32()
    if iphlp.ConvertInterfaceAliasToLuid(c.c_wchar_p(name), c.byref(luid)):
        return None, None
    if iphlp.ConvertInterfaceLuidToIndex(c.byref(luid), c.byref(index)):
        raise RuntimeError('Could not identify TUN interface')
    return luid.value, index.value


def route(ip):
    index = c.c_uint32()
    if iphlp.GetBestInterface(c.c_uint32(int.from_bytes(socket.inet_aton(ip), 'little')), c.byref(index)):
        raise RuntimeError('Could not read route')
    return index.value


def direct(ip):
    curl = Path(os.environ['SystemRoot']) / 'System32/curl.exe'
    result = subprocess.run([str(curl), '--disable', '-4', '--noproxy', '*',
                             '--resolve', f'{HOST}:443:{ip}', '--silent', '--max-time', '5',
                             '--output', 'NUL', '--write-out', '%{http_code}',
                             f'https://{HOST}/cdn-cgi/trace'], capture_output=True)
    return result.returncode == 0 and result.stdout == b'200'


def ipv6_probe(address):
    curl = Path(os.environ['SystemRoot']) / 'System32/curl.exe'
    result = subprocess.run([str(curl), '--disable', '-6', '--noproxy', '*',
                             '--resolve', f'{HOST}:443:[{address}]', '--silent',
                             '--max-time', '3', '--output', 'NUL', '--write-out',
                             '%{http_code}', f'https://{HOST}/cdn-cgi/trace'],
                            capture_output=True, timeout=5)
    return result.returncode == 0 and result.stdout == b'200'


def reachable_ipv6():
    try:
        addresses = socket.getaddrinfo(HOST, 443, socket.AF_INET6, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    for entry in addresses[:2]:
        address = entry[4][0]
        if ipv6_probe(address):
            return address
    return None


def own_core(binary, directory):
    stop = threading.Event()
    def watch_parent():
        sys.stdin.buffer.read(1)
        stop.set()
    threading.Thread(target=watch_parent, daemon=True).start()
    with open(Path(directory) / 'core.log', 'wb') as log:
        core = subprocess.Popen([binary, '-d', directory, '-f', str(Path(directory) / 'trial.json')],
                                stdout=log, stderr=log)
        try:
            end = time.monotonic() + 40
            while core.poll() is None and time.monotonic() < end and not stop.wait(.2):
                pass
        finally:
            if core.poll() is None:
                core.terminate()
            core.wait()


def trial(binary, check, direct_rules=False):
    exe, host = g['read_node']()
    endpoints = g['resolve_node'](host, retries=1)
    ip = socket.gethostbyname(HOST)
    if not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip) in endpoints:
        raise RuntimeError('Probe address unsuitable')
    original = route(ip)
    name = 'BridgeTrial' + uuid.uuid4().hex[:6]
    cfg = {'mode':'rule', 'ipv6':False, 'tun':{'enable':True, 'device':name,
           'stack':'gvisor', 'auto-route':True, 'auto-detect-interface':True,
           'route-address':[ip+'/32'], 'strict-route':False},
           'proxies':[{'name':'v2rayN','type':'socks5','server':'127.0.0.1','port':1081}],
           'rules':['MATCH,v2rayN']}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        conf = root / 'trial.json'
        conf.write_text(json.dumps(cfg))
        subprocess.run([binary,'-t','-d',temp,'-f',str(conf)],check=True)
        if not direct(ip) or not g['dns_probe']() or not g['probe_proxy_targets'](8):
            raise RuntimeError('Baseline unavailable; test did not start')
        v6 = reachable_ipv6()
        print('IPv6 HTTPS baseline:', 'available' if v6 else 'unavailable; IPv6 test skipped', flush=True)
        if check:
            print('PASS: config, direct HTTPS, UDP DNS and 1081 baseline')
            return
        if not c.windll.shell32.IsUserAnAdmin():
            raise RuntimeError('Administrator PowerShell required')
        guard = None
        with tempfile.TemporaryFile() as log:
            owner = subprocess.Popen([sys.executable,__file__,'--own',str(binary),temp],stdin=subprocess.PIPE)
            try:
                deadline = time.monotonic()+8
                while time.monotonic()<deadline:
                    luid, index = iface(name)
                    if luid and route(ip)==index:
                        break
                    time.sleep(.15)
                else:
                    raise RuntimeError('Trial TUN did not acquire probe route: '+(root/'core.log').read_text(errors='replace')[-500:])
                guard = subprocess.Popen([sys.executable,str(GUARD),'--worker','--core',str(exe),
                                          *(['--xray-direct'] if direct_rules else []),'--seconds','30','--tun-luid',str(luid),
                                          *[item for addr in endpoints for item in ('--endpoint',str(addr))]],stdout=log)
                deadline=time.monotonic()+(20 if direct_rules else 5)
                while not os.fstat(log.fileno()).st_size:
                    if guard.poll() is not None or time.monotonic()>deadline:
                        raise RuntimeError('Guard did not activate')
                    time.sleep(.1)
                forwarded = route(ip)==index and direct(ip) and route(ip)==index
                print('1. Unproxied HTTPS through trial TUN:',forwarded,flush=True)
                owner.stdin.close()
                owner.wait(timeout=5)
                deadline=time.monotonic()+3
                while route(ip)!=original and time.monotonic()<deadline:
                    time.sleep(.1)
                blocked = route(ip)==original and not direct(ip) and not g['dns_probe']()
                print('2. TUN stopped, direct HTTPS and UDP DNS blocked:',blocked,flush=True)
                v6_blocked = not ipv6_probe(v6) if v6 else None
                if v6:
                    print('IPv6 direct HTTPS blocked:', v6_blocked, flush=True)
                upstream = g['probe_proxy_targets'](6)
                inside = guard.poll() is None
                print('3. 1081 reachable after TUN exit:',upstream and inside,flush=True)
                guard.wait(timeout=33)
                recovered = guard.returncode==0 and route(ip)==original and direct(ip) and g['dns_probe']()
                print('4. Timed rollback and recovery:',recovered)
                v6_recovered = ipv6_probe(v6) if v6 else None
                if v6:
                    print('IPv6 after rollback:', v6_recovered)
                if not all((forwarded,blocked,upstream,inside,recovered)) or (v6 and not (v6_blocked and v6_recovered)):
                    raise RuntimeError('Acceptance trial incomplete or failed')
            finally:
                if not owner.stdin.closed:
                    owner.stdin.close()
                owner.wait(timeout=7)
                if guard and guard.poll() is None:
                    guard.kill()
                    guard.wait()


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--own',nargs=2,help=argparse.SUPPRESS)
    default=HERE/'runtime/mihomo.exe'
    if not default.exists():
        default=Path(os.environ['LOCALAPPDATA'])/'v2rayn-tun-controller/mihomo-controller.exe'
    parser.add_argument('--mihomo',default=default,type=Path)
    parser.add_argument('--xray-direct', action='store_true')
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    try:
        if args.own:
            own_core(*args.own)
        else:
            trial(args.mihomo,args.check,args.xray_direct)
    except (RuntimeError,OSError,subprocess.SubprocessError,ValueError) as exc:
        sys.exit(str(exc))
