"""Current physical IPv4 link, local address checks, and captive portal session."""
import ctypes as c
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(os.environ['LOCALAPPDATA']) / 'v2rayn-tun-controller'
LOCAL = ROOT / 'local-addresses.json'
CANDIDATES = ROOT / 'hotspot-candidates.json'
PORTAL = ROOT / 'hotspot-session.json'
EVENTS = ROOT / 'hotspot-requests.log'


def save(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix=path.stem+'.', suffix='.tmp', delete=False) as stream:
        tmp = Path(stream.name)
        json.dump(value, stream, ensure_ascii=False)
    try:
        for attempt in range(8):
            try:
                os.replace(tmp, path)
                return
            except PermissionError as exc:
                if exc.winerror not in (5, 32, 33) or attempt == 7:
                    raise
                time.sleep(0.025 * (attempt + 1))
    finally:
        tmp.unlink(missing_ok=True)


def read(path):
    try:
        return json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return {}


def snapshot():
    # Restrict to physical adapters even while the TUN owns the preferred route.
    script = """
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$ids=@((Get-NetAdapter -Physical | Where-Object Status -eq Up).ifIndex)
$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
 Where-Object {$ids -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0'} |
 Sort-Object @{Expression={$_.RouteMetric+$_.InterfaceMetric}} | Select-Object -First 1
if (!$r) {throw 'No physical default route'}
$i=$r.ifIndex
$a=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $i -AddressState Preferred | Where-Object {!$_.SkipAsSource} | Select-Object -First 1
$v6=@(Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex $i -AddressState Preferred -ErrorAction SilentlyContinue | Where-Object {!$_.SkipAsSource} | ForEach-Object {"$($_.IPAddress)/$($_.PrefixLength)"} | Sort-Object)
$n=Get-NetAdapter -InterfaceIndex $i
$p=Get-NetConnectionProfile -InterfaceIndex $i -ErrorAction SilentlyContinue | Select-Object -First 1
$d=@((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses)
$ssid=''; $auth=''; $connected=''
if ([int]$n.NdisPhysicalMedium -in 1,9) {
  $event=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';Id=8001} -MaxEvents 16 -ErrorAction SilentlyContinue | Where-Object {
    $data=@{}; foreach($field in ([xml]$_.ToXml()).Event.EventData.Data){$data[$field.Name]=$field.'#text'}
    $data.InterfaceGuid -eq [string]$n.InterfaceGuid
  } | Select-Object -First 1
  if ($event) {
    $fields=@{};foreach($field in ([xml]$event.ToXml()).Event.EventData.Data){$fields[$field.Name]=$field.'#text'}
    $ssid=$fields.SSID; $auth=$fields.AuthenticationAlgorithm; $connected=[string]$event.RecordId+'-'+[string]$event.TimeCreated.Ticks
  }
}
[pscustomobject]@{ssid=$ssid;auth=$auth;connection=$connected;wifi=([int]$n.NdisPhysicalMedium -in 1,9);ipv6=$v6;name=$n.Name;guid=[string]$n.InterfaceGuid;profile=[string]$p.Name;index=$i;ip=$a.IPAddress;prefix=$a.PrefixLength;gateway=$r.NextHop;dns=$d} | ConvertTo-Json -Compress
"""
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    proc=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-Command',script],
                        capture_output=True,timeout=12,creationflags=subprocess.CREATE_NO_WINDOW)
    if proc.returncode:
        raise RuntimeError('未检测到可用物理网络')
    net=json.loads(proc.stdout.decode('utf-8-sig'))
    net['subnet']=str(ipaddress.ip_network(f"{net['ip']}/{net['prefix']}",strict=False))
    net['id']=hashlib.sha256(json.dumps(net,sort_keys=True).encode()).hexdigest()
    return net


def local_network(text, net):
    value=ipaddress.ip_network(text.strip(),strict=True)
    local=ipaddress.ip_network(net['subnet'])
    allowed=[local]+[ipaddress.ip_interface(addr).network for addr in net.get('ipv6',[])]
    if value.prefixlen==0 or not any(value.version==n.version and value.subnet_of(n) for n in allowed):
        raise ValueError('请输入当前物理网卡直连网段内的 IP 地址或 CIDR')
    return value


def login_url(text):
    raw=text.strip()
    parsed=urlsplit(raw if '://' in raw else 'http://'+raw)
    if parsed.scheme not in ('http','https') or parsed.username is not None or parsed.password is not None:
        raise ValueError('请输入 HTTP 或 HTTPS 登录地址')
    host=(parsed.hostname or '').rstrip('.').encode('idna').decode().lower()
    if (not re.fullmatch(r'[a-z0-9.-]{1,253}',host) or parsed.port not in (None,80,443)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',s) for s in host.split('.'))):
        raise ValueError('仅支持精确主机名或 IPv4，端口 80 或 443')
    if host=='localhost' or host.endswith('.localhost'):
        raise ValueError('不能将本机作为热点登录地址')
    return host,parsed.geturl()

LAN_OPTIONS = ROOT / 'lan-options.json'


def wifi_key(net):
    if not net.get('wifi') or not net.get('ssid') or not net.get('connection'):
        return ''
    return json.dumps([net['guid'].lower(),net['ssid'],net.get('auth','')],ensure_ascii=False)


def clear_temporary_lan():
    data=read(LAN_OPTIONS)
    if 'temporary' in data:
        del data['temporary']
        save(LAN_OPTIONS,data)


def lan_config(net):
    data=read(LAN_OPTIONS)
    key=wifi_key(net)
    saved=data.get('saved',{})
    remembered=bool(key and key in saved)
    session=data.get('temporary',{})
    if remembered:
        items=saved[key]['addresses']
    elif session.get('id')==net['id'] and (not net.get('wifi') or net.get('connection')):
        items=session.get('addresses',[])
    else:
        items=[]
    # A remembered address can be outside today's DHCP subnet. Keep it in the
    # editor but never install it until this interface is on-link again.
    return remembered, list(items)


def set_lan_config(net,items,remember):
    data=read(LAN_OPTIONS)
    saved=data.setdefault('saved',{})
    key=wifi_key(net)
    if net.get('wifi') and not net.get('connection'):
        raise ValueError('未能识别本次 Wi-Fi 连接，请刷新网络状态后重试')
    if remember and not key:
        raise ValueError('无法确认当前 Wi-Fi 身份，配置仅可用于本次连接')
    if remember:
        saved[key]={'ssid':net['ssid'],'addresses':sorted(set(items))}
        data.pop('temporary',None)
    else:
        saved.pop(key,None)
        data['temporary']={'id':net['id'],'addresses':sorted(set(items))}
    save(LAN_OPTIONS,data)


def active_ranges(net,items):
    result=set()
    for item in items:
        try:
            result.add(local_network(item,net))
        except ValueError:
            continue
    return tuple(sorted(result,key=lambda n:(n.version,int(n.network_address),n.prefixlen)))


def link_filters(net, ranges, portal, pins, guard):
    """Hold transient permits in a dynamic WFP session, owned by the network watcher."""
    from contextlib import ExitStack
    stack=ExitStack()
    try:
        engine=guard.ptr()
        sess=guard.g['Session']()
        sess.flags=1
        guard.call('FwpmEngineOpen0',None,10,None,c.byref(sess),c.byref(engine))
        stack.callback(guard.api.FwpmEngineClose0,engine)
        sub=guard.g['Sublayer']()
        sub.key=guard.key
        luid=c.c_uint64()
        if c.windll.iphlpapi.ConvertInterfaceAliasToLuid(c.c_wchar_p(net['name']),c.byref(luid)):
            raise ValueError('物理网卡已离线')
        g=guard.g
        def cond(key,kind,data,match=0):
            return g['Condition'](g['guid'](key),match,g['Value'](kind,data))
        bound=cond('4cd62a49-59c3-4969-b7f3-bda5d32890a4',4,g['Data'](pointer=c.addressof(luid)))
        def add(name, conditions, version=4):
            g['add_filter'](engine,sub,g['LAYERS'][version==6],name,g['PERMIT'],14,[bound,*conditions],temporary=True)
        def port(number,match=0):
            return cond('c35a604d-d22b-4e1a-91b4-68f674ee674b',2,g['Data'](number=number),match)
        def protocol(number):
            return cond('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7',1,g['Data'](number=number))
        with guard.transaction(engine):
            for network in ranges:
                if network.version==4:
                    mask=g['V4Mask'](int(network.network_address),int(network.netmask))
                    kind=0x100
                    source=g['Data'](number=int(ipaddress.IPv4Address(net['ip'])))
                    source_type=3
                else:
                    mask=g['V6Mask']((c.c_ubyte*16).from_buffer_copy(network.network_address.packed),network.prefixlen)
                    kind=0x101
                    source_address=next(ipaddress.ip_interface(a).ip for a in net['ipv6']
                                        if network.subnet_of(ipaddress.ip_interface(a).network))
                    raw=(c.c_ubyte*16).from_buffer_copy(source_address.packed)
                    source=g['Data'](pointer=c.addressof(raw))
                    source_type=11
                local_ip=cond('d9ee00de-c1ef-4617-bfe3-ffd8f5a08957',source_type,source)
                remote=cond(g['REMOTE'],kind,g['Data'](pointer=c.addressof(mask)))
                add('Approved LAN ICMP',[local_ip,remote,protocol(1 if network.version==4 else 58)],network.version)
                # Separate port intervals avoid WFP same-field OR semantics.
                for lo,hi in ((1,52),(54,852),(854,65535)):
                    class Range(c.Structure):
                        _fields_=[('lo',g['Value']),('hi',g['Value'])]
                    interval=Range(g['Value'](2,g['Data'](number=lo)),g['Value'](2,g['Data'](number=hi)))
                    add('Approved LAN address',[local_ip,remote,cond('c35a604d-d22b-4e1a-91b4-68f674ee674b',0x102,g['Data'](pointer=c.addressof(interval)),5)],network.version)
            if portal:
                exe=Path(__file__).resolve().parent/'PortalRelay.exe'
                app=guard.ptr()
                guard.call('FwpmGetAppIdFromFileName0',c.c_wchar_p(str(exe)),c.byref(app))
                try:
                    identity=cond(g['APP'],12,g['Data'](pointer=app.value))
                    resolver=ipaddress.IPv4Address(net['dns'][0])
                    dns=cond(g['REMOTE'],3,g['Data'](number=int(resolver)))
                    add('Portal relay DNS',[identity,dns,protocol(17),port(53)])
                    for address,number in pins:
                        add('Approved portal destination',[identity,cond(g['REMOTE'],3,g['Data'](number=int(address))),protocol(6),port(number)])
                finally:
                    guard.api.FwpmFreeMemory0(c.byref(app))
        return stack
    except BaseException:
        stack.close()
        raise


def watch_link(guard):
    kernel=c.windll.kernel32
    kernel.CreateMutexW.restype=c.c_void_p
    lock=kernel.CreateMutexW(None,False,'Global\\BridgeLocalLinkPermitsV1')
    if not lock:
        raise c.WinError()
    permits=None
    started=time.time()
    owns=False
    previous=None
    try:
        if kernel.WaitForSingleObject(c.c_void_p(lock),0) not in (0,128):
            return
        owns=True
        with guard.engine() as handle:
            while guard.installed(handle) and read(ROOT/'link-stop.json').get('time',0)<started:
                try:
                    net=snapshot()
                except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired):
                    if permits:
                        permits.close()
                        permits=None
                    previous=None
                    save(ROOT/'link-active.json',{})
                    if not read(LAN_OPTIONS).get('saved'):
                        return
                    time.sleep(2)
                    continue
                _,lan=lan_config(net)
                session=read(PORTAL)
                active=(session.get('link')==net['id'] and time.time()<session.get('expires',0))
                selected=frozenset(session.get('hosts',[])) if active else frozenset()
                if session.get('link') and not active:
                    save(PORTAL,{})
                values=active_ranges(net,lan)
                pins=set()
                if active:
                    token=session['token']
                    if not re.fullmatch('[0-9a-f]{32}',token):
                        raise ValueError('无效会话')
                    hostsfile=ROOT/('portal-'+token+'.txt')
                    authorized=selected & set(hostsfile.read_text(encoding='ascii').splitlines())
                    pinfile=Path(str(hostsfile)+'.pins')
                    for line in pinfile.read_text(encoding='ascii').splitlines()[-500:] if pinfile.exists() else []:
                        fields=line.split()
                        if len(fields)==3 and fields[0] in authorized and fields[2] in ('80','443'):
                            ip=ipaddress.IPv4Address(fields[1])
                            if not (ip.is_loopback or ip.is_multicast or ip.is_unspecified or str(ip)==net['ip']):
                                pins.add((ip,int(fields[2])))
                marker=(net['id'],values,session.get('token') if active else None,frozenset(pins),selected)
                if marker!=previous:
                    old=permits
                    if old and not (previous and previous[:3]==marker[:3] and previous[4]==marker[4] and previous[3]<=marker[3]):
                        old.close()
                        old=None
                    permits=link_filters(net,values,bool(active and selected),pins,guard) if values or (active and selected) else None
                    if old:
                        old.close()
                    if active:
                        ack=Path(str(hostsfile)+'.ack')
                        tmp=ack.with_suffix('.ack.tmp')
                        tmp.write_text('\n'.join(f'{ip} {port}' for ip,port in pins),encoding='ascii')
                        os.replace(tmp,ack)
                    previous=marker
                    save(ROOT/'link-active.json',{'link':net['id'],'token':marker[2],'hosts':sorted(selected),'lan':lan,'time':time.time()})
                if not values and not active and not read(LAN_OPTIONS).get('saved'):
                    return
                time.sleep(.5)
    finally:
        if permits:
            permits.close()
        if owns:
            save(ROOT/'link-active.json',{})
        kernel.CloseHandle(c.c_void_p(lock))
