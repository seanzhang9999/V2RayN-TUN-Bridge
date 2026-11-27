"""Read-only five-minute incident history for the Windows guard console."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import select
import socket
import ssl
import struct
import subprocess
import threading
import time

from local_access import ROOT, read, save

HISTORY = ROOT / 'network-last-5m.json'
SAVED = ROOT / 'network-incident.json'
WINDOW, INTERVAL = 300, 15
SYSTEM = Path(os.environ['SystemRoot']) / 'System32'

# Get adapters even when DHCP has left only a link-local address and no route.
# Only retain event fields useful for diagnosis, never raw event messages.
LINK_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$since=[DateTimeOffset]::FromUnixTimeMilliseconds(SINCE_MS).LocalDateTime
$until=[DateTimeOffset]::FromUnixTimeMilliseconds(UNTIL_MS).LocalDateTime
$adapters=@(Get-NetAdapter -Physical)
$profiles=@(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
$cfg=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')
$links=@(foreach($a in $adapters){
  $c=$cfg|Where-Object InterfaceIndex -eq $a.ifIndex|Select-Object -First 1
  $p=$profiles|Where-Object InterfaceIndex -eq $a.ifIndex|Select-Object -First 1
  $s=$a|Get-NetAdapterStatistics -ErrorAction SilentlyContinue
  [ordered]@{adapter=$a.Name;status=[string]$a.Status;profile=$p.Name;index=$a.ifIndex;
    ip=@($c.IPAddress|Where-Object {$_});gateway=@($c.DefaultIPGateway|Where-Object {$_});
    dhcp=$c.DHCPServer;lease=if($c.DHCPLeaseExpires){$c.DHCPLeaseExpires.ToString('s')};
    rx=$s.ReceivedBytes;tx=$s.SentBytes}
})
$events=@(foreach($spec in @(
  @{log='Microsoft-Windows-WLAN-AutoConfig/Operational';ids=@(8001,8002,8003)},
  @{log='Microsoft-Windows-Dhcp-Client/Admin';ids=@(1001,1002,1003)},
  @{log='Security';ids=@(5157)})){
  Get-WinEvent -FilterHashtable @{LogName=$spec.log;Id=$spec.ids;StartTime=$since;EndTime=$until} -MaxEvents 8 -ErrorAction SilentlyContinue |
    ForEach-Object {
      $v=@{};foreach($f in ([xml]$_.ToXml()).Event.EventData.Data){$v[[string]$f.Name]=[string]$f.'#text'}
      [ordered]@{at=$_.TimeCreated.ToString('HH:mm:ss');id=$_.Id;ssid=$v.SSID;
        app=if($v.Application){[IO.Path]::GetFileName($v.Application)};
        dst=$v.DestAddress;port=$v.DestPort;filter=$v.FilterRTID}
    }
})
$tun=Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'mihomo_tun_controller' -AddressState Preferred -ErrorAction SilentlyContinue|Select-Object -First 1
@{links=$links;events=$events;tun=if($tun){@{ip=$tun.IPAddress;index=$tun.InterfaceIndex}}}|ConvertTo-Json -Depth 5 -Compress
"""


def link_snapshot(since, until):
    script = LINK_SCRIPT.replace('SINCE_MS',str(int(1000*since)+1)).replace('UNTIL_MS',str(int(1000*until)))
    ps = SYSTEM / 'WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(ps), '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, timeout=9, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return json.loads(result.stdout.decode('utf-8-sig'))


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size-len(data))
        if not part:
            raise ConnectionError('本机监听器关闭连接')
        data.extend(part)
    return bytes(data)


def socks_udp():
    with socket.create_connection(('127.0.0.1',1081), timeout=1) as sock:
        sock.sendall(bytes.fromhex('050100'))
        if receive(sock,2) != b'\x05\x00':
            return 'SOCKS 握手失败'
        sock.sendall(bytes.fromhex('05030001000000000000'))
        version, status, _, _ = receive(sock,4)
        if version != 5:
            return '响应格式错误'
        return '接受' if status == 0 else f'拒绝 ({status})'


def local_dns():
    ident = os.urandom(2)
    question = bytes.fromhex('01000001000000000000076578616d706c6503636f6d0000010001')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.connect(('127.0.0.1',1053))
        sock.send(ident+question)
        data = sock.recv(2048)
    if len(data)<12 or data[:2]!=ident or not data[2]&128:
        return '无效响应'
    code = data[3]&15
    return '有应答' if code==0 and struct.unpack_from('!H',data,6)[0] else f'RCODE {code} / 无有效答案'


def proxy_https():
    # SOCKS resolves the hostname. A stopped proxy cannot turn this into a direct request.
    result = subprocess.run([str(SYSTEM/'curl.exe'),'--disable','--silent','--noproxy','',
                             '--proxy','socks5h://127.0.0.1:1081','--max-time','4',
                             '--output','NUL','--write-out','%{http_code} %{time_connect} %{time_appconnect}',
                             'https://www.google.com/generate_204'],capture_output=True,timeout=5,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    fields = result.stdout.decode('ascii',errors='replace').split()
    return dict(curl=result.returncode,http=fields[0] if fields else '?',
                tcp_s=fields[1] if len(fields)>1 else None,tls_s=fields[2] if len(fields)>2 else None)


def tunnel_tls(binding):
    # Windows IP_UNICAST_IF takes the interface index in network byte order.
    # Bind both interface and source; never fall back if the adapter vanishes.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.setsockopt(socket.IPPROTO_IP,31,struct.pack('!I',binding['index']))
        sock.bind((binding['ip'],0))
        try:
            sock.connect(('1.1.1.1',443))
        except OSError as exc:
            return f'TCP {type(exc).__name__}'
        try:
            with ssl.create_default_context().wrap_socket(sock,server_hostname='1.1.1.1') as tls:
                return tls.version()
        except OSError as exc:
            return f'TLS {type(exc).__name__}'


class WireCounts:
    """IPv4 counters on physical interfaces. No packet payloads go to disk."""
    def __init__(self,stop):
        self.lock=threading.Lock()
        self.stop=stop
        self.desired=((),(),0)
        self.interval={}
        threading.Thread(target=self.run,name='physical-ipv4-counters',daemon=True).start()

    def exchange(self,net,hb):
        addresses=tuple(sorted({ip for a in net.get('links',[]) if a['status']=='Up'
                                for ip in a['ip'] if ':' not in ip and ip!='0.0.0.0'}))
        with self.lock:
            previous=self.interval
            self.interval={}
            # A temporary CIM failure should not tear down a useful capture.
            if 'error' in net:
                addresses=self.desired[0]
            self.desired=(addresses,tuple(hb.get('addresses') or ()),hb.get('port') or 0)
            return previous

    def run(self):
        sockets={}
        failures={}
        buf=bytearray(65535)
        try:
            while not self.stop.is_set():
                with self.lock:
                    addresses,servers,port=self.desired
                node_ips={socket.inet_aton(ip) for ip in servers if ':' not in ip}
                for ip in list(sockets):
                    if ip not in addresses:
                        sockets.pop(ip).close()
                for ip in addresses:
                    if ip in sockets or failures.get(ip,0)>time.monotonic():
                        continue
                    sock=None
                    try:
                        sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
                        sock.bind((ip,0))
                        sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
                        sock.setblocking(False)
                        sockets[ip]=sock
                    except OSError as exc:
                        if sock: sock.close()
                        failures[ip]=time.monotonic()+10
                        with self.lock:
                            self.interval[ip]={'error':exc.winerror or str(exc)}
                if not sockets:
                    self.stop.wait(.3)
                    continue
                try:
                    ready=select.select(list(sockets.values()),[],[],.35)[0]
                except OSError as exc:
                    with self.lock:
                        for ip,sock in sockets.items():
                            self.interval[ip]={'error':exc.winerror or str(exc)}
                            sock.close()
                        sockets.clear()
                    self.stop.wait(1)
                    continue
                for ip,sock in list(sockets.items()):
                    with self.lock:
                        row=self.interval.setdefault(ip,{'since':time.time(),'node':list(servers),'port':port,
                            'nodeTx':0,'nodeRx':0,'tx':0,'rx':0,'dnsTx':0})
                    if sock not in ready or 'error' in row:
                        continue
                    local=socket.inet_aton(ip)
                    tx_count=rx_count=node_tx=node_rx=dns_tx=0
                    for _ in range(64):
                        try:
                            n=sock.recv_into(buf)
                        except BlockingIOError:
                            break
                        except OSError as exc:
                            sockets.pop(ip).close()
                            with self.lock:
                                self.interval.setdefault(ip,{})['error']=exc.winerror or str(exc)
                            break
                        if n<20 or buf[0]>>4!=4: continue
                        src,dst=bytes(buf[12:16]),bytes(buf[16:20])
                        if src!=local and dst!=local: continue
                        tx=src==local
                        offset=(buf[0]&15)*4
                        ports=buf[9] in (6,17) and n>=offset+4 and not (int.from_bytes(buf[6:8],'big')&8191)
                        sp,dp=struct.unpack_from('!HH',buf,offset) if ports else (0,0)
                        node=(dst if tx else src) in node_ips and (dp if tx else sp)==port
                        if tx:
                            tx_count+=1
                            node_tx+=int(node)
                            dns_tx+=int(dp==53)
                        else:
                            rx_count+=1
                            node_rx+=int(node)
                    with self.lock:
                        if self.interval.get(ip) is row:
                            row['tx']+=tx_count
                            row['rx']+=rx_count
                            row['nodeTx']+=node_tx
                            row['nodeRx']+=node_rx
                            row['dnsTx']+=dns_tx
        except (OSError,ValueError) as exc:
            with self.lock:
                self.interval['采样器']={'error':str(exc)}
        finally:
            for sock in sockets.values(): sock.close()


def probe(fn, *args):
    try:
        return fn(*args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {'error':type(exc).__name__,'code':getattr(exc,'winerror',None) or getattr(exc,'returncode',None)}


def core_events(since, until):
    path=ROOT/'mihomo-runtime-stdout.log'
    try:
        with path.open('rb') as f:
            f.seek(max(0,f.seek(0,2)-65536))
            tail=f.read(65536).decode('utf-8',errors='replace')
    except FileNotFoundError:
        return []
    events=[]
    for line in tail.splitlines():
        match=re.search(r'time="([^"]+)".*?level=(warning|error)',line)
        if not match:
            continue
        try:
            stamp=dt.datetime.fromisoformat(match[1]).timestamp()
        except ValueError:
            continue
        if not since < stamp <= until:
            continue
        reason=next((label for word,label in (
            ('default interface lost','默认接口丢失'),('default interface changed','默认接口改变'),
            ("can't resolve ip",'DNS 解析失败'),('not support','协议不支持'),
            ('deadline exceeded','超时'),('timeout','超时'),('refused','连接被拒绝'),
            ('forcibly closed','连接被重置')) if word in line.lower()),match[2])
        dest=re.search(r' --> ([\w.\[\]:-]{1,255})(?: |")',line)
        events.append([dt.datetime.fromtimestamp(stamp).strftime('%H:%M:%S'),reason,
                       dest[1] if dest else ''])
    return events[-12:]


def trim(rows, now):
    return [row for row in rows if now-WINDOW < row['at'] <= now][-31:]


def preserve(reason):
    history=read(HISTORY)
    if not history.get('rows'):
        return False
    save(SAVED,{**history,'reason':reason,'saved':time.time()})
    return True


def preserve_on_stop(reason):
    try:
        history=read(HISTORY)
        rows=history.get('rows') or []
        if not rows or time.time()-rows[-1]['at']>WINDOW:
            return
        previous=read(SAVED)
        # Users often stop TUN and then disable the guard to recover the link.
        # Keep the last live TUN evidence across that pair of actions.
        if (reason=='关闭保护' and previous.get('session')==history.get('session')
                and previous.get('reason')=='停止 TUN'
                and not any(r.get('tun') and r['at']>previous.get('saved',0)+INTERVAL for r in rows)):
            return
        save(SAVED,{**history,'reason':reason,'saved':time.time()})
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        pass  # A diagnostic write must never prevent network recovery.


def collect(root_guard, since, now, wire=None):
    hb=read(ROOT/'guard-heartbeat.json')
    age=round(now-hb.get('at',0),1) if hb.get('at') else None
    live=bool(hb.get('on') and age is not None and 0<=age<15)
    luid=probe(root_guard.tun_luid)
    row={'at':now,'guard':('开启' if live else '关闭' if hb.get('on') is False else '未确认'),
         'heartbeatAge':age,'node':hb.get('addresses',[]),'port':hb.get('port'),
         'tun':luid,'pid':read(ROOT/'mihomo-runtime-state.json').get('pid'),
         'coreEvents':probe(core_events,since,now),'network':probe(link_snapshot,since,now),
         'udp1081':probe(socks_udp)}
    net=row['network']
    if wire is not None:
        row['wire']=wire.exchange(net,hb)
    binding=net.get('tun')
    row['tunTLS']=probe(tunnel_tls,binding) if live and luid and binding else '未探测'
    row['dns1053']=probe(local_dns) if live and isinstance(luid,int) and luid else '未探测'
    row['https1081']=probe(proxy_https) if live else '未探测'
    return row


def watch(root_guard, stop):
    session=time.time()
    previous=read(HISTORY).get('rows') or []
    rows=trim([r for r in previous if isinstance(r,dict) and isinstance(r.get('at'),(int,float))],session)
    wire=WireCounts(stop)
    since=session-INTERVAL
    while not stop.is_set():
        start=time.monotonic()
        now=time.time()
        try:
            row=collect(root_guard,max(since,now-WINDOW),now,wire)
        except Exception as exc:
            row={'at':now,'error':type(exc).__name__}
        rows=trim(rows+[row],time.time())
        try:
            if not stop.is_set():
                save(HISTORY,{'session':session,'rows':rows})
        except OSError:
            pass  # Keep the in-memory window and retry at the next sample.
        since=now
        stop.wait(max(0,INTERVAL-(time.monotonic()-start)))


def start(root_guard):
    stop=threading.Event()
    threading.Thread(target=watch,args=(root_guard,stop),name='network-history',daemon=True).start()
    return stop


def clock(stamp):
    return dt.datetime.fromtimestamp(stamp).strftime('%H:%M:%S')


def outcome(value):
    if isinstance(value,dict):
        if 'error' in value:
            return str(value['error']) + (f" ({value['code']})" if value.get('code') else '')
        if 'http' in value:
            return f"HTTP {value['http']}" if not value['curl'] else f"curl {value['curl']}"
    return str(value) if value is not None else '—'


def details(row, prior):
    net=row.get('network') or {}
    lines=[f"{clock(row['at'])}  保护 {row.get('guard','未知')}，心跳距采样 {row.get('heartbeatAge','—')} 秒",
           f"节点 {', '.join(row.get('node') or []) or '—'}  端口 {row.get('port') or '—'}",
           f"TUN 接口 LUID {outcome(row.get('tun'))}  核心状态文件 PID {row.get('pid') or '—'}",
           f"绑定 TUN 网卡连接 1.1.1.1:443    {outcome(row.get('tunTLS'))}",
           f"1081 UDP 协商 {outcome(row.get('udp1081'))}    1053 本地 DNS {outcome(row.get('dns1053'))}"]
    https=row.get('https1081')
    lines.append('1081 代理 HTTPS  '+outcome(https))
    if isinstance(https,dict) and 'tcp_s' in https:
        lines.append(f"    TCP 建连 {https['tcp_s']} 秒    TLS 完成 {https['tls_s']} 秒")
    if row.get('error') or net.get('error'):
        lines.append('采样失败  '+outcome(row.get('error') or net))
    previous={x['index']:x for x in (prior or {}).get('network',{}).get('links',[])}
    for link in net.get('links',[]):
        lines.extend([f"{link['adapter']}  {link['status']}  {link.get('profile') or ''}",
                      f"    地址 {', '.join(link['ip']) or '无'}    网关 {', '.join(link['gateway']) or '无'}",
                      f"    DHCP {link.get('dhcp') or '—'}    租约到期 {link.get('lease') or '—'}"])
        old=previous.get(link['index'])
        if old and old['ip']==link['ip'] and all(isinstance(old.get(k),int) and
                isinstance(link.get(k),int) and link[k]>=old[k] for k in ('tx','rx')):
            lines.append(f"    两次采样间物理网卡发送 {link['tx']-old['tx']:,} B，接收 {link['rx']-old['rx']:,} B")
    for ip,counts in row.get('wire',{}).items():
        if 'error' in counts:
            lines.append(f"{ip}  IPv4 包计数不可用（{counts['error']}）")
        else:
            lines.append(f"{ip}  物理 IPv4 自 {clock(counts['since'])}：发 {counts['tx']} / 收 {counts['rx']} 包，"
                         f"其中节点 {','.join(counts['node'])}:{counts['port']} 发 {counts['nodeTx']} / 收 {counts['nodeRx']} 包，"
                         f"目标端口 53 发 {counts['dnsTx']} 包")
    for e in net.get('events',[]):
        lines.append('  '.join(str(v) for v in (e['at'],f"Windows 事件 {e['id']}",e.get('ssid'),
                     e.get('app'),e.get('dst'),e.get('port'),f"过滤器 {e['filter']}" if e.get('filter') else '') if v))
    core=row.get('coreEvents')
    if isinstance(core,list):
        lines.extend('  '.join(e) for e in core)
    elif core:
        lines.append('核心日志读取  '+outcome(core))
    return '\n'.join(lines)


class MonitorPanel:
    def __init__(self,tabs):
        import tkinter as tk
        from tkinter import ttk
        self.tabs=tabs
        self.frame=ttk.Frame(tabs,padding=8)
        tabs.add(self.frame,text='最近 5 分钟网络')
        bar=ttk.Frame(self.frame)
        bar.pack(fill='x')
        self.which=tk.StringVar(value='滚动记录')
        choice=ttk.Combobox(bar,textvariable=self.which,values=('滚动记录','已保留现场'),state='readonly',width=14)
        choice.pack(side='left')
        self.message=tk.StringVar()
        ttk.Label(bar,textvariable=self.message).pack(side='left',padx=8)
        ttk.Button(bar,text='保留当前现场',command=self.keep).pack(side='right')
        grid=ttk.Frame(self.frame)
        grid.pack(fill='x',pady=5)
        self.table=ttk.Treeview(grid,show='headings',height=10,
                                columns=('time','link','guard','tun','https','udp','dns','packets','events'))
        for k,title,width in [('time','采样时间',75),('link','物理网络 / IPv4',220),('guard','保护',55),
                ('tun','TUN / TLS',85),('https','1081 HTTPS',90),('udp','1081 UDP',82),
                ('dns','本地 DNS',76),('packets','节点发 / 收包',97),('events','事件',45)]:
            self.table.heading(k,text=title)
            self.table.column(k,width=width,stretch=k=='link')
        scroll=ttk.Scrollbar(grid,command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y')
        self.table.pack(fill='x',expand=True)
        self.body=tk.Text(self.frame,wrap='word',state='disabled',height=8)
        scroll=ttk.Scrollbar(self.frame,command=self.body.yview)
        scroll.pack(side='right',fill='y')
        self.body.configure(yscrollcommand=scroll.set)
        self.body.pack(fill='both',expand=True)
        self.rows={}
        self.version=None
        self.table.bind('<<TreeviewSelect>>',lambda _:self.show())
        choice.bind('<<ComboboxSelected>>',lambda _:self.refresh())
        self.frame.after(250,self.tick)

    def keep(self):
        try:
            if preserve('手动保留'):
                self.which.set('已保留现场')
                self.refresh()
            else:
                self.message.set('尚无可保留的采样')
        except OSError as exc:
            self.message.set(f'保存失败（{exc}）')

    def show(self):
        keys=self.table.selection()
        if keys and keys[0] in self.rows:
            text=details(*self.rows[keys[0]])
        else:
            text='开启保护后每 15 秒采样，关闭控制台仍会记录。选择一行查看网卡收发、租约、探测和错误。'
        self.body.configure(state='normal')
        self.body.delete('1.0','end')
        self.body.insert('1.0',text)
        self.body.configure(state='disabled')

    def refresh(self):
        path=HISTORY if self.which.get()=='滚动记录' else SAVED
        try:
            version=(path,path.stat().st_mtime_ns)
        except OSError:
            version=(path,None)
        if version==self.version:
            return
        data=read(path)
        if version[1] is not None and not data:
            return  # The writer may be replacing the file. Retry on the next tick.
        self.version=version
        rows=data.get('rows') or []
        selected=self.table.selection()
        items=self.table.get_children()
        follow=not selected or (items and selected[0]==items[0])
        self.table.delete(*items)
        self.rows={}
        prior=None
        for r in rows:
            key=str(r['at'])
            self.rows[key]=(r,prior)
            prior=r
            net=r.get('network') or {}
            links=net.get('links',[])
            physical=' / '.join(' '.join(filter(None,[a.get('profile') or a['adapter'],
                            next((v for v in a['ip'] if ':' not in v), '无 IPv4')]))
                            for a in links if a['status']=='Up') or ('采样失败' if net.get('error') else '未连接')
            events=r.get('coreEvents')
            wire=[c for c in r.get('wire',{}).values() if 'error' not in c and c.get('node')]
            packets=f"{sum(c['nodeTx'] for c in wire)} / {sum(c['nodeRx'] for c in wire)}" if wire else '—'
            self.table.insert('','0',iid=key,values=(clock(r['at']),physical,r.get('guard','未知'),
                outcome(r.get('tunTLS')) if r.get('tun') else '未启动',
                outcome(r.get('https1081')),outcome(r.get('udp1081')),outcome(r.get('dns1053')),
                packets,len(net.get('events',[]))+(len(events) if isinstance(events,list) else 0)))
        if rows:
            self.table.selection_set(str(rows[-1]['at']) if follow or selected[0] not in self.rows else selected[0])
            self.message.set(f"{clock(rows[0]['at'])} – {clock(rows[-1]['at'])}  ·  {len(rows)} 次采样  "+data.get('reason',''))
        else:
            self.message.set('等待后台采样' if path==HISTORY else '暂无已保留现场')
        self.show()

    def tick(self):
        try:
            if self.tabs.select()==str(self.frame):
                self.refresh()
        finally:
            self.frame.after(1500,self.tick)
