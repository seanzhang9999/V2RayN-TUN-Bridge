"""Local Windows console for reviewing Xray routing and running the bounded TUN trial."""
import ctypes
import secrets
import socket
import ipaddress
from collections import defaultdict
import datetime
import json
import queue
import subprocess
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from xray_direct import config_path, direct_rules, literal_targets

HERE = Path(__file__).resolve().parent
TEST = HERE / 'TUN验收.py'
if not TEST.exists():
    TEST = HERE / 'tun-acceptance.py'


# Exact public resolver addresses. Labels are for display only.
DNS = {}
for provider, source, addresses in [
    ('阿里公共 DNS','alidns.com','223.5.5.5 223.6.6.6 2400:3200::1 2400:3200:baba::1'),
    ('114DNS','114dns.com','114.114.114.114 114.114.115.115 114.114.114.119 114.114.115.119 114.114.114.110 114.114.115.110'),
    ('腾讯 DNSPod','cloud.tencent.com','119.29.29.29 2402:4e00:: 2402:4e00:1::'),
    ('百度公共 DNS','dudns.baidu.com','180.76.76.76'),
    ('360 安全 DNS','sdns.360.net','101.226.4.6 218.30.118.6 123.125.81.6 140.207.198.6'),
    ('CNNIC SDNS','cnnic.cn','1.2.4.8 210.2.4.8'),
]:
    for item in addresses.split():
        DNS[ipaddress.ip_address(item)] = provider, source


def grouped_rules(rows):
    groups = defaultdict(list)
    for order, rule in rows:
        eligible = literal_targets(rule)
        keys = {k:v for k,v in rule.items() if k not in ('type','outboundTag')}
        for key, values in (keys or {'匹配':'全部'}).items():
            for v in values if isinstance(values,list) else [values]:
                text = v if isinstance(v,str) else json.dumps(v,ensure_ascii=False)
                group, info, rank = '其他条件', key, (order,0)
                state = '未按此条件放行'
                if key == 'domain':
                    group, info = '域名与域名集', '域名规则'
                elif key == 'ip':
                    try:
                        ip = ipaddress.ip_address(text)
                    except ValueError:
                        group, info = '地址集与网段', '地址条件'
                        if set(rule) <= {'type','ip','outboundTag'} and rule.get('type') == 'field':
                            if text.lower() == 'geoip:cn':
                                info, state = 'v2rayN geoip.dat · CN', '仅 Xray'
                            else:
                                try:
                                    net = ipaddress.ip_network(text)
                                    if net.prefixlen:
                                        info, state = f'IPv{net.version} 网段', '仅 Xray'
                                except ValueError:
                                    pass
                    else:
                        rank = (ip.version,int(ip))
                        group = '其他 IP'
                        info = f'IPv{ip.version} · ' + ('公网' if ip.is_global else '非公网')
                        if ip in DNS:
                            provider, source = DNS[ip]
                            group = 'DNS · ' + provider
                            info += ' · ' + source
                        elif ip in ipaddress.ip_network('118.89.0.0/16'):
                            info += ' · 腾讯云 / CN（APNIC 登记）'
                        else:
                            info += ' · 用途未核实'
                        if ip in eligible:
                            state = '仅 Xray'
                groups[group].append((rank,order,info,text,state))
    return groups


import guard_live
from local_panel import AccessPanel
from local_access import ROOT, read
sys.path.insert(0, str(HERE / 'src'))
from tun_controller.network_monitor import windows_physical_routes


def launch_guard(action):
    executable = str(Path(sys.executable).with_name('pythonw.exe'))
    args = subprocess.list2cmdline(['-X','utf8',str(HERE / 'guard_live.py'),action])
    result = ctypes.windll.shell32.ShellExecuteW(None,'runas',executable,args,str(HERE),0)
    if result <= 32:
        raise OSError('操作未获管理员授权')


TITLE = 'TUN Bridge · 出站保护'


def first_window():
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.restype=ctypes.c_void_p
    mutex=kernel.CreateMutexW(None,False,'Local\\V2RayNTunBridgeConsoleV1')
    if not mutex:raise ctypes.WinError()
    if ctypes.get_last_error()!=183:
        return mutex
    user=ctypes.windll.user32
    user.FindWindowW.restype=ctypes.c_void_p
    import time
    for _ in range(30):
        win=user.FindWindowW('TkTopLevel',TITLE)
        if win:
            user.ShowWindowAsync(ctypes.c_void_p(win),9)
            user.SetForegroundWindow(ctypes.c_void_p(win))
            break
        time.sleep(.05)
    kernel.CloseHandle(ctypes.c_void_p(mutex))
    return None


class Console:
    def __init__(self, root):
        self.root = root
        root.title('TUN Bridge · 出站保护')
        root.geometry('960x690')
        root.minsize(720, 520)
        self.events = queue.Queue()
        self.running = False
        self.rows = None
        self.status = tk.StringVar(value='开启保护会持续生效，直到手动关闭。需要接管应用流量时请点“开启保护并启动 TUN”。')
        self.source = tk.StringVar()
        body = ttk.Frame(root, padding=18)
        body.pack(fill='both', expand=True)
        header = ttk.Frame(body)
        header.pack(fill='x', pady=(0, 10))
        ttk.Label(header, text='出站保护 · 0.3.4-rc.2', font=('Microsoft YaHei UI', 18, 'bold')).pack(side='left')
        self.off = ttk.Button(header, text='关闭保护', command=lambda: self.control('off'))
        self.off.pack(side='right')
        self.on = ttk.Button(header, text='开启保护', command=lambda: self.control('on'))
        self.on.pack(side='right',padx=8)
        ttk.Button(header,text='停止 TUN',command=lambda:self.control('tun-off')).pack(side='right')
        ttk.Button(header,text='开启保护并启动 TUN',command=lambda:self.control('tun-on')).pack(side='right',padx=8)
        bar = ttk.Frame(body)
        bar.pack(fill='x', pady=(0, 6))
        ttk.Label(bar, text='TUN 物理出口').pack(side='left')
        self.choice_file = ROOT / 'physical-choice.json'
        self.saved = read(self.choice_file)
        self.route_options = {'自动选择': ''}
        self.route_box = ttk.Combobox(bar, state='readonly', width=32)
        self.route_box.pack(side='left', padx=6)
        self.route_refresh = ttk.Button(bar, text='刷新列表', command=self.load_routes)
        self.route_refresh.pack(side='left')
        self.apply_route = ttk.Button(bar, text='应用', command=self.save_route)
        self.apply_route.pack(side='left')
        self.bound = tk.StringVar(value='当前出口：读取中')
        ttk.Label(bar, textvariable=self.bound).pack(side='left', padx=8)
        self.load_routes()
        self.guard_status = tk.StringVar(value='正在读取 Windows 保护状态…')
        ttk.Label(body,textvariable=self.guard_status,font=('Microsoft YaHei UI',12,'bold')).pack(anchor='w')
        ttk.Label(body, textvariable=self.status).pack(anchor='w')
        tabs = ttk.Notebook(body)
        tabs.pack(fill='both', expand=True, pady=(10, 0))
        rules = ttk.Frame(tabs, padding=10)
        logs = ttk.Frame(tabs, padding=8)
        from tun_activity import TunActivity
        self.activity=TunActivity(tabs)
        from bridge_monitor import MonitorPanel
        self.network_monitor=MonitorPanel(tabs)
        tabs.add(rules, text='Xray 直连规则')
        self.access=AccessPanel(tabs,self.launch_async)
        tabs.add(self.access.frame,text='局域网与 Wi-Fi 登录')
        tabs.add(logs, text='操作记录')
        root.protocol('WM_DELETE_WINDOW',self.close)
        self.tabs, self.log_tab = tabs, logs
        bar = ttk.Frame(rules)
        bar.pack(fill='x')
        ttk.Button(bar, text='立即同步', command=lambda: self.refresh(True)).pack(side='right')
        ttk.Label(bar, textvariable=self.source, wraplength=690).pack(side='left', fill='x')
        ttk.Label(rules, text='点击分类展开。域名是 Xray 的分流条件；保护按 Xray 身份及目标 IP、网段或 geoip:cn 放行；VPN 节点另限协议和端口。DNS 分类不限制端口。', wraplength=830).pack(anchor='w', pady=8)
        table = ttk.Frame(rules)
        table.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(table, columns=('index','key','value','state'), show='tree headings')
        self.tree.heading('#0',text='地址分类 / 服务商')
        self.tree.column('#0',width=165,stretch=False)
        for name, label, width in [('index','路由顺序',65),('key','地址信息 / 依据',235),('value','规则内容',275),('state','放行策略',150)]:
            self.tree.heading(name,text=label)
            self.tree.column(name,width=width,stretch=name=='value')
        scroll = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y')
        self.tree.pack(fill='both',expand=True)
        self.log = tk.Text(logs, wrap='word', state='disabled', font=('Consolas',10))
        self.log.pack(fill='both',expand=True)
        self.refresh(True)
        threading.Thread(target=self.observe,daemon=True).start()
        self.root.after(2000, self.poll_rules)
        self.root.after(150, self.poll_log)

    def load_routes(self):
        self.route_refresh.configure(state='disabled')
        self.apply_route.configure(state='disabled')
        def scan():
            try:
                self.events.put(('routes', windows_physical_routes()))
            except Exception as exc:
                self.events.put(('route-error', str(exc)))
        threading.Thread(target=scan, daemon=True).start()

    def save_route(self):
        label = self.route_box.get()
        if label not in self.route_options:
            return
        guid = self.route_options[label]
        active = bool(guard_live.tun_luid())
        if active and not messagebox.askokcancel('切换物理出口', '应用此选择会重启 TUN，当前连接可能短暂中断。继续？'):
            return
        choice = {'guid': guid, 'label': label}
        try:
            self.choice_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.choice_file.with_suffix('.tmp')
            tmp.write_text(json.dumps(choice, ensure_ascii=False), encoding='utf8')
            tmp.replace(self.choice_file)
        except OSError as exc:
            self.status.set(str(exc))
            return
        self.saved = choice
        if active:
            self.launch_async('switch-egress')
        self.status.set('已保存，正在切换出口' if active else '已保存，将在启动 TUN 时使用')

    def poll_rules(self):
        self.refresh()
        self.root.after(2000,self.poll_rules)

    def refresh(self, force=False):
        try:
            path = config_path()
            rows = direct_rules(path)
            if not force and rows == self.rows:
                return
            self.tree.delete(*self.tree.get_children())
            self.rows = rows
            targets = set().union(*(literal_targets(rule) for _,rule in rows))
            groups = grouped_rules(rows)
            for name, items in sorted(groups.items(),key=lambda pair: (pair[0].startswith('DNS ·'),pair[0])):
                parent = self.tree.insert('', 'end', text=f'{name}（{len(items)}）',open=name=='其他 IP')
                for _,n,info,text,state in sorted(items,key=lambda item:item[0]):
                    self.tree.insert(parent,'end',values=(n,info,text,state))
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            self.source.set(f'{path}\n{timestamp} 已同步 · {len(rows)} 条路由 · {len(targets)} 个独立 IP')
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self.tree.delete(*self.tree.get_children())
            self.rows = None
            self.source.set(f'规则读取失败：{exc}')

    def observe(self):
        import time
        last = None
        while True:
            try:
                with guard_live.engine() as handle:
                    installed = guard_live.installed(handle)
                interface = guard_live.tun_luid()
                text = ('保护已开启' if installed else '保护已关闭') + '    ·    ' + (
                    'TUN 网卡已创建' if interface else 'TUN 网卡未启动')
            except OSError as exc:
                state=guard_live.recent_status()
                text=(state or '当前权限无法读取实时保护状态')+'    ·    '+('TUN 网卡已创建' if guard_live.tun_luid() else 'TUN 网卡未启动')
            runtime = read(ROOT / 'mihomo-runtime-report.json')
            bound = (runtime.get('boundInterface') or runtime.get('physicalInterface') or '待确认'
                     if runtime.get('state') == 'running' and guard_live.tun_luid() else '未启用或待确认')
            self.events.put(('bound', bound))
            self.events.put(('status',text))
            try:
                stamp=guard_live.STATE.stat().st_mtime_ns
                if stamp!=last:
                    record=json.loads(guard_live.STATE.read_text(encoding='utf-8'))
                    self.events.put(('log',str(record['message'])+'\n'))
                    last=stamp
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(1)

    def close(self):
        self.activity.stop.set()
        self.access.end()
        self.root.destroy()

    def launch_async(self, action):
        def request():
            try:
                launch_guard(action)
            except OSError as exc:
                self.events.put(('log',str(exc)+'\n'))
        threading.Thread(target=request,daemon=True).start()

    def control(self, action):
        try:
            self.launch_async(action)
            self.status.set({'on':'正在开启保护','off':'正在关闭保护','tun-on':'正在开启保护并启动 TUN','tun-off':'正在停止 TUN'}[action])
        except OSError as exc:
            self.status.set(str(exc))

    def poll_log(self):
        while not self.events.empty():
            kind, value = self.events.get()
            if kind == 'bound':
                self.bound.set('当前出口：' + value)
            elif kind in ('routes', 'route-error'):
                self.route_refresh.configure(state='normal')
                if kind == 'route-error':
                    self.status.set('无法读取物理网卡：' + value)
                    continue
                self.route_options = {'自动选择': ''}
                for route in value:
                    label = f"{route['interfaceName']} · {route['localIPv4']}"
                    self.route_options[label] = route['guid']
                labels = list(self.route_options)
                selected = next((k for k,v in self.route_options.items()
                                 if v == self.saved.get('guid', '')), None)
                self.route_box.configure(values=labels)
                self.route_box.set(selected or ('不可用：' + self.saved.get('label', '')))
                self.apply_route.configure(state='normal')
            elif kind=='status':
                self.guard_status.set(value)
            else:
                self.status.set(value.strip())
                self.log.configure(state='normal')
                self.log.insert('end',value)
                self.log.see('end')
                self.log.configure(state='disabled')
        self.root.after(200,self.poll_log)


if __name__ == '__main__':
    instance=first_window()
    if not instance:sys.exit(0)
    root = tk.Tk()
    root.withdraw()
    from local_access import ROOT, read, save
    settings_path = ROOT / 'gui-settings.json'
    settings = read(settings_path)
    while not (Path(settings.get('app_root') or '.') / 'binConfigs/config.json').is_file():
        folder = filedialog.askdirectory(parent=root, title='选择正在运行的 v2rayN 安装目录')
        if not folder:
            sys.exit(0)
        if not all((Path(folder)/name).is_file() for name in
                   ('v2rayN.exe', 'bin/Xray/xray.exe', 'binConfigs/config.json')):
            messagebox.showerror('目录不匹配', '需要 v2rayN.exe、Xray 核心及运行配置 binConfigs/config.json。', parent=root)
            continue
        settings['app_root'] = folder
        save(settings_path, settings)
    app = Console(root)
    root.deiconify()
    root.mainloop()
