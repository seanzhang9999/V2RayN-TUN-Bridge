# Tk panel for trusted LAN ranges and per-network portal exceptions.
import ipaddress
import os
from pathlib import Path
import queue
import secrets
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
import guard_live
import local_access as local


class AccessPanel:
    def __init__(self, parent, launch):
        self.frame=ttk.Frame(parent,padding=12)
        self.launch=launch
        local.clear_temporary_lan()
        self.net=None
        self.relay=None
        self.token=None
        self.hosts=set()
        self.events=queue.Queue()
        self.network=tk.StringVar(value='正在识别物理网络…')
        ttk.Label(self.frame,textvariable=self.network).pack(anchor='w')
        lan=ttk.LabelFrame(self.frame,text='本地地址 · 仅限当前直连网段',padding=8)
        lan.pack(fill='x',pady=8)
        self.local_value=tk.StringVar()
        ttk.Entry(lan,textvariable=self.local_value,width=33).pack(side='left')
        ttk.Button(lan,text='添加地址或网段',command=lambda:self.lan(True)).pack(side='left')
        ttk.Button(lan,text='移除',command=lambda:self.lan(False)).pack(side='left')
        self.remember=tk.BooleanVar(value=False)
        self.remember_box=ttk.Checkbutton(lan,text='记住此 Wi-Fi 的本地地址',variable=self.remember,command=self.change_remember)
        self.remember_box.pack(side='left',padx=8)
        self.remember_box.state(['disabled'])
        self.local_list=tk.Listbox(self.frame,height=3,exportselection=False)
        self.local_list.pack(fill='x')
        self.local_list.bind('<<ListboxSelect>>',lambda e:self.local_value.set(self.selected(self.local_list) or self.local_value.get()))
        portal=ttk.LabelFrame(self.frame,text='Wi-Fi 登录 · 本次连接，最长 10 分钟',padding=8)
        portal.pack(fill='x',pady=8)
        self.url=tk.StringVar(value='')
        ttk.Label(portal,text='起始网址（可空）').pack(side='left')
        ttk.Entry(portal,textvariable=self.url,width=45).pack(side='left',fill='x',expand=True)
        ttk.Button(portal,text='打开专用浏览器',command=self.login).pack(side='left')
        ttk.Button(portal,text='结束登录',command=self.end).pack(side='left')
        self.hint=tk.StringVar(value='可直接打开专用浏览器。需要直连时先开启保护，再点请求主机前的开关。')
        ttk.Label(self.frame,textvariable=self.hint,wraplength=830).pack(anchor='w')
        self.requests=ttk.Treeview(self.frame,columns=('state','host','time','count'),show='headings',height=7,selectmode='browse')
        for key,label,width in [('state','本次放行',90),('host','请求主机',320),('time','最近请求',100),('count','请求次数',80)]:
            self.requests.heading(key,text=label)
            self.requests.column(key,width=width,stretch=key=='host')
        self.requests.pack(fill='both',expand=True,pady=4)
        self.requests.bind('<ButtonRelease-1>',self.click_switch)
        self.requests.bind('<space>',self.toggle_selected)
        self.grant=tk.StringVar(value='当前已放行 0 个主机')
        ttk.Label(self.frame,textvariable=self.grant).pack(anchor='w')
        self.rendered=None
        self.seen={}
        self.check_network()
        self.tick()

    def check_network(self):
        def run():
            try:
                self.events.put(('net',local.snapshot()))
            except Exception as exc:
                self.events.put(('net-error',str(exc)))
        threading.Thread(target=run,daemon=True).start()
        self.frame.after(6000,self.check_network)

    def selected(self, widget):
        sel=widget.curselection()
        return widget.get(sel[0]) if sel else ''

    def require_guard(self):
        if self.net is None:
            raise ValueError('当前物理网络尚未识别')
        try:
            with guard_live.engine() as h:
                if not guard_live.installed(h):
                    raise ValueError('请先开启出站保护')
        except OSError:
            pass  # Elevated link watcher checks the live sublayer before creating exceptions.

    def render_lan(self):
        self.local_list.delete(0,'end')
        if self.net:
            remembered,items=local.lan_config(self.net)
            self.remember.set(remembered)
            self.remember_box.state(['!disabled'] if local.wifi_key(self.net) else ['disabled'])
            for ip in items:
                self.local_list.insert('end',ip)

    def change_remember(self):
        try:
            if not self.net:return
            _,items=local.lan_config(self.net)
            local.set_lan_config(self.net,items,self.remember.get())
            self.hint.set('已记住此 Wi-Fi 的本地地址。' if self.remember.get() else '已取消记住；当前配置仅用于本次连接。')
        except (OSError,ValueError) as exc:
            self.render_lan()
            self.hint.set(str(exc))

    def lan(self,add):
        try:
            self.require_guard()
            value=str(local.local_network(self.local_value.get(),self.net) if add else ipaddress.ip_network(self.local_value.get().strip()))
            _,items=local.lan_config(self.net)
            entries=set(items)
            if add: entries.add(value)
            else: entries.discard(value)
            local.set_lan_config(self.net,entries,self.remember.get())
            self.render_lan()
            self.launch('local')
            self.hint.set('已保存本地规则，等待 Windows 应用。常规 DNS 端口 53 / 853 仍受保护。')
        except Exception as exc:
            self.hint.set(str(exc))

    def click_switch(self,event):
        if self.requests.identify_column(event.x)=='#1':
            self.toggle(self.requests.identify_row(event.y))

    def toggle_selected(self,_event):
        selection=self.requests.selection()
        if selection:self.toggle(selection[0])
        return 'break'

    def toggle(self,host):
        if not self.token or not host or host not in self.seen:return
        try:
            stored=local.read(local.PORTAL)
            if stored.get('token')!=self.token:return
            normalized,_=local.login_url(host)
            if normalized!=host:raise ValueError('无效的请求主机')
            if host in self.hosts:self.hosts.remove(host)
            else:self.hosts.add(host)
            self.write_hosts()
            first=not stored.get('hosts') and bool(self.hosts)
            stored['hosts']=sorted(self.hosts)
            local.save(local.PORTAL,stored)
            if first or local.read(local.ROOT/'link-active.json').get('token')!=self.token:
                self.launch('local')
            self.sync_enabled()
            self.render_requests()
            self.hint.set('已更新本次授权。刚打开开关的页面可回到专用浏览器刷新。')
        except (OSError,ValueError) as exc:
            self.hint.set(str(exc))

    def render_requests(self):
        for host,(stamp,count) in self.seen.items():
            values=('● 开' if host in self.hosts else '○ 关',host,stamp,count)
            if self.requests.exists(host):self.requests.item(host,values=values)
            else:self.requests.insert('', 'end',iid=host,values=values)
        self.grant.set(f'当前已放行 {len(self.hosts)} 个主机 · 点击开关列可单独开关')

    def reset_requests(self):
        self.requests.delete(*self.requests.get_children())
        self.hosts.clear()
        self.seen={}
        self.rendered=None
        self.render_requests()

    def login(self):
        try:
            if not self.net or not self.net.get('wifi'):
                raise ValueError('当前默认物理连接不是 Wi-Fi')
            if not self.net['dns']:
                raise ValueError('当前热点没有可用的 IPv4 DNS')
            if self.token:
                self.hint.set('专用浏览器会话已开启，请选中请求记录进行批准。')
                return
            _,url=local.login_url(self.url.get().strip() or 'http://www.msftconnecttest.com/connecttest.txt')
            self.token=secrets.token_hex(16)
            self.reset_requests()
            self.write_hosts()
            self.target=url
            self.expires=time.time()+600
            self.wait_until=time.time()+35
            local.EVENTS.write_text('',encoding='utf-8')
            local.save(local.PORTAL,{'token':self.token,'link':self.net['id'],'hosts':[],'expires':self.expires})
            self.open_browser()
        except Exception as exc:
            if self.token and not self.relay: self.end()
            self.hint.set(str(exc))

    def write_hosts(self):
        self.hostfile=local.ROOT/('portal-'+self.token+'.txt')
        tmp=self.hostfile.with_suffix('.tmp')
        tmp.write_text('\n'.join(sorted(self.hosts))+'\n',encoding='ascii')
        os.replace(tmp,self.hostfile)

    def sync_enabled(self):
        live=local.read(local.ROOT/'link-active.json')
        allowed=self.hosts.intersection(live.get('hosts',[])) if live.get('token')==self.token else set()
        enabled=Path(str(self.hostfile)+'.enabled')
        text='\n'.join(sorted(allowed))
        if not enabled.exists() or enabled.read_text(encoding='ascii')!=text:
            tmp=enabled.with_suffix('.new')
            tmp.write_text(text,encoding='ascii')
            os.replace(tmp,enabled)

    def open_browser(self):
        if guard_live.c.windll.shell32.IsUserAnAdmin():
            raise ValueError('请用桌面快捷方式以普通用户启动控制台，再打开登录浏览器')
        edge=next((Path(os.environ[key])/'Microsoft/Edge/Application/msedge.exe'
                   for key in ('ProgramFiles(x86)','ProgramFiles','LOCALAPPDATA')
                   if (Path(os.environ[key])/'Microsoft/Edge/Application/msedge.exe').is_file()),None)
        if edge is None:raise ValueError('找不到用于热点登录的 Edge')
        relay=Path(__file__).with_name('PortalRelay.exe')
        self.relay=subprocess.Popen([str(relay),str(self.hostfile),str(local.EVENTS),self.net['ip'],
                                     self.net['dns'][0],str(self.net['index'])],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        port=int(self.relay.stdout.readline().strip())
        subprocess.Popen([str(edge),'--user-data-dir='+str(local.ROOT/('hotspot-edge-'+self.token)),
                          '--inprivate','--new-window','--disable-quic','--disable-http2','--no-first-run',
                          '--disable-background-networking','--proxy-bypass-list=<-loopback>',
                          '--proxy-server=http://127.0.0.1:'+str(port),self.target])
        self.hint.set('默认全部拦截。选中请求主机并批准后，在专用浏览器刷新。')

    def end(self):
        if self.relay:
            self.relay.terminate()
            self.relay.wait(timeout=3)
            self.relay=None
        if self.token:
            if local.read(local.PORTAL).get('token')==self.token:
                local.save(local.PORTAL,{})
            for suffix in ('','.pins','.ack','.enabled'):
                Path(str(self.hostfile)+suffix).unlink(missing_ok=True)
        self.token=None
        self.reset_requests()
        self.hint.set('登录会话已结束')

    def tick(self):
        try:
            while not self.events.empty():
                kind,data=self.events.get_nowait()
                if kind=='net':
                    if self.net and self.net['id']!=data['id'] and self.token:self.end()
                    self.net=data
                    self.network.set(f"{data.get('ssid') or data['profile']} · {data['name']} · 网段 {data['subnet']} · 网关 {data['gateway']}")
                    self.render_lan()
                else:
                    if self.token:self.end()
                    self.net=None
                    self.network.set(data)
            if self.token:
                stored=local.read(local.PORTAL)
                if (stored.get('token')!=self.token or time.time()>=self.expires
                        or (self.relay and self.relay.poll() is not None)):
                    self.end()
                elif not self.relay:
                    if local.read(local.ROOT/'link-active.json').get('token')==self.token:
                        self.open_browser()
                    elif time.time()>self.wait_until:
                        raise ValueError('热点例外尚未生效，请查看操作记录')
                else:
                    self.sync_enabled()
                    rows=local.EVENTS.read_text(encoding='utf-8-sig',errors='replace').splitlines()
                    if rows!=self.rendered:
                        self.rendered=rows
                        self.seen={}
                        for row in rows:
                            fields=row.split()
                            if len(fields)==3 and fields[1] in ('BLOCK','REQUEST'):
                                stamp,_,host=fields
                                self.seen[host]=(stamp,self.seen.get(host,('',0))[1]+1)
                        self.render_requests()
        except Exception as exc:
            self.end()
            self.hint.set(str(exc))
        self.frame.after(600,self.tick)
