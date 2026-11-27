"""Bounded live connection history and tails of Bridge command/core logs."""
import ctypes as c
import datetime
import heapq
import json
import os
from pathlib import Path, PureWindowsPath
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk
import urllib.request

ROOT=Path(os.environ['LOCALAPPDATA'])/'v2rayn-tun-controller'
LOGS={'控制命令':'tun-commands.log','核心输出':'mihomo-runtime-stdout.log',
      '核心错误':'mihomo-runtime-stderr.log','主管进程输出':'mihomo-supervisor-stdout.log',
      '主管进程错误':'mihomo-supervisor-stderr.log','上次核心输出':'mihomo-runtime-stdout.previous.log'}


def socket_owners():
    result={}
    for protocol,function,cls,words,port,pid in [
            ('tcp',c.windll.iphlpapi.GetExtendedTcpTable,5,6,2,5),
            ('udp',c.windll.iphlpapi.GetExtendedUdpTable,1,3,1,2)]:
        size=c.c_uint32()
        function(None,c.byref(size),False,2,cls,0)
        buf=c.create_string_buffer(size.value)
        if function(buf,c.byref(size),False,2,cls,0):continue
        rows=memoryview(buf).cast('B').cast('I')
        for i in range(rows[0]):
            start=1+i*words
            if start+words>len(rows):break
            key=(protocol,socket.ntohs(rows[start+port]&65535))
            result.setdefault(key,set()).add(rows[start+pid])
    return result


def process_name(pid):
    api=c.windll.kernel32
    api.OpenProcess.restype=c.c_void_p
    handle=api.OpenProcess(0x1000,False,pid)
    if not handle:return f'PID {pid}'
    try:
        buf=c.create_unicode_buffer(32768);size=c.c_uint32(len(buf))
        if api.QueryFullProcessImageNameW(c.c_void_p(handle),0,buf,c.byref(size)):
            return PureWindowsPath(buf.value).name
        return f'PID {pid}'
    finally:
        api.CloseHandle(c.c_void_p(handle))


def latest(history,connections):
    owners=None
    names={}
    counts={'其他应用':0,'Xray':0}
    for x in connections:
        m=x.get('metadata') or {}
        if str(m.get('type','')).lower()!='tun':
            continue
        host=m.get('host') or m.get('destinationIP') or '未知'
        port=str(m.get('destinationPort',''))
        proto=str(m.get('network',''))
        source=str(m.get('sourcePort',''))
        name=PureWindowsPath(m.get('processPath') or m.get('process') or '').name
        if not name and source.isdigit():
            if owners is None:
                try:
                    owners=socket_owners()
                except (OSError, ValueError, TypeError):
                    owners={}
            pids=owners.get((proto.lower(),int(source)),set())
            if len(pids)==1:
                pid=next(iter(pids))
                if pid not in names:names[pid]=process_name(pid)
                name=names[pid]
        name=name or '未识别'
        group='Xray' if name.casefold()=='xray.exe' else '其他应用'
        counts[group]+=1
        ident=(host,port,name.casefold(),proto)
        row=(x.get('start',''),name,host,port,proto,int(x.get('upload') or 0),int(x.get('download') or 0))
        if ident not in history or row[0]>=history[ident][0]:history[ident]=row
    # Truncate each history separately so bursts from the core cannot evict apps.
    rows={}
    retained={}
    for group in counts:
        items=heapq.nlargest(20,((k,v) for k,v in history.items()
                                 if (k[2]=='xray.exe')==(group=='Xray')),key=lambda item:item[1][0])
        retained.update(items)
        rows[group]=[row for _,row in items]
    history.clear()
    history.update(retained)
    return rows,counts


def tail(path):
    try:
        with path.open('rb') as stream:
            size=stream.seek(0,2);stream.seek(max(0,size-98304))
            if size>98304:stream.readline()
            data=stream.read(98304)
        try:text=data.decode('utf-8')
        except UnicodeDecodeError:text=data.decode('mbcs',errors='replace')
        return '\n'.join(text.splitlines()[-220:]) or '暂无输出'
    except FileNotFoundError:return '暂无日志'


class TunActivity:
    def __init__(self,tabs):
        self.stop=threading.Event();self.update=queue.Queue(maxsize=1)
        self.page=ttk.Frame(tabs,padding=8);tabs.add(self.page,text='最近 20 个 TUN 目标')
        self.state=tk.StringVar(value='正在读取 Mihomo…')
        bar=ttk.Frame(self.page)
        bar.pack(fill='x')
        self.group=tk.StringVar(value='其他应用')
        self.rows={'其他应用':[],'Xray':[]}
        for group in self.rows:
            ttk.Radiobutton(bar,text=group,variable=self.group,value=group,
                            command=self.show_group).pack(side='left',padx=(0,8))
        ttk.Label(bar,textvariable=self.state).pack(side='left')
        self.table=ttk.Treeview(self.page,columns=('time','app','host','port','proto','up','down'),show='headings')
        for k,h,w in [('time','连接时间',85),('app','应用',150),('host','目标域名 / IP',275),('port','端口',60),('proto','协议',65),('up','上传 B',85),('down','下载 B',85)]:
            self.table.heading(k,text=h);self.table.column(k,width=w,stretch=k in ('app','host'))
        self.table.pack(fill='both',expand=True)
        self.logs=ttk.Frame(tabs,padding=8);tabs.add(self.logs,text='TUN 工作日志')
        self.which=tk.StringVar(value='控制命令')
        ttk.Combobox(self.logs,textvariable=self.which,values=list(LOGS),state='readonly').pack(anchor='w')
        self.text=tk.Text(self.logs,wrap='none',state='disabled')
        scroll=ttk.Scrollbar(self.logs,command=self.text.yview);scroll.pack(side='right',fill='y')
        self.text.configure(yscrollcommand=scroll.set);self.text.pack(fill='both',expand=True)
        self.previous=None
        self.tabs=tabs
        threading.Thread(target=self.sample,daemon=True).start()
        self.tick()

    def sample(self):
        history={};pid=None;opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while not self.stop.is_set():
            delay=2;rows=None
            try:
                a=json.loads((ROOT/'mihomo-controller-access.json').read_text(encoding='utf-8-sig'))
                if pid!=a['corePid']:history.clear();pid=a['corePid']
                req=urllib.request.Request(f"http://127.0.0.1:{int(a['port'])}/connections",headers={'Authorization':'Bearer '+a['secret']})
                with opener.open(req,timeout=3) as resp:data=resp.read(40*1024*1024+1)
                if len(data)>40*1024*1024:raise ValueError('连接快照超过 40 MB，已限制刷新')
                connections=json.loads(data)['connections'] or []
                rows,counts=latest(history,connections)
                state=f"当前连接：其他应用 {counts['其他应用']} 条 · Xray {counts['Xray']} 条"
                if len(connections)>3000:delay=15
            except FileNotFoundError:state='当前没有 TUN 监控接口 · 保留本窗口本次观测记录'
            except (OSError,ValueError,KeyError,TypeError) as exc:
                state=f'采样暂不可用（{type(exc).__name__}）';delay=5
            try:self.update.put_nowait((state,rows))
            except queue.Full:pass
            self.stop.wait(delay)

    def tick(self):
        if self.stop.is_set():return
        if not self.update.empty():
            state,rows=self.update.get_nowait();self.state.set(state)
            if rows is not None:
                self.rows=rows
                self.show_group()
        if self.tabs.select()==str(self.logs):
            try:value=tail(ROOT/LOGS[self.which.get()])
            except OSError as exc:value=str(exc)
            if value!=self.previous:
                self.previous=value;self.text.configure(state='normal');self.text.delete('1.0','end')
                self.text.insert('end',value);self.text.see('end');self.text.configure(state='disabled')
        self.page.after(750,self.tick)

    def show_group(self):
        self.table.delete(*self.table.get_children())
        for stamp,*row in self.rows[self.group.get()]:
            try:stamp=datetime.datetime.fromisoformat(stamp).astimezone().strftime('%H:%M:%S')
            except ValueError:pass
            self.table.insert('','end',values=[stamp,*row])
