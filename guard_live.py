"""Persistent WFP guard. Only objects in our dedicated sublayer are managed."""
import contextlib
import ctypes as c
import functools
import json
import os
import runpy
import socket
import subprocess
import sys
import time
from pathlib import Path
from xray_direct import config_path, direct_networks, verify_core

HERE = Path(__file__).resolve().parent
source = HERE / '限时出站保护.py'
g = runpy.run_path(str(source if source.exists() else HERE / 'outbound-guard-trial.py'))
api, call, ptr = g['api'], g['call'], c.c_void_p
key = g['guid'](g['GUARD_KEY'])
alias = 'mihomo_tun_controller'
STATE = Path(os.environ['LOCALAPPDATA']) / 'v2rayn-tun-controller/guard-live.json'


def tun_luid():
    value = c.c_uint64()
    if not c.windll.iphlpapi.ConvertInterfaceAliasToLuid(c.c_wchar_p(alias), c.byref(value)):
        index=c.c_uint32()
        api=c.windll.iphlpapi
        if api.ConvertInterfaceLuidToIndex(c.byref(value),c.byref(index)):
            return None
        # MIB_IFROW: WCHAR name[256], then index; oper status follows admin status.
        row=c.create_string_buffer(1024)
        c.c_uint32.from_buffer(row,512).value=index.value
        if api.GetIfEntry(c.byref(row))==0 and c.c_uint32.from_buffer(row,544).value in (4,5):
            return value.value
    return None


@contextlib.contextmanager
def engine():
    handle = ptr()
    call('FwpmEngineOpen0', None, 10, None, None, c.byref(handle))
    try:
        yield handle
    finally:
        api.FwpmEngineClose0(handle)


def installed(handle):
    out = ptr()
    result = api.FwpmSubLayerGetByKey0(handle, c.byref(key), c.byref(out)) & 0xffffffff
    if result == 0x80320007:  # FWP_E_SUBLAYER_NOT_FOUND
        return False
    if result:
        raise OSError(f'WFP status 0x{result:08x}')
    api.FwpmFreeMemory0(c.byref(out))
    return True


@contextlib.contextmanager
def transaction(handle):
    call('FwpmTransactionBegin0', handle, 0)
    try:
        yield
        call('FwpmTransactionCommit0', handle)
    except BaseException:
        api.FwpmTransactionAbort0(handle)
        raise


def clear(handle, remove_layer=True):
    if not installed(handle):
        return
    enum = ptr()
    call('FwpmFilterCreateEnumHandle0', handle, None, c.byref(enum))
    ids = []
    try:
        while True:
            rows = c.POINTER(c.POINTER(g['Filter']))()
            count = c.c_uint32()
            call('FwpmFilterEnum0', handle, enum, 512, c.byref(rows), c.byref(count))
            try:
                ids.extend(rows[i].contents.id for i in range(count.value)
                           if bytes(rows[i].contents.sublayer) == bytes(key) and rows[i].contents.flags & 1)
            finally:
                if rows:
                    api.FwpmFreeMemory0(c.byref(rows))
            if count.value < 512:
                break
    finally:
        api.FwpmFilterDestroyEnumHandle0(handle, enum)
    for ident in ids:
        call('FwpmFilterDeleteById0', handle, c.c_uint64(ident))
    if remove_layer:
        call('FwpmSubLayerDeleteByKey0', handle, c.byref(key))


def add_tun_filters(handle, sub, luid):
    if not luid:
        return []
    value = c.c_uint64(luid)
    condition = g['Condition'](g['guid']('4cd62a49-59c3-4969-b7f3-bda5d32890a4'), 0,
                               g['Value'](4, g['Data'](pointer=c.addressof(value))))
    return [g['add_filter'](handle, sub, layer, 'Mihomo TUN', g['PERMIT'], 13, [condition])
            for layer in g['LAYERS']]


def replace_tun_filters(handle, previous, luid):
    with transaction(handle):
        if not installed(handle):
            return None
        for ident in previous:
            call('FwpmFilterDeleteById0', handle, ident)
        sub = g['Sublayer']()
        sub.key = key
        return add_tun_filters(handle, sub, luid)

@functools.lru_cache(maxsize=1)
def physical_luids(interface_list):
    # The list of local interfaces is the cache key. An SSID change on the
    # same adapter needs no update. Discovery must also work before DHCP.
    ps = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    indices = subprocess.check_output(
        [str(ps), '-NoProfile', '-NonInteractive', '-Command',
         "$ErrorActionPreference='Stop'; (Get-NetAdapter -Physical).ifIndex"],
        timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    values = []
    for index in indices.split():
        luid = c.c_uint64()
        if c.windll.iphlpapi.ConvertInterfaceIndexToLuid(int(index), c.byref(luid)) == 0:
            values.append(luid.value)
    return tuple(sorted(values))


def add_dhcp_filters(handle, sub, interfaces):
    if not interfaces:
        return
    app, descriptor = ptr(), ptr()
    size = c.c_uint32()
    # NT SERVICE\Dhcp. Grant only FWP_ACTRL_MATCH_FILTER to its service token.
    sid = 'S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582'
    sddl = c.c_wchar_p(f'O:SYG:SYD:(A;;0x1;;;{sid})')
    if not c.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, c.byref(descriptor), c.byref(size)):
        raise c.WinError()
    try:
        image = Path(os.environ['SystemRoot']) / 'System32/svchost.exe'
        call('FwpmGetAppIdFromFileName0', c.c_wchar_p(str(image)), c.byref(app))
        blob = g['Blob'](size.value, descriptor.value)
        def number(key, kind, value):
            return g['Condition'](g['guid'](key), 0, g['Value'](kind, g['Data'](number=value)))
        def pointer(key, kind, value):
            return g['Condition'](g['guid'](key), 0, g['Value'](kind, g['Data'](pointer=value)))
        for layer, client, server in zip(g['LAYERS'], (68, 546), (67, 547)):
            for interface in interfaces:
                luid = c.c_uint64(interface)
                conditions = [
                    pointer(g['APP'], 12, app.value),
                    pointer('af043a0a-b34d-4f86-979c-c90371af6e66', 14, c.addressof(blob)),
                    pointer('4cd62a49-59c3-4969-b7f3-bda5d32890a4', 4, c.addressof(luid)),
                    number('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7', 1, 17),
                    number('0c1ba1af-5765-453f-af22-a8f791ac775b', 2, client),
                    number('c35a604d-d22b-4e1a-91b4-68f674ee674b', 2, server),
                ]
                g['add_filter'](handle, sub, layer, 'Windows DHCP client', g['PERMIT'], 13, conditions)
    finally:
        if app:
            api.FwpmFreeMemory0(c.byref(app))
        c.windll.kernel32.LocalFree(descriptor)


def install(handle, core, addresses, transport, networks, luid, refresh=False, dhcp_interfaces=()):
    app = ptr()
    if addresses or networks:
        call('FwpmGetAppIdFromFileName0', c.c_wchar_p(str(core)), c.byref(app))
    try:
        with transaction(handle):
            if refresh and not installed(handle):
                return
            exists = installed(handle)
            clear(handle, remove_layer=False)
            sub = g['Sublayer']()
            sub.key, sub.flags, sub.weight = key, 1, 0x8000
            sub.display.name = 'V2RayN TUN Bridge outbound protection'
            if not exists:
                call('FwpmSubLayerAdd0', handle, c.byref(sub), None)
            for layer in g['LAYERS']:
                def add(label, action, weight, conditions):
                    g['add_filter'](handle, sub, layer, label, action, weight, conditions)
                add('loopback', g['PERMIT'],14,[g['Condition'](g['guid'](g['FLAGS']),6,g['Value'](3,g['Data'](number=1)))])
                add('physical egress',g['BLOCK'],1,[])
            tun_filters = add_tun_filters(handle, sub, luid)
            add_dhcp_filters(handle, sub, dhcp_interfaces)
            for ip in addresses:
                g['permit_endpoint'](handle, sub, app, ip, transport)
            for network in networks:
                g['permit_network'](handle, sub, app, network)
        return tun_filters
    finally:
        if app:
            api.FwpmFreeMemory0(c.byref(app))


def report(message):
    if sys.stdout is not None:
        print(message,flush=True)
    from local_access import save
    save(STATE, {'message': message, 'time': time.time(), 'pid': os.getpid()})


@contextlib.contextmanager
def action_lock():
    kernel = c.windll.kernel32
    kernel.CreateMutexW.restype = ptr
    lock = kernel.CreateMutexW(None, False, 'Global\\V2RayNTunBridgeGuardActionV1')
    if not lock:
        raise c.WinError()
    try:
        if kernel.WaitForSingleObject(ptr(lock), 120000) not in (0, 128):
            raise RuntimeError('Another protection operation is still running')
        try:
            yield
        finally:
            kernel.ReleaseMutex(ptr(lock))
    finally:
        kernel.CloseHandle(ptr(lock))


def record_status(on, host='', transport=(0, 0), addresses=(), interface=None):
    from local_access import save
    save(STATE.with_name('guard-heartbeat.json'), {
        'on': on, 'at': time.time(), 'host': host, 'port': transport[0],
        'addresses': [str(address) for address in addresses],
        'tunLuid': interface,
    })


def recent_status():
    from local_access import read
    record=read(STATE.with_name('guard-heartbeat.json'))
    if time.time()-record.get('at',0)<15:
        return '保护已开启（后台已核验）' if record.get('on') else '保护已关闭（后台已核验）'
    return ''


def acknowledge():
    if len(sys.argv)==3:
        from local_access import save
        save(STATE.with_name('guard-ready.json'),{'token':sys.argv[2]})


def activate(handle):
    # The mutex lives until the watcher exits, including across GUI restarts.
    kernel=c.windll.kernel32
    kernel.CreateMutexW.restype=ptr
    mutex=kernel.CreateMutexW(None,False,'Global\\V2RayNTunBridgeGuardWatcherV1')
    if not mutex:
        raise c.WinError()
    try:
        if kernel.WaitForSingleObject(ptr(mutex),2000) not in (0,128):
            if installed(handle):
                report('保护已开启')
                acknowledge()
                return
            raise RuntimeError('保护进程正在切换状态，请稍后再试')
        with action_lock():
            core,host,transport=None,'',(0,0)
            addresses,networks=[],set()
            try:
                candidate,host,transport=g['read_node_details']()
                verify_core(candidate)
                core=candidate
                networks=direct_networks(config_path())
                addresses=g['resolve_node'](host,retries=1)
            except (OSError, ValueError, RuntimeError, KeyError, TypeError):
                # Keep protection and captive login available before VPN connectivity exists.
                addresses=[]
            next_identity_check=0
            interface=tun_luid()
            dhcp_interfaces = physical_luids(tuple(socket.if_nameindex()))
            tun_filters = install(handle,core,addresses,transport,networks,interface,dhcp_interfaces=dhcp_interfaces)
            report('保护已开启 · IPv4 / IPv6')
            record_status(True, host, transport, addresses, interface)
            acknowledge()
            import local_access, subprocess
            if local_access.read(local_access.LAN_OPTIONS):
                subprocess.Popen([str(Path(sys.executable).with_name('pythonw.exe')),
                                  str(Path(__file__).resolve()),'local'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        last_heartbeat=time.monotonic()
        while True:
            time.sleep(1)
            if not installed(handle):
                return
            if time.monotonic()-last_heartbeat>=5:
                record_status(True, host, transport, addresses, interface)
                last_heartbeat=time.monotonic()
            try:
                updated_core,new_host,new_transport=g['read_node_details']()
                if updated_core != core:
                    if time.monotonic()<next_identity_check:
                        raise ValueError('Awaiting identity check')
                    next_identity_check=time.monotonic()+15
                    verify_core(updated_core)
                new_networks=direct_networks(config_path())
                try:
                    new_addresses=addresses if core==updated_core and host==new_host and addresses else g['resolve_node'](new_host)
                except (OSError, ValueError):
                    new_addresses=[]
            except (OSError, ValueError, RuntimeError, KeyError, TypeError):
                updated_core,new_host,new_addresses,new_networks,new_transport=None,'',[],set(),transport
            new_interface=tun_luid()
            try:
                new_dhcp = physical_luids(tuple(socket.if_nameindex()))
            except (OSError, ValueError, subprocess.SubprocessError):
                new_dhcp = dhcp_interfaces
            if (updated_core,new_host,new_transport,new_networks,new_addresses,new_dhcp) != (core,host,transport,networks,addresses,dhcp_interfaces):
                # Stop wins if the off transaction has already removed the sublayer.
                tun_filters = install(handle,updated_core,new_addresses,new_transport,new_networks,new_interface,refresh=True,dhcp_interfaces=new_dhcp)
                if tun_filters is None:
                    return
                core=updated_core
                dhcp_interfaces=new_dhcp
                host,transport,networks,interface,addresses=new_host,new_transport,new_networks,new_interface,new_addresses
                record_status(True, host, transport, addresses, interface)
                report('保护已开启 · 放行规则已同步' if addresses else '保护已开启 · 待确认节点，物理公网默认阻断')
            elif new_interface != interface:
                tun_filters = replace_tun_filters(handle, tun_filters, new_interface)
                if tun_filters is None:
                    return
                interface = new_interface
                record_status(True, host, transport, addresses, interface)
                report('保护已开启 · TUN 接口已放行' if interface else '保护已开启 · TUN 接口已移除')
    finally:
        kernel.CloseHandle(ptr(mutex))


def tun_control(start):
    import subprocess
    from local_access import ROOT
    repo=HERE
    ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    if start:
        with engine() as h:
            python=Path(sys.executable).with_name('pythonw.exe')
            synchronized=ROOT/'guard-ready.json'
            token=os.urandom(12).hex()
            with (ROOT/'tun-commands.log').open('ab', buffering=0) as log:
                log.write(f'\n[{time.strftime("%Y-%m-%d %H:%M:%S")}] 保护初始化\n'.encode())
                proc=subprocess.Popen([str(python),'-X','utf8',str(Path(__file__).resolve()),'on',token],
                                      stdout=subprocess.DEVNULL,stderr=log,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            end=time.monotonic()+90
            while time.monotonic()<end:
                try:
                    ack=json.loads(synchronized.read_text(encoding='utf-8'))
                except (OSError,ValueError):
                    ack={}
                if ack.get('token')==token and installed(h):
                    break
                if proc.poll() is not None and proc.returncode!=0:
                    from local_access import read
                    detail = read(STATE)
                    message = detail.get('message', '') if detail.get('pid') == proc.pid else ''
                    raise RuntimeError(f'保护初始化失败：{message or "请查看 TUN 工作日志"}')
                time.sleep(.25)
            else:
                raise RuntimeError('保护未确认就绪，已取消 TUN 启动')
    args=[str(ps),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(repo/'mihomo-tun.ps1'),
          '-Action','Start' if start else 'Stop','-AppRoot',str(config_path().parents[1]),
          '-ManualV2rayN','-Elevated']
    with (ROOT/'tun-commands.log').open('ab', buffering=0) as log:
        label='Start' if start else 'Stop'
        started_at = time.time()
        log.write(f'\n[{time.strftime("%Y-%m-%d %H:%M:%S")}] {label} TUN\n'.encode())
        try:
            environment = os.environ.copy()
            if start:
                environment['TUN_BRIDGE_GUARDED_START'] = '1'
            result=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=125,env=environment,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        except (subprocess.TimeoutExpired,OSError) as exc:
            log.write((str(exc)+'\n').encode('utf-8'))
            raise
        log.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] exit={result.returncode}\n'.encode())
        if result.returncode and not (start and result.returncode==11 and tun_luid()):
            from local_access import read
            message = f'TUN 操作失败（{result.returncode}），请查看 TUN 工作日志'
            status_path = ROOT/'mihomo-runtime-report.json'
            if start and result.returncode == 2 and status_path.is_file() and status_path.stat().st_mtime >= started_at:
                status = read(status_path)
                if status.get('state') == 'failed' and status.get('errorMessage'):
                    message = f"TUN 启动失败 [{status.get('errorCheckpoint')}] {status['errorMessage']}"
            log.write((message + '\n').encode('utf-8'))
            raise RuntimeError(message)
    report('TUN 已启动' if start else 'TUN 已停止，保护状态独立保持')


def main(action):
    import local_access as local
    if action in ('tun-on','tun-off'):
        return tun_control(action=='tun-on')
    if action=='local':
        with engine() as handle:
            live=installed(handle)
            if not live:raise RuntimeError('请先开启保护，再批准直连')
        return local.watch_link(sys.modules[__name__])
    with engine() as handle:
        if action=='off':
            local.save(local.PORTAL,{})
            local.save(local.ROOT/'link-stop.json',{'time':time.time()})
            deadline=time.monotonic()+15
            while local.read(local.ROOT/'link-active.json') and time.monotonic()<deadline:
                time.sleep(.2)
            with action_lock(), transaction(handle):
                clear(handle)
            record_status(False)
            report('保护已关闭')
        elif action=='on':
            activate(handle)
        else:
            print('on' if installed(handle) else 'off')


if __name__=='__main__':
    try:
        main(sys.argv[1])
    except Exception as exc:
        if sys.stderr is not None:
            import traceback
            traceback.print_exc()
        report(f'操作失败：{exc}')
        sys.exit(1)
