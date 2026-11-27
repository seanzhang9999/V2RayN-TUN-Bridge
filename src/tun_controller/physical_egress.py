"""A loopback-only Xray outbound for sockets already routed by v2rayN."""
import ctypes
import ipaddress
import json
import re
import socket
import subprocess
import time
import uuid


def endpoint_hosts(host, addresses):
    """Pin only the exact server name resolved before enabling the TUN."""
    host = host.strip().rstrip(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
        ):
            raise ValueError("VPN 节点域名无效") from None
        return {host: list(addresses)}
    return {}


class PhysicalEgress:
    def __init__(self, app_root, interface, hosts):
        self.exe = (app_root / "bin/Xray/xray.exe").resolve(strict=True)
        self.identity = str(uuid.uuid4())
        self.interface = interface
        self.hosts = hosts
        self.process = None
        self.job = None
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]

    def start(self):
        config = {
            "inbounds": [{"listen": "127.0.0.1", "port": self.port, "protocol": "vless",
                          "settings": {"decryption": "none", "clients": [{"id": self.identity}]}}],
            # A TUN fake-IP may have been converted back to a domain by Mihomo.
            # Resolve it through 1081; the OS resolver can return the fake-IP again.
            "dns": {"tag": "egress-dns", "servers": ["https://1.1.1.1/dns-query"],
                    "hosts": {f"full:{host}": ips for host, ips in self.hosts.items()}},
            "routing": {"rules": [{"type": "field", "inboundTag": ["egress-dns"],
                                   "outboundTag": "dns-via-v2rayn"}]},
            "outbounds": [
                {"tag": "physical", "protocol": "freedom", "settings": {"targetStrategy": "ForceIP"},
                 "streamSettings": {"sockopt": {"interface": self.interface}}},
                {"tag": "dns-via-v2rayn", "protocol": "socks", "settings": {
                    "servers": [{"address": "127.0.0.1", "port": 1081}]}}
            ],
        }
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = ctypes.c_void_p
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        self.job = ctypes.c_void_p(job)
        try:
            # JOBOBJECT_EXTENDED_LIMIT_INFORMATION, 64-bit Windows (as required by WFP).
            limits = ctypes.create_string_buffer(144)
            ctypes.c_uint32.from_buffer(limits, 16).value = 0x2000  # KILL_ON_JOB_CLOSE
            if not kernel.SetInformationJobObject(self.job, 9, limits, len(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.process = subprocess.Popen(
                [str(self.exe), "run", "-format", "json", "-config", "stdin:"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            if not kernel.AssignProcessToJobObject(self.job, ctypes.c_void_p(self.process._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.process.stdin.write(json.dumps(config).encode())
            self.process.stdin.close()
            deadline = time.monotonic() + 5
            while self.process.poll() is None and time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=.2):
                        return
                except OSError:
                    time.sleep(.1)
            raise RuntimeError("物理出口 Xray 未能启动")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.job:
            ctypes.windll.kernel32.CloseHandle(self.job)
            self.job = None
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None
