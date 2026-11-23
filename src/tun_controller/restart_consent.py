"""Fail-closed desktop consent for disruptive TUN restarts."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from concurrent.futures import Future
import threading
from typing import Any


class _SessionInfo(ctypes.Structure):
    _fields_ = [
        ("session_id", wintypes.DWORD), ("state", ctypes.c_int),
        ("flags", wintypes.LONG), ("station", wintypes.WCHAR * 33),
        ("user", wintypes.WCHAR * 21), ("domain", wintypes.WCHAR * 18),
        ("logon", ctypes.c_longlong), ("connect", ctypes.c_longlong),
        ("disconnect", ctypes.c_longlong), ("last_input", ctypes.c_longlong),
        ("current", ctypes.c_longlong),
        ("incoming_bytes", wintypes.DWORD), ("outgoing_bytes", wintypes.DWORD),
        ("incoming_frames", wintypes.DWORD), ("outgoing_frames", wintypes.DWORD),
        ("incoming_compressed", wintypes.DWORD), ("outgoing_compressed", wintypes.DWORD),
    ]


class _SessionInfoEx(ctypes.Structure):
    _fields_ = [("level", wintypes.DWORD), ("data", _SessionInfo)]


def session_locked() -> bool | None:
    """Query this process's Windows session; errors are never treated as locked."""
    buffer = ctypes.c_void_p()
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
        session = wintypes.DWORD()
        kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        kernel.ProcessIdToSessionId.restype = wintypes.BOOL
        if not kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId(), ctypes.byref(session)):
            return None
        query = wts.WTSQuerySessionInformationW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        size = wintypes.DWORD()
        if not query(None, session, 25, ctypes.byref(buffer), ctypes.byref(size)):
            return None
        if size.value < ctypes.sizeof(_SessionInfoEx):
            return None
        info = ctypes.cast(buffer, ctypes.POINTER(_SessionInfoEx)).contents
        if info.level != 1 or info.data.session_id != session.value:
            return None
        return {0: True, 1: False}.get(info.data.flags)
    except (OSError, AttributeError, ValueError):
        return None
    finally:
        if buffer.value:
            wts.WTSFreeMemory(buffer)


def ask_restart(reason: str) -> bool:
    """Only an explicit Yes permits a restart; Cancel/close/API failure deny."""
    try:
        show = ctypes.WinDLL("user32", use_last_error=True).MessageBoxW
        show.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
        show.restype = ctypes.c_int
        text = (f"{reason}\n\n重启 TUN 会短暂中断网络连接。是否允许现在重启？"
                "\n选择“是”允许重启；选择“否”、取消或关闭窗口均不重启。"
                "\n锁屏后允许自动恢复。")
        # YESNOCANCEL + question + default No + foreground + topmost.
        return show(None, text, "TUN 重启请示", 0x3 | 0x20 | 0x100 | 0x10000 | 0x40000) == 6
    except (OSError, AttributeError):
        return False


def confirm_restart(reason: str) -> bool:
    return session_locked() is True or ask_restart(reason)


def _start_prompt(reason: str) -> Future:
    result: Future = Future()
    def run() -> None:
        try:
            result.set_result(ask_restart(reason))
        except Exception:
            result.set_result(False)
    threading.Thread(target=run, name="restart-consent", daemon=True).start()
    return result


class RestartConsent:
    """Nonblocking approval tied to one snapshot, never reused after a change."""
    def __init__(self, *, locked=None, prompt=None):
        self.locked = locked or session_locked
        self.prompt = prompt or _start_prompt
        self.pending: tuple[Any, Future] | None = None
        self.seen: set[Any] = set()
        self.state = "idle"

    def allow(self, candidate: Any, key: Any, reason: str) -> bool:
        # Invalidate a displayed request as soon as its target changes.
        if self.pending and self.pending[0] != candidate:
            self.pending = (None, self.pending[1])
        if candidate is not None and self.locked() is True:
            if self.pending:
                self.pending = (None, self.pending[1])
            self.state = "locked-auto-restart"
            return True
        if self.pending:
            target, result = self.pending
            if not result.done():
                self.state = "awaiting-restart-approval"
                return False
            self.pending = None
            if target is not None and target == candidate and result.result() is True:
                self.state = "restart-approved"
                return True
            self.state = "restart-deferred"
        if candidate is not None and key not in self.seen:
            self.seen.add(key)
            self.pending = (candidate, self.prompt(reason))
            self.state = "awaiting-restart-approval"
        return False
