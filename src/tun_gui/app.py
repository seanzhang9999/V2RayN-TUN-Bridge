"""Tkinter GUI for the v2rayN-powered Mihomo TUN controller."""

from __future__ import annotations

import json
import os
import queue
import ctypes
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from tkinter import filedialog, messagebox, Tk, StringVar, BooleanVar, Text, ttk

from tun_bridge.resources import resource_root
from tun_gui.monitor import (
    ConnectionAccumulator,
    fetch_connections,
    format_rate,
    format_transfer,
)
from tun_controller.v2rayn_source import DEFAULT_APP_ROOT, list_v2rayn_profiles

PROJECT_ROOT = resource_root()
CONTROL_SCRIPT = PROJECT_ROOT / "mihomo-tun.ps1"
RUNTIME_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "v2rayn-tun-controller"
STATUS_PATH = RUNTIME_ROOT / "mihomo-runtime-report.json"
SETTINGS_PATH = RUNTIME_ROOT / "gui-settings.json"
CONTROLLER_ACCESS_PATH = RUNTIME_ROOT / "mihomo-controller-access.json"


def build_control_command(
    action: str,
    app_root: Path,
    *,
    profile_id: str = "",
    manual_v2rayn: bool = False,
    elevated: bool = False,
    app_executable: Path | None = None,
) -> list[str]:
    """Build the exact PowerShell control path used by the manual launcher."""
    args = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(CONTROL_SCRIPT),
        "-Action",
        action,
        "-AppRoot",
        str(app_root),
    ]
    if action == "Start":
        args += ["-ProfileId", profile_id]
        if manual_v2rayn:
            args.append("-ManualV2rayN")
    if elevated:
        args.append("-Elevated")
    if app_executable is not None:
        args += ["-AppExecutable", str(app_executable)]
    return args


class TunGuiApp:
    CHECKS = (
        ("google", "系统链路 Google", "google"),
        ("chatgpt", "系统链路 ChatGPT", "chatgpt"),
        ("mihomo-google", "本地代理 Google", "mihomo-google"),
        ("mihomo-chatgpt", "本地代理 ChatGPT", "mihomo-chatgpt"),
        ("direct-baidu", "直连 Baidu", "direct-baidu"),
    )

    def __init__(self) -> None:
        self.root = Tk()
        self.root.title("V2RayN TUN Bridge")
        self.root.geometry("980x820")
        self.root.configure(bg="#101820")
        self.root.minsize(900, 680)

        self.style = ttk.Style(self.root)
        self._configure_style()

        self.app_root_var = StringVar(value=str(DEFAULT_APP_ROOT))
        self.profile_display_var = StringVar()
        self.status_var = StringVar(value="未启动")
        self.checkpoint_var = StringVar(value="")
        self.route_var = StringVar(value="")
        self.message_var = StringVar(value="就绪，正在读取配置…")
        self.profile_supported_var = StringVar(value="")
        self.unsupported_var = StringVar(value="")
        self.manual_var = BooleanVar(value=False)
        self.proxy_speed_var = StringVar(value="↑ 0 B/s    ↓ 0 B/s")
        self.direct_speed_var = StringVar(value="↑ 0 B/s    ↓ 0 B/s")
        self.monitor_status_var = StringVar(value="等待 Mihomo 启动")
        self.proxy_info_var = StringVar(value="尚未读取到当前代理")

        self._profiles: list[str] = []
        self._profile_lookup: dict[str, str] = {}
        self._health_rows: dict[str, tuple[StringVar, StringVar]] = {}
        self._cmd_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self._busy = False
        self._monitor_stop = threading.Event()
        self._connection_accumulator = ConnectionAccumulator()

        self._build_ui()
        self._load_settings()
        self.refresh_profiles()
        self._poll_status()
        self._poll_queue()
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self) -> None:
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#101820")
        self.style.configure("TLabel", foreground="#dce7ff", background="#101820", font=("Segoe UI", 10))
        self.style.configure(
            "Title.TLabel",
            foreground="#e6ffea",
            background="#101820",
            font=("Segoe UI", 12, "bold"),
        )
        self.style.configure("TButton", foreground="#0f1f24", background="#7be8b7", font=("Segoe UI", 10, "bold"))
        self.style.map("TButton", background=[("pressed", "#47c58d"), ("active", "#56d59a")])
        self.style.configure("TCombobox", fieldbackground="#0f1f24", foreground="#dce7ff")
        self.style.configure("TLabelframe", background="#101820", foreground="#e8f4ff")
        self.style.configure("TLabelframe.Label", background="#101820", foreground="#bde3ff")
        self.style.configure("Status.TLabel", foreground="#f4ffde", background="#101820", font=("Consolas", 10))
        self.style.configure("Metric.TLabel", foreground="#7be8b7", background="#101820", font=("Consolas", 12, "bold"))
        self.style.configure("Treeview", background="#081117", fieldbackground="#081117", foreground="#dce7ff", rowheight=24)
        self.style.configure("Treeview.Heading", background="#172832", foreground="#dce7ff", font=("Segoe UI", 9, "bold"))
        self.style.configure("TNotebook", background="#101820", borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(14, 7), font=("Segoe UI", 9, "bold"))

    def _build_ui(self) -> None:
        body = ttk.Frame(self.root, padding=16)
        body.pack(fill="both", expand=True)

        title = ttk.Label(body, text="Mihomo TUN 控制台", style="Title.TLabel")
        title.pack(anchor="w", pady=(0, 10))

        self._build_config_section(body)
        self._build_action_section(body)
        self._build_status_section(body)
        self._build_detail_tabs(body)

    def _build_detail_tabs(self, parent: ttk.Frame) -> None:
        tabs = ttk.Notebook(parent)
        tabs.pack(fill="both", expand=True)
        monitor_tab = ttk.Frame(tabs, padding=(0, 8, 0, 0))
        health_tab = ttk.Frame(tabs, padding=(0, 8, 0, 0))
        log_tab = ttk.Frame(tabs, padding=(0, 8, 0, 0))
        tabs.add(monitor_tab, text="实时监控")
        tabs.add(health_tab, text="连通检测")
        tabs.add(log_tab, text="运行日志")
        self._build_monitor_section(monitor_tab)
        self._build_health_section(health_tab)
        self._build_log_section(log_tab)

    def _build_config_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="1) 选择运行参数", padding=12)
        frame.pack(fill="x", pady=(0, 12))

        path_row = ttk.Frame(frame)
        path_row.pack(fill="x")
        ttk.Label(path_row, text="v2rayN 安装目录").pack(side="left")
        ttk.Entry(path_row, textvariable=self.app_root_var, width=72).pack(
            side="left", padx=(12, 8), fill="x", expand=True
        )
        ttk.Button(path_row, text="浏览", command=self._choose_app_root).pack(side="right")

        profile_row = ttk.Frame(frame)
        profile_row.pack(fill="x", pady=(10, 0))
        ttk.Label(profile_row, text="支持的节点").pack(side="left")
        self.profile_combo = ttk.Combobox(
            profile_row, textvariable=self.profile_display_var, width=72, state="readonly"
        )
        self.profile_combo.pack(side="left", padx=(12, 8), fill="x", expand=True)
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_select)
        ttk.Button(profile_row, text="刷新", command=self.refresh_profiles).pack(side="right")

        bottom_row = ttk.Frame(frame)
        bottom_row.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(
            bottom_row,
            text="兼容模式：保留 v2rayN（Mihomo 使用 1082）",
            variable=self.manual_var,
        ).pack(side="left")
        ttk.Label(bottom_row, textvariable=self.profile_supported_var, foreground="#c3e8ff").pack(
            side="right"
        )

        notes_row = ttk.Frame(frame)
        notes_row.pack(fill="x")
        ttk.Label(notes_row, textvariable=self.unsupported_var, foreground="#97d6ff").pack(anchor="w")

    def _build_action_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="2) 启动与停止", padding=12)
        frame.pack(fill="x")
        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x")
        self.start_btn = ttk.Button(btn_row, text="启动 TUN", command=self._start_tun)
        self.start_btn.pack(side="left", padx=(0, 10))
        self.stop_btn = ttk.Button(btn_row, text="停止 TUN", command=self._stop_tun)
        self.stop_btn.pack(side="left")
        ttk.Label(btn_row, textvariable=self.message_var, style="Status.TLabel").pack(
            side="left", padx=(16, 0), anchor="w"
        )

    def _build_status_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="3) 运行状态", padding=12)
        frame.pack(fill="x", pady=(12, 12))

        top = ttk.Frame(frame)
        top.pack(fill="x")
        ttk.Label(top, text="当前状态：").pack(side="left")
        ttk.Label(top, textvariable=self.status_var, style="Title.TLabel").pack(side="left", padx=(8, 16))
        ttk.Label(top, text="阶段：").pack(side="left")
        ttk.Label(top, textvariable=self.checkpoint_var, style="Status.TLabel").pack(side="left")

        route_row = ttk.Frame(frame)
        route_row.pack(fill="x", pady=(8, 0))
        ttk.Label(route_row, text="本次路由摘要：").pack(side="left")
        ttk.Label(route_row, textvariable=self.route_var, style="Status.TLabel").pack(side="left")

    def _build_health_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(
            parent, text="启动后连通检测（仅提示，不影响 TUN 运行）", padding=12
        )
        frame.pack(fill="both", expand=True)

        for key, label, _ in self.CHECKS:
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=(0, 6))
            ttk.Label(row, text=label, width=20).pack(side="left")
            status_var = StringVar(value="待测")
            detail_var = StringVar(value="未开始")
            self._health_rows[key] = (status_var, detail_var)
            ttk.Label(row, textvariable=status_var, width=12).pack(side="left")
            ttk.Label(row, textvariable=detail_var, style="Status.TLabel").pack(side="left", padx=(6, 0))

    def _build_monitor_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="实时流量与最近连接", padding=12)
        frame.pack(fill="both", expand=True)

        metrics = ttk.Frame(frame)
        metrics.pack(fill="x")
        ttk.Label(metrics, text="代理速度").grid(row=0, column=0, sticky="w")
        ttk.Label(metrics, textvariable=self.proxy_speed_var, style="Metric.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 36)
        )
        ttk.Label(metrics, text="直连速度").grid(row=0, column=1, sticky="w")
        ttk.Label(metrics, textvariable=self.direct_speed_var, style="Metric.TLabel").grid(
            row=1, column=1, sticky="w", padx=(0, 36)
        )
        ttk.Label(metrics, textvariable=self.monitor_status_var, style="Status.TLabel").grid(
            row=1, column=2, sticky="e"
        )
        metrics.columnconfigure(2, weight=1)

        ttk.Label(frame, textvariable=self.proxy_info_var, style="Status.TLabel").pack(
            fill="x", pady=(10, 8)
        )

        detail_tabs = ttk.Notebook(frame)
        detail_tabs.pack(fill="both", expand=True, pady=(6, 0))
        tun_tab = ttk.Frame(detail_tabs, padding=(0, 6, 0, 0))
        proxy_tab = ttk.Frame(detail_tabs, padding=(0, 6, 0, 0))
        detail_tabs.add(tun_tab, text="最近 TUN 连接（10 条）")
        detail_tabs.add(proxy_tab, text="最近 1081 代理连接（10 条）")

        self.tun_connections_table = self._build_connection_table(tun_tab)
        self.proxy_connections_table = self._build_connection_table(proxy_tab)

    def _build_connection_table(self, parent: ttk.Frame) -> ttk.Treeview:
        """Create one connection view so both source tabs keep identical columns."""

        columns = ("time", "target", "source", "route", "process", "traffic")
        table = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            height=10,
            selectmode="browse",
        )
        headings = {
            "time": "时间",
            "target": "目标",
            "source": "入口",
            "route": "出口",
            "process": "进程",
            "traffic": "累计流量",
        }
        widths = {
            "time": 70,
            "target": 255,
            "source": 70,
            "route": 70,
            "process": 135,
            "traffic": 185,
        }
        for key in columns:
            table.heading(key, text=headings[key])
            table.column(key, width=widths[key], anchor="w")
        table.pack(fill="both", expand=True)
        return table

    def _build_log_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="最近日志", padding=12)
        frame.pack(fill="both", expand=True)
        self.log_box = Text(
            frame,
            bg="#081117",
            fg="#c6f7ff",
            insertbackground="#fff",
            height=7,
            wrap="word",
            state="disabled",
            font=("Consolas", 10),
        )
        self.log_box.pack(fill="both", expand=True)

    def _safe_read_json(self, path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _load_settings(self) -> None:
        data = self._safe_read_json(SETTINGS_PATH)
        if not data:
            return
        app_root = str(data.get("app_root", "") or "")
        if app_root:
            self.app_root_var.set(app_root)
        last_profile = str(data.get("last_profile_id", "") or "")
        if last_profile:
            self.profile_display_var.set(last_profile)

    def _save_settings(self) -> None:
        RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
        payload = {
            "app_root": self.app_root_var.get().strip(),
            "last_profile_id": self.profile_display_var.get(),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        SETTINGS_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _choose_app_root(self) -> None:
        value = filedialog.askdirectory(
            title="选择 v2rayN 安装目录",
            initialdir=self.app_root_var.get() or str(Path.home()),
        )
        if value:
            self.app_root_var.set(value)
            self.save_and_refresh()

    def save_and_refresh(self) -> None:
        self._save_settings()
        self.refresh_profiles()

    def _on_profile_select(self, _event: Any = None) -> None:
        self._save_settings()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.start_btn.config(state="disabled" if busy else "normal")
        self.stop_btn.config(state="disabled" if busy else "normal")
        self.profile_combo.config(state="disabled" if busy else "readonly")

    def refresh_profiles(self) -> None:
        app_root = Path(self.app_root_var.get().strip())
        self._append_log("读取 v2rayN profile 列表…")
        try:
            if not app_root.is_dir():
                raise FileNotFoundError(f"目录不存在：{app_root}")
            summaries = list_v2rayn_profiles(app_root)
            supported = [s for s in summaries if s.supported]
            unsupported = [s for s in summaries if not s.supported]
            self._profiles = supported
            display_items: list[str] = []
            self._profile_lookup.clear()
            for summary in supported:
                item = f"{summary.remarks}  [{summary.protocol}/{summary.transport}]"
                display_items.append(item)
                self._profile_lookup[item] = summary.profile_id

            self.profile_combo["values"] = display_items
            self.unsupported_var.set(
                f"当前目录可见：支持 {len(supported)} 个节点，暂不支持 {len(unsupported)} 个节点"
            )
            if supported:
                preselect = next(
                    (item for item in supported if item.profile_id == self._get_selected_profile_id()),
                    supported[0],
                )
                self.profile_combo.set(f"{preselect.remarks}  [{preselect.protocol}/{preselect.transport}]")
                self.profile_supported_var.set(f"已选：{preselect.remarks}｜{preselect.support_detail}")
            else:
                self.profile_combo.set("")
                self.profile_supported_var.set("未找到可用支持节点；请确认协议为 Hysteria2 / VLESS(tcp/raw/grpc/ws)")
            self._save_settings()
            self.message_var.set("已刷新节点列表")
        except Exception as exc:
            self._append_log(f"刷新失败：{exc}")
            self.message_var.set(f"刷新失败：{exc}")
            self.profile_combo["values"] = []
            self.profile_combo.set("")
            self.profile_supported_var.set("未读取到可用节点")
            self.unsupported_var.set("")

        self._append_health(None)

    def _get_selected_profile_id(self) -> str:
        display = self.profile_combo.get()
        return self._profile_lookup.get(display, "")

    def _health_status(self, status: str | None, code: str) -> tuple[str, str]:
        if status == "passed":
            return "通过", code or "200"
        if status == "failed":
            return "未通过（提示）", code or "unknown"
        if status == "testing":
            return "检测中", code or "—"
        return "待测", code or "—"

    def _append_health(self, checks: dict[str, Any] | None) -> None:
        if not checks:
            for status_var, detail_var in self._health_rows.values():
                status_var.set("待测")
                detail_var.set("—")
            return
        for key, status_var, detail_var in (
            (k, self._health_rows[k][0], self._health_rows[k][1])
            for k, _, _ in self.CHECKS
        ):
            check = checks.get(key, {})
            status_txt, detail_txt = self._health_status(
                str(check.get("state") or ""),
                str(check.get("httpStatus") or ""),
            )
            status_var.set(status_txt)
            detail_var.set(detail_txt)

    def _append_log(self, message: str) -> None:
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _monitor_loop(self) -> None:
        """Fetch controller data away from Tk's main thread."""
        while not self._monitor_stop.is_set():
            try:
                payload = fetch_connections(CONTROLLER_ACCESS_PATH)
                snapshot = self._connection_accumulator.update(payload)
                self._cmd_queue.put(("monitor", snapshot))
            except Exception:
                self._connection_accumulator.reset_rates()
                self._cmd_queue.put(("monitor-unavailable", None))
            self._monitor_stop.wait(1.0)

    def _render_monitor(self, snapshot: dict[str, Any]) -> None:
        rates = snapshot.get("rates", {})
        proxy = rates.get("proxy", {})
        direct = rates.get("direct", {})
        self.proxy_speed_var.set(
            f"↑ {format_rate(float(proxy.get('up', 0)))}    ↓ {format_rate(float(proxy.get('down', 0)))}"
        )
        self.direct_speed_var.set(
            f"↑ {format_rate(float(direct.get('up', 0)))}    ↓ {format_rate(float(direct.get('down', 0)))}"
        )
        unknown_count = int(snapshot.get("unknown_source_count", 0))
        monitor_text = "实时更新"
        if unknown_count:
            monitor_text += f" · 未识别入口 {unknown_count} 条"
        self.monitor_status_var.set(monitor_text)
        self._render_connection_table(
            self.tun_connections_table, snapshot.get("tun_connections", [])
        )
        self._render_connection_table(
            self.proxy_connections_table, snapshot.get("proxy_connections", [])
        )

    @staticmethod
    def _render_connection_table(table: ttk.Treeview, items: Any) -> None:
        for item_id in table.get_children():
            table.delete(item_id)
        if not isinstance(items, list):
            return
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            route = "直连" if item.get("route") == "direct" else "代理"
            if not item.get("active", True):
                route += "·已结束"
            source = {
                "tun": "TUN",
                "mixed": "本地代理",
                "unknown": "未知",
            }.get(str(item.get("source")), "未知")
            table.insert(
                "",
                "end",
                values=(
                    item.get("started", "—"),
                    item.get("target", "—"),
                    source,
                    route,
                    item.get("process", "—"),
                    format_transfer(int(item.get("upload", 0)), int(item.get("download", 0))),
                ),
            )

    def _run_command(self, action: str, args: list[str]) -> None:
        """Run PowerShell in a worker; all Tk access stays on the main thread."""
        try:
            process = subprocess.run(
                args,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = (process.stdout or "").strip()
            stderr = (process.stderr or "").strip()
            ok = process.returncode == 0
            message = "操作完成" if ok else f"执行返回码 {process.returncode}"
            if not ok and not stdout and not stderr:
                message = "执行失败（无输出）"
            self._cmd_queue.put(
                (
                    "done",
                    {
                        "action": action,
                        "ok": ok,
                        "message": message,
                        "stdout": stdout,
                        "stderr": stderr,
                    },
                )
            )
        except Exception as exc:
            self._cmd_queue.put(("done", {"action": action, "ok": False, "message": str(exc)}))

    def _begin_command(self, action: str) -> None:
        """Capture UI values on the Tk thread, then start the worker."""
        app_root_text = self.app_root_var.get().strip()
        if action == "Start" and not app_root_text:
            messagebox.showwarning("提示", "v2rayN 路径为空")
            return
        profile_id = self._get_selected_profile_id() if action == "Start" else ""
        if action == "Start" and not profile_id:
            messagebox.showwarning("提示", "当前无可启动的可用节点，或未选中任何节点")
            return
        self._save_settings()
        args = build_control_command(
            action,
            Path(app_root_text or "."),
            profile_id=profile_id,
            manual_v2rayn=bool(self.manual_var.get()),
            elevated=self._is_admin(),
            app_executable=Path(sys.executable) if getattr(sys, "frozen", False) else None,
        )
        self._set_busy(True)
        self.message_var.set("控制脚本执行中，请稍候…")
        self._append_log(f"开始执行 {action}（使用与命令行版相同的控制入口）")
        threading.Thread(
            target=self._run_command, args=(action, args), daemon=True
        ).start()

    @staticmethod
    def _is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _start_tun(self) -> None:
        if self._busy:
            return
        self._append_log("开始启动 TUN；网站检测仅作启动后提示")
        self._begin_command("Start")

    def _stop_tun(self) -> None:
        if self._busy:
            return
        self._append_log("开始停止 TUN")
        self._begin_command("Stop")

    def _poll_status(self) -> None:
        status = self._safe_read_json(STATUS_PATH)
        if status:
            state = str(status.get("state") or "unknown")
            checkpoint = str(status.get("checkpoint") or "")
            selected = status.get("selectedProfile") or {}
            if isinstance(selected, dict):
                route_text = ", ".join(
                    item
                    for item in (
                        str(selected.get("routeName", "")).strip(),
                        str(selected.get("protocol", "")).strip(),
                    )
                    if item
                ) or "—"
                self.route_var.set(route_text or "—")
                proxy_parts = [
                    str(selected.get("remarks", "")).strip(),
                    "/".join(
                        value
                        for value in (
                            str(selected.get("protocol", "")).strip(),
                            str(selected.get("transport", "")).strip(),
                        )
                        if value
                    ),
                    str(selected.get("routeName", "")).strip(),
                    str(status.get("physicalInterface", "")).strip(),
                    f"SOCKS/HTTP 127.0.0.1:{int(status.get('localProxyPort') or 1081)}",
                ]
                self.proxy_info_var.set("当前代理｜" + "｜".join(part for part in proxy_parts if part))

            self.status_var.set(_pretty_state(state))
            self.checkpoint_var.set(checkpoint or "—")
            self._append_health(status.get("healthChecks") if isinstance(status.get("healthChecks"), dict) else None)

            error_checkpoint = status.get("errorCheckpoint")
            error_type = status.get("errorType")
            error_message = status.get("errorMessage")
            error_check = status.get("errorCheck")
            if state == "failed" and error_type:
                detail = (
                    f"{error_type}（{error_checkpoint}）"
                    if error_checkpoint
                    else error_type
                )
                if error_check:
                    detail = f"{detail}，失败检查：{error_check}"
                if error_message:
                    detail = f"{detail}，信息：{error_message}"
                self.message_var.set(f"运行失败：{detail}")
                self._append_log(f"运行状态: failed - {detail}")
            elif state == "running":
                if checkpoint.startswith("health-") or checkpoint == "connectivity-tests":
                    self.message_var.set("TUN 已运行，正在收集网站检测结果（结果不影响运行）")
                else:
                    self.message_var.set("TUN 已在线运行；网站检测结果仅供参考")
            elif state == "stopped":
                self.message_var.set("TUN 已停止，1081 已释放；可按需手动启动 v2rayN")
        else:
            self.status_var.set(_pretty_state("not-started"))
            self.checkpoint_var.set("—")
            self.route_var.set("—")
            self._append_health(None)
        self.root.after(750, self._poll_status)

    def _poll_queue(self) -> None:
        while True:
            try:
                item = self._cmd_queue.get_nowait()
            except queue.Empty:
                break
            kind, payload = item
            if kind == "done":
                self._set_busy(False)
                action = payload.get("action", "")
                ok = payload.get("ok", False)
                msg = payload.get("message", "")
                stdout = payload.get("stdout", "")
                stderr = payload.get("stderr", "")
                if stdout:
                    self._append_log(stdout)
                if stderr:
                    self._append_log(stderr)
                if ok:
                    self._append_log(f"{action} 成功：{msg}")
                    self.message_var.set(f"{action} 成功")
                else:
                    self._append_log(f"{action} 失败：{msg}")
                    self.message_var.set(f"{action} 失败：{msg}")
            elif kind == "monitor":
                self._render_monitor(payload)
            elif kind == "monitor-unavailable":
                self.proxy_speed_var.set("↑ 0 B/s    ↓ 0 B/s")
                self.direct_speed_var.set("↑ 0 B/s    ↓ 0 B/s")
                self.monitor_status_var.set("等待 TUN 监控接口")
        self.root.after(200, self._poll_queue)

    def _on_close(self) -> None:
        self._monitor_stop.set()
        self._save_settings()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def _pretty_state(state: str) -> str:
    mapping = {
        "created": "未启动",
        "offline-prepare": "离线预检",
        "online-health-check": "执行连通检测",
        "starting": "启动中",
        "running": "运行中",
        "restarting": "重新配置",
        "stopping": "停止中",
        "stopped": "已停止",
        "failed": "失败",
        "not-started": "未启动",
    }
    return mapping.get(state, "状态：" + state)


def main() -> int:
    app = TunGuiApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
