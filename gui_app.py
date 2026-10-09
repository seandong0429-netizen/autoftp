# -*- coding: utf-8 -*-
"""AutoFTP 图形界面。

基于 tkinter，整合 FTP 服务、防火墙、复印机自动注册。
所有耗时操作在子线程执行，避免界面卡顿。
"""
from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, Optional, Tuple

import config_loader
import firewall_helper
import mfp_register
import mfp_scanner
from ftp_server import FTPServerManager, USER_PERM, ANON_PERM

logger = logging.getLogger(__name__)

# ---- 现代化配色（扁平卡片风） ----
BG_APP = "#f4f6fb"          # 应用背景
BG_CARD = "#ffffff"         # 卡片背景
BG_HEADER = "#1e3a8f"       # 顶栏（深蓝）
ACCENT = "#2563eb"          # 主色（蓝）
ACCENT_HOVER = "#1d4ed8"
ACCENT_SOFT = "#dbeafe"
TEXT = "#0f172a"            # 主文字
MUTED = "#64748b"           # 次要文字
BORDER = "#e2e8f0"          # 卡片边框
SUCCESS = "#16a34a"         # 成功（绿）
WARN = "#d97706"            # 警告（橙，不使用叉号避免误解）
RUNNING = "#2563eb"
FONT = "Segoe UI"
FONT_MONO = "Consolas"

# 权限常量由 ftp_server 提供（匿名/账号均为全权限 elradfmwMT，硬编码不可改）。
# 此处 ANON_PERM/USER_PERM 为从 ftp_server 导入的别名。

# 状态徽标：启用 ✅ / 未启用 ○ / 进行中 ⟳ / 警告 ⚠️（全程不使用叉号避免误解）


class GuiLogHandler(logging.Handler):
    """将日志写入队列，供主线程安全刷新到 Text 控件。"""

    def __init__(self, log_queue: "queue.Queue[str]"):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.log_queue.put(self.format(record))
        except Exception:  # noqa: BLE001
            pass


class AutoFTPApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("AutoFTP — 复印机扫描到 FTP 部署工具")
        self.root.geometry("1040x760")
        self.root.minsize(920, 680)
        self.root.configure(bg=BG_APP)

        self.config: Dict[str, Any] = config_loader.load_config()
        self.ftp_manager = FTPServerManager(self.config, log=self._thread_log)
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self._fields = config_loader.load_fields()
        self._detected_mfps: list = []

        self._apply_theme()
        self._build_logging()
        self._build_ui()
        self._refresh_network_info()
        self._refresh_status()
        self._poll_log_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------------------- 主题 --------------------
    def _apply_theme(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=BG_APP)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("TLabel", background=BG_CARD, foreground=TEXT, font=(FONT, 10))
        style.configure("Muted.TLabel", background=BG_CARD, foreground=MUTED, font=(FONT, 9))
        style.configure("Title.TLabel", background=BG_CARD, foreground=TEXT,
                         font=(FONT, 12, "bold"))
        style.configure("Section.TLabel", background=BG_APP, foreground=MUTED,
                         font=(FONT, 9, "bold"))

        # 输入框
        style.configure("TEntry", fieldbackground=BG_CARD, foreground=TEXT,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                        insertcolor=TEXT, padding=4)
        style.configure("TCombobox", fieldbackground=BG_CARD, foreground=TEXT,
                        background=BG_CARD, bordercolor=BORDER, arrowcolor=ACCENT,
                        padding=4)

        # 按钮：主按钮（accent）/ 次按钮（描边）
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        borderwidth=0, focusthickness=0, padding=(14, 7),
                        font=(FONT, 10, "bold"))
        style.map("Accent.TButton",
                  background=[("active", ACCENT_HOVER), ("disabled", "#94a3b8")],
                  foreground=[("disabled", "#e2e8f0")])

        style.configure("TButton", background=BG_CARD, foreground=TEXT,
                        borderwidth=0, focusthickness=0, padding=(12, 6),
                        font=(FONT, 10))
        style.map("TButton",
                  background=[("active", ACCENT_SOFT)],
                  foreground=[("active", ACCENT)])

        style.configure("TCheckbutton", background=BG_CARD, foreground=TEXT,
                        font=(FONT, 10), focuscolor=BG_CARD)
        style.map("TCheckbutton",
                  background=[("active", BG_CARD)],
                  foreground=[("active", ACCENT)])

        # 滚动条
        style.configure("Vertical.TScrollbar", background=BG_APP, troughcolor=BG_APP,
                        bordercolor=BG_APP, arrowcolor=MUTED)

    # -------------------- 日志 --------------------
    def _build_logging(self) -> None:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S")
        handler = GuiLogHandler(self.log_queue)
        handler.setFormatter(fmt)
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        if not any(isinstance(h, GuiLogHandler) for h in root_logger.handlers):
            root_logger.addHandler(handler)

    def _thread_log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _poll_log_queue(self) -> None:
        try:
            while True:
                self._append_log(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(200, self._poll_log_queue)

    def _append_log(self, msg: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # -------------------- 卡片容器 --------------------
    def _card(self, parent: tk.Widget, title: str | None = None,
              accent: bool = False) -> tk.Frame:
        """创建一张白色卡片，可选标题。返回内部内容 Frame 的父容器（卡片本身）。"""
        card = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                        highlightthickness=1, bd=0)
        if title:
            head = tk.Frame(card, bg=BG_CARD)
            head.pack(fill="x", padx=16, pady=(12, 4))
            bar = tk.Frame(head, bg=ACCENT if accent else ACCENT_SOFT,
                           width=3, height=18)
            bar.pack(side="left", fill="y", padx=(0, 8))
            tk.Label(head, text=title, bg=BG_CARD, fg=TEXT,
                     font=(FONT, 12, "bold")).pack(side="left")
        body = tk.Frame(card, bg=BG_CARD)
        body.pack(fill="both", expand=True, padx=16, pady=(4, 14))
        card.body = body  # type: ignore[attr-defined]
        return card

    # -------------------- 自定义开关 --------------------
    def _make_toggle(self, parent: tk.Widget, text: str, var: tk.BooleanVar,
                     command=None) -> tk.Button:
        """自定义开关按钮：选中显示 ✅，未选中显示 ⬜。

        用以替代 ttk.Checkbutton——其 clam 主题选中态渲染为叉号，易让用户误读为关闭。
        使用扁平 tk.Button + command，点击语义可靠；✅ 在 Segoe UI Emoji / Apple Color
        Emoji 中为彩色字形，文字仍为 TEXT 色。
        """
        def sync() -> None:
            btn.configure(text=("✅  " if var.get() else "⬜  ") + text)

        def toggle() -> None:
            var.set(not var.get())
            sync()
            if command:
                command()

        btn = tk.Button(parent, text="", bg=BG_CARD, fg=TEXT, font=(FONT, 10),
                        relief="flat", borderwidth=0, highlightthickness=0,
                        padx=0, pady=2, cursor="hand2",
                        activebackground=ACCENT_SOFT, activeforeground=TEXT,
                        command=toggle)
        btn.sync = sync  # type: ignore[attr-defined]
        sync()
        return btn

    # -------------------- UI 构建 --------------------
    def _build_ui(self) -> None:
        # 顶栏
        header = tk.Frame(self.root, bg=BG_HEADER, height=62)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        tk.Label(header, text="AutoFTP", bg=BG_HEADER, fg="#ffffff",
                 font=(FONT, 18, "bold")).pack(side="left", padx=(18, 0), pady=10)
        tk.Label(header, text="复印机扫描到 FTP 部署工具", bg=BG_HEADER,
                 fg="#bfdbfe", font=(FONT, 10)).pack(side="left", padx=10, pady=10)
        # 顶栏右侧 FTP 状态徽标
        self.ftp_status_var = tk.StringVar(value="○ FTP 服务未运行")
        self.ftp_status_lbl = tk.Label(header, textvariable=self.ftp_status_var,
                                       bg=BG_HEADER, fg="#fca5a5",
                                       font=(FONT, 10, "bold"))
        self.ftp_status_lbl.pack(side="right", padx=18, pady=10)

        container = tk.Frame(self.root, bg=BG_APP)
        container.pack(fill="both", expand=True, padx=14, pady=10)

        # ---- 网络信息卡 ----
        net_card = self._card(container, "本机网络信息")
        net_card.pack(fill="x", pady=(0, 10))
        net = net_card.body
        self.ipv4_var = tk.StringVar(value="检测中…")
        self.ipv6_var = tk.StringVar(value="检测中…")
        tk.Label(net, text="IPv4", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=0, column=0, sticky="w", padx=4, pady=6)
        tk.Label(net, textvariable=self.ipv4_var, bg=BG_CARD, fg=TEXT,
                 font=(FONT, 10, "bold")).grid(row=0, column=1, sticky="w", padx=8)
        tk.Label(net, text="IPv6 Global", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=0, column=2, sticky="w", padx=12)
        tk.Label(net, textvariable=self.ipv6_var, bg=BG_CARD, fg=TEXT,
                 font=(FONT, 10, "bold")).grid(row=0, column=3, sticky="w", padx=8)
        ttk.Button(net, text="刷新", command=self._refresh_network_info).grid(
            row=0, column=4, padx=12, sticky="e")

        # ---- 主区域：左 FTP 右 MFP ----
        main = tk.Frame(container, bg=BG_APP)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        self._build_ftp_card(main)
        self._build_mfp_card(main)

        # ---- 日志卡 ----
        log_card = self._card(container, "运行日志")
        log_card.pack(fill="both", expand=True, pady=(10, 0))
        self.log_text = tk.Text(log_card.body, height=10, state="disabled",
                               wrap="word", bg="#0f172a", fg="#e2e8f0",
                               insertbackground="#e2e8f0",
                               selectbackground=ACCENT,
                               font=(FONT_MONO, 9), bd=0, padx=10, pady=8,
                               highlightthickness=0)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_card.body, command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)

    # ---- FTP 卡 ----
    def _build_ftp_card(self, parent: tk.Widget) -> None:
        card = self._card(parent, "FTP 服务", accent=True)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        body = card.body
        body.columnconfigure(1, weight=1)

        ftp = self.config["ftp"]
        self.scan_dir_var = tk.StringVar(value=ftp.get("scan_dir", r"D:\Scan"))
        self.port_var = tk.StringVar(value=str(ftp.get("port", 2121)))
        self.passive_var = tk.StringVar(value=ftp.get("passive_ports", "30000-30010"))
        self.username_var = tk.StringVar(value=ftp.get("username", "scanner"))
        self.password_var = tk.StringVar(value=ftp.get("password", ""))
        self.anon_var = tk.BooleanVar(value=bool(ftp.get("enable_anonymous", True)))

        pad = {"padx": 6, "pady": 5}
        r = 0
        tk.Label(body, text="扫描目录", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        box = tk.Frame(body, bg=BG_CARD)
        box.grid(row=r, column=1, columnspan=2, sticky="we", **pad)
        box.columnconfigure(0, weight=1)
        ttk.Entry(box, textvariable=self.scan_dir_var).grid(row=0, column=0, sticky="we")
        ttk.Button(box, text="选择…", command=self._choose_scan_dir).grid(
            row=0, column=1, padx=(6, 0))

        r += 1
        tk.Label(body, text="控制端口", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        ttk.Entry(body, textvariable=self.port_var, width=10).grid(
            row=r, column=1, sticky="w", **pad)
        tk.Label(body, text="被动端口", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=2, sticky="w", **pad)
        ttk.Entry(body, textvariable=self.passive_var, width=14).grid(
            row=r, column=3, sticky="w", **pad)

        r += 1
        tk.Label(body, text="用户名", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        ttk.Entry(body, textvariable=self.username_var).grid(
            row=r, column=1, sticky="we", **pad)
        tk.Label(body, text="密码", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=2, sticky="w", **pad)
        ttk.Entry(body, textvariable=self.password_var, show="•").grid(
            row=r, column=3, sticky="we", **pad)

        # 匿名访问（自定义开关：✅/⬜，避免原生复选框叉号误导）
        r += 1
        anon_row = tk.Frame(body, bg=BG_CARD)
        anon_row.grid(row=r, column=0, columnspan=4, sticky="we", **pad)
        self.anon_toggle = self._make_toggle(
            anon_row, "启用匿名访问（账号 anonymous）",
            self.anon_var, self._on_anon_toggle)
        self.anon_toggle.pack(side="left")

        # 操作按钮（权限已硬编码为全权限 elradfmwMT，不暴露给用户修改）
        r += 1
        btns = tk.Frame(body, bg=BG_CARD)
        btns.grid(row=r, column=0, columnspan=4, sticky="we", **pad)
        self.start_btn = ttk.Button(btns, text="▶  启动 FTP", style="Accent.TButton",
                                   command=self._start_ftp)
        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = ttk.Button(btns, text="■  停止", command=self._stop_ftp,
                                  state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(btns, text="配置防火墙", command=self._configure_firewall).pack(
            side="left", padx=4)
        ttk.Button(btns, text="保存配置", command=self._save_config).pack(
            side="left", padx=4)

    # ---- MFP 卡 ----
    def _build_mfp_card(self, parent: tk.Widget) -> None:
        card = self._card(parent, "复印机注册", accent=True)
        card.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        body = card.body
        body.columnconfigure(1, weight=1)

        mfp = self.config.get("mfp", {})
        net_cfg = self.config.get("network", {})
        self.brand_var = tk.StringVar(value=mfp.get("brand", "konica_minolta"))
        self.mfp_ip_var = tk.StringVar(value=mfp.get("ip", ""))
        self.admin_user_var = tk.StringVar(value=mfp.get("admin_user", "admin"))
        self.admin_pass_var = tk.StringVar(value=mfp.get("admin_password", ""))
        self.prefer_ipv6_var = tk.BooleanVar(value=bool(net_cfg.get("prefer_ipv6", True)))
        self.reg_status_var = tk.StringVar(value="○ 待注册")

        pad = {"padx": 6, "pady": 5}
        r = 0
        tk.Label(body, text="品牌", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        brands = ["konica_minolta"]
        ttk.OptionMenu(body, self.brand_var, self.brand_var.get(), *brands).grid(
            row=r, column=1, sticky="we", **pad)

        r += 1
        tk.Label(body, text="复印机 IP", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        ip_box = tk.Frame(body, bg=BG_CARD)
        ip_box.grid(row=r, column=1, columnspan=2, sticky="we", **pad)
        ip_box.columnconfigure(0, weight=1)
        ttk.Entry(ip_box, textvariable=self.mfp_ip_var).grid(row=0, column=0, sticky="we")
        self.scan_btn = ttk.Button(ip_box, text="扫描局域网", command=self._scan_mfps)
        self.scan_btn.grid(row=0, column=1, padx=(6, 0))

        r += 1
        tk.Label(body, text="检测结果", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        self.mfp_combo_var = tk.StringVar()
        self.mfp_combo = ttk.Combobox(body, textvariable=self.mfp_combo_var,
                                      state="readonly")
        self.mfp_combo.grid(row=r, column=1, columnspan=2, sticky="we", **pad)
        self.mfp_combo.bind("<<ComboboxSelected>>", self._on_mfp_selected)

        r += 1
        tk.Label(body, text="管理员账号（可选）", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=0, sticky="w", **pad)
        ttk.Entry(body, textvariable=self.admin_user_var).grid(
            row=r, column=1, sticky="we", **pad)
        tk.Label(body, text="管理员密码（可选）", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=r, column=2, sticky="w", **pad)
        ttk.Entry(body, textvariable=self.admin_pass_var, show="•").grid(
            row=r, column=3, sticky="we", **pad)

        r += 1
        tk.Label(body, text="先免管理员尝试；仅在提示权限不足时再填此处账号密码重试。",
                 bg=BG_CARD, fg=MUTED, font=(FONT, 9)).grid(
            row=r, column=0, columnspan=4, sticky="w", **pad)

        r += 1
        self.ipv6_toggle = self._make_toggle(
            body, "注册时优先使用 IPv6 地址（默认开启）", self.prefer_ipv6_var)
        self.ipv6_toggle.grid(row=r, column=0, columnspan=4, sticky="w", **pad)

        # 注册按钮 + 状态徽标
        r += 1
        reg_row = tk.Frame(body, bg=BG_CARD)
        reg_row.grid(row=r, column=0, columnspan=4, sticky="we", **pad)
        self.register_btn = ttk.Button(reg_row, text="一键注册到复印机",
                                      style="Accent.TButton",
                                      command=self._auto_register)
        self.register_btn.pack(side="left")
        self.manual_btn = ttk.Button(reg_row, text="手动注册（浏览器）",
                                     command=self._manual_register)
        self.manual_btn.pack(side="left", padx=(8, 0))
        self.reg_status_lbl = tk.Label(reg_row, textvariable=self.reg_status_var,
                                       bg=BG_CARD, fg=MUTED,
                                       font=(FONT, 10, "bold"))
        self.reg_status_lbl.pack(side="left", padx=12)

        r += 1
        hint = (
            "使用流程：点「扫描局域网」自动检测复印机 → 在「检测结果」中选择目标 →\n"
            "直接点「一键注册到复印机」先免管理员尝试；若提示权限不足，再填管理员账号密码重试。\n"
            "扫描不到时可直接在「复印机 IP」手动输入 IP 再点注册。\n"
            "无法自动完成时会打开浏览器并显示需手动填写的参数。"
        )
        tk.Label(body, text=hint, bg=BG_CARD, fg=MUTED, justify="left",
                 font=(FONT, 9)).grid(row=r, column=0, columnspan=4, sticky="w", **pad)

    # -------------------- 状态徽标 --------------------
    def _set_ftp_status(self, running: bool) -> None:
        if running:
            self.ftp_status_var.set("✅ FTP 服务运行中")
            self.ftp_status_lbl.configure(fg="#86efac")
        else:
            self.ftp_status_var.set("○ FTP 服务未运行")
            self.ftp_status_lbl.configure(fg="#fca5a5")

    def _set_reg_status(self, state: str) -> None:
        """state ∈ idle / running / success / warn / admin"""
        if state == "success":
            self.reg_status_var.set("✅ 注册成功")
            self.reg_status_lbl.configure(fg=SUCCESS)
        elif state == "running":
            self.reg_status_var.set("⟳ 注册中…")
            self.reg_status_lbl.configure(fg=RUNNING)
        elif state == "admin":
            self.reg_status_var.set("⚠️ 需管理员权限，请补填重试")
            self.reg_status_lbl.configure(fg=WARN)
        elif state == "warn":
            self.reg_status_var.set("⚠️ 未自动完成，见日志")
            self.reg_status_lbl.configure(fg=WARN)
        else:
            self.reg_status_var.set("○ 待注册")
            self.reg_status_lbl.configure(fg=MUTED)

    def _refresh_status(self) -> None:
        self.anon_toggle.sync()
        self._set_ftp_status(self.ftp_manager.running)
        self._set_reg_status("idle")

    # -------------------- 行为 --------------------
    def _choose_scan_dir(self) -> None:
        d = filedialog.askdirectory(initialdir=self.scan_dir_var.get() or "/")
        if d:
            self.scan_dir_var.set(d)

    def _on_anon_toggle(self) -> None:
        # 开关标签已自行刷新 ✅/⬜，此处仅记录日志
        if not self.anon_var.get():
            self._append_log("已关闭匿名访问，仅允许账号密码登录")

    def _refresh_network_info(self) -> None:
        def worker():
            ipv4 = config_loader.get_local_ipv4()
            ipv6 = config_loader.get_local_ipv6_global() or "未检测到全局 IPv6"
            self.root.after(0, lambda: (self.ipv4_var.set(ipv4), self.ipv6_var.set(ipv6)))
        threading.Thread(target=worker, daemon=True).start()

    # -------------------- 复印机扫描 --------------------
    def _scan_mfps(self) -> None:
        self.scan_btn.configure(state="disabled")
        self.mfp_combo["values"] = []
        self.mfp_combo_var.set("")
        self._detected_mfps = []
        self._thread_log("开始扫描局域网复印机…")

        def worker():
            try:
                result = mfp_scanner.scan_lan(on_progress=self._thread_log)
            except Exception as e:  # noqa: BLE001
                self._thread_log(f"扫描异常: {e}")
                result = []
            self.root.after(0, lambda: self._apply_scan_result(result))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_scan_result(self, result: list) -> None:
        self.scan_btn.configure(state="normal")
        self._detected_mfps = result
        if not result:
            self._thread_log("未扫描到复印机，请在「复印机 IP」手动输入 IP 后点「一键注册到复印机」")
            self.mfp_combo["values"] = []
            self.mfp_combo_var.set("")
            return
        labels = []
        for item in result:
            label = item.get("title") or item.get("brand") or "MFP"
            labels.append(f"{item['ip']}  |  {label}")
        self.mfp_combo["values"] = labels
        self.mfp_combo_var.set(labels[0])
        self._on_mfp_selected()
        self._thread_log(f"扫描完成，共 {len(result)} 台，请在「检测结果」中选择目标")

    def _on_mfp_selected(self, _event=None) -> None:
        idx = self.mfp_combo.current()
        if idx < 0 or idx >= len(self._detected_mfps):
            return
        item = self._detected_mfps[idx]
        self.mfp_ip_var.set(item["ip"])
        self._thread_log(f"已选择复印机 {item['ip']}（{item.get('title') or item.get('brand')}）")

    def _collect_config(self) -> Dict[str, Any]:
        return {
            "ftp": {
                "host": "::",
                "port": int(self.port_var.get() or 2121),
                "passive_ports": self.passive_var.get() or "30000-30010",
                "scan_dir": self.scan_dir_var.get(),
                "username": self.username_var.get(),
                "password": self.password_var.get(),
                "enable_anonymous": bool(self.anon_var.get()),
                "anonymous_perm": ANON_PERM,
                "user_perm": USER_PERM,
            },
            "mfp": {
                "brand": self.brand_var.get(),
                "ip": self.mfp_ip_var.get().strip(),
                "admin_user": self.admin_user_var.get(),
                "admin_password": self.admin_pass_var.get(),
                "timeout": 15,
                # 保留配置开关（默认 true：先免管理员尝试）
                "try_without_admin": bool(
                    self.config.get("mfp", {}).get("try_without_admin", True)
                ),
            },
            "network": {
                "prefer_ipv6": bool(self.prefer_ipv6_var.get()),
            },
        }

    def _sync_config(self) -> None:
        self.config = self._collect_config()
        self.ftp_manager.config = self.config

    def _validate_passive(self, show_dialog: bool = False) -> bool:
        """校验被动端口输入；不合法时提示（保存 / 启动前调用）。"""
        try:
            config_loader.parse_passive_ports(self.passive_var.get())
            return True
        except ValueError as e:
            if show_dialog:
                messagebox.showerror("被动端口错误", str(e))
            else:
                self._append_log(f"被动端口错误：{e}")
            return False

    def _save_config(self) -> None:
        self._sync_config()
        if not self._validate_passive(show_dialog=True):
            return
        try:
            config_loader.save_config(self.config)
            self._append_log("配置已保存到 configs/scan_config.json")
        except ValueError as e:
            messagebox.showerror("保存失败", str(e))
        except OSError as e:
            messagebox.showerror("保存失败", str(e))

    def _start_ftp(self) -> None:
        self._sync_config()
        try:
            int(self.port_var.get())
        except ValueError:
            messagebox.showerror("端口错误", "控制端口必须为整数")
            return
        if not self._validate_passive(show_dialog=True):
            return

        def worker():
            ok = self.ftp_manager.start()
            self.root.after(0, lambda: self._after_start_ftp(ok))

        threading.Thread(target=worker, daemon=True).start()

    def _after_start_ftp(self, ok: bool) -> None:
        if ok:
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
        self._set_ftp_status(self.ftp_manager.running)

    def _stop_ftp(self) -> None:
        def worker():
            self.ftp_manager.stop()
            self.root.after(0, self._after_stop_ftp)

        threading.Thread(target=worker, daemon=True).start()

    def _after_stop_ftp(self) -> None:
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._set_ftp_status(self.ftp_manager.running)

    def _configure_firewall(self) -> None:
        self._sync_config()
        try:
            port = int(self.port_var.get() or 2121)
        except ValueError:
            messagebox.showerror("端口错误", "控制端口必须为整数")
            return
        if not self._validate_passive(show_dialog=True):
            return
        passive = self.passive_var.get() or "30000-30010"

        def worker():
            if not firewall_helper.is_admin():
                self._thread_log("警告：当前非管理员身份，防火墙规则可能添加失败")
            added = firewall_helper.configure_firewall(port, passive)
            if added:
                self._thread_log(f"防火墙已放行：{added}")
            else:
                self._thread_log("防火墙配置未完成，请检查日志或以管理员身份运行")

        threading.Thread(target=worker, daemon=True).start()

    def _auto_register(self) -> None:
        self._sync_config()
        if not self.mfp_ip_var.get().strip():
            messagebox.showwarning("缺少信息", "请先填写复印机 IP 地址")
            return
        self.register_btn.configure(state="disabled")
        self._set_reg_status("running")
        # 可选开关：try_without_admin=False 时首次即用管理员
        first_use_admin = not bool(
            self.config.get("mfp", {}).get("try_without_admin", True)
        )
        self._start_register_worker(use_admin=first_use_admin)

    def _start_register_worker(self, use_admin: bool) -> None:
        """在子线程执行一次注册尝试，结果回主线程处理。"""
        def worker():
            params: Dict[str, Any] = {}
            try:
                params = mfp_register.build_ftp_params(
                    self.config, prefer_ipv6=bool(self.prefer_ipv6_var.get())
                )
                self._thread_log(
                    f"准备注册 FTP 目的地：host={params['host']} port={params['port']} "
                    f"user={params['user']}（use_admin={use_admin}）"
                )
                result, strategy = mfp_register.register_to_mfp(
                    self.config, self._fields, params,
                    use_admin=use_admin, log=self._thread_log,
                )
            except Exception as e:  # noqa: BLE001
                result = mfp_register.RegisterResult(
                    False, mfp_register.STATUS_FALLBACK_SEMI_AUTO, f"注册异常：{e}"
                )
                strategy = None
            self.root.after(
                0, lambda: self._handle_register_result(result, strategy, params)
            )

        threading.Thread(target=worker, daemon=True).start()

    def _finish_register(self) -> None:
        self.register_btn.configure(state="normal")

    def _handle_register_result(self, result, strategy, params) -> None:
        """按状态码分支处理注册结果（主线程）。"""
        status = result.status
        self._append_log(f"注册最终状态：{status}")

        # 成功
        if status in (mfp_register.STATUS_OK, mfp_register.STATUS_NO_ADMIN_REQUIRED):
            self._set_reg_status("success")
            how = "已使用管理员账号" if result.used_admin else "免管理员完成"
            messagebox.showinfo("注册成功", f"{result.message}\n完成方式：{how}")
            self._finish_register()
            return

        # 权限不足 → 补填管理员重试
        if status == mfp_register.STATUS_ADMIN_REQUIRED:
            self._set_reg_status("admin")
            if self._prompt_admin_retry(result, params):
                return  # 已发起重试，保持按钮禁用
            self._set_reg_status("warn")
            self._finish_register()
            return

        # 缺映射表 / 字段 → 提示转半自动
        if status == mfp_register.STATUS_FIELDS_MISSING:
            self._set_reg_status("warn")
            messagebox.showwarning(
                "字段映射缺失",
                f"{result.message}\n\n无法自动填写表单，将打开浏览器由你手动注册。\n"
                f"可按 configs/mfp_fields.json 补充字段映射后重试。",
            )
            self._open_manual(strategy, params, "字段映射缺失")
            self._finish_register()
            return

        # 设备不可达 → 单独提示
        if status == mfp_register.STATUS_UNREACHABLE:
            self._set_reg_status("warn")
            messagebox.showerror(
                "无法连接复印机",
                f"{result.message}\n\n请核对：复印机 IP 是否正确、是否与本机同网段、"
                f"复印机 Web Connection 是否已启用。",
            )
            self._finish_register()
            return

        # 其余 → 兜底半自动（register() 已自动打开浏览器）
        self._set_reg_status("warn")
        messagebox.showwarning(
            "已切换半自动",
            f"{result.message}\n\n已在浏览器打开注册页，请按日志中的参数手动填写并提交。",
        )
        self._open_manual(strategy, params, result.message, already_opened=True)
        self._finish_register()

    def _prompt_admin_retry(self, result, params) -> bool:
        """弹出补填对话框，确认后用管理员会话重试。返回是否已发起重试。"""
        creds = self._ask_admin_credentials(result.message)
        if creds is None:
            self._append_log("已取消管理员重试")
            return False
        user, password = creds
        self.admin_user_var.set(user)
        self.admin_pass_var.set(password)
        self._sync_config()
        self._append_log("已填入管理员账号，改用管理员会话重试注册…")
        self._set_reg_status("running")
        self._start_register_worker(use_admin=True)
        return True

    def _ask_admin_credentials(self, message: str) -> Optional[Tuple[str, str]]:
        """补填管理员账号密码对话框。确定返回 (user, password)，取消返回 None。"""
        dlg = tk.Toplevel(self.root)
        dlg.title("需要管理员权限")
        dlg.configure(bg=BG_CARD)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        holder: Dict[str, Optional[Tuple[str, str]]] = {"value": None}

        tk.Label(dlg, text=message, bg=BG_CARD, fg=TEXT, justify="left",
                 wraplength=360, font=(FONT, 10)).pack(
            padx=16, pady=(14, 4), anchor="w")
        tk.Label(dlg, text="当前账户没有权限写入目的地，请输入管理员账号后重试。",
                 bg=BG_CARD, fg=MUTED, justify="left", wraplength=360,
                 font=(FONT, 9)).pack(padx=16, pady=(0, 10), anchor="w")

        form = tk.Frame(dlg, bg=BG_CARD)
        form.pack(padx=16, pady=(0, 8), fill="x")
        tk.Label(form, text="管理员账号", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=0, column=0, sticky="w", pady=4)
        user_var = tk.StringVar(value=self.admin_user_var.get() or "admin")
        ttk.Entry(form, textvariable=user_var, width=24).grid(
            row=0, column=1, pady=4, padx=(8, 0))
        tk.Label(form, text="管理员密码", bg=BG_CARD, fg=MUTED,
                 font=(FONT, 9)).grid(row=1, column=0, sticky="w", pady=4)
        pass_var = tk.StringVar(value=self.admin_pass_var.get())
        ttk.Entry(form, textvariable=pass_var, show="•", width=24).grid(
            row=1, column=1, pady=4, padx=(8, 0))

        def on_ok() -> None:
            holder["value"] = (user_var.get().strip(), pass_var.get())
            dlg.destroy()

        def on_cancel() -> None:
            holder["value"] = None
            dlg.destroy()

        btns = tk.Frame(dlg, bg=BG_CARD)
        btns.pack(padx=16, pady=(4, 14), fill="x")
        ttk.Button(btns, text="重试注册", style="Accent.TButton",
                   command=on_ok).pack(side="right")
        ttk.Button(btns, text="取消", command=on_cancel).pack(side="right", padx=(0, 8))

        dlg.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dlg.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dlg.winfo_height()) // 3
        dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.root.wait_window(dlg)
        return holder["value"]

    def _open_manual(self, strategy, params, reason: str,
                     already_opened: bool = False) -> None:
        """打开浏览器手动注册（半自动兜底）。"""
        if already_opened:
            return
        if strategy is None:
            url = self._default_register_url()
            try:
                webbrowser.open(url)
            except Exception as e:  # noqa: BLE001
                self._append_log(f"打开浏览器失败：{e}")
            self._append_log(f"已打开浏览器：{url}")
            if params:
                self._append_log("请在浏览器中按以下参数手动填写：")
                for k, v in params.items():
                    self._append_log(f"  {k}: {v}")
            return
        strategy.fallback_semi_auto(params, reason)

    def _default_register_url(self) -> str:
        ip = self.mfp_ip_var.get().strip() or "127.0.0.1"
        return f"http://{ip}/wcd_reg_ftp.cgi"

    def _manual_register(self) -> None:
        """用户手动触发半自动注册（打开浏览器并列出参数）。"""
        self._sync_config()
        if not self.mfp_ip_var.get().strip():
            messagebox.showwarning("缺少信息", "请先填写复印机 IP 地址")
            return
        self._set_reg_status("warn")
        params: Dict[str, Any] = {}
        strategy = None
        try:
            params = mfp_register.build_ftp_params(
                self.config, prefer_ipv6=bool(self.prefer_ipv6_var.get())
            )
            strategy = mfp_register.get_register(
                self.config, self._fields, log=self._thread_log
            )
        except Exception as e:  # noqa: BLE001
            self._thread_log(f"手动注册准备失败：{e}")
        self._append_log("手动注册：打开浏览器并列出待填参数")
        self._open_manual(strategy, params, "用户手动选择半自动")

    def _on_close(self) -> None:
        if self.ftp_manager.running:
            if messagebox.askyesno("退出", "FTP 服务正在运行，是否停止并退出？"):
                self.ftp_manager.stop()
            else:
                return
        self.root.destroy()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    root = tk.Tk()
    AutoFTPApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
