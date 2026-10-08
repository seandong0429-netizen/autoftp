# -*- coding: utf-8 -*-
"""基于 pyftpdlib 的双栈 FTP 服务管理。

- 监听 IPv6 "::" 并关闭 IPV6_V6ONLY，实现 IPv4/IPv6 双栈。
- 被动端口范围固定可配置。
- 匿名访问与账号访问由配置控制。
"""
from __future__ import annotations

import logging
import os
import socket
import threading
from typing import Any, Callable, Dict, Optional

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logger = logging.getLogger(__name__)

# 权限字符含义：
# e=改目录  l=列表  r=读  a=追加  d=删除  f=重命名  m=建目录  w=写  M=改文件权限  T=改文件时间
# 为降低配置出错风险，匿名与账号均硬编码为全权限 elradfmwMT（不再开放界面修改）。
ANON_PERM = "elradfmwMT"
USER_PERM = "elradfmwMT"


class FTPServerManager:
    """FTP 服务管理器，在独立线程中运行。"""

    def __init__(self, config: Dict[str, Any], log: Optional[Callable[[str], None]] = None):
        self.config = config
        self._log = log or (lambda msg: logger.info(msg))
        self.server: Optional[FTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def _log_ftp(self, msg: str) -> None:
        logger.info(msg)
        self._log(msg)

    def _ensure_scan_dir(self, scan_dir: str) -> None:
        try:
            os.makedirs(scan_dir, exist_ok=True)
        except OSError as e:
            self._log_ftp(f"创建扫描目录失败 {scan_dir}: {e}")

    def _build_authorizer(self) -> DummyAuthorizer:
        ftp_cfg = self.config["ftp"]
        scan_dir = ftp_cfg["scan_dir"]
        self._ensure_scan_dir(scan_dir)
        auth = DummyAuthorizer()
        if ftp_cfg.get("enable_anonymous", True):
            anon_perm = ftp_cfg.get("anonymous_perm", ANON_PERM)
            auth.add_anonymous(scan_dir, perm=anon_perm)
            self._log_ftp(f"启用匿名访问（账号 anonymous，权限 {anon_perm}）")
        else:
            self._log_ftp("已关闭匿名访问，仅允许账号密码登录")
        auth.add_user(
            ftp_cfg["username"],
            ftp_cfg["password"],
            scan_dir,
            perm=ftp_cfg.get("user_perm", USER_PERM),
        )
        return auth

    def _build_handler(self) -> FTPHandler:
        ftp_cfg = self.config["ftp"]
        handler = FTPHandler
        pp = ftp_cfg.get("passive_ports", "30000-30010")
        start, _, end = pp.partition("-")
        handler.passive_ports = range(int(start), int(end) + 1)
        handler.masquerade_address = None
        handler.permit_foreign_address = True
        handler.encoding = "utf-8"
        return handler

    def _build_dual_stack_socket(self, host: str, port: int) -> socket.socket:
        """构建 IPv6 双栈监听 socket。"""
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 关闭 IPV6_V6ONLY，使其同时接受 IPv4 连接（双栈）
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError as e:
            self._log_ftp(f"设置 IPV6_V6ONLY 失败（可能非双栈）: {e}")
        sock.bind((host, port, 0, 0))
        sock.listen(100)
        sock.settimeout(1)
        return sock

    def start(self) -> bool:
        if self._running:
            self._log_ftp("FTP 服务已在运行")
            return False
        ftp_cfg = self.config["ftp"]
        host = ftp_cfg.get("host", "::")
        port = int(ftp_cfg.get("port", 2121))
        try:
            auth = self._build_authorizer()
            handler = self._build_handler()
            handler.authorizer = auth
            sock = self._build_dual_stack_socket(host, port)
            self.server = FTPServer(sock, handler)
        except OSError as e:
            self._log_ftp(f"FTP 服务启动失败: {e}")
            return False

        self._running = True
        self._log_ftp(f"FTP 服务已启动 监听=[{host}]:{port} 被动端口={ftp_cfg.get('passive_ports')}")

        def _serve():
            try:
                self.server.serve_forever()
            except Exception as e:  # noqa: BLE001
                self._log_ftp(f"FTP 服务异常: {e}")
            finally:
                self._running = False
                self._log_ftp("FTP 服务已停止")

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> bool:
        if not self._running or self.server is None:
            self._log_ftp("FTP 服务未运行")
            return False
        try:
            self.server.close_all()
        except Exception as e:  # noqa: BLE001
            self._log_ftp(f"停止 FTP 服务异常: {e}")
        self.server = None
        self._running = False
        return True
