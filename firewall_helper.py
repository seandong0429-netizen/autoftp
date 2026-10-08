# -*- coding: utf-8 -*-
"""Windows 防火墙配置助手。

通过 netsh 自动放行 FTP 控制端口和被动端口范围。
需要管理员权限；非管理员时给出提示并返回失败。
"""
from __future__ import annotations

import ctypes
import logging
import subprocess
import sys

logger = logging.getLogger(__name__)


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    """判断当前进程是否以管理员身份运行。"""
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return False


def run_netsh(args: list[str]) -> tuple[bool, str]:
    """执行 netsh 命令并返回 (是否成功, 输出)。"""
    cmd = ["netsh", "advfirewall", "firewall"] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="gbk", errors="replace"
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output
    except FileNotFoundError:
        return False, "netsh 不可用（非 Windows 系统）"
    except OSError as e:
        return False, f"执行 netsh 失败: {e}"


def rule_exists(name: str) -> bool:
    ok, _ = run_netsh(["show", "rule", f"name={name}"])
    return ok


def add_rule(name: str, ports: str, protocol: str = "TCP") -> bool:
    """添加入站放行规则。ports 可以是单端口或 30000-30010 范围。"""
    if not is_windows():
        logger.warning("非 Windows 系统，跳过防火墙配置")
        return False
    if not is_admin():
        logger.error("需要管理员权限才能配置防火墙，请以管理员身份运行本程序")
        return False
    if rule_exists(name):
        run_netsh(["delete", "rule", f"name={name}"])
    ok, output = run_netsh([
        "add", "rule",
        f"name={name}",
        "dir=in",
        "action=allow",
        f"protocol={protocol}",
        f"localport={ports}",
    ])
    if ok:
        logger.info("已添加防火墙规则 %s（%s/%s）", name, ports, protocol)
    else:
        logger.error("添加防火墙规则 %s 失败: %s", name, output.strip())
    return ok


def configure_firewall(ftp_port: int, passive_ports: str) -> list[str]:
    """放行 FTP 控制端口与被动端口范围，返回成功添加的规则名列表。"""
    added: list[str] = []
    if add_rule("AutoFTP Control", str(ftp_port)):
        added.append("AutoFTP Control")
    if add_rule("AutoFTP Passive", passive_ports):
        added.append("AutoFTP Passive")
    return added


def remove_rules() -> None:
    """移除本工具添加的防火墙规则。"""
    if not is_windows():
        return
    for name in ("AutoFTP Control", "AutoFTP Passive"):
        if rule_exists(name):
            run_netsh(["delete", "rule", f"name={name}"])
            logger.info("已删除防火墙规则 %s", name)
