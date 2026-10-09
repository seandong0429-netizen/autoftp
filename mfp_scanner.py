# -*- coding: utf-8 -*-
"""局域网复印机（MFP）自动探测模块。

策略：
- 取本机出口 IPv4（连到默认网关的那块网卡），据此获取真实子网掩码并计算网段；
  掩码取不到时回退 /24。已排除回环与常见虚拟网卡。
- 并发对子网内每个地址的 Web 端口（80/443/8080）做 TCP 连接探测。
- 对可达主机抓取首页，根据关键字识别柯尼卡美能达 bizhub。
- 443 以 https 探测，且关闭证书校验（自签名证书常见）。
- 返回 [{ip, title, url, brand}, ...] 供界面选择。

仅依赖标准库 + requests + bs4（子网掩码优先用 psutil，缺失时可降级）。
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import subprocess
from typing import Any, Callable, Dict, List, Optional

import requests
import urllib3
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# 识别关键字（小写匹配）
KONICA_KEYWORDS = ("konica minolta", "bizhub", "web connection")
# 通用打印机关键字，便于后续扩展
GENERIC_PRINTER_KEYWORDS = ("printer", "mfp", "scan", "复印", "扫描")

# 常见 Web 端口，依次尝试（443 使用 https 探测）
PROBE_PORTS = (80, 443, 8080)

# 虚拟网卡/回环名称特征（用于排除，避免选错网卡）
VIRTUAL_IF_PATTERNS = (
    "vmware", "virtualbox", "vethernet", "hyper-v", "docker", "loopback",
    "tap", "tun", "zerotier", "tailscale", "utun", "bridge", "awdl", "llw",
    "vbox", "vmnet", "ppp", "bluetooth",
)

# 子网过大时（地址数超过该值）回退 /24，避免扫描时间失控
MAX_HOSTS = 1024


def _connect_ok(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
        return True
    except OSError:
        return False


def _run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return out.stdout or ""
    except Exception:  # noqa: BLE001
        return ""


def _normalize_netmask(value: str) -> Optional[str]:
    """把 0x 十六进制或点分十进制掩码统一为点分十进制。"""
    value = value.strip()
    if value.lower().startswith("0x"):
        try:
            return str(ipaddress.IPv4Address(int(value, 16)))
        except ValueError:
            return None
    return value


def _netmask_from_psutil(ip: str) -> Optional[str]:
    """用 psutil 获取指定 IP 所在网卡的掩码（跨平台、与系统语言无关）。"""
    try:
        import psutil  # 可选依赖
    except ImportError:
        return None
    try:
        for name, addrs in psutil.net_if_addrs().items():
            lname = name.lower()
            if any(p in lname for p in VIRTUAL_IF_PATTERNS):
                continue
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip and a.netmask:
                    return _normalize_netmask(a.netmask)
    except Exception as e:  # noqa: BLE001
        logger.debug("psutil 获取掩码失败: %s", e)
    return None


def _netmask_from_os(ip: str) -> Optional[str]:
    """解析系统命令输出获取掩码（psutil 不可用时的回退）。"""
    if os.name == "nt":
        text = _run_cmd(["ipconfig"])
        # 按空行切分为适配器块，定位含目标 IP 的块
        for block in re.split(r"\r?\n\s*\r?\n", text):
            if ip not in block:
                continue
            m = re.search(
                r"(?:Subnet Mask|子网掩码|子網路遮罩)\s*[:.]*\s*"
                r"((?:\d{1,3}\.){3}\d{1,3})",
                block,
            )
            if m:
                return m.group(1)
        return None
    # Unix: ifconfig / ip addr
    text = _run_cmd(["ifconfig"])
    for line in text.splitlines():
        if ip in line and "netmask" in line:
            m = re.search(
                r"netmask\s+(0x[0-9a-fA-F]+|(?:\d{1,3}\.){3}\d{1,3})", line
            )
            if m:
                return _normalize_netmask(m.group(1))
    return None


def _netmask_for_ip(ip: str) -> Optional[str]:
    return _netmask_from_psutil(ip) or _netmask_from_os(ip)


def detect_subnet() -> Optional[ipaddress.IPv4Network]:
    """根据本机出口 IPv4 的真实子网掩码推断网段。

    - 出口 IP 由默认路由决定，天然排除回环与未接入默认路由的虚拟网卡。
    - 掩码取不到时回退 /24。
    - 网段过大（地址数 > MAX_HOSTS）时回退 /24，避免扫描失控。
    """
    from config_loader import get_local_ipv4

    ip = get_local_ipv4()
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError as e:
        logger.error("本机 IPv4 无效: %s", e)
        return None
    if addr.is_loopback:
        logger.warning("出口 IPv4 为回环地址，无法推断网段")
        return None

    mask = _netmask_for_ip(ip)
    if mask:
        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError as e:
            logger.warning("掩码 %s 解析失败，回退 /24: %s", mask, e)
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
    else:
        logger.info("未取到 %s 的子网掩码，回退 /24", ip)
        net = ipaddress.ip_network(f"{ip}/24", strict=False)

    if net.num_addresses > MAX_HOSTS:
        logger.warning(
            "推断网段 %s 过大（%d 地址），回退 /24 扫描", net, net.num_addresses
        )
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return net


def _probe_http(ip: str, port: int, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """抓取首页，识别复印机品牌/型号。443 用 https 且不校验证书。"""
    urllib3.disable_warnings()
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}"
    try:
        # 只读首页，不跟随跳转（避免被重定向到 https 或无关页面）
        r = requests.get(
            url, timeout=timeout, allow_redirects=False, verify=False
        )
    except requests.RequestException:
        return None
    if r.status_code >= 500 or not r.text:
        return None
    text = r.text
    lower = text.lower()
    brand = ""
    if any(k in lower for k in KONICA_KEYWORDS):
        brand = "konica_minolta"
    elif any(k in lower for k in GENERIC_PRINTER_KEYWORDS):
        brand = "unknown"
    else:
        return None
    title = ""
    try:
        soup = BeautifulSoup(text, "html.parser")
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
    except Exception:  # noqa: BLE001
        pass
    return {"ip": ip, "port": port, "title": title, "url": url, "brand": brand}


def scan_lan(
    on_progress: Optional[Callable[[str], None]] = None,
    max_workers: int = 64,
    port_timeout: float = 1.0,
) -> List[Dict[str, Any]]:
    """扫描局域网，返回识别到的复印机列表。

    Args:
        on_progress: 进度回调（接收日志字符串）。
        max_workers: 并发线程数。
        port_timeout: 端口连接超时（秒）。
    """
    net = detect_subnet()
    if net is None:
        if on_progress:
            on_progress("无法推断局域网子网，请手动填写复印机 IP")
        return []

    hosts = [str(h) for h in net.hosts()]
    if on_progress:
        on_progress(f"开始扫描子网 {net}（共 {len(hosts)} 个地址）…")

    # 端口探测：返回 (host, [开放端口...])，便于后续只识别实际开放的端口
    reachable: List[tuple] = []

    def _port_check(host: str) -> Optional[tuple]:
        open_ports = [
            p for p in PROBE_PORTS if _connect_ok(host, p, timeout=port_timeout)
        ]
        if open_ports:
            return (host, open_ports)
        return None

    found: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_port_check, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            try:
                result = fut.result()
            except Exception:  # noqa: BLE001
                result = None
            if result:
                reachable.append(result)

    if on_progress:
        on_progress(
            f"端口探测完成，{len(reachable)} 个主机开放 Web 端口，开始识别复印机…"
        )

    # 对可达主机做 HTTP/HTTPS 识别（仅识别实际开放的端口）
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        probe_futs = {}
        for host, ports in reachable:
            for port in ports:
                probe_futs[ex.submit(_probe_http, host, port)] = (host, port)
        for fut in concurrent.futures.as_completed(probe_futs):
            try:
                info = fut.result()
            except Exception:  # noqa: BLE001
                info = None
            if info:
                found.append(info)
                if on_progress:
                    label = info["title"] or info["brand"]
                    on_progress(f"发现: {info['ip']} ({label})")

    if on_progress:
        on_progress(f"扫描结束，共发现 {len(found)} 台设备")
    # 排序便于查看
    found.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return found


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("推断子网:", detect_subnet())
    for item in scan_lan(on_progress=print):
        print(item)
