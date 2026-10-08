# -*- coding: utf-8 -*-
"""局域网复印机（MFP）自动探测模块。

策略：
- 取本机 IPv4，按 /24 推断子网（家庭/小型办公网络最常见）。
- 并发对子网内每个地址的 HTTP(80) 端口做连接探测。
- 对可达主机抓取首页，根据关键字识别柯尼卡美能达 bizhub。
- 返回 [{ip, title, url, brand}, ...] 供界面选择。

仅依赖标准库 + requests + bs4，不引入额外扫描依赖。
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import socket
from typing import Any, Callable, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# 识别关键字（小写匹配）
KONICA_KEYWORDS = ("konica minolta", "bizhub", "web connection")
# 通用打印机关键字，便于后续扩展
GENERIC_PRINTER_KEYWORDS = ("printer", "mfp", "scan", "复印", "扫描")

# 常见 Web 端口，依次尝试
PROBE_PORTS = (80, 8080)


def _connect_ok(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
        return True
    except OSError:
        return False


def detect_subnet() -> Optional[ipaddress.IPv4Network]:
    """根据本机 IPv4 推断 /24 子网。"""
    from config_loader import get_local_ipv4

    ip = get_local_ipv4()
    try:
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError as e:
        logger.error("推断子网失败: %s", e)
        return None


def _probe_http(ip: str, port: int, timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    """抓取 HTTP 首页，识别复印机品牌/型号。"""
    url = f"http://{ip}:{port}"
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
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
    port_timeout: float = 0.4,
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

    reachable: List[str] = []

    def _port_check(host: str) -> Optional[str]:
        for port in PROBE_PORTS:
            if _connect_ok(host, port, timeout=port_timeout):
                return host
        return None

    found: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_port_check, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                result = fut.result()
            except Exception:  # noqa: BLE001
                result = None
            if result:
                reachable.append(result)

    if on_progress:
        on_progress(f"端口探测完成，{len(reachable)} 个主机开放 Web 端口，开始识别复印机…")

    # 对可达主机做 HTTP 识别
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        probe_futs = {}
        for host in reachable:
            for port in PROBE_PORTS:
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
    for item in scan_lan(on_progress=print):
        print(item)
