# -*- coding: utf-8 -*-
"""局域网复印机（MFP）自动探测模块。

识别策略（SNMP 优先，Web 兜底）：
- 取本机出口 IPv4（连到默认网关的那块网卡），据此获取真实子网掩码并计算网段；
  掩码取不到时回退 /24。已排除回环与常见虚拟网卡。
- 并发对子网内每个地址做 **SNMP v2c GET**（sysDescr / sysName / sysObjectID），
  超时 0.8s。厂商由 sysObjectID 的 enterprise 前缀判定，无值再用 sysDescr 关键字兜底。
- **SNMP 已识别的地址跳过 Web 探测**；其余地址再并发探测 Web 端口
  （80/443/8080，443 走 https 且关闭证书校验），抓首页关键字识别。

每条结果字段：ip / title / url / brand（兼容旧字段），
另含 source(snmp|web) / vendor / model / status(identified|suspect|unknown)。

SNMP 部分仅用标准库（见 snmp_client，varbind 结构化解析，不做可打印串猜测）；
Web 部分用 requests + bs4。
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import subprocess
from typing import Any, Callable, Dict, List, Optional, Set

import requests
import urllib3
from bs4 import BeautifulSoup

import snmp_client

logger = logging.getLogger(__name__)

# 识别关键字（小写匹配，Web 兜底用）
KONICA_KEYWORDS = ("konica minolta", "bizhub", "web connection")
# 通用打印机关键字，便于后续扩展
GENERIC_PRINTER_KEYWORDS = ("printer", "mfp", "scan", "复印", "扫描")

# 厂商关键字（sysObjectID 无值时的兜底判定，小写匹配）
VENDOR_KEYWORDS = {
    "konica_minolta": ("konica minolta", "konicaminolta", "bizhub"),
    "canon": ("canon", "imagerunner", "i-sensys", "imageclass"),
    "ricoh": ("ricoh", "aficio", "lanier", "savin", "gestetner"),
    "hp": ("hewlett-packard", "hewlett packard", "laserjet", "officejet", "pagewide"),
}

# sysObjectID 的 enterprise 号 -> 厂商（OID 形如 1.3.6.1.4.1.<enterprise>...）
VENDOR_BY_ENTERPRISE = {
    2636: "konica_minolta",
    118: "canon",
    367: "ricoh",
    23: "hp",
}

# SNMP 探测参数
SNMP_COMMUNITY = "public"
SNMP_TIMEOUT = 0.8

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


def _vendor_from_objectid(object_id: str) -> str:
    """由 sysObjectID 的 enterprise 前缀判定厂商（优先）。"""
    parts = object_id.strip().split(".")
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            enterprise = int(parts[6])
        except ValueError:
            return ""
        return VENDOR_BY_ENTERPRISE.get(enterprise, "")
    return ""


def _vendor_from_text(text: str) -> str:
    """由文本（sysDescr / 网页）关键字判定厂商（兜底）。"""
    lower = text.lower()
    for vendor, keywords in VENDOR_KEYWORDS.items():
        if any(k in lower for k in keywords):
            return vendor
    return ""


def _extract_model(descr: str, vendor: str) -> str:
    """尽量从 sysDescr 抽出简短型号，如 'bizhub C550i'。"""
    text = descr.strip()
    if not text:
        return ""
    for pattern in (
        r"(bizhub\s+[\w\-]+)",
        r"(imageRUNNER\s+[\w\-]+)",
        r"(Aficio\s+[\w\-]+)",
        r"(LaserJet\s+[\w\-]+)",
    ):
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return text if len(text) <= 40 else ""


def _probe_snmp(ip: str, timeout: float = SNMP_TIMEOUT) -> Optional[Dict[str, Any]]:
    """SNMP v2c 主识别路径。命中返回结果字典，无响应返回 None。

    厂商判定顺序：sysObjectID enterprise 前缀 -> sysDescr 关键字。
    所有取值均来自结构化 varbind，绝不把团体名等非 varbind 文本当数据。
    """
    system = snmp_client.probe_system(ip, community=SNMP_COMMUNITY, timeout=timeout)
    if not system:
        return None
    descr = system.get("sysDescr", "").strip()
    object_id = system.get("sysObjectID", "").strip()
    sys_name = system.get("sysName", "").strip()

    vendor = _vendor_from_objectid(object_id) or _vendor_from_text(descr)
    model = _extract_model(descr, vendor)
    status = "identified" if vendor else "suspect"
    # title 优先型号，其次 sysName（sysName 缺失时留空，不用团体名兜底）
    title = model or sys_name
    return {
        "ip": ip,
        "port": snmp_client.DEFAULT_PORT,
        "title": title,
        "url": "",
        "brand": vendor or "unknown",
        "source": "snmp",
        "vendor": vendor,
        "model": model,
        "status": status,
        "sys_name": sys_name,
        "sys_descr": descr,
        "sys_object_id": object_id,
    }


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
    vendor = _vendor_from_text(text)
    if not vendor and any(k in lower for k in KONICA_KEYWORDS):
        vendor = "konica_minolta"
    if not vendor and not any(k in lower for k in GENERIC_PRINTER_KEYWORDS):
        return None
    title = ""
    try:
        soup = BeautifulSoup(text, "html.parser")
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
    except Exception:  # noqa: BLE001
        pass
    return {
        "ip": ip,
        "port": port,
        "title": title,
        "url": url,
        "brand": vendor or "unknown",
        "source": "web",
        "vendor": vendor,
        "model": title,
        "status": "identified" if vendor else "unknown",
    }


def scan_lan(
    on_progress: Optional[Callable[[str], None]] = None,
    max_workers: int = 64,
    port_timeout: float = 1.0,
    snmp_timeout: float = SNMP_TIMEOUT,
) -> List[Dict[str, Any]]:
    """扫描局域网，返回识别到的复印机列表。

    先做 SNMP 主识别，SNMP 命中的地址跳过 Web 探测；其余地址再做
    Web 端口探测 + 首页识别兜底。

    Args:
        on_progress: 进度回调（接收日志字符串）。
        max_workers: 并发线程数（SNMP 与端口探测共用）。
        port_timeout: TCP 端口连接超时（秒）。
        snmp_timeout: SNMP 超时（秒，默认 0.8）。
    """
    net = detect_subnet()
    if net is None:
        if on_progress:
            on_progress("无法推断局域网子网，请手动填写复印机 IP")
        return []

    hosts = [str(h) for h in net.hosts()]
    if on_progress:
        on_progress(f"开始扫描子网 {net}（共 {len(hosts)} 个地址）…")

    found: List[Dict[str, Any]] = []
    snmp_hits: Set[str] = set()

    # ---- 阶段 1：SNMP 主识别（并发，复用同一声明式并发） ----
    if on_progress:
        on_progress(
            f"阶段 1：SNMP 探测 {len(hosts)} 个地址（超时 {snmp_timeout}s）…"
        )
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe_snmp, h, snmp_timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            try:
                info = fut.result()
            except Exception:  # noqa: BLE001
                info = None
            if info:
                found.append(info)
                snmp_hits.add(info["ip"])
                if on_progress:
                    label = info.get("model") or info.get("title") or info.get("brand")
                    on_progress(
                        f"发现(SNMP): {info['ip']} ({label}) [{info.get('status')}]"
                    )

    if on_progress:
        on_progress(
            f"SNMP 识别 {len(snmp_hits)} 台，其余地址进入 Web 兜底探测…"
        )

    # ---- 阶段 2：Web 兜底（跳过 SNMP 已识别的 IP） ----
    remaining = [h for h in hosts if h not in snmp_hits]

    def _port_check(host: str) -> Optional[tuple]:
        open_ports = [
            p for p in PROBE_PORTS if _connect_ok(host, p, timeout=port_timeout)
        ]
        return (host, open_ports) if open_ports else None

    reachable: List[tuple] = []
    if remaining:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_port_check, h): h for h in remaining}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    result = fut.result()
                except Exception:  # noqa: BLE001
                    result = None
                if result:
                    reachable.append(result)
        if on_progress:
            on_progress(
                f"Web 端口探测完成，{len(reachable)} 个主机开放 Web 端口，开始识别…"
            )

    # 对可达主机做 HTTP/HTTPS 识别（仅识别实际开放的端口）
    if reachable:
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
                        on_progress(
                            f"发现(Web): {info['ip']} ({label}) [{info.get('status')}]"
                        )

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
