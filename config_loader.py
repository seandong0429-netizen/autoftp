# -*- coding: utf-8 -*-
"""配置加载与本地网络信息获取。

- 首次运行时若配置文件缺失，自动生成默认配置。
- 提供 IPv4 / IPv6 Global 地址探测。
- 默认密码仅为示例，请在部署后修改。
"""
from __future__ import annotations

import json
import logging
import socket
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

# 默认配置：仅作为示例，包含的密码请务必在部署时修改。
DEFAULT_CONFIG: Dict[str, Any] = {
    "ftp": {
        "host": "::",                 # 双栈监听地址
        "port": 2121,
        "passive_ports": "30000-30010",
        "scan_dir": r"D:\Scan",
        "username": "scanner",
        "password": "Scan@2026",      # 示例密码，请修改
        "enable_anonymous": True,
        "anonymous_perm": "elradfmwMT",  # 硬编码全权限，不再开放修改
        "user_perm": "elradfmwMT",
    },
    "mfp": {
        "brand": "konica_minolta",
        "ip": "",
        "admin_user": "admin",
        "admin_password": "",         # 由用户在界面填入
        "timeout": 15,
    },
    "network": {
        "prefer_ipv6": True,
    },
}


def get_project_root() -> Path:
    return Path(__file__).resolve().parent


def get_config_dir() -> Path:
    return get_project_root() / "configs"


def get_config_path() -> Path:
    return get_config_dir() / "scan_config.json"


def get_fields_path() -> Path:
    return get_config_dir() / "mfp_fields.json"


def _deep_merge(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """递归合并：用 override 的值覆盖 default。"""
    result: Dict[str, Any] = {}
    for k, v in default.items():
        result[k] = v
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config() -> Dict[str, Any]:
    """加载配置；不存在则生成默认配置。"""
    path = get_config_path()
    if not path.exists():
        save_config(DEFAULT_CONFIG)
        logger.info("未发现配置文件，已生成默认配置: %s", path)
        return _deep_merge(DEFAULT_CONFIG, {})
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("读取配置失败，回退默认: %s", e)
        return _deep_merge(DEFAULT_CONFIG, {})
    return _deep_merge(DEFAULT_CONFIG, cfg)


def save_config(cfg: Dict[str, Any]) -> None:
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def load_fields() -> Dict[str, Any]:
    """加载 mfp_fields.json 字段映射；不存在返回空 dict。"""
    path = get_fields_path()
    if not path.exists():
        logger.warning("字段映射文件缺失: %s", path)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("字段映射读取失败: %s", e)
        return {}


def get_local_ipv4() -> str:
    """通过 UDP 套接字探测本机出口 IPv4 地址。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def get_local_ipv6_global() -> str | None:
    """获取本机 IPv6 全局地址（2xxx/3xxx）。"""
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return None
    for info in infos:
        ip = info[4][0]
        # 去掉 zone id
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        # 全局单播地址前缀：2000::/3
        if ip.lower().startswith(("2", "3")) and not ip.lower().startswith("fe80"):
            return ip
    return None


def get_listen_address(prefer_ipv6: bool = False) -> str:
    """返回用于在界面展示的访问地址（IPv4 或 IPv6）。"""
    if prefer_ipv6:
        v6 = get_local_ipv6_global()
        if v6:
            return v6
    return get_local_ipv4()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("IPv4:", get_local_ipv4())
    print("IPv6 Global:", get_local_ipv6_global())
    print("配置路径:", get_config_path())
