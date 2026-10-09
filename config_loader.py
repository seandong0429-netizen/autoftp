# -*- coding: utf-8 -*-
"""配置加载与本地网络信息获取。

- 首次运行时若配置文件缺失，自动生成默认配置。
- 提供 IPv4 / IPv6 Global 地址探测。
- 默认密码仅为示例，请在部署后修改。
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---- 被动端口范围约束 ----
MIN_PASSIVE_PORT = 1024
MAX_PASSIVE_PORT = 65535
MAX_PASSIVE_SPAN = 1000  # 跨度上限（结束 - 起始）

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
        "admin_password": "",         # 由用户在界面填入；允许为空（先免管理员尝试）
        "timeout": 15,
        "try_without_admin": True,    # 先尝试免管理员提交，遇权限拒绝再升级
    },
    "network": {
        "prefer_ipv6": True,
    },
}


def get_project_root() -> Path:
    return Path(__file__).resolve().parent


def get_app_dir() -> str:
    """返回“应用目录”：打包后为 exe 所在目录，开发环境为项目根目录。

    用户可修改的配置应放在这里（exe 同目录），而不是打包内部的临时解压目录。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return str(get_project_root())


def get_resource_path(*parts: str) -> str:
    """返回内置资源文件的绝对路径，兼容 PyInstaller 打包环境（可复用）。

    - 打包后（--onefile）：资源随 exe 解压到 ``sys._MEIPASS`` 临时目录。
    - 开发环境：相对于本文件所在目录（项目根）。
    统一用 ``os.path.join`` 拼接，不硬编码路径分隔符；
    也兼容传入 "configs/mfp_fields.json" 这类已含分隔符的写法。
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        base = str(get_project_root())
    segments = []
    for part in parts:
        # 兼容正/反斜杠输入，按段重组后再用 os.path.join 拼接
        segments.extend(seg for seg in re.split(r"[\\/]+", str(part)) if seg)
    return os.path.join(base, *segments)


def get_config_dir() -> str:
    """配置文件目录（exe 同目录 / 项目根 下的 configs）。"""
    return os.path.join(get_app_dir(), "configs")


def get_config_path() -> str:
    return os.path.join(get_config_dir(), "scan_config.json")


def get_fields_path() -> str:
    return os.path.join(get_config_dir(), "mfp_fields.json")


def parse_passive_ports(value: Any) -> Tuple[int, int]:
    """解析并校验被动端口范围字符串，返回 (start, end)。

    规则：格式必须是 ``起始-结束``（纯数字、单个半角减号），
    ``1024 <= 起始 <= 结束 <= 65535`` 且跨度 ``结束-起始 <= 1000``。
    不合法时抛 ValueError（中文提示），绝不静默解析或回退随机端口。
    """
    text = str(value).strip()
    parts = text.split("-")
    if len(parts) != 2 or not all(re.fullmatch(r"[0-9]+", p.strip()) for p in parts):
        raise ValueError(
            f"被动端口格式错误：“{value}”，应为“起始-结束”"
            f"（纯数字、单个半角减号），例如 30000-30010"
        )
    start, end = int(parts[0]), int(parts[1])
    if not (MIN_PASSIVE_PORT <= start <= end <= MAX_PASSIVE_PORT):
        raise ValueError(
            f"被动端口范围非法：“{value}”，需满足 "
            f"{MIN_PASSIVE_PORT} <= 起始 <= 结束 <= {MAX_PASSIVE_PORT}，例如 30000-30010"
        )
    if end - start > MAX_PASSIVE_SPAN:
        raise ValueError(
            f"被动端口跨度过大：“{value}”，跨度不得超过 {MAX_PASSIVE_SPAN}，例如 30000-30010"
        )
    return start, end


def validate_passive_ports(value: Any) -> str:
    """校验并返回规范化后的被动端口字符串（不合法则抛 ValueError）。"""
    start, end = parse_passive_ports(value)
    return f"{start}-{end}"


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


def _read_json(path: str, label: str) -> Optional[Dict[str, Any]]:
    """读取 JSON 文件；失败时记录错误并返回 None（保持原有异常处理风格）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("读取%s失败: %s", label, e)
        return None


def load_config() -> Dict[str, Any]:
    """加载主配置。

    顺序：外部（exe 同目录 / 项目 configs）scan_config.json → 打包内置副本 → 内置默认。
    外部不存在时会用内置内容生成一份外部配置，方便用户修改。
    """
    external = get_config_path()
    if os.path.exists(external):
        cfg = _read_json(external, "配置")
        if cfg is not None:
            logger.info("[External] 已加载配置: %s", external)
            return _deep_merge(DEFAULT_CONFIG, cfg)
        return _deep_merge(DEFAULT_CONFIG, {})

    # 外部不存在：尝试打包内置副本（确保开箱即用）
    builtin = get_resource_path("configs", "scan_config.json")
    cfg: Optional[Dict[str, Any]] = None
    if os.path.exists(builtin) and os.path.abspath(builtin) != os.path.abspath(external):
        cfg = _read_json(builtin, "内置配置")
        if cfg is not None:
            logger.info("[Built-in] 未发现外部配置，使用内置配置: %s", builtin)
    if cfg is None:
        cfg = DEFAULT_CONFIG

    # 落一份到外部目录，便于用户修改（失败不影响启动）
    try:
        save_config(cfg)
        logger.info("[External] 已生成外部配置文件: %s", external)
    except (ValueError, OSError) as e:
        logger.warning("生成外部配置失败（忽略）: %s", e)
    return _deep_merge(DEFAULT_CONFIG, cfg)


def save_config(cfg: Dict[str, Any]) -> None:
    """保存配置。

    保存前校验 ``ftp.passive_ports``：不合法则抛 ValueError 拒绝保存
    （不会静默解析或回退随机端口）。
    """
    ftp = cfg.get("ftp") if isinstance(cfg, dict) else None
    if isinstance(ftp, dict) and "passive_ports" in ftp:
        ftp["passive_ports"] = validate_passive_ports(ftp["passive_ports"])
    path = get_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def load_fields() -> Dict[str, Any]:
    """加载字段映射 mfp_fields.json（先外后内）。

    第一步：外部（exe 同目录 / 项目 configs）存在则读取返回；
    第二步：否则读取通过 ``get_resource_path`` 定位的打包内置副本；
    第三步：两者都不存在则返回空 dict 并记录 Warning（保持原有降级逻辑）。
    """
    external = get_fields_path()
    if os.path.exists(external):
        data = _read_json(external, "外部字段映射")
        if data is None:
            return {}
        logger.info("[External] 已加载字段映射: %s", external)
        return data

    builtin = get_resource_path("configs", "mfp_fields.json")
    if os.path.exists(builtin):
        data = _read_json(builtin, "内置字段映射")
        if data is None:
            return {}
        logger.info("[Built-in] 已加载内置字段映射: %s", builtin)
        return data

    logger.warning("字段映射文件缺失（外部与内置均未找到）: %s", external)
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
