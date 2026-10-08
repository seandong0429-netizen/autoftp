# -*- coding: utf-8 -*-
"""复印机（MFP）FTP 扫描目的地自动注册模块。

设计要点：
- 采用策略模式，便于后续扩展理光 / 富士等品牌。
- 仅使用 requests + BeautifulSoup，不依赖浏览器自动化。
- 自动注册失败时降级为半自动模式：打开浏览器并显示需填写的参数。
"""
from __future__ import annotations

import logging
import urllib.parse
import webbrowser
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# 全局禁用未验证 HTTPS 的告警（部分复印机使用自签名证书）
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # noqa: BLE001
    pass


class RegistrationError(Exception):
    """注册流程中出现的可向用户展示的错误。"""


class MFPRegisterStrategy(ABC):
    """复印机注册策略基类。"""

    brand: str = "base"

    def __init__(
        self,
        config: Dict[str, Any],
        fields: Dict[str, Any],
        log: Optional[Callable[[str], None]] = None,
    ):
        self.config = config
        self.fields = fields or {}
        self._log = log or (lambda msg: logger.info(msg))
        mfp = config.get("mfp", {})
        ip = mfp.get("ip", "").strip()
        self.ip = ip
        self.base_url = f"http://{ip}" if ip else ""
        self.timeout = int(mfp.get("timeout", 15))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 AutoFTP"})
        self.session.verify = False

    # ---- 工具方法 ----
    def _log_msg(self, msg: str) -> None:
        logger.info(msg)
        self._log(msg)

    def _require_fields(self, *keys: str) -> Dict[str, Any]:
        """从字段映射中取出必需键，缺失则抛错。"""
        section = self.fields.get(self.brand, {})
        missing: List[str] = []
        result: Dict[str, Any] = {}
        for k in keys:
            if k not in section:
                missing.append(k)
            else:
                result[k] = section[k]
        if missing:
            raise RegistrationError(
                f"字段映射缺失（brand={self.brand}, keys={missing}），"
                f"请在 configs/mfp_fields.json 中补充对应字段"
            )
        return result

    def _check_reachable(self) -> None:
        if not self.ip:
            raise RegistrationError("未配置复印机 IP 地址")
        try:
            r = self.session.get(self.base_url, timeout=self.timeout)
        except requests.RequestException as e:
            raise RegistrationError(f"无法连接复印机 {self.ip}（{e}）")
        if r.status_code >= 500:
            raise RegistrationError(f"复印机返回错误状态 {r.status_code}")

    # ---- 子类必须实现 ----
    @abstractmethod
    def register(self, ftp_params: Dict[str, Any]) -> bool:
        """执行自动注册，成功返回 True。"""

    @abstractmethod
    def open_manual_page(self, ftp_params: Dict[str, Any]) -> str:
        """半自动模式：打开浏览器并返回目标 URL。"""

    # ---- 共用的半自动降级 ----
    def _fallback_semi_auto(self, ftp_params: Dict[str, Any], reason: str) -> bool:
        self._log_msg(f"自动注册失败：{reason}，切换至半自动模式")
        url = self.open_manual_page(ftp_params)
        self._log_msg(f"已在浏览器打开注册页：{url}")
        self._log_msg("请在浏览器中按以下参数手动填写并提交：")
        for k, v in ftp_params.items():
            self._log_msg(f"  {k}: {v}")
        return False


class KonicaMinoltaRegister(MFPRegisterStrategy):
    """柯尼卡美能达 bizhub 系列通过 Web Connection 自动注册。"""

    brand = "konica_minolta"

    def _admin_login(self, admin_user: str, admin_password: str) -> None:
        try:
            login_cfg = self._require_fields("login")["login"]
        except RegistrationError:
            self._log_msg("未配置 login 字段映射，尝试默认登录路径 /wcd_login.cgi")
            login_cfg = {
                "action": "/wcd_login.cgi",
                "user_field": "user",
                "pass_field": "password",
            }
        url = self.base_url + login_cfg.get("action", "/wcd_login.cgi")
        data = {
            login_cfg.get("user_field", "user"): admin_user,
            login_cfg.get("pass_field", "password"): admin_password,
        }
        try:
            r = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            raise RegistrationError(f"管理员登录请求失败：{e}")
        if r.status_code != 200:
            raise RegistrationError(f"管理员登录返回状态 {r.status_code}")
        text = r.text.lower()
        # 登录成功的常见标志
        if "logout" in text or "logoff" in text or "admin" in text:
            self._log_msg("管理员登录成功")
            return
        raise RegistrationError("管理员登录失败（账号/密码错误或被锁定）")

    def _open_register_ftp_page(self) -> str:
        """进入：目的地注册 → 新建 FTP，返回表单页 URL。"""
        try:
            reg_cfg = self._require_fields("registration_entry")["registration_entry"]
        except RegistrationError as e:
            raise RegistrationError(f"未配置 registration_entry 映射：{e}")
        try:
            r = self.session.get(
                self.base_url + reg_cfg.get("url", "/wcd_main.cgi"),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise RegistrationError(f"进入注册页失败：{e}")
        soup = BeautifulSoup(r.text, "html.parser")
        # 通过链接文本定位“目的地注册”入口
        link_text = reg_cfg.get("link_text", "目的地注册")
        entry_link = None
        for a in soup.find_all("a"):
            if link_text in a.get_text(strip=True):
                href = a.get("href", "")
                entry_link = href
                break
        if not entry_link:
            raise RegistrationError("未找到“目的地注册”入口链接")
        # 解析新注册 FTP 表单页
        try:
            form_cfg = self._require_fields("ftp_form")["ftp_form"]
        except RegistrationError as e:
            raise RegistrationError(f"未配置 ftp_form 映射：{e}")
        form_url = self.base_url + form_cfg.get("url", "/wcd_reg_ftp.cgi")
        self._log_msg(f"进入 FTP 注册表单页：{form_url}")
        return form_url

    def _fill_and_submit(self, form_url: str, ftp_params: Dict[str, Any]) -> None:
        try:
            form_cfg = self._require_fields("ftp_form")["ftp_form"]
        except RegistrationError as e:
            raise RegistrationError(f"字段映射缺失：{e}")
        fields_map: Dict[str, str] = form_cfg.get("fields", {})
        required = ("name", "host", "port", "user", "password", "dir")
        missing = [k for k in required if k not in fields_map]
        if missing:
            raise RegistrationError(f"ftp_form.fields 缺少映射：{missing}")
        payload = {
            fields_map["name"]: ftp_params.get("name", "ScanToPC"),
            fields_map["host"]: ftp_params.get("host", ""),
            fields_map["port"]: str(ftp_params.get("port", 2121)),
            fields_map["user"]: ftp_params.get("user", ""),
            fields_map["password"]: ftp_params.get("password", ""),
            fields_map["dir"]: ftp_params.get("dir", "/"),
        }
        # 兼容附加隐藏字段
        extras = form_cfg.get("extras", {})
        payload.update(extras)
        action = form_cfg.get("url", form_url)
        submit_url = self.base_url + action if not action.startswith("http") else action
        self._log_msg(f"提交 FTP 注册表单至 {submit_url}")
        try:
            r = self.session.post(submit_url, data=payload, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            raise RegistrationError(f"提交注册表单失败：{e}")
        if r.status_code not in (200, 201, 302):
            raise RegistrationError(f"注册提交返回状态 {r.status_code}")
        text = r.text.lower()
        if any(k in text for k in ("error", "失败", "failed")):
            raise RegistrationError("复印机返回错误，请检查提交参数")
        self._log_msg("FTP 目的地注册成功")

    def register(self, ftp_params: Dict[str, Any]) -> bool:
        self._check_reachable()
        mfp = self.config.get("mfp", {})
        try:
            self._admin_login(mfp.get("admin_user", "admin"), mfp.get("admin_password", ""))
            form_url = self._open_register_ftp_page()
            self._fill_and_submit(form_url, ftp_params)
            return True
        except RegistrationError as e:
            return self._fallback_semi_auto(ftp_params, str(e))

    def open_manual_page(self, ftp_params: Dict[str, Any]) -> str:
        try:
            form_cfg = self._require_fields("ftp_form")["ftp_form"]
            url = self.base_url + form_cfg.get("url", "/wcd_reg_ftp.cgi")
        except RegistrationError:
            url = self.base_url or "about:blank"
        try:
            webbrowser.open(url)
        except Exception as e:  # noqa: BLE001
            self._log_msg(f"打开浏览器失败：{e}，请手动访问：{url}")
        return url


# ---- 策略注册表 ----
_REGISTRY: Dict[str, type[MFPRegisterStrategy]] = {
    "konica_minolta": KonicaMinoltaRegister,
}


def register_brand(brand: str, cls: type[MFPRegisterStrategy]) -> None:
    """注册新的品牌策略（扩展点）。"""
    _REGISTRY[brand] = cls


def get_register(
    config: Dict[str, Any],
    fields: Dict[str, Any],
    log: Optional[Callable[[str], None]] = None,
) -> MFPRegisterStrategy:
    """根据配置中的 brand 创建注册策略实例。"""
    brand = config.get("mfp", {}).get("brand", "konica_minolta")
    cls = _REGISTRY.get(brand)
    if cls is None:
        raise RegistrationError(
            f"不支持的品牌 {brand}，已注册品牌：{list(_REGISTRY)}。"
            f"可通过 mfp_register.register_brand 扩展。"
        )
    return cls(config, fields, log)


def build_ftp_params(config: Dict[str, Any], prefer_ipv6: bool = False) -> Dict[str, Any]:
    """根据当前配置生成交给复印机填写的 FTP 参数。"""
    # 延迟导入以避免循环依赖
    from config_loader import get_local_ipv4, get_local_ipv6_global

    ftp = config["ftp"]
    if prefer_ipv6:
        host = get_local_ipv6_global() or get_local_ipv4()
    else:
        host = get_local_ipv4()
    return {
        "name": ftp.get("dest_name", "ScanToPC"),
        "host": host,
        "port": int(ftp.get("port", 2121)),
        "user": ftp.get("username", "scanner"),
        "password": ftp.get("password", ""),
        "dir": "/",
    }


if __name__ == "__main__":
    # 演示参数构造
    import config_loader
    cfg = config_loader.load_config()
    print(build_ftp_params(cfg))
