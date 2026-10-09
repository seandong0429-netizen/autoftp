# -*- coding: utf-8 -*-
"""复印机（MFP）FTP 扫描目的地自动注册模块。

设计要点：
- 策略模式，便于后续扩展理光 / 富士等品牌。
- 仅使用 requests + BeautifulSoup，不依赖浏览器自动化。
- 管理员登录由“前置必经”改为“失败后升级”三级递进：
  先免管理员提交 → 权限拒绝则返回状态码由界面补填管理员重试 → 仍失败 / 缺
  映射表 / 设备不可达各自分流，必要时兜底半自动。
- register() 在所有分支（含异常）都返回 RegisterResult，不向 GUI 抛异常。
"""
from __future__ import annotations

import logging
import webbrowser
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# 全局禁用未验证 HTTPS 的告警（部分复印机使用自签名证书）
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # noqa: BLE001
    pass


# ---- 状态码（单处定义，基类与子类共用）----
STATUS_OK = "OK"                                  # 注册成功
STATUS_NO_ADMIN_REQUIRED = "NO_ADMIN_REQUIRED"    # 注册成功且无需管理员
STATUS_ADMIN_REQUIRED = "ADMIN_REQUIRED"          # 权限不足，需补填管理员重试
STATUS_FIELDS_MISSING = "FIELDS_MISSING"          # 缺映射表 / 缺字段
STATUS_UNREACHABLE = "UNREACHABLE"                # 设备不可达
STATUS_FALLBACK_SEMI_AUTO = "FALLBACK_SEMI_AUTO"  # 兜底半自动

# 权限拒绝关键词（集中定义；中英文，统一按小写匹配）
PERMISSION_DENIED_KEYWORDS = (
    "没有权限", "无权限", "权限不足", "权限不够", "拒绝访问", "访问被拒绝",
    "只读", "被锁定", "无法修改", "未授权",
    "unauthorized", "forbidden", "permission denied", "access denied",
    "not authorized", "not permitted", "no permission", "read-only",
    "readonly", "not allowed",
)


@dataclass
class RegisterResult:
    """注册结果：状态码 + 可读消息，含少量上下文。"""

    success: bool
    status: str
    message: str
    used_admin: bool = False
    url: str = ""

    def __iter__(self) -> Iterator[Any]:
        """允许 `success, status, message = result` 解包。"""
        return iter((self.success, self.status, self.message))

    def __str__(self) -> str:
        return f"[{self.status}] {self.message}"


class RegistrationError(Exception):
    """注册流程内部的分类错误。

    携带 ``status`` 供 register() 归类；不会直接抛给 GUI。
    """

    def __init__(self, message: str, status: str = STATUS_FALLBACK_SEMI_AUTO):
        super().__init__(message)
        self.status = status


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
        self.admin_user = mfp.get("admin_user", "admin")
        self.admin_password = mfp.get("admin_password", "")
        # 可选开关：为 True 时先尝试免管理员提交（默认 True）
        self.try_without_admin = bool(mfp.get("try_without_admin", True))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 AutoFTP"})
        self.session.verify = False

    # ---- 工具方法 ----
    def _log_msg(self, msg: str) -> None:
        logger.info(msg)
        self._log(msg)

    def _require_fields(self, *keys: str) -> Dict[str, Any]:
        """从字段映射中取出必需键；缺失抛 FIELDS_MISSING。"""
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
                f"请在 configs/mfp_fields.json 中补充对应字段",
                STATUS_FIELDS_MISSING,
            )
        return result

    def _result(
        self,
        success: bool,
        status: str,
        message: str,
        used_admin: bool = False,
        url: str = "",
    ) -> RegisterResult:
        return RegisterResult(success, status, message, used_admin=used_admin, url=url)

    def _detect_permission_denied(
        self, resp: Optional[requests.Response], soup: Optional[BeautifulSoup] = None
    ) -> bool:
        """判断响应是否表示“没有权限写入”。401/403 或命中权限/只读文案。"""
        if resp is None:
            return False
        if resp.status_code in (401, 403):
            return True
        if soup is not None:
            text = soup.get_text(" ", strip=True)
        else:
            text = getattr(resp, "text", "") or ""
        lower = text.lower()
        return any(k in lower for k in PERMISSION_DENIED_KEYWORDS)

    def _check_reachable(self) -> Tuple[bool, str]:
        """探测复印机 Web 是否可达。返回 (ok, message)。"""
        if not self.ip:
            return False, "未配置复印机 IP 地址"
        try:
            r = self.session.get(self.base_url, timeout=self.timeout)
        except requests.RequestException as e:
            return False, f"无法连接复印机 {self.ip}（{e}）"
        if r.status_code >= 500:
            return False, f"复印机返回错误状态 {r.status_code}"
        return True, ""

    # ---- 子类必须实现 ----
    @abstractmethod
    def register(
        self, ftp_params: Dict[str, Any], use_admin: bool = False
    ) -> RegisterResult:
        """执行自动注册，返回 RegisterResult（任何分支都返回，不外抛）。"""

    @abstractmethod
    def open_manual_page(self, ftp_params: Dict[str, Any]) -> str:
        """半自动模式：打开浏览器并返回目标 URL。"""

    # ---- 共用的半自动降级 ----
    def _fallback_semi_auto(self, ftp_params: Dict[str, Any], reason: str) -> str:
        """打开浏览器手动注册，返回目标 URL。"""
        self._log_msg(f"自动注册未完成：{reason}，切换至半自动模式")
        url = self.open_manual_page(ftp_params)
        self._log_msg(f"已在浏览器打开注册页：{url}")
        self._log_msg("请在浏览器中按以下参数手动填写并提交：")
        for k, v in ftp_params.items():
            self._log_msg(f"  {k}: {v}")
        return url

    def fallback_semi_auto(self, ftp_params: Dict[str, Any], reason: str) -> str:
        """公开的半自动兜底（供界面在缺映射 / 用户手动时调用）。"""
        return self._fallback_semi_auto(ftp_params, reason)


class KonicaMinoltaRegister(MFPRegisterStrategy):
    """柯尼卡美能达 bizhub 系列通过 Web Connection 自动注册。"""

    brand = "konica_minolta"

    # 自动注册所需的最小映射键
    REQUIRED_SECTIONS = ("registration_entry", "ftp_form")
    REQUIRED_FORM_FIELDS = ("name", "host", "port", "user", "password", "dir")

    def _missing_required_fields(self) -> List[str]:
        """返回缺失的映射键列表（空列表表示齐全）。缺文件也在此返回。"""
        if not self.fields:
            return ["<configs/mfp_fields.json 未加载>"]
        section = self.fields.get(self.brand, {})
        missing = [k for k in self.REQUIRED_SECTIONS if k not in section]
        if not missing:
            form_fields = section.get("ftp_form", {}).get("fields", {})
            missing += [
                f"ftp_form.fields.{k}"
                for k in self.REQUIRED_FORM_FIELDS
                if k not in form_fields
            ]
        return missing

    def _admin_login(self, admin_user: str, admin_password: str) -> Tuple[bool, str]:
        """管理员登录。返回 (ok, message)。"""
        if not admin_user:
            return False, "未填写管理员账号"
        try:
            login_cfg = self._require_fields("login").get("login", {})
        except RegistrationError:
            self._log_msg("未配置 login 字段映射，尝试默认登录路径 /wcd_login.cgi")
            login_cfg = {}
        login_cfg = login_cfg or {}
        url = self.base_url + login_cfg.get("action", "/wcd_login.cgi")
        data = {
            login_cfg.get("user_field", "user"): admin_user,
            login_cfg.get("pass_field", "password"): admin_password,
        }
        try:
            r = self.session.post(
                url, data=data, timeout=self.timeout, allow_redirects=True
            )
        except requests.RequestException as e:
            return False, f"管理员登录请求失败：{e}"
        if r.status_code != 200:
            return False, f"管理员登录返回状态 {r.status_code}"
        text = r.text.lower()
        # 登录成功的常见标志（不同固件文案不同，具体见真机确认点）
        if "logout" in text or "logoff" in text or "admin" in text:
            self._log_msg("管理员登录成功")
            return True, ""
        return False, "管理员登录失败（账号/密码错误或被锁定）"

    def _open_register_ftp_page(self) -> str:
        """进入：目的地注册 → 新建 FTP，返回表单页 URL。

        失败时抛 RegistrationError，并带上分类状态：
        - 权限拒绝 → ADMIN_REQUIRED
        - 缺映射 / 找不到入口 → FIELDS_MISSING
        - 网络异常 → UNREACHABLE
        """
        reg_cfg = self._require_fields("registration_entry").get("registration_entry", {})
        reg_cfg = reg_cfg or {}
        try:
            r = self.session.get(
                self.base_url + reg_cfg.get("url", "/wcd_main.cgi"),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise RegistrationError(f"进入注册页失败：{e}", STATUS_UNREACHABLE)
        if self._detect_permission_denied(r):
            raise RegistrationError(
                "访问目的地注册页被拒绝（权限不足或需管理员登录）",
                STATUS_ADMIN_REQUIRED,
            )
        soup = BeautifulSoup(r.text, "html.parser")
        link_text = reg_cfg.get("link_text", "目的地注册")
        entry_link = None
        for a in soup.find_all("a"):
            if link_text in a.get_text(strip=True):
                entry_link = a.get("href", "")
                break
        if not entry_link:
            raise RegistrationError(
                f"未找到“{link_text}”入口链接，请核对 registration_entry 映射",
                STATUS_FIELDS_MISSING,
            )
        form_cfg = self._require_fields("ftp_form").get("ftp_form", {}) or {}
        form_url = self.base_url + form_cfg.get("url", "/wcd_reg_ftp.cgi")
        self._log_msg(f"进入 FTP 注册表单页：{form_url}")
        return form_url

    def _verify_submitted(
        self, form_cfg: Dict[str, Any], ftp_params: Dict[str, Any]
    ) -> None:
        """可选校验：提交后目的地是否已生效。

        仅当 ftp_form.verify_url 配置时启用；未配置则跳过（真机确认点）。
        """
        verify_url = form_cfg.get("verify_url")
        if not verify_url:
            return
        url = verify_url if str(verify_url).startswith("http") else self.base_url + str(verify_url)
        try:
            r = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            self._log_msg(f"校验注册结果失败（忽略）：{e}")
            return
        name = str(ftp_params.get("name", ""))
        if name and name not in r.text:
            raise RegistrationError(
                f"提交后未在目的地列表中找到“{name}”，可能未生效（权限不足）",
                STATUS_ADMIN_REQUIRED,
            )

    def _fill_and_submit(self, form_url: str, ftp_params: Dict[str, Any]) -> None:
        """填写并提交 FTP 注册表单。失败按原因抛分类 RegistrationError。"""
        form_cfg = self._require_fields("ftp_form").get("ftp_form", {}) or {}
        fields_map: Dict[str, str] = form_cfg.get("fields", {})
        missing = [k for k in self.REQUIRED_FORM_FIELDS if k not in fields_map]
        if missing:
            raise RegistrationError(
                f"ftp_form.fields 缺少映射：{missing}", STATUS_FIELDS_MISSING
            )
        payload = {
            fields_map["name"]: ftp_params.get("name", "ScanToPC"),
            fields_map["host"]: ftp_params.get("host", ""),
            fields_map["port"]: str(ftp_params.get("port", 2121)),
            fields_map["user"]: ftp_params.get("user", ""),
            fields_map["password"]: ftp_params.get("password", ""),
            fields_map["dir"]: ftp_params.get("dir", "/"),
        }
        extras = form_cfg.get("extras", {})
        payload.update(extras)
        action = form_cfg.get("url", form_url)
        submit_url = self.base_url + action if not str(action).startswith("http") else action
        self._log_msg(f"提交 FTP 注册表单至 {submit_url}")
        try:
            r = self.session.post(
                submit_url, data=payload, timeout=self.timeout, allow_redirects=True
            )
        except requests.RequestException as e:
            raise RegistrationError(f"提交注册表单失败：{e}", STATUS_UNREACHABLE)
        if self._detect_permission_denied(r):
            raise RegistrationError(
                f"提交被拒绝（HTTP {r.status_code}），可能没有写入目的地的权限",
                STATUS_ADMIN_REQUIRED,
            )
        if r.status_code not in (200, 201, 302):
            raise RegistrationError(
                f"注册提交返回状态 {r.status_code}", STATUS_FALLBACK_SEMI_AUTO
            )
        text = r.text.lower()
        if any(k in text for k in ("error", "失败", "failed")):
            raise RegistrationError(
                "复印机返回错误，请检查提交参数", STATUS_FALLBACK_SEMI_AUTO
            )
        self._verify_submitted(form_cfg, ftp_params)
        self._log_msg("FTP 目的地注册提交完成")

    def register(
        self, ftp_params: Dict[str, Any], use_admin: bool = False
    ) -> RegisterResult:
        """三级递进注册。任何分支都返回 RegisterResult，不外抛异常。"""
        # ① 不可达
        ok, msg = self._check_reachable()
        if not ok:
            self._log_msg(f"前置检查失败：{msg}")
            return self._result(False, STATUS_UNREACHABLE, msg, url=self.base_url)

        # ② 缺字段（不崩）
        missing = self._missing_required_fields()
        if missing:
            self._log_msg(f"字段映射缺失：{missing}")
            return self._result(
                False,
                STATUS_FIELDS_MISSING,
                f"字段映射缺失：{missing}（请在 configs/mfp_fields.json 补充）",
                url=self.base_url,
            )

        used_admin = False
        # ⑥ 仅在要求时先做管理员登录
        if use_admin:
            ok, msg = self._admin_login(self.admin_user, self.admin_password)
            if not ok:
                url = self._fallback_semi_auto(ftp_params, f"管理员登录失败：{msg}")
                return self._result(
                    False,
                    STATUS_FALLBACK_SEMI_AUTO,
                    f"管理员登录失败：{msg}",
                    used_admin=False,
                    url=url,
                )
            used_admin = True

        # ③④⑤ 打开注册页 → 填表提交
        try:
            form_url = self._open_register_ftp_page()
            self._fill_and_submit(form_url, ftp_params)
        except RegistrationError as e:
            if e.status == STATUS_ADMIN_REQUIRED:
                # 已用管理员仍被拒 → 二次失败，兜底半自动
                if use_admin:
                    url = self._fallback_semi_auto(ftp_params, str(e))
                    return self._result(
                        False,
                        STATUS_FALLBACK_SEMI_AUTO,
                        f"管理员会话仍无法写入：{e}",
                        used_admin=True,
                        url=url,
                    )
                # 免管理员被拒 → 交回界面补填管理员重试（非失败、非半自动）
                return self._result(
                    False, STATUS_ADMIN_REQUIRED, str(e), url=self.base_url
                )
            if e.status == STATUS_FIELDS_MISSING:
                return self._result(
                    False, STATUS_FIELDS_MISSING, str(e), url=self.base_url
                )
            if e.status == STATUS_UNREACHABLE:
                return self._result(
                    False, STATUS_UNREACHABLE, str(e), url=self.base_url
                )
            # 其它（含提交失败）→ 兜底半自动
            url = self._fallback_semi_auto(ftp_params, str(e))
            return self._result(
                False,
                STATUS_FALLBACK_SEMI_AUTO,
                str(e),
                used_admin=used_admin,
                url=url,
            )

        # ⑤ 成功
        status = STATUS_OK if used_admin else STATUS_NO_ADMIN_REQUIRED
        msg = "注册成功（已使用管理员）" if used_admin else "注册成功（无需管理员）"
        self._log_msg(msg)
        return self._result(True, status, msg, used_admin=used_admin, url=form_url)

    def open_manual_page(self, ftp_params: Dict[str, Any]) -> str:
        try:
            form_cfg = self._require_fields("ftp_form").get("ftp_form", {}) or {}
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
            f"可通过 mfp_register.register_brand 扩展。",
            STATUS_FALLBACK_SEMI_AUTO,
        )
    return cls(config, fields, log)


def register_to_mfp(
    config: Dict[str, Any],
    fields: Dict[str, Any],
    ftp_params: Dict[str, Any],
    use_admin: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> Tuple[RegisterResult, Optional[MFPRegisterStrategy]]:
    """便捷封装：内部消化异常，始终返回 (RegisterResult, strategy|None)。

    strategy 供界面在缺映射 / 用户手动时调用半自动兜底。
    """
    try:
        strategy = get_register(config, fields, log=log)
    except RegistrationError as e:
        return RegisterResult(False, e.status, str(e)), None
    except Exception as e:  # noqa: BLE001
        return (
            RegisterResult(False, STATUS_FALLBACK_SEMI_AUTO, f"初始化注册策略失败：{e}"),
            None,
        )
    try:
        return strategy.register(ftp_params, use_admin=use_admin), strategy
    except Exception as e:  # noqa: BLE001
        return (
            RegisterResult(False, STATUS_FALLBACK_SEMI_AUTO, f"注册流程异常：{e}"),
            strategy,
        )


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
