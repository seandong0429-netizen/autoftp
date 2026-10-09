# AutoFTP — 复印机「扫描到 FTP」部署工具

在 Windows 电脑上一键启动 FTP 服务，并自动把「扫描到 FTP」目的地注册到柯尼卡美能达 bizhub 复印机。复印机面板点击后，扫描文件直接上传到电脑指定文件夹。

## 功能特性

- 基于 `pyftpdlib` 的 FTP 服务，支持 **IPv4 / IPv6 双栈**监听（默认 `::`，端口 `2121`）。
- 被动模式端口范围固定 `30000-30010`（可配置）。
- 默认扫描目录 `D:\Scan`，不存在时自动创建。
- 默认账号 `scanner / Scan@2026`（**示例密码，部署后请修改**）。
- 默认启用匿名访问（账号名 `anonymous`，权限与账号用户相同，均为全权限 `elradfmwMT`）。
- 匿名与账号权限均**硬编码为 `elradfmwMT`**（含读写删改等全部操作），界面不暴露修改入口，以降低配置出错风险。
- 通过 `enable_anonymous` 开关控制是否开启匿名访问；关闭后仅允许账号密码登录。
- 默认优先使用 **IPv6** 地址注册到复印机（可在界面取消勾选回退 IPv4）。
- 自动检测本机 IPv4 与 IPv6 全局地址并显示。
- **自动扫描局域网内复印机**：先做 SNMP v2c 探测（`sysDescr`/`sysObjectID`/`sysName`）识别厂商与型号，未命中的地址再用 Web 关键字兜底，结果以下拉框列出供选择。
- 扫描不到时可直接手动填写复印机 IP，点「一键注册到复印机」完成注册。
- 自动配置 Windows 防火墙（放行控制端口与被动端口）。
- 柯尼卡美能达 bizhub 系列通过 Web Connection 自动注册目的地（`requests` + `BeautifulSoup`，不依赖浏览器自动化）。
- 字段映射可配置（`configs/mfp_fields.json`），适配不同固件版本。
- 自动注册失败时**自动降级为半自动模式**：打开浏览器跳转注册页并显示需填写的参数。
- MFP 注册模块采用**策略模式**，可扩展理光 / 富士等品牌。

## 项目结构

```
autoftp/
├── configs/
│   ├── scan_config.json      # 主配置（端口/账号/匿名/复印机 IP 等）
│   └── mfp_fields.json       # 各品牌复印机 Web 页面字段映射
├── config_loader.py          # 配置加载 / 保存 / 网络信息获取
├── firewall_helper.py        # Windows 防火墙配置（netsh）
├── ftp_server.py             # pyftpdlib 双栈 FTP 服务管理
├── mfp_scanner.py            # 局域网复印机自动探测（SNMP 优先 + Web 兜底）
├── snmp_client.py            # 纯标准库 SNMP v2c GET（手写 BER）
├── mfp_register.py           # 策略模式：复印机目的地自动注册
├── gui_app.py                # tkinter 图形界面
├── requirements.txt
└── README.md
```

## 环境要求

- Windows 10 / 11（防火墙自动配置依赖 `netsh`，双栈监听需系统启用 IPv6）。
- Python 3.9+（建议 3.10+）。

## 安装依赖

```bash
# 建议使用虚拟环境
python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
```

依赖清单：

| 包 | 用途 |
|----|------|
| `pyftpdlib` | FTP 服务实现 |
| `requests` | 复印机 Web Connection HTTP 交互 |
| `beautifulsoup4` | 解析复印机 HTML 页面、定位字段 |
| `psutil` | 获取本机网卡子网掩码（推断扫描网段；缺失时回退系统命令/`/24`） |

> SNMP 扫描为**纯标准库**实现（`socket` + 手写 BER，见 [snmp_client.py](snmp_client.py)），无需 `pysnmp` 等额外依赖。

## 运行

> 强烈建议**以管理员身份**启动，以便自动配置防火墙。

```bash
python gui_app.py
```

或在 Python 安装目录下创建快捷方式指向 `pythonw.exe gui_app.py` 以无控制台窗口启动。

首次运行若 `configs/scan_config.json` 不存在，会自动生成默认配置。

## 界面操作流程

1. 在「扫描目录」选择目标文件夹（默认 `D:\Scan`）。
2. 设置控制端口（默认 2121）、被动端口（默认 `30000-30010`）、账号密码。
3. 按需勾选「启用匿名访问」；关闭后仅允许账号密码登录（匿名账号名为 `anonymous`）。
4. 点击「保存配置」。
5. 点击「配置防火墙」放行端口（需管理员权限）。
6. 点击「启动 FTP」开始监听。
7. 在右侧点击「扫描局域网」自动探测复印机，在「检测结果」下拉框中选择目标；
   若扫描不到，直接在「复印机 IP」手动输入 IP。
8. 填写管理员账号 / 密码，按需勾选「注册时优先使用 IPv6 地址」（默认开启）。
9. 点击「一键注册到复印机」，等待日志反馈结果。

## 配置说明

### `configs/scan_config.json`

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `ftp.host` | 监听地址，`::` 表示双栈 | `::` |
| `ftp.port` | FTP 控制端口 | `2121` |
| `ftp.passive_ports` | 被动端口范围 | `30000-30010` |
| `ftp.scan_dir` | 扫描文件存放目录 | `D:\Scan` |
| `ftp.username` / `ftp.password` | FTP 账号 | `scanner` / `Scan@2026` |
| `ftp.enable_anonymous` | 是否启用匿名访问 | `true` |
| `ftp.anonymous_perm` | 匿名权限（已硬编码，界面不暴露） | `elradfmwMT` |
| `ftp.user_perm` | 账号用户权限（已硬编码，界面不暴露） | `elradfmwMT` |
| `mfp.brand` | 复印机品牌 | `konica_minolta` |
| `mfp.ip` | 复印机 IP | 空 |
| `mfp.admin_user` / `mfp.admin_password` | Web Connection 管理员账号 | `admin` / 空 |
| `network.prefer_ipv6` | 注册时优先用 IPv6 地址作为主机 | `true` |

> 权限字符（pyftpdlib 约定）：
> `e`改目录、`l`列表、`r`读、`a`追加、`d`删除、`f`重命名、`m`建目录、`w`写、`M`改权限、`T`改时间。

### `configs/mfp_fields.json`

不同固件版本的 Web Connection HTML 字段名不同，因此把字段名抽到配置文件。结构示例：

```json
{
  "konica_minolta": {
    "login": { "action": "/wcd_login.cgi", "user_field": "user", "pass_field": "password" },
    "registration_entry": { "url": "/wcd_main.cgi", "link_text": "目的地注册" },
    "ftp_form": {
      "url": "/wcd_reg_ftp.cgi",
      "fields": { "name": "dest_name", "host": "host_address", "port": "port_no",
                  "user": "login_name", "password": "login_password", "dir": "save_path" }
    }
  }
}
```

当某字段缺失时，程序会报 `字段映射缺失` 错误，请打开复印机 Web 页面查看实际 `name` 属性后补充。

## 配置柯尼卡美能达复印机

1. 确认复印机与电脑在同一局域网，可在浏览器访问 `http://<复印机IP>` 打开 Web Connection。
2. 在复印机端：`效用/计数器 → 管理员设置 → 网络设置 → Web Connection`，确认已启用并设置管理员密码。
3. 在本工具右侧点击「扫描局域网」自动发现复印机，从「检测结果」下拉选择；
   或直接在「复印机 IP」手动输入 IP，填入管理员账号与密码。
4. 点击「一键注册到复印机」。成功后复印机「扫描/传真 → 地址簿」会出现新条目。
5. 在面板上选择该条目，放置原稿，按「开始」即可将扫描文件上传至电脑。

## 局域网复印机自动扫描

识别采用 **SNMP 优先、Web 兜底** 两级策略：

1. **SNMP 主识别（v2c，默认团体名 `public`，超时 `0.8s`）**
   - 并发对子网内每个地址做 SNMP GET，读取 `sysDescr`(1.3.6.1.2.1.1.1.0)、`sysObjectID`(1.3.6.1.2.1.1.2.0)、`sysName`(1.3.6.1.2.1.1.5.0)。
   - 按 varbind 结构取值，不做“报文里找可打印串”的猜测；`sysName` 为空时不会把团体名 `public` 误当作主机名。
   - 厂商判定：`sysObjectID` 的 enterprise 前缀优先（`2636`=柯尼卡美能达、`118`=佳能、`367`=理光、`23`=惠普），无值再用 `sysDescr` 关键字兜底。
   - 示例：`sysDescr` 返回 `KONICA MINOLTA bizhub C550i` → 厂商 `konica_minolta`，型号 `bizhub C550i`。
   - SNMP 的实现是纯标准库（`socket` + 手写 BER，见 [snmp_client.py](snmp_client.py)），未引入 `pysnmp`。
2. **Web 兜底**：仅对 SNMP 未命中的地址，探测 Web 端口（`80` / `443` / `8080`，`443` 走 HTTPS 且关闭证书校验），抓首页关键字识别。**SNMP 已识别的 IP 跳过 Web 探测。**

其它：

- 网段按本机出口 IPv4 的**真实子网掩码**推断（已排除回环与常见虚拟网卡）；掩码取不到或网段过大时回退 `/24`。
- 每条结果含 `source`(`snmp`/`web`)、`vendor`、`model`、`status`(`identified`/`suspect`/`unknown`)，并保留旧字段 `ip`/`title`/`url`/`brand` 以兼容界面。
- 结果以「`IP  |  型号`」形式填入下拉框，选中即自动填入复印机 IP。
- 扫描在子线程执行，期间界面不卡顿，进度实时写入日志区。
- 使用前提：复印机需启用 SNMP 且团体名为 `public`（多数 bizhub 默认开启）；若未开启 SNMP，会自动回退到 Web 识别。
- 若仍扫描不到，直接在「复印机 IP」手动输入即可继续注册。扫描仅用于发现设备，不会修改任何主机。

## IPv6 地址处理

- 双栈监听：监听 `::` 并关闭 `IPV6_V6ONLY`，同时接受 IPv4 与 IPv6 连接，无需分别监听两个 socket。
- 注册到复印机时默认优先使用 IPv6（界面默认勾选，可取消），会取本机 IPv6 全局地址（`2000::/3`，排除链路本地 `fe80`）作为主机地址。
- IPv6 地址在复印机中作为主机名填写时，部分固件要求去掉中括号或使用 FQDN；若注册后扫描失败，请改用 IPv4 并取消勾选「优先使用 IPv6」。
- 若电脑 IPv6 由运营商动态分配，建议改用 IPv4 注册以保证稳定性。

## 开启 / 关闭匿名访问

- 界面：勾选 / 取消「启用匿名访问」。
- 配置文件：设置 `ftp.enable_anonymous` 为 `true` / `false`。
- 匿名账号名为 `anonymous`，无需密码（pyftpdlib 约定）。
- 关闭后，匿名登录将被拒绝，仅 `username/password` 可登录。
- 匿名与账号权限均已硬编码为全权限 `elradfmwMT`，界面不再提供修改入口；如确需收紧权限，可直接编辑 `configs/scan_config.json`（但 GUI 保存时会覆盖回硬编码值），或在 `ftp_server.py` 修改 `ANON_PERM` / `USER_PERM` 常量。

## 排查扫描失败

| 现象 | 排查方向 |
|------|---------|
| 「扫描局域网」找不到复印机 | 复印机跨网段、Web 端口非 80/443/8080、被防火墙拦截，或出口网卡非预期；直接在「复印机 IP」手动输入 IP 即可继续注册 |
| 复印机提示连接超时 | 防火墙未放行 2121 与 30000-30010；未以管理员身份运行；电脑处于「公用网络」防火墙策略 |
| 复印机登录失败 | 检查 `admin_user` / `admin_password` 是否正确；是否被管理员锁定 |
| 注册页打不开 | 复印机 Web Connection 未启用；`mfp_fields.json` 中 `registration_entry.url` 与实际不符 |
| 字段映射缺失 | 参考上方 `mfp_fields.json` 段落，补充实际字段名 |
| 上传后找不到文件 | 确认 `scan_dir` 存在且可写；匿名用户无写权限（`w`）时会失败 |
| IPv6 注册后无法扫描 | 改用 IPv4；确认复印机与电脑同 IPv6 网段且无防火墙拦截 |
| 端口被占用 | 修改 `ftp.port` 并同步更新防火墙规则 |

## 自动注册错误提示

程序在以下情况会给出明确错误：

- `未配置复印机 IP 地址`
- `无法连接复印机 <ip>`（网络不可达）
- `管理员登录失败`（账号密码错误 / 被锁定）
- `未找到"目的地注册"入口链接`（页面结构变更）
- `字段映射缺失（brand=..., keys=...）`（`mfp_fields.json` 需补充）
- `注册提交返回状态 <code>`（提交被拒绝）

任一错误后都会**自动降级为半自动模式**：用默认浏览器打开复印机的 FTP 注册页，并在日志区列出需要填写的 `name / host / port / user / password / dir`，由用户手动完成提交。

## 扩展到理光 / 富士等品牌

MFP 注册采用策略模式，扩展步骤：

1. 在 `configs/mfp_fields.json` 中补充新品牌的字段映射。
2. 新建策略类继承 `mfp_register.MFPRegisterStrategy`，实现 `register()` 与 `open_manual_page()`。
3. 调用 `mfp_register.register_brand("ricoh", RicohRegister)` 注册策略。
4. 在 `gui_app.py` 的品牌下拉菜单中加入对应品牌名。

```python
from mfp_register import MFPRegisterStrategy, register_brand

class RicohRegister(MFPRegisterStrategy):
    brand = "ricoh"
    def register(self, ftp_params): ...
    def open_manual_page(self, ftp_params): ...

register_brand("ricoh", RicohRegister)
```

## 安全提示

- 默认密码 `Scan@2026` 仅为示例，**部署后务必修改**。
- 匿名访问默认开启，权限不含 `MT`；如在公网或不可信网络使用，请关闭匿名访问。
- 工具仅放行本机所需端口，不会修改其他防火墙规则。
- 建议在局域网内使用，不要将 2121 / 30000-30010 暴露到公网。

## 许可

MIT License
