# -*- coding: utf-8 -*-
"""极简 SNMP v2c GET 客户端（纯标准库，socket + 手写 BER）。

只实现扫描所需的最小功能：对一个 UDP 目标发一条 GetRequest，按 **varbind 结构**
解析返回的每个 (OID, value)，不做任何“在报文里找可打印串”的启发式猜测——
那样会把团体名（如 public）误当成主机名。

用法::

    vals = snmp_get("192.168.1.50", ["1.3.6.1.2.1.1.1.0"])
    # -> {"1.3.6.1.2.1.1.1.0": "KONICA MINOLTA bizhub C550i"}

无第三方依赖，供 PyInstaller 打包安全（无动态导入）。
"""
from __future__ import annotations

import random
import socket
from typing import Dict, List, Optional, Sequence, Tuple

# ---- 常用 OID ----
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"      # sysDescr
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"  # sysObjectID
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"       # sysName

DEFAULT_COMMUNITY = "public"
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 0.8

# SNMP 版本号：v2c == 1
_VERSION_V2C = 1

# BER tag
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_GET_RESPONSE = 0xA2

# 空值 OID 前缀（用于判断是否 noSuchName 等）
_ERROR_NO_SUCH_NAME = 2


class SnmpError(Exception):
    """SNMP 传输或解析失败。"""


# ------------------------- BER 编码 -------------------------
def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = bytearray()
    while length:
        body.append(length & 0xFF)
        length >>= 8
    body.reverse()
    return bytes([0x80 | len(body)]) + bytes(body)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _ber_int(value: int) -> bytes:
    """编码非负 INTEGER（request-id / version / error-status / error-index）。"""
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:          # 补一个 0x00 避免被当作负数
            body = b"\x00" + body
    return _ber_tlv(_TAG_INTEGER, body)


def _ber_octet_string(value: bytes) -> bytes:
    return _ber_tlv(_TAG_OCTET_STRING, value)


def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip().split(".") if p != ""]
    if len(parts) < 2:
        raise SnmpError(f"非法 OID: {oid}")
    subs = [40 * parts[0] + parts[1]] + parts[2:]
    body = bytearray()
    for sub in subs:
        if sub < 0:
            raise SnmpError(f"OID 子标识符不能为负: {oid}")
        chunk = [sub & 0x7F]
        sub >>= 7
        while sub:
            chunk.append((sub & 0x7F) | 0x80)
            sub >>= 7
        body.extend(reversed(chunk))
    return _ber_tlv(_TAG_OID, bytes(body))


# ------------------------- BER 解码 -------------------------
def _read_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise SnmpError("BER 数据不完整（长度域）")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num = first & 0x7F
    if num == 0:
        raise SnmpError("非法的 BER 长度形式")
    if offset + num > len(data):
        raise SnmpError("BER 长度域越界")
    return int.from_bytes(data[offset:offset + num], "big"), offset + num


def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """读取一个 TLV，返回 (tag, value_bytes, 下一个偏移)。"""
    if offset >= len(data):
        raise SnmpError("BER 数据不完整（tag）")
    tag = data[offset]
    length, offset = _read_length(data, offset + 1)
    end = offset + length
    if end > len(data):
        raise SnmpError("BER value 越界")
    return tag, data[offset:end], end


def _decode_int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    subs: List[int] = []
    cur = 0
    for byte in value:
        cur = (cur << 7) | (byte & 0x7F)
        if not byte & 0x80:
            subs.append(cur)
            cur = 0
    if not subs:
        return ""
    first = subs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(x) for x in head + subs[1:])


def _decode_value(tag: int, value: bytes) -> str:
    if tag == _TAG_OCTET_STRING:
        return value.decode("utf-8", errors="replace")
    if tag == _TAG_OID:
        return _decode_oid(value)
    if tag == _TAG_INTEGER:
        return str(_decode_int(value))
    if tag == _TAG_NULL:
        return ""
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter/Gauge/TimeTicks/Counter64
        return str(int.from_bytes(value, "big"))
    if tag in (0x40,):                    # IpAddress
        return ".".join(str(b) for b in value)
    return value.decode("latin-1", errors="replace")


# ------------------------- 报文构造与解析 -------------------------
def _build_get_request(request_id: int, oids: Sequence[str], community: bytes) -> bytes:
    varbinds = b"".join(
        _ber_tlv(_TAG_SEQUENCE, _ber_oid(oid) + _ber_tlv(_TAG_NULL, b""))
        for oid in oids
    )
    pdu_body = (
        _ber_int(request_id)
        + _ber_int(0)  # error-status
        + _ber_int(0)  # error-index
        + _ber_tlv(_TAG_SEQUENCE, varbinds)
    )
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU
    return _ber_tlv(
        _TAG_SEQUENCE,
        _ber_int(_VERSION_V2C) + _ber_octet_string(community) + pdu,
    )


def _parse_response(data: bytes) -> Tuple[int, int, Dict[str, str]]:
    """解析 GetResponse，返回 (request_id, error_status, {oid: value})。"""
    tag, message, _ = _read_tlv(data, 0)
    if tag != _TAG_SEQUENCE:
        raise SnmpError("响应最外层不是 SEQUENCE")

    offset = 0
    _, ver_val, offset = _read_tlv(message, offset)
    if _decode_int(ver_val) != _VERSION_V2C:
        raise SnmpError("非 SNMP v2c 响应")

    comm_tag, _, offset = _read_tlv(message, offset)
    if comm_tag != _TAG_OCTET_STRING:
        raise SnmpError("响应缺少 community 字段")

    pdu_tag, pdu, offset = _read_tlv(message, offset)
    if pdu_tag != _TAG_GET_RESPONSE:
        raise SnmpError(f"非 GetResponse PDU: 0x{pdu_tag:02X}")

    po = 0
    _, rid_val, po = _read_tlv(pdu, po)
    request_id = _decode_int(rid_val)
    _, err_val, po = _read_tlv(pdu, po)
    error_status = _decode_int(err_val)
    _, _, po = _read_tlv(pdu, po)  # error-index，扫描场景无需使用
    _, vbs, po = _read_tlv(pdu, po)

    results: Dict[str, str] = {}
    vo = 0
    while vo < len(vbs):
        _, vb, vo = _read_tlv(vbs, vo)
        inner = 0
        _, oid_val, inner = _read_tlv(vb, inner)
        oid = _decode_oid(oid_val)
        vtag, vval, inner = _read_tlv(vb, inner)
        results[oid] = _decode_value(vtag, vval)
    return request_id, error_status, results


# ------------------------- 对外接口 -------------------------
def snmp_get(
    ip: str,
    oids: Sequence[str],
    community: str = DEFAULT_COMMUNITY,
    timeout: float = DEFAULT_TIMEOUT,
    port: int = DEFAULT_PORT,
) -> Dict[str, str]:
    """对一个目标执行一次 SNMP v2c GET。

    返回 ``{oid: value}``，仅包含响应中真实出现的 varbind；
    传输超时/解析失败抛出 :class:`SnmpError`。
    """
    if not oids:
        return {}
    request_id = random.randint(1, 0x7FFFFFFF)
    packet = _build_get_request(request_id, oids, community.encode("utf-8"))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(packet)
            data, _ = sock.recvfrom(65535)
    except socket.timeout as e:
        raise SnmpError(f"SNMP 超时（{timeout}s）") from e
    except OSError as e:
        raise SnmpError(f"SNMP 网络错误: {e}") from e

    rid, error_status, results = _parse_response(data)
    if rid != request_id:
        raise SnmpError("响应的 request-id 不匹配")
    if error_status == _ERROR_NO_SUCH_NAME:
        # v2c 下通常返回空 varbind，此处直接给出空结果
        return {}
    return results


def probe_system(
    ip: str,
    community: str = DEFAULT_COMMUNITY,
    timeout: float = DEFAULT_TIMEOUT,
    port: int = DEFAULT_PORT,
) -> Optional[Dict[str, str]]:
    """探测 sysDescr / sysName / sysObjectID。

    成功返回 ``{"sysDescr","sysName","sysObjectID"}``（缺失的键为空串）；
    设备无 SNMP 响应时返回 ``None``。
    """
    try:
        values = snmp_get(
            ip,
            [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME],
            community=community,
            timeout=timeout,
            port=port,
        )
    except SnmpError:
        return None
    if not values:
        return None
    return {
        "sysDescr": values.get(OID_SYS_DESCR, ""),
        "sysObjectID": values.get(OID_SYS_OBJECT_ID, ""),
        "sysName": values.get(OID_SYS_NAME, ""),
    }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(probe_system(target))
