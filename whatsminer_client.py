#!/usr/bin/env python3
"""WhatsMiner 8889 protocol client
Protocol reverse-engineered from WhatsMinerTool 9.2.5.

Encryption: AES-256-ECB with hardcoded keys in the binary.
Frame format: 5A5A7F7F header + auth payload, encrypted.
Session: auth via Key1 (cmdcode 0) → session_id, then queries via Key2 (cmdcode 0x16).
"""

import socket
import struct
import time
import os
import binascii
from Crypto.Cipher import AES

# AES-256 keys, hardcoded in binary at VAs 0x7254c0 / 0x7254e0
KEY_AUTH = bytes.fromhex(
    "f0d379ee4188bc6216cfa09adcd49100"
    "ee7f971217aaba26bc86c0b6ae1da90f"
)
KEY_QUERY = bytes.fromhex(
    "66476cc48201182b9c27c302e48e1207"
    "24a0e460fb970474a7539a48e787c296"
)

ACCOUNT = "super"
PASSWORD = "super"
TOOL_VERSION = "9.2.5.0721"
DEFAULT_PORT = 8889


def _build_auth_message(ip, account, password, version):
    """Build 64-byte auth message (5A5A7F7F frame, Key1, cmdcode 0x00).

    Frame layout (encrypted as AES-256-ECB with Key1):
      +0x00 magic    = 0x7F7F5A5A
      +0x04 cmdcode  = 0x00 (auth)
      +0x08 len1     = payload length
      +0x0a len2     = 0
      +0x0c checksum = CRC32(payload) ^ 0xFFFFFFFF
      +0x10 payload  = "ip|ts|account|password|version" + zero padding
    Server responds with 24-byte ack containing session_id.
    """
    ts = int(time.time())
    payload = f"{ip}|{ts}|{account}|{password}|{version}"
    pb = payload.encode("ascii")
    pad_len = (16 - len(pb) % 16) % 16
    padded = pb + b"\x00" * pad_len
    crc = binascii.crc32(pb) ^ 0xFFFFFFFF

    hdr = struct.pack("<I", 0x7F7F5A5A)
    hdr += struct.pack("<I", 0x00)
    hdr += struct.pack("<H", len(pb))
    hdr += struct.pack("<H", 0)
    hdr += struct.pack("<I", crc)

    frame = hdr + padded
    while len(frame) < 64:
        frame += b"\x00"

    cipher = AES.new(KEY_AUTH, AES.MODE_ECB)
    return cipher.encrypt(frame)


def _build_query_message(ip, account, password, version, session_id, cmdcode=0x16, param=""):
    """Build framed query/command message (5A5A7F7F header, Key2).

    Frame layout (encrypted as single AES-256-ECB block):
      +0x00 magic    = 0x7F7F5A5A
      +0x04 cmdcode  = operation code
      +0x08 len1     = auth payload length
      +0x0a len2     = command parameter length (0 for queries)
      +0x0c checksum = CRC32(part1 + part2) ^ 0xFFFFFFFF
      +0x10 part1    = "ip|ts|account|password|session_id|version"
      +0x10+len1     part2 = "N=V" (for cmdcode 0x0D only)
    """
    ts = int(time.time())
    part1 = f"{ip}|{ts}|{account}|{password}|{session_id}|{version}"
    pb1 = part1.encode("ascii")
    pb2 = param.encode("ascii") if param else b""
    full = pb1 + pb2
    crc = binascii.crc32(full) ^ 0xFFFFFFFF

    hdr = struct.pack("<I", 0x7F7F5A5A)
    hdr += struct.pack("<I", cmdcode)
    hdr += struct.pack("<H", len(pb1))
    hdr += struct.pack("<H", len(pb2))
    hdr += struct.pack("<I", crc)

    frame = hdr + full
    while len(frame) < 80:
        frame += b"\x00"

    cipher = AES.new(KEY_QUERY, AES.MODE_ECB)
    return cipher.encrypt(frame)


def _recv_all(sock, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(8208)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def _parse_5a5a_header(data):
    """Parse 5A5A7F7F response header."""
    if len(data) < 16:
        return None
    magic = struct.unpack("<I", data[0:4])[0]
    if magic != 0x7F7F5A5A:
        return None
    return {
        "cmdcode": struct.unpack("<I", data[4:8])[0],
        "len1": struct.unpack("<H", data[8:10])[0],
        "len2": struct.unpack("<H", data[10:12])[0],
        "checksum": struct.unpack("<I", data[12:16])[0],
        "payload": data[16:],
    }


def get_session_id(ip, port=DEFAULT_PORT, account=ACCOUNT, password=PASSWORD, version=TOOL_VERSION):
    """Perform auth handshake and return session_id."""
    msg = _build_auth_message(ip, account, password, version)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((ip, port))
        sock.send(msg)
        resp = _recv_all(sock, timeout=3.0)
        sock.close()
        # Response is 24 bytes: 16-byte header + 8-byte payload
        # Payload bytes 4-7 contain the session_id as 4 raw bytes (hex-encoded for use)
        if len(resp) >= 24:
            payload = resp[16:24]
            if len(payload) >= 8:
                return payload[4:8].hex()
    except Exception:
        sock.close()
    return None


def get_miner_info(ip, session_id=None, port=DEFAULT_PORT):
    """Query MinerInfo from the miner. Returns parsed dict or None.

    If session_id is None, uses a known default (from auth handshake).
    """
    if session_id is None:
        # Try to get fresh session_id, fall back to known default
        session_id = get_session_id(ip, port) or "2b974662"

    msg = _build_query_message(ip, ACCOUNT, PASSWORD, TOOL_VERSION, session_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    try:
        sock.connect((ip, port))
        sock.send(msg)
        resp = _recv_all(sock, timeout=10.0)
        sock.close()
    except Exception:
        sock.close()
        return None

    header = _parse_5a5a_header(resp)
    if not header or header["cmdcode"] != 0x16 or len(header["payload"]) == 0:
        return None

    return _parse_miner_info(header["payload"].decode("utf-8", errors="replace"))


def _parse_miner_info(text):
    """Parse MinerInfo response text into structured dict.

    The response contains:
    - [MinerInfo] section: hardware details
    - [PowerInfo] section: power supply details
    - Inline SUMMARY/EDEVS/Power data in the last field (pipe/hash delimited)
    """
    result = {"_raw": {}, "_summary": {}, "_power": {}, "_slots": []}

    # Parse key=value lines
    for line in text.strip().split("\n"):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            result["_raw"][key.strip()] = val.strip()

    # Parse inline SUMMARY/EDEVS/Power data
    inline = ""
    for val in result["_raw"].values():
        if isinstance(val, str) and "#SUMMARY" in val:
            inline = val
            break

    if inline:
        sections = inline.split("|")
        for section in sections:
            section = section.lstrip("#")
            if "SUMMARY" in section:
                for item in section.split(","):
                    if "=" in item:
                        k, _, v = item.partition("=")
                        result["_summary"][k.strip()] = v.strip()
            elif "ASC=" in section:
                slot = {}
                for item in section.split(","):
                    if "=" in item:
                        k, _, v = item.partition("=")
                        slot[k.strip()] = v.strip()
                if slot:
                    result["_slots"].append(slot)
            elif "Uptime=" in section:
                for item in section.replace("#", "").split(","):
                    if "=" in item:
                        k, _, v = item.partition("=")
                        result["_power"][k.strip()] = v.strip()

    return result


def get_csv_row(ip, session_id=None, port=DEFAULT_PORT):
    """Get miner data as a dict matching the WhatsMinerTool CSV columns."""
    info = get_miner_info(ip, session_id, port)
    if not info:
        return None

    raw = info["_raw"]
    summary = info["_summary"]
    power = info["_power"]

    # Combine fields as the tool does
    miner_type = raw.get("MinerType", "")
    hb_version = raw.get("HashBoardVersion", "")
    if hb_version:
        miner_type = f"{miner_type}_{hb_version}"

    version_info = raw.get("FirmwareVersion", "")
    cb_type = raw.get("ControlBoardType", "")
    cb_ver = raw.get("ControlBoardVersion", "")
    if cb_type and cb_ver:
        version_info = f"{cb_type}-{cb_ver}-{version_info}"

    power_ver = raw.get("PowerRevision", "")
    power_type = raw.get("PowerType", "")
    hw_rev = raw.get("HwRevision", "")
    power_ver_full = f"{power_type}-{power_ver}" if power_type else power_ver
    if hw_rev and not power_ver_full.endswith(hw_rev):
        power_ver_full = f"{power_ver_full}-{hw_rev}"

    # MAC address: extract from the #web_pool inline data
    mac_addr = ""
    for val in raw.values():
        if isinstance(val, str) and "#" in val:
            for part in val.split("#"):
                if ":" in part and len(part.strip()) == 17:
                    mac_addr = part.strip()
                    break

    # Power SN with GB prefix
    power_sn = raw.get("PowerSerialNo", "")
    hw_rev_sn = raw.get("HwRevision", "")
    if power_sn and hw_rev_sn:
        power_sn = f"GB{power_sn}{hw_rev_sn}"

    return {
        "IP": ip,
        "Status": "Running" if summary.get("Elapsed", "0") != "0" else "Paused",
        "Miner Type": miner_type,
        "Power Version": power_ver_full,
        "MAC Addr": mac_addr,
        "Error Code": summary.get("Error Code Count", ""),
        "UpTime": power.get("Uptime", ""),
        "Elapsed": summary.get("Elapsed", ""),
        "THS RT": summary.get("HS RT", ""),
        "THS Avg": summary.get("MHS av", ""),
        "Efficiency(W/T)": "",
        "Power Avg(W)": summary.get("Power", ""),
        "PowerRT(W)": power.get("PowerRT", ""),
        "PowerLimitSet": summary.get("Power Limit", ""),
        "Version Info": version_info,
        "ChipType0": raw.get("ChipData", ""),
        "FreqAvg": summary.get("freq_avg", ""),
        "HashBoardTemp": "_".join(power.get(f"BoardTemp{i}", "") for i in range(4)),
        "EnvTemp": power.get("EnvTemp", ""),
        "Volt": power.get("PowerVIn", ""),
        "SpdIn": power.get("FanSpeedIn", ""),
        "SpdOut": power.get("FanSpeedOut", ""),
        "UpfreqSpeed": "",
        "Miner SN": raw.get("MinerSn", ""),
        "Customer SN": "",
        "Power SN": power_sn,
        "Performance": summary.get("Power Mode", ""),
        "Active Pool": "",
        "Reject Rate": summary.get("Pool Rejected%", ""),
        "Last Valid Work": info["_slots"][0].get("Last Valid Work", "") if info["_slots"] else "",
        "Pool 1": "",
        "Worker 1": "",
        "Pool 2": "",
        "Worker 2": "",
        "Pool 3": "",
        "Worker 3": "",
    }


def send_remote_control(ip, param, session_id=None, port=DEFAULT_PORT):
    """Send a remote control command (cmdcode 0x0D).

    Args:
        param: Operation parameter in "N=V" format, e.g. "8=1" for Resume Work.
            Operation codes:
                6=0: Disable API (port 4028)
                6=1: Enable API
                8=0: Stop Work
                8=1: Resume Work
    """
    if session_id is None:
        session_id = get_session_id(ip, port) or "2b974662"

    msg = _build_query_message(ip, ACCOUNT, PASSWORD, TOOL_VERSION, session_id, cmdcode=0x0D, param=param)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    try:
        sock.connect((ip, port))
        sock.send(msg)
        resp = _recv_all(sock, timeout=5.0)
        sock.close()
        header = _parse_5a5a_header(resp)
        return header is not None and header["cmdcode"] == 0x0D
    except Exception:
        sock.close()
        return False


def resume_work(ip, session_id=None, port=DEFAULT_PORT):
    """Resume mining on the miner."""
    return send_remote_control(ip, "8=1", session_id, port)


def stop_work(ip, session_id=None, port=DEFAULT_PORT):
    """Stop mining on the miner."""
    return send_remote_control(ip, "8=0", session_id, port)


def disable_api(ip, session_id=None, port=DEFAULT_PORT):
    """Disable API on port 4028 (prevents external shutdown but 8889 still works)."""
    return send_remote_control(ip, "6=0", session_id, port)


def enable_api(ip, session_id=None, port=DEFAULT_PORT):
    """Enable API on port 4028."""
    return send_remote_control(ip, "6=1", session_id, port)


def main():
    import sys

    ip = sys.argv[1] if len(sys.argv) > 1 else "10.3.1.128"
    session_id = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"WhatsMiner 8889 Protocol Client")
    print(f"Target: {ip}:{DEFAULT_PORT}")
    print(f"{'='*60}")

    row = get_csv_row(ip, session_id)
    if row:
        for k, v in row.items():
            if v:
                print(f"  {k}: {v}")
    else:
        print("Failed to get miner info")


if __name__ == "__main__":
    main()
