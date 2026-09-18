#!/usr/bin/env python3
"""WhatsMiner 8889 protocol client
Protocol reverse-engineered from WhatsMinerTool 9.2.5.

Encryption: AES-256-ECB with hardcoded keys in the binary.
Frame format: 5A5A7F7F header + auth payload, encrypted.
Session: auth via Key1 (cmdcode 0) → session_id, then queries via Key2.
"""

import socket
import struct
import time
import binascii
import json

import typer
from rich.console import Console
from rich.table import Table
from Crypto.Cipher import AES

app = typer.Typer(help="WhatsMiner 8889 protocol CLI", add_completion=False)
console = Console()

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


# ── Protocol internals ──────────────────────────────────────────────

def _build_auth_message(ip: str, account: str, password: str, version: str) -> bytes:
    """Build 64-byte auth message (5A5A7F7F frame, Key1, cmdcode 0x00)."""
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

    return AES.new(KEY_AUTH, AES.MODE_ECB).encrypt(frame)


def _build_query_message(ip: str, account: str, password: str, version: str,
                         session_id: str, cmdcode: int = 0x16, param: str = "") -> bytes:
    """Build framed query/command message (5A5A7F7F header, Key2)."""
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

    return AES.new(KEY_QUERY, AES.MODE_ECB).encrypt(frame)


def _recv_all(sock: socket.socket, timeout: float = 5.0) -> bytes:
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


def _parse_header(data: bytes) -> dict | None:
    if len(data) < 16:
        return None
    if struct.unpack("<I", data[0:4])[0] != 0x7F7F5A5A:
        return None
    return {
        "cmdcode": struct.unpack("<I", data[4:8])[0],
        "len1": struct.unpack("<H", data[8:10])[0],
        "len2": struct.unpack("<H", data[10:12])[0],
        "checksum": struct.unpack("<I", data[12:16])[0],
        "payload": data[16:],
    }


# ── Public API ──────────────────────────────────────────────────────

def get_session_id(ip: str, port: int = DEFAULT_PORT) -> str | None:
    """Auth handshake → returns hex session_id."""
    msg = _build_auth_message(ip, ACCOUNT, PASSWORD, TOOL_VERSION)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((ip, port))
        sock.send(msg)
        resp = _recv_all(sock, timeout=3.0)
        sock.close()
        if len(resp) >= 24:
            return resp[20:24].hex()
    except Exception:
        sock.close()
    return None


def query_cmd(ip: str, cmdcode: int, session_id: str | None = None,
           param: str = "", timeout: float = 10.0) -> bytes | None:
    """Send a framed command and return raw response."""
    if session_id is None:
        session_id = get_session_id(ip)
        if not session_id:
            return None
    msg = _build_query_message(ip, ACCOUNT, PASSWORD, TOOL_VERSION,
                               session_id, cmdcode=cmdcode, param=param)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, DEFAULT_PORT))
        sock.send(msg)
        resp = _recv_all(sock, timeout=timeout)
        sock.close()
        return resp
    except Exception:
        sock.close()
        return None


def query_cmd_text(ip: str, cmdcode: int, session_id: str | None = None,
                param: str = "") -> str | None:
    """Query and return decoded payload text."""
    resp = query_cmd(ip, cmdcode, session_id, param)
    if not resp or len(resp) <= 16:
        return None
    hdr = _parse_header(resp)
    if not hdr or len(hdr["payload"]) == 0:
        return None
    return hdr["payload"].decode("utf-8", errors="replace")


def get_miner_info(ip: str, session_id: str | None = None) -> dict | None:
    """Query MinerInfo (cmdcode 0x16) and return parsed dict."""
    text = query_cmd_text(ip, 0x16, session_id)
    if not text:
        return None
    return _parse_miner_info(text)


def get_summary(ip: str, session_id: str | None = None) -> str | None:
    """Query summary (cmdcode 0x11)."""
    return query_cmd_text(ip, 0x11, session_id)


def get_compact_info(ip: str, session_id: str | None = None) -> str | None:
    """Query compact info (cmdcode 0x13)."""
    return query_cmd_text(ip, 0x13, session_id)


def send_remote_control(ip: str, param: str,
                        session_id: str | None = None) -> bool:
    """Send remote control command (cmdcode 0x0D, param N=V)."""
    resp = query_cmd(ip, 0x0D, session_id, param)
    hdr = _parse_header(resp) if resp else None
    return hdr is not None and hdr["cmdcode"] == 0x0D


def resume_work(ip: str, sid: str | None = None) -> bool:
    return send_remote_control(ip, "8=1", sid)


def stop_work(ip: str, sid: str | None = None) -> bool:
    return send_remote_control(ip, "8=0", sid)


def disable_api(ip: str, sid: str | None = None) -> bool:
    return send_remote_control(ip, "6=0", sid)


def enable_api(ip: str, sid: str | None = None) -> bool:
    return send_remote_control(ip, "6=1", sid)


def set_pools(ip: str, pools: list[dict], session_id: str | None = None) -> bool:
    """Set pool configuration (cmdcode 0x02).

    Each pool dict: {"url": str, "worker": str, "strategy": "FAILOVER", "password": str}
    Up to 3 pools (index 0-2).
    """
    parts = []
    for i, pool in enumerate(pools):
        url = pool.get("url", "")
        worker = pool.get("worker", "")
        strategy = pool.get("strategy", "FAILOVER")
        password = pool.get("password", "")
        parts.append(f"{i},{url},{worker},{strategy},,{password}")
    # Pad to 3 pools
    for i in range(len(pools), 3):
        parts.append(f"{i},,,FAILOVER,,")
    param = "|".join(parts) + "|"

    resp = query_cmd(ip, 0x02, session_id, param)
    hdr = _parse_header(resp) if resp else None
    return hdr is not None and hdr["cmdcode"] == 0x02


def set_coin_type(ip: str, coin: str = "BTC/BCH/BSV",
                  session_id: str | None = None) -> bool:
    """Set coin type (cmdcode 0x06)."""
    resp = query_cmd(ip, 0x06, session_id, coin)
    hdr = _parse_header(resp) if resp else None
    return hdr is not None and hdr["cmdcode"] == 0x06


def query_4028(ip: str, command: str) -> dict | None:
    """Query via port 4028 JSON API."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((ip, 4028))
        sock.send(json.dumps({"command": command}).encode())
        data = _recv_all(sock, timeout=3.0)
        sock.close()
        return json.loads(data.decode())
    except Exception:
        sock.close()
        return None


# ── Parsers ─────────────────────────────────────────────────────────

def _parse_miner_info(text: str) -> dict:
    """Parse MinerInfo response into structured dict."""
    result = {"_raw": {}, "_summary": {}, "_power": {}, "_slots": []}

    for line in text.strip().split("\n"):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            result["_raw"][key.strip()] = val.strip()

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


# ── CLI commands ─────────────────────────────────────────────────────

@app.command()
def info(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Show full miner information."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    data = get_miner_info(ip, sid)
    if not data:
        console.print("[red]MinerInfo query failed[/red]")
        raise typer.Exit(1)

    raw = data["_raw"]
    summary = data["_summary"]
    power = data["_power"]

    table = Table(title=f"WhatsMiner @ {ip}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Miner Type", f"{raw.get('MinerType', '')}_{raw.get('HashBoardVersion', '')}")
    table.add_row("Firmware", raw.get("FirmwareVersion", ""))
    table.add_row("Control Board", f"{raw.get('ControlBoardType', '')}-{raw.get('ControlBoardVersion', '')}")
    table.add_row("Miner SN", raw.get("MinerSn", ""))
    table.add_row("Power Type", raw.get("PowerType", ""))
    table.add_row("Power SN", raw.get("PowerSerialNo", ""))
    table.add_row("Coin Type", raw.get("CoinType", ""))
    table.add_row("Detected HashRate", raw.get("DetectedHashRate", ""))
    table.add_row("Board Num", raw.get("BoardNum", ""))
    table.add_row("Power Mode", summary.get("Power Mode", ""))
    table.add_row("Elapsed", summary.get("Elapsed", ""))
    table.add_row("Uptime", power.get("Uptime", ""))
    table.add_row("Env Temp", power.get("EnvTemp", ""))
    table.add_row("Power", summary.get("Power", ""))
    table.add_row("Error Count", summary.get("Error Code Count", ""))

    console.print(table)


@app.command()
def compact(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Show compact miner info (cmdcode 0x13)."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    text = get_compact_info(ip, sid)
    if not text:
        console.print("[red]Query failed[/red]")
        raise typer.Exit(1)

    # Parse the compact format: model-info#MAC#perms#SUMMARY,...|EDEVS,...|#Power,...
    parts = text.split("#")
    table = Table(title=f"Compact Info @ {ip}", show_lines=True)
    table.add_column("Section", style="cyan")
    table.add_column("Value")

    # Split model string: WhatsMiner-Type-Board-BoardVer-HashBoard-Power-Firmware-HashRate-Coin-SN
    if parts:
        model_parts = parts[0].strip().split("-")
        labels = ["Brand", "Miner Type", "Control Board", "Board Version",
                   "Hash Board", "Power Type", "Firmware", "Detected HashRate",
                   "Coin Type"]
        for i, label in enumerate(labels):
            if i < len(model_parts) and model_parts[i]:
                table.add_row(label, model_parts[i])
        # SN is after "MinerSn = " in the last part
        if len(model_parts) > len(labels):
            sn = "-".join(model_parts[len(labels):])
            if "MinerSn" in sn:
                sn = sn.split("=")[-1].strip()
            table.add_row("Miner SN", sn)
    if len(parts) > 1:
        table.add_row("MAC", parts[1].strip())

    # Parse SUMMARY section
    for part in parts:
        if "SUMMARY" in part:
            for item in part.split(","):
                if "=" in item:
                    k, _, v = item.partition("=")
                    table.add_row(k.strip(), v.strip())

    # Parse Power section
    for part in parts:
        if "Uptime=" in part:
            for item in part.replace("#", "").split(","):
                if "=" in item:
                    k, _, v = item.partition("=")
                    table.add_row(f"Power.{k.strip()}", v.strip())

    console.print(table)


@app.command()
def hashrate(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Show hashrate information."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    data = get_miner_info(ip, sid)
    if not data:
        console.print("[red]Query failed[/red]")
        raise typer.Exit(1)

    raw = data["_raw"]
    summary = data["_summary"]
    power = data["_power"]

    table = Table(title=f"Hashrate @ {ip}", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")

    table.add_row("Detected HashRate", raw.get("DetectedHashRate", ""))
    table.add_row("HS RT", summary.get("HS RT", ""))
    table.add_row("MHS Avg", summary.get("MHS av", ""))
    table.add_row("MHS 15m", summary.get("MHS 15m", ""))
    table.add_row("Freq Avg", summary.get("freq_avg", ""))
    table.add_row("Hash Stable", summary.get("Hash Stable", ""))
    table.add_row("Factory GHS", summary.get("Factory GHS", ""))
    table.add_row("Power", summary.get("Power", ""))
    table.add_row("Power Rate", summary.get("Power Rate", ""))
    table.add_row("Reject Rate", summary.get("Pool Rejected%", ""))

    # Per-board temps
    temps = "_".join(power.get(f"BoardTemp{i}", "") for i in range(4))
    table.add_row("Board Temps", temps)
    table.add_row("Env Temp", power.get("EnvTemp", ""))

    console.print(table)


@app.command()
def pools(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Show pool configuration."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    data = get_miner_info(ip, sid)
    if not data:
        console.print("[red]Query failed[/red]")
        raise typer.Exit(1)

    raw = data["_raw"]
    table = Table(title=f"Pools @ {ip}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Pool Strategy", raw.get("PoolStrategy", ""))
    table.add_row("Coin Type", raw.get("CoinType", ""))
    table.add_row("Web Pool", raw.get("web_pool", ""))
    table.add_row("API Switch", raw.get("MinerApiSwitch", ""))
    console.print(table)
    console.print("[dim]Note: Pool URLs require a separate query (not yet implemented)[/dim]")


@app.command()
def resume(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Resume mining."""
    console.print(f"[bold]Resuming {ip}...[/bold]")
    if resume_work(ip):
        console.print("[green]Resume Work sent successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command()
def stop(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Stop mining."""
    console.print(f"[bold]Stopping {ip}...[/bold]")
    if stop_work(ip):
        console.print("[green]Stop Work sent successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("disable-api")
def disable_api_cmd(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Disable API on port 4028."""
    console.print(f"[bold]Disabling API on {ip}...[/bold]")
    if disable_api(ip):
        console.print("[green]API disabled successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("enable-api")
def enable_api_cmd(ip: str = typer.Argument("10.50.3.95", help="Miner IP address")):
    """Enable API on port 4028."""
    console.print(f"[bold]Enabling API on {ip}...[/bold]")
    if enable_api(ip):
        console.print("[green]API enabled successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("set-pools")
def set_pools_cmd(
    ip: str = typer.Argument("10.50.3.95", help="Miner IP address"),
    pool1: str = typer.Option("", "--pool1", help="Pool 1 URL (e.g. stratum+tcp://host:port)"),
    worker1: str = typer.Option("", "--worker1", help="Pool 1 worker"),
    password1: str = typer.Option("", "--password1", help="Pool 1 password"),
    pool2: str = typer.Option("", "--pool2", help="Pool 2 URL"),
    worker2: str = typer.Option("", "--worker2", help="Pool 2 worker"),
    password2: str = typer.Option("", "--password2", help="Pool 2 password"),
):
    """Configure mining pools."""
    pools = []
    if pool1:
        pools.append({"url": pool1, "worker": worker1, "password": password1})
    if pool2:
        pools.append({"url": pool2, "worker": worker2, "password": password2})
    if not pools:
        console.print("[red]At least one pool required (--pool1)[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Setting pools on {ip}...[/bold]")
    for i, p in enumerate(pools):
        console.print(f"  Pool {i}: {p['url']} / {p['worker']}")
    if set_pools(ip, pools):
        console.print("[green]Pools configured successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("set-coin")
def set_coin_cmd(
    ip: str = typer.Argument("10.50.3.95", help="Miner IP address"),
    coin: str = typer.Option("BTC/BCH/BSV", help="Coin type"),
):
    """Set coin type."""
    console.print(f"[bold]Setting coin to {coin} on {ip}...[/bold]")
    if set_coin_type(ip, coin):
        console.print("[green]Coin type set successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command()
def raw(ip: str = typer.Argument("10.50.3.95", help="Miner IP address"),
        cmdcode: int = typer.Option(0x16, "--cmd", "-c", help="Command code (hex)"),
        param: str = typer.Option("", "--param", "-p", help="Parameter (N=V format)")):
    """Send raw command and show response."""
    console.print(f"[bold]Sending cmd=0x{cmdcode:02X} to {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    text = query_cmd_text(ip, cmdcode, sid, param)
    if text:
        console.print(text)
    else:
        resp = query_cmd(ip, cmdcode, sid, param)
        if resp:
            console.print(f"Response: {len(resp)} bytes (no text payload)")
            if len(resp) >= 16:
                console.print(f"Header: {resp[:16].hex()}")
        else:
            console.print("[red]No response[/red]")


if __name__ == "__main__":
    app()
