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

# Cmdcodes that modify miner state — never send these with empty/guessed params
WRITE_CMDCODES = {0x02, 0x06, 0x0D}

# Known safe read-only cmdcodes
READ_CMDCODES = {0x11, 0x13, 0x16}

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
    # Pad to next 16-byte boundary (minimum 80 bytes)
    min_len = max(80, len(frame))
    pad_len = (16 - min_len % 16) % 16
    frame += b"\x00" * (min_len - len(frame) + pad_len)

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
    """Auth handshake → returns hex session_id.

    NOTE: Each auth invalidates the previous session_id.
    Avoid calling this repeatedly — rapid re-auths may reset miner state.
    """
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


def get_hashrate(ip: str, session_id: str | None = None) -> str | None:
    """Query detected hashrate (cmdcode 0x0F). Returns colon-separated values."""
    return query_cmd_text(ip, 0x0F, session_id)


def get_power_realtime(ip: str, session_id: str | None = None) -> str | None:
    """Query power realtime info (cmdcode 0x1A)."""
    return query_cmd_text(ip, 0x1A, session_id)


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
def info(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
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

    # All raw MinerInfo fields
    for k, v in raw.items():
        table.add_row(k, v)

    # SUMMARY fields
    if summary:
        table.add_row("─" * 20, "─" * 40)
        for k, v in summary.items():
            table.add_row(f"SUMMARY.{k}", v)

    # Power fields
    if power:
        table.add_row("─" * 20, "─" * 40)
        for k, v in power.items():
            table.add_row(f"Power.{k}", v)

    console.print(table)


@app.command()
def compact(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
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

    # Structure: model#MAC##perms#users#SUMMARY|EDEVS|POOLS|#Power
    parts = text.split("#")

    # ── Model info ──
    table = Table(title=f"Compact Info @ {ip}", show_lines=True)
    table.add_column("Section", style="cyan")
    table.add_column("Value")

    if parts:
        mp = parts[0].strip().split("-")
        labels = ["Brand", "Miner Type", "Control Board", "Board Version",
                   "Hash Board", "Power Type", "Firmware", "Detected HashRate",
                   "Coin Type"]
        for i, label in enumerate(labels):
            if i < len(mp) and mp[i]:
                table.add_row(label, mp[i])
        if len(mp) > len(labels):
            sn = "-".join(mp[len(labels):])
            if "MinerSn" in sn:
                sn = sn.split("=")[-1].strip()
            table.add_row("Miner SN", sn)
    if len(parts) > 1:
        table.add_row("MAC", parts[1].strip())

    # ── Main data (pipe-separated: SUMMARY|EDEVS|POOLS|Power) ──
    main_data = parts[5] if len(parts) > 5 else ""
    sections = main_data.split("|")

    # SUMMARY
    if sections:
        for item in sections[0].split(","):
            if "=" in item:
                k, _, v = item.partition("=")
                k = k.strip()
                if k and k != "SUMMARY":
                    table.add_row(k, v.strip())

    # EDEVS (per-board)
    for s in sections:
        if s.startswith("ASC="):
            fields = dict(item.split("=", 1) for item in s.split(",") if "=" in item)
            slot = fields.get("Slot", "?")
            mhs = fields.get("MHS av", "0")
            freq = fields.get("Chip Frequency", "?")
            chips = fields.get("Effective Chips", "?")
            table.add_row(f"Board {slot}", f"{mhs} H/s, {freq} MHz, {chips} chips")

    # POOLS
    for s in sections:
        if s.startswith("POOL="):
            fields = dict(item.split("=", 1) for item in s.split(",") if "=" in item)
            pool_id = fields.get("POOL", "?")
            url = fields.get("URL", "")
            user = fields.get("User", "")
            active = fields.get("Stratum Active", "")
            table.add_row(f"Pool {pool_id}", f"{url} / {user} (active={active})")

    # Power section (last # part)
    power_data = parts[-1] if len(parts) > 5 else ""
    for item in power_data.split(","):
        if "=" in item:
            k, _, v = item.partition("=")
            k = k.strip()
            if k and k != "Uptime":
                table.add_row(f"Power.{k}", v.strip())

    console.print(table)


def _get_summary_dict(ip: str, sid: str | None = None) -> dict | None:
    """Extract SUMMARY section from compact info."""
    text = get_compact_info(ip, sid)
    if not text:
        return None
    parts = text.split("#")
    main_data = parts[5] if len(parts) > 5 else ""
    sections = main_data.split("|")
    summary = {}
    if sections:
        for item in sections[0].split(","):
            if "=" in item:
                k, _, v = item.partition("=")
                k = k.strip()
                if k and k != "SUMMARY":
                    summary[k] = v.strip()
    return summary


@app.command()
def summary(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Show mining summary (hashrate, power, temps)."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    data = _get_summary_dict(ip, sid)
    if not data:
        console.print("[red]Query failed[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Summary @ {ip}", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")

    # Hashrate
    table.add_row("HS RT", data.get("HS RT", "?"))
    table.add_row("MHS av", data.get("MHS av", "?"))
    table.add_row("MHS 15m", data.get("MHS 15m", "?"))
    table.add_row("Freq Avg", f"{data.get('freq_avg', '?')} MHz")
    table.add_row("Hash Stable", data.get("Hash Stable", "?"))

    # Power
    table.add_row("Power", f"{data.get('Power', '?')} W")
    table.add_row("Power Rate", f"{data.get('Power Rate', '?')} J/TH")
    table.add_row("Power Limit", f"{data.get('Power Limit', '?')} W")
    table.add_row("Power Mode", data.get("Power Mode", "?"))

    # Temps
    table.add_row("Chip Temp Min", f"{data.get('Chip Temp Min', '?')} C")
    table.add_row("Chip Temp Max", f"{data.get('Chip Temp Max', '?')} C")
    table.add_row("Chip Temp Avg", f"{data.get('Chip Temp Avg', '?')} C")

    # Pool
    table.add_row("Pool Rejected%", data.get("Pool Rejected%", "?"))

    # Uptime
    uptime = int(data.get("Uptime", 0))
    elapsed = int(data.get("Elapsed", 0))
    table.add_row("Uptime", f"{uptime // 3600}h {(uptime % 3600) // 60}m")
    table.add_row("Elapsed", f"{elapsed // 3600}h {(elapsed % 3600) // 60}m")

    # Errors
    table.add_row("Error Count", data.get("Error Code Count", "0"))

    console.print(table)


@app.command()
def hashrate(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
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
def power(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Show power supply realtime info (cmdcode 0x1A)."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    text = get_power_realtime(ip, sid)
    if not text:
        console.print("[red]Query failed[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Power @ {ip}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    for line in text.strip().split("\n"):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            continue
        if line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            table.add_row(k.strip(), v.strip())

    console.print(table)


@app.command()
def pools(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Show pool configuration."""
    console.print(f"[bold]Querying {ip}...[/bold]")
    sid = get_session_id(ip)
    if not sid:
        console.print("[red]Auth failed[/red]")
        raise typer.Exit(1)

    data = get_miner_info(ip, sid)
    compact = get_compact_info(ip, sid)
    if not data or not compact:
        console.print("[red]Query failed[/red]")
        raise typer.Exit(1)

    raw = data["_raw"]
    web_pool = raw.get("web_pool", "")
    if not web_pool:
        # MinerInfo embeds the compact string; the flag shows up as "#web_pool"
        web_pool = raw.get("#web_pool", "").split(",")[0]
    table = Table(title=f"Pools @ {ip}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Pool Strategy", raw.get("PoolStrategy", ""))
    table.add_row("Coin Type", raw.get("CoinType", ""))
    table.add_row("Web Pool", web_pool)
    table.add_row("API Switch", raw.get("MinerApiSwitch", ""))

    main = next((p for p in compact.split("#") if "POOL=" in p), "")
    for s in main.split("|"):
        if s.startswith("POOL="):
            fields = dict(item.split("=", 1) for item in s.split(",") if "=" in item)
            pool_id = fields.get("POOL", "?")
            url = fields.get("URL", "")
            user = fields.get("User", "")
            active = fields.get("Stratum Active", "")
            table.add_row(f"Pool {pool_id}", f"{url} / {user} (active={active})")

    console.print(table)


@app.command()
def resume(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Resume mining."""
    console.print(f"[bold]Resuming {ip}...[/bold]")
    if resume_work(ip):
        console.print("[green]Resume Work sent successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command()
def stop(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Stop mining."""
    console.print(f"[bold]Stopping {ip}...[/bold]")
    if stop_work(ip):
        console.print("[green]Stop Work sent successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("disable-api")
def disable_api_cmd(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Disable API on port 4028."""
    console.print(f"[bold]Disabling API on {ip}...[/bold]")
    if disable_api(ip):
        console.print("[green]API disabled successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("enable-api")
def enable_api_cmd(ip: str = typer.Argument("10.50.3.254", help="Miner IP address")):
    """Enable API on port 4028."""
    console.print(f"[bold]Enabling API on {ip}...[/bold]")
    if enable_api(ip):
        console.print("[green]API enabled successfully[/green]")
    else:
        console.print("[red]Failed[/red]")
        raise typer.Exit(1)


@app.command("set-pools")
def set_pools_cmd(
    ip: str = typer.Argument("10.50.3.254", help="Miner IP address"),
    pool1: str = typer.Option("", "--pool1", help="Pool 1 URL (e.g. stratum+tcp://host:port)"),
    worker1: str = typer.Option("", "--worker1", help="Pool 1 worker"),
    password1: str = typer.Option("", "--password1", help="Pool 1 password"),
    pool2: str = typer.Option("", "--pool2", help="Pool 2 URL"),
    worker2: str = typer.Option("", "--worker2", help="Pool 2 worker"),
    password2: str = typer.Option("", "--password2", help="Pool 2 password"),
    pool3: str = typer.Option("", "--pool3", help="Pool 3 URL"),
    worker3: str = typer.Option("", "--worker3", help="Pool 3 worker"),
    password3: str = typer.Option("", "--password3", help="Pool 3 password"),
):
    """Configure mining pools."""
    pools = []
    if pool1:
        pools.append({"url": pool1, "worker": worker1, "password": password1})
    if pool2:
        pools.append({"url": pool2, "worker": worker2, "password": password2})
    if pool3:
        pools.append({"url": pool3, "worker": worker3, "password": password3})
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
    ip: str = typer.Argument("10.50.3.254", help="Miner IP address"),
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
def raw(ip: str = typer.Argument("10.50.3.254", help="Miner IP address"),
        cmdcode: int = typer.Option(0x16, "--cmd", "-c", help="Command code (hex)"),
        param: str = typer.Option("", "--param", "-p", help="Parameter (N=V format)"),
        force: bool = typer.Option(False, "--force", "-f", help="Allow write cmdcodes")):
    """Send raw command and show response."""
    if cmdcode in WRITE_CMDCODES and not force:
        console.print(f"[red]cmdcode 0x{cmdcode:02X} is a WRITE command that modifies miner state.[/red]")
        console.print(f"[red]Use --force to confirm. Known write cmdcodes: {[f'0x{x:02X}' for x in WRITE_CMDCODES]}[/red]")
        raise typer.Exit(1)
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
