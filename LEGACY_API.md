# WhatsMiner legacy `api` daemon — command reference (API v1.3)

Reverse-engineered from `api` (ELF aarch64, musl, stripped — copied from an older
miner firmware). This is the miner-side daemon the tool talks to on **old firmware**:
it listens on TCP **4028**, authenticates, and either answers directly or forwards
to btminer's internal API at `127.0.0.1:4029`.

New firmware (e.g. 20250321.14.Rel on the M53S+) replaced this JSON surface with the
binary 5A5A7F7F/AES protocol on port 8889 (see PROTOCOL.md), but both expose the same
control surface — e.g. this daemon's `enable_web_pools`/`disable_web_pools` toggle the
`web_pool` flag that still shows up in the compact-info perms section.

## Wire format

Plain (no encryption) JSON line:

```json
{"command":"summary"}
{"command":"set_led","param":"auto","token":"<md5crypt-body>"}
```

Responses use the cgminer-style envelope:

```json
{"STATUS":"S","When":<unixtime>,"Code":<n>,"Msg":"<text>","Description":"<text>"}
```

Observed codes: 131 = command OK, 14 = invalid cmd, 45 = command join err,
69 = ?, 135 = check token err, plus "can't access write cmd" (write without auth).

### Encrypted wrapper (`enc|`)

Request or reply body may be `enc|<base64>` = base64 of AES-256-ECB(JSON), key from
libwhatsminer (`aes_init(0x20)` + `aes_key_expansion`). **Key derivation is
per-miner**: SHA-256 over the admin line of `/etc/shadow` (salt + md5crypt hash
body) — see `crypto_init` at 0x4056c8. `uci get miner_setting.admin_api_switch`
bypasses this (default key path). The 22-char string `RxmaDUO33TS7O26yeMHZ81` in the
binary is the md5crypt hash body of the factory admin password.

### Token auth (write commands only)

1. Client sends `get_token` (read, no auth).
2. Server: generates 8-char random salt, computes `crypt(admin_pw, "$1$<newsalt>")`,
   stores the 22-char hash body in a session table (32 slots, 30-min validity),
   replies `{"time":"<4-digit>","salt":"<old salt>","newsalt":"<new salt>"}`.
3. Client computes the same md5crypt body locally (knows admin password) and adds
   `"token":"<body>"` to every write request.
4. Server validates token + expiry (`check_token` at 0x403838), sets the global
   write-access flag for the connection.

A legacy text mode also exists: `command+param` joined with `+` — read commands only.

## Command table

Dispatch: array of 39 structs at `0x4194d8`, `{char *name; void (*handler)(); u8 needs_write; u8 flag2}`.
`needs_write` (offset +0x10) = 1 → requires valid token. Handlers verified in disasm.

### Read commands (no token)

| Command | Handler @ | What it does |
|---|---|---|
| `get_token` | 0x403980 | Auth handshake — see above |
| `get_version` | 0x4028e0 | `{"api_ver":"whatsminer v1.3","fw_ver":<from /etc/microbt_release>}` |
| `get_psu` | 0x404300 | Reads `/sys/bitmicro/power/{name,hw_version,model,sw_version}` |
| `summary` | 0x4029b8 | Forwarded to btminer |
| `pools` | 0x4029c8 | Forwarded to btminer |
| `edevs` | 0x4029d8 | Forwarded to btminer |
| `devs` | 0x4029d8 | Forwarded to btminer as `edevs` |
| `devdetails` | 0x4029e8 | Forwarded to btminer |
| `status` | 0x405608 | `pidof btminer` → `{"btmineroff":"false","Firmware Version":"..."}` |

### Write commands (token required)

| Command | Handler @ | Action |
|---|---|---|
| `reboot` | 0x4029f8 | `reboot_system("by whatsminer API")` |
| `restart_btminer` | 0x402cb0 | `/etc/init.d/btminer restart` |
| `factory_reset` | 0x402d10 | `/usr/bin/restore-factory-settings 'by whatsminer API'` |
| `power_off` | 0x402d70 | `/usr/bin/poweroff.sh 'by whatsminer API'` |
| `power_on` | 0x402e50 | `/etc/init.d/btminer start &` |
| `set_low_power` | 0x402eb0 | `/usr/bin/set-power-mode 0 &` |
| `set_normal_power` | 0x402f10 | `/usr/bin/set-power-mode 1 &` |
| `set_high_power` | 0x402f70 | `/usr/bin/set-power-mode 2 &` |
| `update_firmware` | 0x402fd0 | Receives package → `/tmp/upgrade-package-api.bin`, "update_firmware by " |
| `update_pwd` | 0x403188 | `chpwd <user> <pw>`, checks /tmp/pwdsuccess |
| `net_config` | 0x403418 | Params: proto(dhcp/static), ipaddr, netmask, gateway, hostname → uci `/etc/config/network` |
| `set_led` | 0x402a58 | `param="auto"` or sscanf `%[^,],%d,%d,%d` → `set-led <color> <period> <duration> <start>` |
| `update_pools` | 0x403be8 | JSON pool1-3/worker1-3/passwd1-3/share1-3 → uci `pools.default.*`, `btminer-api remove_pool/add_pool/switch_pool` |
| `time_randomized` | 0x404640 | start_net_max_delay_seconds, stop_mining_max_delay_seconds |
| `set_fan_manual` | 0x404788 | Manual fan mode |
| `set_fan_speed` | 0x404830 | Param: percent |
| `load_log` | 0x4048a0 | Remote logging: log_ip, system, log_port, log_proto → uci `/etc/config/system` |
| `set_zone` | 0x404ae0 | timezone, zonename |
| `set_hostname` | 0x404c68 | hostname → uci system |
| `enable_web_pools` | 0x404550 | Sets web_pool flag (=1 in compact perms) |
| `disable_web_pools` | 0x4045c8 | Clears web_pool flag |
| `enable_btminer_fast_boot` | 0x404d80 | `/usr/bin/set-miner-fast-boot.sh 1 &` |
| `disable_btminer_fast_boot` | 0x404df0 | `/usr/bin/set-miner-fast-boot.sh 0 &` |
| `set_target_freq` | 0x404eb8 | freq_percent (liquid cooling only) → `/usr/bin/adjust-hash.sh %d &` |
| `download_logs` | 0x405038 | `/usr/bin/pack-miner-logs` → /tmp/logs.tgz → `{"logfilelen":"%d"}` |
| `disable_btminer_init` | 0x4051d0 | `rm /etc/rc.d/S99btminer` (no autostart) |
| `enable_btminer_init` | 0x4052b0 | `ln -s /etc/init.d/btminer /etc/rc.d/S99btminer` |
| `set_power_pct` | 0x405390 | Param: percent → `btminer-api 'set_power_pct|%d' &`, adjust-temp state machine (`{"complete":"false","msg":"wait for adjust temp"}`) |
| `pre_power_on` | 0x405468 | Polls adjust-temp completion: "adjust complete" / "adjust continue" |

## Notable

- Every handler shells out with `system()` — `param` strings become shell args;
  the daemon runs as root.
- `update_pools` is the old-firmware equivalent of cmdcode 0x02 — same uci
  `pools.default.poolN{url,user,pw}` backing store.
- `get_version` reporting "whatsminer v1.3" is how the tool tells old miners from
  new ones (the 8889 cmdcode 0x07 precondition `version >= 4` in the new tool).
- Token table: 32 entries × 48 bytes at 0x41a970, expiry 1800 s.
