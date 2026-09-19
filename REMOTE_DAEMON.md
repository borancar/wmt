# `remote-daemon` — the port 8889 responder (firmware 20210109.23.REL)

From the decrypted rootfs of the old miner (`rootfs/usr/bin/remote-daemon`,
md5 `acff4dad7124b09faad988ad593d4106`, listed in `/etc/microbt_release`).
Startup banner: `remote-daemon version 2020-11-18 started (API version: 13)`.
**This — not `api` — is the process that answers WhatsMinerTool on port 8889,
even on this 2021 firmware.** Correction to the earlier LEGACY_API.md note:
8889 has existed alongside the 4028 JSON API since at least 2020-11-18.

## Listener (main @ 0x402650)

```
daemon(); enable_coredump(); openlog("remote-daemon")
syslog("remote-daemon version 2020-11-18 started (API version: 13)")
fcn.00403a88()                  ; config init (uci)
make_crc_table()                ; runtime CRC table, same as the tool
ctx = aes_init(0x20)            ; AES-256
aes_key_expansion(key = .rodata 0x419960, ctx)   ; ONE key
s = socket(AF_INET, SOCK_STREAM, 0)
bind(0.0.0.0:htons(0x22B9=8889)); listen(s, 0x64)
→ pthread per accepted connection (handler fcn.004059c0)
```

**AES key @ 0x419960 = `f0d379ee4188bc6216cfa09adcd49100ee7f971217aaba26bc86c0b6ae1da90f`**
— byte-identical to the Windows tool's Key1 (0x7254c0). The old daemon uses a
single key for all cmdcodes; the Key2/Key3 split seen in the tool came later.

## Connection handler (fcn.004059c0) — protocol verified

1. `recv(fd, buf, 0x10, 0)` — one AES block (the frame header).
2. `aes_inv_cipher(buf, plain, ctx)` — AES-256-ECB decrypt.
3. `cmp u32[0], 0x7F7F5A5A` — magic check (`mov w0,0x5a5a; movk 0x7f7f<<16`).
4. `cmdcode = u32[1]`; must be **≤ 0x16**, else 16-byte error reply
   (magic+cmd preserved, halfwords set to (2,0)).
5. Frame length = len1+len2+0x10, rounded up to 16 (`and w22, 0xfffffff0`).
6. recv rest; `crc32(0xFFFFFFFF, payload, len1+len2)` compared against u32[3].
7. Payload is `|`-delimited (`strtok`): fields[0]=IP, [1]=account, [2]=password, …
8. **Auth: `strcmp(fields[0], eth0_IP)`** (ioctl SIOCGIFADDR) — the payload IP
   must be the miner's own. Account/password checked against
   `/etc/config/permissions` (`<user>_pwd` / `<user>_perm` uci options,
   e.g. super=255). **No session_id — every message carries credentials.**
9. Two permission masks on cmdcode:
   - `0x00780093` → bits {0,1,4,7,19,20,21,22} = {0x00,0x01,0x04,0x07,0x13,0x14,0x15,0x16}
   - `0x007FFFFF` → all 0x00–0x16 (checked against `<user>_perm`, needs 2 or 0xFF)

## Cmdcode → handler table @ 0x407310 (23 entries, 16 bytes each)

| cmd | handler | function (evidence) |
|---|---|---|
| 0x00 | 0x403d88 | **Remote control / config**: net config writer (`/tmp/network.config` → /etc/config/network), `reboot`, `/usr/bin/pre-reboot 'by whatsminer tool'`, `poweroff.sh`, `factory-mode-commands`, `detect-power-info`, `pack-miner-logs` → /tmp/logs.tgz |
| 0x01 | 0x406318 | **Set pools** — `pool1::worker1::ipadd1::pwd1::endpool1`-style `::` delimited params, `uci set pools.default.poolN…` |
| 0x02 | 0x4067c0 | **Set pools (uci form)** — `uci delete/set pools.default.pool%d{url,user,pw}`, pool_strategy, quota_share; logs `%d: id=%s pool=%s worker=%s pwd=%s policy=%s quota=%s` |
| 0x03 | 0x4040c8 | net config params (`::gateway ::broadcastaddr ::dns ::enddns`) |
| 0x04 | 0x4051b0 | password/admin (`/etc/shadow`, `/etc/config/permissions`, miner_setting) |
| 0x05 | 0x405018 | `set_power_mode: %d` → `/usr/bin/set-power-mode %d &` |
| 0x06 | 0x404058 | **set coin type** → `/usr/bin/set-coin-type %s &` |
| 0x07 | 0x404f60 | **firmware upgrade** — `recv_remote_file` → `/tmp/upgrade-package.bin`, "To upgrade miner by %s" (matches new-firmware finding: 0x07 is firmware) |
| 0x08 | 0x4044c8 | reboot + logs pack |
| 0x09–0x0B | 0x404e50/0x404e18/0x404de0 | small; share the admin-shadow/`%02X` helper region |
| 0x0C | 0x404860 | pool strategy switch (`pools_switch`, `/etc/config/miner_setting`) |
| 0x0D | 0x4048d0 | whatsminer api switch region |
| 0x0E | 0x4046c0 | permissions query (`_perm`, "default") |
| 0x0F | 0x404da8 | small (helper region) |
| 0x10–0x12 | 0x404a18/0x404a50/0x404970 | small; near upgrade/power helpers |
| 0x13 | 0x406148 | **summary/compact query** (uses `btminer-api -o summary/pools/edevs`, SUMMARY/POOLS/EDEVS/Uptime/PowerRT builders — same text format the new 0x13 returns) |
| 0x14 | 0x404518 | **download logs** → /tmp/logs.tgz |
| 0x15 | 0x405808 | **upgrade status** (`/tmp/fw-upgrade-status[-valid]`, `upgrade=success`) |
| 0x16 | 0x406138 | **MinerInfo query** (same builder region as 0x13) |

## Old (2021) vs new (2025) protocol diff

| aspect | 2021 remote-daemon | 2025 M53S+ |
|---|---|---|
| magic / crc / framing | identical | identical |
| AES keys | one key (Key1) for all | Key1 auth, Key2 queries, Key3 ? |
| auth | per-message IP+user+pwd, no state | cmdcode 0x00 → session_id (4 bytes), expires ~5 min |
| cmdcodes | 0x00–0x16 ALL implemented | only subset live (0x00,0x01,0x02,0x06,0x0D,0x0F,0x13,0x16,0x1A); 0x07 firmware-gated |
| 0x00 meaning | remote control | auth handshake |
| pool payload | `::`-delimited (`pool1::worker1::…`) | comma/pipe `0,url,worker,strategy,,pwd\|1,…` |

On the old firmware, `api` (4028 JSON) and `remote-daemon` (8889 binary) run side
by side; the tool's "API disable" op only affects the 4028 side, same as now.

## Factory mode & SSH gating (from /etc/profile, confirmed in binary)

`/etc/profile` gates interactive shells at login:

```sh
if [ ! -f /tmp/dropbear_on ]; then exit; fi                  # SSH master switch
if [ ! -f /tmp/factory_mode ] && [ "$USER" = "admin" ]; then exit; fi
```

So: SSH (dropbear) runs only when `/tmp/dropbear_on` exists, and the **admin**
user specifically gets no shell unless `/tmp/factory_mode` also exists — factory
mode is exactly the "allow admin SSH sessions" switch. Other users (root) are
not blocked by the second check.

Attribution in `remote-daemon` (the 4028 `api` daemon has none of these strings):

- `/tmp/dropbear_on` + `/etc/init.d/dropbear start &` / `stop &` + log
  `turn ssh %s by %s` → SSH on/off, reachable via 8889 (cmdcode 0x04 family).
  The `sshd=%d` status reported in the compact perms string (`web_pool=1,sshd=0`)
  is `file_exist("/tmp/dropbear_on")` at 0x405658 — same field the new
  firmware still reports.
- `/tmp/factory_mode` → cmdcode **0x0D** handler (0x4048d0): `is_factory_mode()`
  → `set_factory_mode()` → "setting factory mode" / "Restart btminer as %s", and
  cmdcode 0x00 runs `/usr/bin/factory-mode-commands &` (just `write-hash-rate`,
  records hash rate into EEPROM for factory test).
- cmdcode **0x04** handler (0x4051b0): admin/permissions management — reads
  `/etc/shadow` + `/etc/config/permissions`, restores default admin password
  ("Password of user 'admin' was restored to default value, disable miner api
  switch and restart api service").

Lead for the new firmware: factory mode there is likely one of the unknown
cmdcode 0x0D remote-control ops (the tool's Work Control dialog has
"Allow Miner to Work" / "Disable Auto-Start Work" = op codes 7/9 still
uncaptured).

## New-firmware evolution of this surface (2025 M53S+ / 20250321.14.Rel)

The 8889 responder role survives on current firmware (different binary, not
available for RE), but the control surface was consolidated and gained a
status-code system. Mapped live against 10.50.3.254 — full detail and the
investigative trail in PROTOCOL.md ("CMD 0x0D" and "How this was found"):

- 16-byte acks carry a result code: 0=executed, 3=unknown op, 4=invalid
  value, 9=precondition failed. The old daemon's acks carried no such codes.
- The 0x00–0x16 handler table shrank to a numeric N=V op space: 6=API
  switch (enable gated on a password-change ritual, ack 9 until then —
  the ritual is cmdcode 0x04 part2 `5,5,5,adminadminadmin`), 8=work control,
  **10=SSH/dropbear toggle**, plus unknowns 7/12/13/19. Several ops execute
  arbitrary values and one wiped pool config during the sweep — see the
  warnings in PROTOCOL.md.
- Old-firmware functions not present in the new op table: net config
  (0x03), perms/SSH admin (0x04 repurposed as the password ritual), power
  mode (0x05), reboot (0x08), pool strategy (0x0C), perm query (0x0E),
  logs (0x14), upgrade status (0x15). Power-mode/reboot style actions are
  presumably reachable through the multi-value ops (13/19?) or removed.
- `web_pool` / `sshd` flags still reported in the compact perms section
  (`web_pool=1,sshd=0`) — same fields the old daemon generated
  (`file_exist("/tmp/dropbear_on")` at 0x405658); the new `10=1` op sets the
  same dropbear state.
