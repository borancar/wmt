# WhatsMiner 8889 Protocol - Response Structure Reference

All responses use the 5A5A7F7F frame header:
```
+0x00  magic    = 0x7F7F5A5A (4 bytes, LE)
+0x04  cmdcode  (4 bytes, LE)
+0x08  len1     (2 bytes, LE) - always 0 for data responses
+0x0a  len2     (2 bytes, LE) - payload length
+0x0c  checksum (4 bytes, LE)
+0x10  payload  (len2 bytes)
```

---

## CMD 0x0F: Detected HashRate

**Header**: cmdcode=0x0F, len1=0, len2=24

**Payload**: 24 bytes, colon-separated ASCII, one value per board

Example: `73774:73774:73358:73358`

| Field | Description |
|-------|-------------|
| Board0 | Board 0 hash rate (H/s) |
| Board1 | Board 1 hash rate (H/s) |
| Board2 | Board 2 hash rate (H/s) |
| Board3 | Board 3 hash rate (H/s) |

---

## CMD 0x16: MinerInfo

**Header**: cmdcode=0x16, len1=0, len2=~2300

**Payload**: ~2300 bytes, newline-delimited `key = value`

### [MinerInfo] section

| Field | Example | Description |
|-------|---------|-------------|
| MinerType | M53S+ | Miner model |
| ControlBoardType | H616 | Control board type |
| ControlBoardVersion | CB6V5 | Control board firmware version |
| HashBoardVersion | J40 | Hash board version |
| PowerType | P564B | Power supply model |
| FirmwareVersion | 20250321.14.Rel | Firmware version |
| DetectedHashRate | 73774:73774:73358:73358 | Per-board detected hash rate (H/s) |
| CoinType | BTC | Mining coin type |
| PoolStrategy | FAILOVER | Pool failover strategy |
| PowerMode | 1 | Power mode (1=Normal, 2=High) |
| HeatMode | | Heat mode (empty if not set) |
| HashPercent | | Hash percent limit |
| EepromLiquidCooling | 0-0-0 | Liquid cooling status per board |
| ChipData | H35A07-23081101 BINVE1-197306A | Chip data for board 0 |
| ChipDataAll | H35A07-23081101 BINVE1-197306A_... | Chip data for all boards (_ separated) |
| MinerApiSwitch | 0 | API port 4028 enabled (0/1) |
| BtminerFastBoot | 0 | Fast boot enabled (0/1) |
| BoardNum | 4 | Number of hash boards |
| HashBoardStruct | 6244 | Hash board structure code |
| PcbSn0 | MJM35PF8404116K10133 | PCB serial number board 0 |
| PcbSn1 | MJM35PF8404116K10133 | PCB serial number board 1 |
| PcbSn2 | MJM35PF8404116K10029 | PCB serial number board 2 |
| PcbSn3 | MJM35PF8404116K10029 | PCB serial number board 3 |
| is_btrom | 0 | Is BT ROM |
| MinerSn | MAM35P40JG24032629473366244H06416 | Miner serial number |

### Inline: MAC address
After [MinerInfo] section, separated by `#`:
```
#CC:58:16:00:04:90#
```

### [PowerInfo] section

| Field | Example | Description |
|-------|---------|-------------|
| PowerName | P564B | Power supply name |
| HwRevision | R00018 | Hardware revision |
| PowerRevision | 20221024_P00032.20230729_S00034_R00018 | Power firmware revision |
| PowerOnOff | off | Power state |
| MinerWasPoweroff | 0 | Was miner powered off |
| PowerVout | 0 | Power output voltage (mV) |
| PowerIout | 0 | Power output current (mA) |
| PowerFanSpeed | 0 | Power supply fan speed |
| PowerVender | 1 | Power vendor ID |
| PowerModel | P564B | Power model |
| PowerSerialNo | 1413C2335302222 | Power serial number |

### Inline: Permissions
```
#web_pool=1,sshd=0#super=255 user1=0 user2=0 user3=0
```

### Inline: SUMMARY + EDEVS + POOLS + Power (last field, `#` and `|` delimited)

**SUMMARY** (comma-separated key=value):

| Field | Example | Description |
|-------|---------|-------------|
| Error Code 0 | 20 | Latest error code |
| Error Time | 2026-09-19 06:23:23 | Latest error time |
| Error Code 1 | 2000 | Second error code |
| Error Code Count | 2 | Total error count |
| Factory Error Code 0 | 2110 | Factory error code |
| Factory Error Code Count | 2 | Factory error count |
| Elapsed | 169 | Mining elapsed (seconds) |
| Uptime | 3846 | Miner uptime (seconds) |
| MHS av | 0 | Average hash rate (MHS) |
| MHS 15m | 0 | 15-minute average hash rate (MHS) |
| HS RT | 0 | Real-time hash rate (HS) |
| Pool Rejected% | 0.000 | Pool rejection rate |
| freq_avg | 0 | Average frequency |
| Power | 95 | Power consumption (W) |
| Power Rate | 0.00 | Power rate (J/TH) |
| Hash Stable | false | Hash rate stable |
| Power Mode | Normal | Power mode |
| Power Limit | 7700 | Power limit (W) |
| Chip Temp Min | 0.0 | Min chip temperature |
| Chip Temp Max | 0.0 | Max chip temperature |
| Chip Temp Avg | 0.0 | Average chip temperature |
| Btminer Fast Boot | disable | Fast boot status |
| Upfreq Complete | 0 | Frequency ramp complete |
| Debug | | Debug info |
| Fan Speed In | 0 | Intake fan speed |
| Fan Speed Out | 0 | Exhaust fan speed |

**EDEVS** (per-board, pipe-separated):

| Field | Example | Description |
|-------|---------|-------------|
| ASC | 0 | Board index |
| Slot | 0 | Slot number |
| MHS av | 0 | Board average hash rate (MHS) |
| Chip Frequency | 0 | Board chip frequency |
| Effective Chips | 0 | Number of effective chips |
| Last Valid Work | 1789770630 | Last valid work timestamp |
| Chip Data | H35A07-23081101 BINVE1-197306A | Board chip data |

**POOLS** (pipe-separated):

| Field | Example | Description |
|-------|---------|-------------|
| POOL | 1 | Pool index |
| URL | stratum+tcp://host:port | Pool URL |
| User | worker | Worker name |
| Stratum Active | true/false | Pool connection status |

**Power** (comma-separated):

| Field | Example | Description |
|-------|---------|-------------|
| Uptime | 3847 | Power uptime (seconds) |
| PowerRT | 95 | Real-time power (W) |
| PowerVOut | 3900 | Power output voltage (mV) |
| PowerVIn | 477.00 | Input voltage (V) |
| PowerIIn | 0.04 | Input current (A) |
| LiquidTemp | 39.1 | Liquid temperature |
| PowerFanSpeed | 0 | Power fan speed |
| FanSpeedIn | 0 | Intake fan speed |
| FanSpeedOut | 0 | Exhaust fan speed |
| EnvTemp | 41.1 | Environment temperature |
| BoardNum | 4 | Number of boards |
| BoardTemp0 | 39.1 | Board 0 temperature |
| BoardTemp1 | 39.1 | Board 1 temperature |
| BoardTemp2 | 39.1 | Board 2 temperature |
| BoardTemp3 | 39.1 | Board 3 temperature |
| PowerTemp | 44.1 | Power supply temperature |

---

## CMD 0x1A: PowerRealTimeInfo

**Header**: cmdcode=0x1A, len1=0, len2=~900

**Payload**: ~900 bytes, newline-delimited `key = value`

### [PowerRealTimeInfo] section

| Field | Example | Description |
|-------|---------|-------------|
| PowerStatus | 0 | Power status |
| PowerIin0 | 0.04 | Rail 0 input current (A) |
| PowerVin0 | 477.00 | Rail 0 input voltage (V) |
| PowerIin1 | 0.03 | Rail 1 input current (A) |
| PowerVin1 | 485.50 | Rail 1 input voltage (V) |
| PowerIin2 | 0.23 | Rail 2 input current (A) |
| PowerVin2 | 474.00 | Rail 2 input voltage (V) |
| PowerTemp0 | 44.1 | Power temp sensor 0 |
| PowerTemp1 | 36.1 | Power temp sensor 1 |
| PowerTemp2 | 38.8 | Power temp sensor 2 |

### [PowerAgingStatusInfo] section

| Field | Example | Description |
|-------|---------|-------------|
| PowerAgingResult | | Aging test result |
| PowerAgingElapsed | | Aging test elapsed time |

### [PowerInfo] section (same as CMD 0x16)

| Field | Example | Description |
|-------|---------|-------------|
| PowerName | P564B | Power supply name |
| HwRevision | R00018 | Hardware revision |
| PowerRevision | 20221024_P00032.20230729_S00034_R00018 | Power firmware revision |
| PowerOnOff | off | Power state |
| MinerWasPoweroff | 0 | Was miner powered off |
| PowerVout | 0 | Power output voltage (mV) |
| PowerIout | 0 | Power output current (mA) |
| PowerFanSpeed | 0 | Power supply fan speed |
| PowerVender | 1 | Power vendor ID |
| PowerModel | P564B | Power model |
| PowerSerialNo | 1413C2335302222 | Power serial number |

### Inline: Power metrics (last field, `#` and `|` delimited)

| Field | Example | Description |
|-------|---------|-------------|
| Uptime | 3847 | Power uptime (seconds) |
| PowerRT | 95 | Real-time power (W) |
| PowerVOut | 3900 | Power output voltage (mV) |
| PowerVIn | 477.00 | Input voltage (V) |
| PowerIIn | 0.04 | Input current (A) |
| LiquidTemp | 39.1 | Liquid temperature |
| PowerFanSpeed | 0 | Power fan speed |

### Inline: Error codes (comma-separated)

| Field | Example | Description |
|-------|---------|-------------|
| Error Code 0 | 20 | Latest error code |
| Error Time | 2026-09-19 06:23:23 | Latest error time |
| Error Code 1 | 2000 | Second error code |
| Error Code Count | 2 | Total error count |
| Factory Error Code 0 | 2110 | Factory error code |
| Factory Error Code Count | 2 | Factory error count |

---

## CMD 0x0D: Remote Control (N=V) — ack codes, parser, op table

Request: cmdcode=0x0D (Key2), part2 = `N=V` (appended directly after part1,
no separator; len2 = 3 for single-digit pairs). Response is a 16-byte ack:
```
5a5a7f7f 0d000000 <code> 0000 ffff0000
```
The first halfword after the cmdcode is a **result code**, not data:

| ack | meaning |
|-----|---------|
| 0 | op known, value parsed, **action executed** |
| 1 | seen on ops 13, 19 with out-of-range values (meaning TBD) |
| 3 | **unknown op** — nothing executed (safe probe response) |
| 4 | known op, **invalid value** — nothing executed |
| 9 | known op, valid value, **precondition failed** — nothing executed |

### Value parser semantics (calibrated with malformed inputs)

Both sides of the first `=` are parsed with atoi-like semantics:
trailing junk ignored (`6=1x` → 1), whitespace skipped (` 6=1`, `6 =1` work),
and **any value with no leading digits becomes 0 — which is in range for bool
ops, so it executes as 0**. Consequently `6=on` / `6=enable` / `6=true` /
`6==1` all parse to 0 and *disable* the API. There is no word form; "enable"
is exactly `6=1`. Out-of-range numbers (`6=2`, `6=-1`, `6=999999`) and empty
values (`6=`) return ack 4. Inputs without a recognizable op (`abc`, `=`)
return ack 3.

An ack of 0 therefore always means "something ran" — never probe unknown ops
with plausible values; the ack-4 bool-op existence check (below) is the only
side-effect-free discovery mechanism, and even that must not be followed by
live-value guesses on ops that acked 0 with junk values.

### Op table (M53S+, firmware 20250321.14.Rel)

| op | type | function |
|----|------|----------|
| 6 | bool | API switch: 1 = enable write/command API on 4028, 0 = disable (reads always work). **Enable requires the password-change ritual first** (ack 9 otherwise) |
| 7 | bool | executes; no observed effect on api/sshd/work — TBD |
| 8 | bool | Work control: 0 = stop mining, 1 = resume |
| 10 | bool | **SSH (dropbear)**: 1 = enable (perms `sshd=1`, port 22 opens), 0 = disable |
| 12 | — | ack 4 on `=1`: not a plain bool (different arity/semantics), TBD |
| 13, 19 | numeric | accept multi-value (ack 1 on V=2), semantics TBD |
| 1,2,4,5,9,11,14,15,17,18,20,21,22 | — | **execute arbitrary values** (acked 0 with V=2; the wipe of pool config during the sweep came from this group) |
| 0,3,16,23–30 | — | unknown op (ack 3) |

### Enable-API password-change ritual (all firmwares)

`6=1` returns ack 9 until a password change has been performed on the miner
(even changing to the same password counts; miners can "forget" the flag,
e.g. after reboots). Captured from WhatsMinerTool 9.2.5:

1. `6=1` → ack 9 (precondition failed)
2. **cmdcode 0x04** (Key2), part2 = `5,5,5,adminadminadmin` → ack 0
3. `6=1` → ack 0 — API enabled (`MinerApiSwitch` becomes 1)

The 0x04 payload marks the password as changed; the `super` login is
unaffected (payload format is strict — `on`/`sshd=1` return ack 4).
CLI: `change-password`, and `enable-api` runs the ritual automatically on
ack 9.

---

## How this was found (investigative trail, 2026-09-19)

1. **Ack codes discovered by calibration.** Valid commands returned ack 0,
   but early `6=1` attempts on a miner whose flag was lost returned a
   mysterious ack 9 while doing nothing. Only a live packet capture of the
   tool GUI revealed why: the tool sent `6=1`, got ack 9, then sent a
   **cmdcode 0x04** frame with part2 `5,5,5,adminadminadmin` (decrypted,
   CRC-verified), retried `6=1` and got ack 0.
2. **Parser semantics mapped with malformed inputs.** Sending `6=on`,
   `6=enable`, `6=true`, `6=2`, `6=-1`, `6=`, `abc`, `=`, `6==1`, `6=1x`,
   ` 6=1`, `6 =1` exposed the atoi behavior and the 0/3/4 code split.
3. **Op existence sweep — and its lesson.** Probing `N=2` for N=0..30 was
   intended as a safe "invalid value" scan: ops {6,7,8,10,12} acked 4 (known
   bool ops), {13,19} acked 1, the rest of the space acked 3 (unknown) —
   but **13 ops acked 0, meaning they executed foreign values**, and one of
   them wiped the pool configuration (factory placeholder pool, btminer
   restart). Restored immediately; the incident is why "ack 0 = executed"
   is the first rule above.
4. **Crossing with the SSH search.** Earlier `sshd=1`/`sshd=on` attempts had
   acked 3 — with the parser known, that means "sshd" parses to op 0, i.e.
   word-named ops are impossible; SSH had to be a numeric bool op. With
   6=api and 8=work already known, candidates were 7/10/12. Testing `7=1`,
   `10=1`, `12=1` individually (with pools/perms/port-22 verification after
   each): `7=1` executed with no visible effect; **`10=1` flipped
   `sshd=0→1` and opened port 22**; `12=1` acked 4. Dropbear on the miner
   offers legacy ssh-rsa only.
