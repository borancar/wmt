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
