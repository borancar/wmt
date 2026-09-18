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

## CMD 0x0F: Detected HashRate

**Header**: cmdcode=0x0F, len1=0, len2=24

**Payload**: 24 bytes, colon-separated ASCII

```
board0_Hs:board1_Hs:board2_Hs:board3_Hs
```

Example: `73774:73774:73358:73358`

| Index | Field | Description |
|-------|-------|-------------|
| 0 | Board 0 hash rate | H/s |
| 1 | Board 1 hash rate | H/s |
| 2 | Board 2 hash rate | H/s |
| 3 | Board 3 hash rate | H/s |

---

## CMD 0x13: Compact Info

**Header**: cmdcode=0x13, len1=0, len2=~1500

**Payload**: ~1500 bytes, `#` and `|` delimited

### Top-level sections (separated by `#`):

| Section | Content | Separator |
|---------|---------|-----------|
| 0 | Model string | `-` (dash) |
| 1 | MAC address | - |
| 2 | (empty) | - |
| 3 | Permissions | `,` |
| 4 | User levels | space |
| 5 | Main data (SUMMARY + EDEVS + POOLS) | `\|` (pipe) |
| 6 | Power metrics | `,` |

### Section 0: Model string (dash-separated)
```
Brand-Type-Board-BoardVer-HashBoard-Power-Firmware-HashRate-Coin-MinerSn
```
Example: `WhatsMiner-M53S+-H616-CB6V5-J40-P564B-20250321.14.Rel-73774:73774:73358:73358-BTC-MinerSn = MAM35P40...`

### Section 5: Main data (pipe-separated)

| Index | Content | Format |
|-------|---------|--------|
| 0 | SUMMARY | comma-separated key=value |
| 1 | EDEVS header | `EDEVS,Msg=4` |
| 2-5 | Per-board data (ASC=0..3) | comma-separated key=value |
| 6 | POOLS header | `POOLS,Msg=N Pool(s)` |
| 7-9 | Pool data (POOL=1..3) | comma-separated key=value |

**SUMMARY fields**: Error Code 0/1, Error Time, Elapsed, Uptime, MHS av, MHS 15m, HS RT, Pool Rejected%, freq_avg, Power, Power Rate, Hash Stable, Power Mode, Power Limit, Chip Temp Min/Max/Avg, Fan Speed In/Out, etc.

**Per-board fields**: ASC, Slot, MHS av, Chip Frequency, Effective Chips, Last Valid Work, Chip Data

**Pool fields**: POOL, URL, User, Stratum Active

### Section 6: Power metrics (comma-separated)
Uptime, PowerRT, PowerVOut, PowerVIn, PowerIIn, LiquidTemp, PowerFanSpeed, FanSpeedIn/Out, EnvTemp, BoardNum, BoardTemp0-3, PowerTemp

---

## CMD 0x16: MinerInfo

**Header**: cmdcode=0x16, len1=0, len2=~2300

**Payload**: ~2300 bytes, newline-delimited `key = value`

### Sections:

**[MinerInfo]** - 37 fields:
MinerType, ControlBoardType, ControlBoardVersion, HashBoardVersion, PowerType, FirmwareVersion, DetectedHashRate, CoinType, PoolStrategy, PowerMode, HeatMode, HashPercent, EepromLiquidCooling, ChipData, ChipDataAll, MinerApiSwitch, BtminerFastBoot, BtminerFastMining, BoardNum, HashBoardStruct, PcbSn0-7, is_btrom, joint_mining, MinerSn, DisableFactoryMode, DisableUpgrade, ServiceMode, etc.

**[PowerInfo]** - 14 fields:
PowerName, HwRevision, PowerRevision, PowerOnOff, MinerWasPoweroff, PowerVout, PowerIout, PowerFanSpeed, PowerVender, PowerModel, PowerSerialNo, etc.

**Inline data** (last field, `#` and `|` delimited):
Same structure as CMD 0x13 Section 5 (SUMMARY + EDEVS + POOLS + Power)

---

## CMD 0x1A: PowerRealTimeInfo

**Header**: cmdcode=0x1A, len1=0, len2=~850

**Payload**: ~850 bytes, newline-delimited `key = value`

### [PowerRealTimeInfo] - 24 fields:
PowerStatus, PowerIin0-2, PowerVin0-2, PowerTemp0-2, PowerAgingResult, PowerAgingElapsed, PowerName, HwRevision, PowerRevision, PowerOnOff, MinerWasPoweroff, PowerVout, PowerIout, PowerFanSpeed, PowerVender, PowerModel, PowerSerialNo

### Inline data (last field, `#` and `|` delimited):
Uptime, PowerRT, PowerVOut, PowerVIn, PowerIIn, LiquidTemp, PowerFanSpeed, Error codes (Factory Error Code 0/1, Error Time, counts)
