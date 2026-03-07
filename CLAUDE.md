# CLAUDE.md — ESP32 WiFi Probe Request Sniffer

## Project Overview

An ESP32-based WiFi probe request sniffer that passively captures 802.11 management frames and builds an in-memory profile of each observed device (MAC address → set of queried SSIDs). Output goes to the serial monitor only. Nothing is transmitted and no connections are made.

**Purpose:** Single-device, controlled lab demonstration showing what information 802.11 probe requests expose — stable vs. randomized MACs, historically-joined network names, signal strength. Intended as a thesis/research POC.

**Legal note:** Passive capture of broadcast probe frames. Usage may be subject to local wiretapping and privacy laws — verify compliance before use. Lab/controlled environment only.

---

## Repository Structure

```
esp8266-sniffer/
├── src/
│   └── main.ino          # All firmware logic (single-file Arduino sketch)
├── lib/
│   └── readme.txt        # PlatformIO private-library directory (currently empty)
├── doc/
│   └── capture.jpg       # Serial output screenshot from original ESP8266 version
├── platformio.ini        # PlatformIO build config — target: ESP32 DevKit
├── .travis.yml           # CI reference templates (not active)
├── .gitignore            # Ignores PlatformIO build artifacts
├── LICENSE               # License file
└── README.md             # User-facing documentation
```

---

## Key Source File: `src/main.ino`

Single-file Arduino sketch. All logic lives here.

### Configuration Constants

| Constant | Default | Purpose |
|---|---|---|
| `MAX_TRACKED_DEVICES` | 64 | Maximum distinct MACs held in RAM; oldest evicted when full |
| `MAX_SSIDS_PER_DEVICE` | 30 | Maximum unique SSIDs stored per device |
| `CHANNEL_HOP_INTERVAL_MS` | 500 | Milliseconds per channel before hopping |
| `SUMMARY_INTERVAL_MS` | 15000 | Milliseconds between full profile summaries on serial |
| `CHANNELS[]` | 1–13 | Channel sweep list (covers most regulatory domains) |

### 802.11 Frame Constants / Offsets

| Constant | Value | Meaning |
|---|---|---|
| `TYPE_MANAGEMENT` | 0x00 | 802.11 frame type: management |
| `SUBTYPE_PROBE_REQUEST` | 0x04 | 802.11 management subtype: probe request |
| `OFFSET_SRC_MAC` | 10 | Byte offset of 6-byte source address in frame |
| `OFFSET_SSID_TAG` | 24 | Byte offset of SSID information element tag (must be 0x00) |
| `OFFSET_SSID_LEN` | 25 | Byte offset of SSID length byte |
| `OFFSET_SSID_DATA` | 26 | Byte offset where SSID string begins |
| `MIN_PROBE_FRAME_LEN` | 27 | Minimum valid probe request byte count |

### Data Structures

**`DeviceProfile`** (per-MAC record stored in `deviceProfiles` map):
- `ssids` — `std::set<std::string>` of every SSID this MAC has probed for
- `lastRssi` — most recent RSSI (dBm)
- `lastChannel` — channel of most recent probe
- `probeCount` — total probe packets seen from this MAC
- `macRandomized` — true if locally-administered bit (bit 1 of first octet) is set

**`deviceProfiles`** — `std::map<std::string, DeviceProfile>` keyed on lower-case colon-hex MAC string (e.g. `"aa:bb:cc:dd:ee:ff"`).

**`insertionOrder[]`** / `insertionHead` — simple ring buffer tracking insertion order for LRU eviction when `MAX_TRACKED_DEVICES` is reached.

### Key Functions

- **`setup()`** — Reduces CPU to 80 MHz, stops Bluetooth, initialises WiFi in `WIFI_MODE_NULL`, installs management-only promiscuous filter, registers `snifferCallback`, starts on channel 1.
- **`loop()`** — Drives channel hopping timer and periodic `printSummary()` call; sleeps 10 ms otherwise.
- **`snifferCallback(void*, wifi_promiscuous_pkt_type_t)`** — ESP-IDF promiscuous callback (runs in ISR context, marked `IRAM_ATTR`). Parses frame control, filters to probe requests, updates `deviceProfiles`, prints a one-line log per packet.
- **`printSummary()`** — Iterates `deviceProfiles` and prints a formatted table of all tracked devices and their queried SSIDs.
- **`formatMAC(const uint8_t*)`** — Returns `std::string` colon-hex representation of a 6-byte MAC.
- **`isRandomizedMAC(const uint8_t*)`** — Returns true if locally-administered bit is set (iOS/Android/Windows privacy randomisation).

### 802.11 Frame Parsing

Frame control word at `data[0..1]` (little-endian):
```
Byte 0:  bits [1:0] = protocol version
         bits [3:2] = frame type      (0x00 = management)
         bits [7:4] = frame subtype   (0x04 = probe request)
```

Management frame fixed header layout:
```
Offset  Length  Field
  0       2     Frame Control
  2       2     Duration
  4       6     Destination Address (DA) — broadcast
 10       6     Source Address (SA)  ← probing device MAC
 16       6     BSSID — broadcast
 22       2     Sequence Control
 24       1     IE Tag (0x00 = SSID)
 25       1     SSID Length
 26      ≤32    SSID bytes
```

`sig_len` from `wifi_pkt_rx_ctrl_t` includes the 4-byte FCS on ESP32. Usable payload length = `sig_len - 4`. The code accounts for this when bounds-checking the SSID field.

### MAC Randomisation Note

Modern iOS, Android, and Windows randomize MAC addresses per-network or per-session. A device with the locally-administered bit set will appear as a new MAC each time it reconnects, limiting the effectiveness of MAC-based tracking. Wildcard probes (`ssidLen == 0`) are increasingly common on randomised devices.

---

## Build System: PlatformIO

**`platformio.ini`:**
```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
build_flags =
    -DCORE_DEBUG_LEVEL=0
```

Target board: **ESP32 DevKit v1** (38-pin, CP2102 USB-serial). Any ESP32 module with at least 4 MB flash works.

### Common Commands

```bash
# Build firmware
platformio run

# Build and upload to connected board
platformio run --target upload

# Open serial monitor at 115200 baud
platformio device monitor

# Clean build artifacts
platformio run --target clean
```

### Build Artifacts (gitignored)
- `.pio/` — compiled objects and firmware binaries
- `.clang_complete`, `.gcc-flags.json` — editor integration

---

## Development Conventions

### Code Style
- C++ with Arduino framework conventions
- `std::map` / `std::set` for in-memory storage (ESP32 has sufficient heap)
- `IRAM_ATTR` on the promiscuous callback — it runs at interrupt priority and must reside in IRAM
- `constexpr`/`#define` constants at the top of the file for easy tuning
- `snprintf` preferred over `sprintf` for all string formatting

### ESP-IDF WiFi API (used directly)
```cpp
#include "esp_wifi.h"
#include "esp_system.h"
```
These are C headers; when included from a `.ino` (C++) file, the Arduino framework's build system handles the linkage automatically — no `extern "C"` wrapper needed unlike the old ESP8266 SDK pattern.

Key API calls:
```cpp
esp_wifi_init(&cfg);
esp_wifi_set_mode(WIFI_MODE_NULL);          // monitor only — no AP, no STA
esp_wifi_set_promiscuous(true);
esp_wifi_set_promiscuous_rx_cb(callback);
esp_wifi_set_promiscuous_filter(&filter);   // management frames only
esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
```

### Power Efficiency
- CPU reduced to 80 MHz via `setCpuFrequencyMhz(80)` — adequate for packet processing, saves ~20–30% versus 240 MHz
- Bluetooth stopped via `btStop()` — saves ~30 mA
- Management-only promiscuous filter reduces callback frequency substantially versus capturing all frame types

---

## Hardware Requirements

- **ESP32 module** — DevKit v1 / NodeMCU-32S recommended (onboard USB-serial)
- **USB cable** — for programming and serial monitoring
- **Power** — USB power bank for portable/battery use; typical current draw ~80–100 mA at 80 MHz with WiFi active

Serial output format (one line per probe packet):
```
[Ch06] RSSI  -65 dBm  aa:bb:cc:dd:ee:ff  [rand]   "HomeNetwork"
[Ch06] RSSI  -72 dBm  11:22:33:44:55:66           "CoffeeShopWifi"
```

Periodic summary (every 15 s):
```
══════════════ DEVICE PROFILE SUMMARY ══════════════
  Devices tracked: 3    Total probe packets: 47
─────────────────────────────────────────────────────
  aa:bb:cc:dd:ee:ff  [RANDOMIZED]  probes: 12    last RSSI: -65 dBm
    Networks queried (3):
      "<wildcard>"
      "HomeNetwork"
      "Work-5GHz"
  ...
═════════════════════════════════════════════════════
```

---

## Limitations and Known Issues

1. **MAC randomisation** — Modern devices rotate MACs; profiles may be fragmented across multiple apparent "devices" that are actually one physical device.
2. **Fixed memory cap** — `MAX_TRACKED_DEVICES` × `MAX_SSIDS_PER_DEVICE` bounds RAM use; eviction is FIFO not LRU.
3. **sig_len / FCS** — ESP-IDF `sig_len` includes the 4-byte FCS in some SDK versions. The bounds check `(OFFSET_SSID_DATA + ssidLen) <= (len - 4)` compensates; verify against your SDK version if seeing truncated SSIDs.
4. **Channel dwell time** — 500 ms per channel means fast-moving devices may only be seen on one channel. Adjust `CHANNEL_HOP_INTERVAL_MS` for dwell vs. coverage trade-off.
5. **No persistence** — Profiles exist only in RAM; power cycle clears all data.
6. **ISR context** — `snifferCallback` runs at interrupt priority. Avoid adding blocking calls or dynamic allocation inside it.

---

## CI/CD

`.travis.yml` contains commented-out Travis CI templates (Python 2.7, outdated). CI is not active. For new CI, use GitHub Actions with the [PlatformIO action](https://github.com/marketplace/actions/platformio-ci) and Python 3.x.

---

## Scope Guidance for AI Assistants

- **Single-file structure** — Keep all logic in `src/main.ino` unless a library abstraction is clearly justified.
- **Output only to Serial** — Do not add WiFi transmission, BLE, HTTP clients, MQTT, or any form of remote data export.
- **No active WiFi operations** — Do not configure the ESP32 as an AP or STA, do not send any frames. Mode must remain `WIFI_MODE_NULL`.
- **No persistent storage** — Do not add SPIFFS, LittleFS, SD card, or NVS writes.
- **Frame parsing changes** — Consult the IEEE 802.11-2020 standard to verify byte offsets before modifying.
- **ISR safety** — Any code added to `snifferCallback` must be ISR-safe: no `malloc`, no `Serial` calls that block, no `std::` operations that acquire locks.
- **Power budget** — Preserve the 80 MHz CPU frequency and `btStop()` calls; they matter for battery life.
