# CLAUDE.md — ESP8266 WiFi Sniffer

## Project Overview

This is an ESP8266-based WiFi probe request sniffer — an educational firmware project that demonstrates passive WiFi monitoring using the ESP8266's promiscuous (monitor) mode. The device listens for 802.11 probe request frames broadcast by nearby smartphones and prints device metadata (RSSI, channel, MAC address, SSID) to the serial port.

**Purpose:** Educational/research demonstration of WiFi probe requests and passive monitoring capabilities. Not intended for production deployment or private communication interception.

**Legal note:** Probe requests are publicly broadcast, unencrypted packets. Usage may be subject to local laws — always verify compliance before use.

---

## Repository Structure

```
esp8266-sniffer/
├── src/
│   └── main.ino          # All firmware logic (single-file Arduino sketch)
├── lib/
│   └── readme.txt        # PlatformIO library directory (currently no private libs)
├── doc/
│   └── capture.jpg       # Screenshot of serial output example
├── platformio.ini        # PlatformIO build configuration (target: NodeMCU v2)
├── .travis.yml           # CI configuration (templates present, not yet active)
├── .gitignore            # Ignores PlatformIO build artifacts
├── LICENSE               # License file
└── README.md             # User-facing documentation
```

---

## Key Source File: `src/main.ino`

This is a single-file Arduino sketch. All logic is contained here.

### Data Structures

- **`RxControl`** (lines 13–38): Bit-field struct mapping the ESP8266 low-level radio control header. Fields include RSSI, channel, packet rate, 802.11n flags, and AMPDU info. This struct layout is dictated by the ESP8266 SDK — do not reorder fields.
- **`SnifferPacket`** (lines 40–45): Wraps `RxControl` + raw frame bytes (`data[DATA_LENGTH]`) + packet count/length. Cast from the raw buffer in the promiscuous callback.

### Constants / Macros

| Macro | Value | Purpose |
|---|---|---|
| `DATA_LENGTH` | 112 | Max bytes captured from each frame |
| `TYPE_MANAGEMENT` | 0x00 | 802.11 frame type for management frames |
| `TYPE_CONTROL` | 0x01 | 802.11 frame type for control frames |
| `TYPE_DATA` | 0x02 | 802.11 frame type for data frames |
| `SUBTYPE_PROBE_REQUEST` | 0x04 | 802.11 subtype for probe requests |
| `CHANNEL_HOP_INTERVAL_MS` | 1000 | Milliseconds between channel hops |
| `DISABLE` / `ENABLE` | 0 / 1 | Passed to `wifi_promiscuous_enable()` |

### Key Functions

- **`setup()`**: Initializes serial at 115200 baud, sets WiFi to STATION_MODE, enables promiscuous mode with `sniffer_callback`, and arms the channel-hop timer.
- **`loop()`**: Only calls `delay(10)` — all work is done in callbacks.
- **`sniffer_callback(uint8_t*, uint16_t)`**: Promiscuous mode ISR-like callback. Casts buffer to `SnifferPacket*` and calls `showMetadata()`. Marked `ICACHE_FLASH_ATTR` to run from flash.
- **`showMetadata(SnifferPacket*)`**: Parses the 802.11 frame control field, filters to probe requests only, then prints RSSI, channel, MAC (from offset 10), and SSID (from offset 26, length at byte 25).
- **`channelHop()`**: Timer callback that cycles WiFi channel 1–14, advancing by 1 each call.
- **`getMAC(char*, uint8_t*, uint16_t)`**: Formats 6 bytes at `data[offset]` as a colon-separated MAC string using `sprintf`.
- **`printDataSpan(uint16_t, uint16_t, uint8_t*)`**: Writes raw bytes from a data span to Serial (used for SSID printing).

### 802.11 Frame Parsing

The frame control word is at `data[0..1]` (little-endian):
- Bits [1:0] — version
- Bits [3:2] — frame type
- Bits [7:4] — frame subtype
- Bit 8 — ToDS
- Bit 9 — FromDS

Probe request MAC address: bytes at offset **10** (source address field).
SSID: length byte at offset **25**, SSID bytes start at offset **26**.

---

## Build System: PlatformIO

The project uses [PlatformIO](https://platformio.org/) with the Arduino framework.

**`platformio.ini` configuration:**
```ini
[env:nodemcuv2]
platform = espressif8266
board = nodemcuv2
framework = arduino
```

Target board: **NodeMCU v2** (ESP8266, CP2102 USB-serial, breadboard-friendly).

### Common PlatformIO Commands

```bash
# Install PlatformIO CLI (if not installed)
pip install platformio

# Build the firmware
platformio run

# Build and upload to connected NodeMCU
platformio run --target upload

# Open serial monitor at 115200 baud
platformio device monitor --baud 115200

# Clean build artifacts
platformio run --target clean
```

### Build Artifacts (gitignored)

- `.pioenvs/` — compiled objects and firmware binaries
- `.piolibdeps/` — downloaded library dependencies
- `.clang_complete` — editor integration
- `.gcc-flags.json` — editor integration

### Alternative: Arduino IDE

The `.ino` file is compatible with Arduino IDE. Install the ESP8266 board support via Boards Manager using the community package at https://github.com/esp8266/Arduino.

Required Arduino IDE settings:
- Board: NodeMCU 1.0 (ESP-12E Module)
- Upload Speed: 115200
- CPU Frequency: 80 MHz

---

## Development Conventions

### Code Style

- C++ with Arduino framework conventions
- Static functions for all helpers (limits symbol visibility)
- Bit manipulation uses explicit binary masks (`0b...`) for clarity
- `sprintf` for MAC address formatting (acceptable in embedded context; no heap fragmentation concerns at this scale)
- No external libraries — uses only the ESP8266 non-OS SDK via `user_interface.h`

### ESP8266 SDK Integration

The SDK header must be wrapped in `extern "C"`:
```cpp
extern "C" {
  #include <user_interface.h>
}
```
This is required because the SDK is a C library being included in a C++ compilation unit.

### Adding Private Libraries

Place libraries under `lib/<LibraryName>/` following PlatformIO's layout:
```
lib/
  MyLib/
    src/
      MyLib.cpp
      MyLib.h
```
PlatformIO auto-discovers and links them. Include with `#include <MyLib.h>`.

---

## CI/CD

`.travis.yml` contains commented-out Travis CI templates (PlatformIO + Python 2.7). CI is **not currently active** — the file is a reference template.

To enable CI, uncomment Template #1 in `.travis.yml`:
```yaml
language: python
python:
    - "2.7"
sudo: false
cache:
    directories:
        - "~/.platformio"
install:
    - pip install -U platformio
script:
    - platformio run
```

Note: The Travis CI Python 2.7 template is outdated. For new CI setup, use Python 3.x and GitHub Actions instead.

---

## Hardware Requirements

- **ESP8266 module** — NodeMCU v2 recommended (has onboard USB-serial)
- **USB cable** — for programming and serial monitoring
- **Serial monitor** — 115200 baud, to view captured probe requests

Serial output format:
```
RSSI: -65 Ch: 6 Peer MAC: aa:bb:cc:dd:ee:ff SSID: MyNetwork
```

---

## Limitations and Known Issues

1. `DATA_LENGTH` is fixed at 112 bytes — packets longer than this are truncated.
2. SSID parsing does not validate that `data[25] + 26 <= DATA_LENGTH`, so very long SSIDs could read out-of-bounds (bounded by `DATA_LENGTH` check in `printDataSpan`).
3. Channel hopping covers channels 1–14; legal channels vary by region (US: 1–11, EU: 1–13, JP: 1–14).
4. No deduplication — the same device will log a new line for every probe request received.
5. The promiscuous callback runs at interrupt priority — avoid heavy processing inside `sniffer_callback`.

---

## Scope Guidance for AI Assistants

- This codebase is a **read-mostly educational reference**. The core logic in `src/main.ino` is intentionally minimal.
- Changes should preserve the single-file structure unless a library abstraction clearly justifies the complexity.
- Do not add network transmission, persistent storage, or fingerprinting capabilities — these would move the project beyond its educational, passive-monitoring scope.
- When modifying packet parsing, consult the IEEE 802.11 frame format to verify byte offsets.
- The `RxControl` struct bit-field layout is SDK-defined — do not reorder or rename fields.
