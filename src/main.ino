/**
 * ESP32 WiFi Probe Request Sniffer — Lab POC
 *
 * Educational demonstration of what 802.11 probe requests reveal:
 * each nearby device broadcasts its list of previously-joined networks
 * in plaintext, along with a MAC address that may or may not be stable.
 *
 * This device passively captures those frames and builds a per-device
 * profile (MAC -> set of queried SSIDs) that it prints to the serial
 * monitor.  Nothing is transmitted; no connections are made.
 *
 * Intended for single-device, controlled lab use only.
 * Observe all applicable local laws before deployment.
 */

#include <Arduino.h>
#include <map>
#include <set>
#include <string>
#include <sys/time.h>
#include "esp_wifi.h"
#include "esp_system.h"

// ── Configuration ────────────────────────────────────────────────────────────

// Maximum number of distinct MACs held in memory at once.
// Oldest entries are evicted when the limit is reached.
#define MAX_TRACKED_DEVICES    64

// Maximum unique SSIDs stored per device before further ones are dropped.
#define MAX_SSIDS_PER_DEVICE   30

// Time (ms) spent listening on each channel before hopping.
#define CHANNEL_HOP_INTERVAL_MS  500

// Interval (ms) between full profile summaries printed to serial.
#define SUMMARY_INTERVAL_MS    15000

// Channels to cycle through (1–13 covers most regulatory domains).
static const uint8_t CHANNELS[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
#define NUM_CHANNELS (sizeof(CHANNELS) / sizeof(CHANNELS[0]))

// ── 802.11 frame constants ────────────────────────────────────────────────────

#define TYPE_MANAGEMENT        0x00
#define SUBTYPE_PROBE_REQUEST  0x04

// Fixed 802.11 management frame header offsets (bytes):
//   0–1   Frame Control
//   2–3   Duration
//   4–9   Destination Address  (DA — broadcast FF:FF:FF:FF:FF:FF)
//  10–15  Source Address       (SA — the probing device)
//  16–21  BSSID                (broadcast FF:FF:FF:FF:FF:FF)
//  22–23  Sequence Control
//  24     First IE tag (0x00 = SSID)
//  25     SSID length
//  26+    SSID bytes
#define OFFSET_SRC_MAC         10
#define OFFSET_SSID_TAG        24
#define OFFSET_SSID_LEN        25
#define OFFSET_SSID_DATA       26
#define MIN_PROBE_FRAME_LEN    27   // FC(2)+Dur(2)+DA(6)+SA(6)+BSSID(6)+Seq(2)+IE_tag(1)+IE_len(1)+FCS(4)

// ── Storage ───────────────────────────────────────────────────────────────────

struct DeviceProfile {
    std::set<std::string> ssids;   // networks this device has probed for
    int8_t  lastRssi    = 0;
    uint8_t lastChannel = 0;
    uint32_t probeCount = 0;
    bool    macRandomized = false;
};

// MAC string (lower-case colon-hex) → profile
static std::map<std::string, DeviceProfile> deviceProfiles;

// Ordered insertion list — used to evict oldest entry when map is full.
// Simple ring-style tracking; accurate enough for a lab POC.
static std::string insertionOrder[MAX_TRACKED_DEVICES];
static uint8_t insertionHead = 0;   // points to the oldest entry slot

static uint32_t totalProbePackets = 0;

// ── Channel state ─────────────────────────────────────────────────────────────

static uint8_t  channelIndex   = 0;
static uint32_t lastChannelHop = 0;
static uint32_t lastSummary    = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────

// ── Wall-clock seeding (compile-time) ────────────────────────────────────────
//
// The preprocessor macros __DATE__ ("Mar  8 2026") and __TIME__ ("14:30:00")
// are baked in at build time.  We parse them once in setup() and call
// settimeofday() so the ESP32 software RTC keeps wall-clock time for the
// duration of the session without any external hardware or network access.
//
// Accuracy: the internal crystal drifts ~±40 ppm; over a typical lab session
// (a few hours) that is well within a few seconds — perfectly adequate.

static void seedClockFromBuildTime() {
    // Parse __TIME__ = "HH:MM:SS"
    struct tm t = {};
    sscanf(__TIME__, "%d:%d:%d", &t.tm_hour, &t.tm_min, &t.tm_sec);

    // Parse __DATE__ = "Mon DD YYYY" (day may be space-padded, e.g. "Mar  8 2026")
    char mon[4] = {};
    sscanf(__DATE__, "%3s %d %d", mon, &t.tm_mday, &t.tm_year);
    t.tm_year -= 1900;

    static const char* months[12] = {
        "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
    };
    for (int i = 0; i < 12; i++) {
        if (strncmp(mon, months[i], 3) == 0) { t.tm_mon = i; break; }
    }
    t.tm_isdst = -1;

    time_t epoch = mktime(&t);
    struct timeval tv = { epoch, 0 };
    settimeofday(&tv, nullptr);
}

// Formats the current wall-clock time as "HH:MM:SS" into buf.
// Uses localtime_r (reentrant) so it is safe to call from the promiscuous
// callback, which runs at interrupt priority.
static void formatTime(char* buf, size_t bufLen) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    struct tm t;
    localtime_r(&tv.tv_sec, &t);
    strftime(buf, bufLen, "%H:%M:%S", &t);
}

static std::string formatMAC(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// The locally-administered bit (bit 1 of the first octet) is set by
// iOS / Android / Windows when using MAC randomisation.
static bool isRandomizedMAC(const uint8_t* mac) {
    return (mac[0] & 0x02) != 0;
}

// ── Promiscuous callback ──────────────────────────────────────────────────────

static void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    // We only asked for management frames via the filter below, but guard anyway.
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t* pkt =
        reinterpret_cast<const wifi_promiscuous_pkt_t*>(buf);
    const uint8_t* data = pkt->payload;

    // sig_len includes the 4-byte FCS on ESP32; ensure usable payload is long enough.
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < MIN_PROBE_FRAME_LEN) return;

    // ── Frame-control field (little-endian, bytes 0–1) ──
    // Bits [3:2] = frame type  |  bits [7:4] = frame subtype
    uint8_t frameType    = (data[0] >> 2) & 0x03;
    uint8_t frameSubtype = (data[0] >> 4) & 0x0F;

    if (frameType != TYPE_MANAGEMENT || frameSubtype != SUBTYPE_PROBE_REQUEST) return;

    totalProbePackets++;

    // ── Source MAC (offset 10) ──
    const uint8_t* srcMAC = data + OFFSET_SRC_MAC;
    std::string macStr    = formatMAC(srcMAC);

    // ── SSID information element ──
    // Verify the IE tag is actually SSID (0x00) before trusting the length.
    if (data[OFFSET_SSID_TAG] != 0x00) return;

    uint8_t ssidLen = data[OFFSET_SSID_LEN];
    std::string ssid;

    if (ssidLen == 0) {
        // Wildcard probe — device will associate with any network it knows.
        // Common on modern OSes to reduce fingerprinting surface.
        ssid = "<wildcard>";
    } else if ((OFFSET_SSID_DATA + ssidLen) <= (len - 4)) {
        // Directed probe — device is asking for a specific network.
        ssid = std::string(reinterpret_cast<const char*>(data + OFFSET_SSID_DATA), ssidLen);
    } else {
        return;  // Malformed / truncated
    }

    int8_t  rssi    = pkt->rx_ctrl.rssi;
    uint8_t channel = pkt->rx_ctrl.channel;

    // ── Log this packet to serial immediately ──
    char ts[9];
    formatTime(ts, sizeof(ts));
    Serial.printf("[%s][Ch%02d] RSSI %4d dBm  %s%s  \"%s\"\n",
        ts, channel, rssi,
        macStr.c_str(),
        isRandomizedMAC(srcMAC) ? "  [rand]" : "        ",
        ssid.c_str());

    // ── Update in-memory profile ──
    // If we haven't seen this MAC before and are at capacity, evict oldest.
    if (deviceProfiles.find(macStr) == deviceProfiles.end()) {
        if (static_cast<int>(deviceProfiles.size()) >= MAX_TRACKED_DEVICES) {
            deviceProfiles.erase(insertionOrder[insertionHead]);
        }
        insertionOrder[insertionHead] = macStr;
        insertionHead = (insertionHead + 1) % MAX_TRACKED_DEVICES;
    }

    DeviceProfile& profile = deviceProfiles[macStr];
    profile.lastRssi      = rssi;
    profile.lastChannel   = channel;
    profile.probeCount++;
    profile.macRandomized = isRandomizedMAC(srcMAC);

    if (profile.ssids.size() < MAX_SSIDS_PER_DEVICE) {
        profile.ssids.insert(ssid);
    }
}

// ── Summary printer ───────────────────────────────────────────────────────────

static void printSummary() {
    char ts[9];
    formatTime(ts, sizeof(ts));
    Serial.println();
    Serial.printf( "══════════════ DEVICE PROFILE SUMMARY  %s ══════════════\n", ts);
    Serial.printf( "  Devices tracked: %-4d  Total probe packets: %lu\n",
                   deviceProfiles.size(), totalProbePackets);
    Serial.println("─────────────────────────────────────────────────────");

    for (auto& kv : deviceProfiles) {
        const std::string&   mac     = kv.first;
        const DeviceProfile& profile = kv.second;

        Serial.printf("  %s  %s  probes: %-5lu  last RSSI: %d dBm\n",
            mac.c_str(),
            profile.macRandomized ? "[RANDOMIZED]" : "[STABLE    ]",
            profile.probeCount,
            profile.lastRssi);

        Serial.printf("    Networks queried (%d):\n", profile.ssids.size());
        for (auto& s : profile.ssids) {
            Serial.printf("      \"%s\"\n", s.c_str());
        }
    }

    Serial.println("═════════════════════════════════════════════════════");
    Serial.println();
}

// ── Arduino entry points ──────────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(500);

    Serial.println();
    Serial.println("ESP32 Probe Request Sniffer — Lab POC");
    Serial.println("Educational use only. Observe local laws.");
    Serial.println("──────────────────────────────────────");

    // Seed the software RTC from the compile-time timestamp.
    // The clock keeps wall time for the session via the internal crystal.
    seedClockFromBuildTime();
    char ts[9];
    formatTime(ts, sizeof(ts));
    Serial.printf("Clock set to build time: %s (%s %s)\n", ts, __DATE__, __TIME__);

    // Reduce CPU frequency to save power (promiscuous mode doesn't need 240 MHz).
    setCpuFrequencyMhz(80);

    // Bluetooth is unused — shut it down to save ~30 mA.
    btStop();

    // Initialise WiFi driver in NULL (monitor-only) mode.
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    // Filter to management frames only — reduces callback frequency significantly.
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(snifferCallback);

    // Start on first channel.
    esp_wifi_set_channel(CHANNELS[channelIndex], WIFI_SECOND_CHAN_NONE);
    Serial.printf("Listening on channel %d...\n\n", CHANNELS[channelIndex]);

    lastChannelHop = millis();
    lastSummary    = millis();
}

void loop() {
    uint32_t now = millis();

    // ── Channel hop ──
    if (now - lastChannelHop >= CHANNEL_HOP_INTERVAL_MS) {
        lastChannelHop = now;
        channelIndex   = (channelIndex + 1) % NUM_CHANNELS;
        esp_wifi_set_channel(CHANNELS[channelIndex], WIFI_SECOND_CHAN_NONE);
    }

    // ── Periodic profile summary ──
    if (now - lastSummary >= SUMMARY_INTERVAL_MS) {
        lastSummary = now;
        printSummary();
    }

    delay(10);
}
