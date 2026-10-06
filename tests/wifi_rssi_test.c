/* Portable test for the Wi-Fi RSSI reader (wifi_com/wifi_rssi.h): parsing
 * `iw station dump`, and the fresh sampler over a simulated driver whose
 * cached RSSI changes only when a frame arrives. */
#include "../wifi_com/wifi_rssi.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define DUMP(rx, signal)                                              \
    "Station 00:11:22:33:44:55 (on wlan1)\n"                          \
    "\tinactive time:\t40 ms\n"                                       \
    "\trx bytes:\t4096\n"                                             \
    "\trx packets:\t" rx "\n"                                         \
    "\ttx packets:\t30\n"                                             \
    "\tsignal:  \t" signal " [" signal "] dBm\n"                      \
    "\tsignal avg:\t-90 [-90] dBm\n"

static void parse_tests(void) {
    wifi_station_info info;
    assert(wifi_station_parse(DUMP("28", "-16"), &info) == 0);
    assert(info.signal_dbm == -16 && info.rx_packets == 28);
    /* No station, two stations, or a missing field: refused. */
    assert(wifi_station_parse("", &info) == -1);
    assert(wifi_station_parse(DUMP("1", "-16") DUMP("2", "-20"), &info) == -1);
    assert(wifi_station_parse("Station 00:11:22:33:44:55 (on wlan1)\n"
                              "\tsignal:  \t-16 [-16] dBm\n",
                              &info) == -1);
    assert(wifi_station_parse("Station 00:11:22:33:44:55 (on wlan1)\n"
                              "\trx packets:\t3\n"
                              "\tsignal avg:\t-16 [-16] dBm\n",
                              &info) == -1);
    assert(wifi_station_parse(DUMP("3", "-200"), &info) == -1);
}

/* The driver: a frame counter and the RSSI of the last frame. A probe
 * makes the peer send `frames_per_probe` frames, each at `next_rssi`. */
typedef struct {
    wifi_station_info now;
    int frames_per_probe;
    int8_t next_rssi;
    int probes, reads, fail_read;
} fake_radio;

static int fake_read(void* ctx, wifi_station_info* out) {
    fake_radio* r = ctx;
    ++r->reads;
    if (r->fail_read) return -1;
    *out = r->now;
    return 0;
}

static int fake_probe(void* ctx) {
    fake_radio* r = ctx;
    ++r->probes;
    if (r->frames_per_probe) {
        r->now.rx_packets += (uint64_t)r->frames_per_probe;
        r->now.signal_dbm = r->next_rssi;
    }
    return 0;
}

static void sampler_tests(void) {
    /* The cached RSSI predates begin(): it is never returned. */
    fake_radio radio = {{-30, 100}, 1, -55, 0, 0, 0};
    wifi_fresh_sampler s = {&radio, fake_read, fake_probe, 0};
    int8_t rssi = 0;
    assert(wifi_fresh_begin(&s) == 0 && s.last_rx_packets == 100);
    assert(wifi_fresh_sample(&s, &rssi) == 0 && rssi == -55);
    assert(s.last_rx_packets == 101 && radio.probes == 1);
    /* Each sample needs a frame newer than the previous sample's. */
    radio.next_rssi = -60;
    assert(wifi_fresh_sample(&s, &rssi) == 0 && rssi == -60);
    assert(s.last_rx_packets == 102);

    /* An idle peer (no new frame however often it is probed): the sample
     * fails rather than repeating the cached value. */
    radio.frames_per_probe = 0;
    radio.probes = 0;
    assert(wifi_fresh_sample(&s, &rssi) == -1);
    assert(radio.probes == WIFI_FRESH_TRIES);

    /* A read failure fails the sample, and begin. */
    radio.frames_per_probe = 1;
    radio.fail_read = 1;
    assert(wifi_fresh_sample(&s, &rssi) == -1);
    assert(wifi_fresh_begin(&s) == -1);

    /* A counter that goes backwards (e.g. the peer re-associated) is not
     * trusted. */
    radio.fail_read = 0;
    assert(wifi_fresh_begin(&s) == 0);
    s.last_rx_packets = radio.now.rx_packets + 10;
    radio.probes = 0;
    assert(wifi_fresh_sample(&s, &rssi) == -1);
}

int main(void) {
    parse_tests();
    sampler_tests();
    puts("Wi-Fi RSSI: station dump parsing and fresh sampler tests passed.");
    return 0;
}
