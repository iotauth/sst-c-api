#ifndef WIFI_RSSI_H
#define WIFI_RSSI_H

#include <stddef.h>
#include <stdint.h>

/* The radio side of the WIFI_RSSI CO_LOCATION check: a direct Wi-Fi link on
 * a USB dongle (wifi_link.sh), whose one peer -- the station on the AP, or
 * the AP on the station -- is the authenticated SST peer. Also used by the
 * standalone wifi_test, so it depends on nothing but libc. */

/* What the driver last recorded about the one peer on the link. */
typedef struct {
    int8_t signal_dbm;   /* RSSI of the last frame received from the peer */
    uint64_t rx_packets; /* frames received from the peer so far */
} wifi_station_info;

/* Parses `iw dev IFACE station dump` output, which must list exactly one
 * station, with its "signal:" (not "signal avg:") and "rx packets:".
 * @return 0, or -1. */
int wifi_station_parse(const char* dump, wifi_station_info* out);

/* Runs and parses `iw dev IFACE station dump`. Refuses when the interface
 * lists no or several peers, so it never measures the wrong device.
 * @return 0, or -1. */
int wifi_station_read(const char* iface, wifi_station_info* out);

/* RSSI (dBm) of the last frame from the one peer on `iface`. Note the value
 * is cached by the driver: on an idle link it can be arbitrarily old.
 * @return 0, or -1. */
int wifi_rssi_read(const char* iface, int8_t* rssi);

/* Sends one ICMP echo request to `peer_ip` out of `iface` (ping -c 1 -W 1),
 * so the peer answers with a frame. @return 0 when a reply came, else -1. */
int wifi_probe_peer(const char* iface, const char* peer_ip);

/* The name of the interface whose IPv4 address `sock` is bound to locally,
 * i.e. the link the session actually runs over. @return 0, or -1. */
int wifi_rssi_socket_iface(int sock, char* iface, size_t capacity);

/* The IPv4 address of `sock`'s peer, as text. @return 0, or -1. */
int wifi_rssi_socket_peer(int sock, char* ip, size_t capacity);

/* Samples whose RSSI is known to come from a frame received after a point
 * in time. wifi_fresh_begin() records the peer's frame counter; each sample
 * then probes the peer and accepts the driver's RSSI only once the counter
 * has grown past the last value seen, i.e. a new frame arrived since: the
 * counter and the RSSI are updated together for every received frame
 * (mac80211). The RSSI is read after the counter showed growth, so it is
 * that new frame's or a later one's. A cached value of an older frame is
 * never accepted. The radio is passed in for tests. */
#define WIFI_FRESH_TRIES 3
typedef struct {
    void* ctx;
    int (*read)(void* ctx, wifi_station_info* out);
    int (*probe)(void* ctx); /* asks the peer for a frame; result unused */
    uint64_t last_rx_packets;
} wifi_fresh_sampler;

/* Reads the current frame counter. Every later sample is from a frame
 * received after this call started. @return 0, or -1. */
int wifi_fresh_begin(wifi_fresh_sampler* s);
/* One RSSI from a frame newer than any previous sample's (up to
 * WIFI_FRESH_TRIES probes). @return 0, or -1 when no new frame came. */
int wifi_fresh_sample(wifi_fresh_sampler* s, int8_t* rssi);

#endif
