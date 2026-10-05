#ifndef WIFI_RSSI_H
#define WIFI_RSSI_H

#include <stddef.h>
#include <stdint.h>

/* The radio side of the WIFI_RSSI CO_LOCATION check: a direct Wi-Fi link on
 * a USB dongle (wifi_link.sh), whose one peer -- the station on the AP, or
 * the AP on the station -- is the authenticated SST peer. Also used by the
 * standalone wifi_test, so it depends on nothing but libc. */

/* RSSI (dBm) of the last frame from the one peer on `iface`, via
 * `iw dev IFACE station dump`. Refuses when the interface lists no or
 * several peers, so it never measures the wrong device.
 * @return 0, or -1. */
int wifi_rssi_read(const char* iface, int8_t* rssi);

/* The name of the interface whose IPv4 address `sock` is bound to locally,
 * i.e. the link the session actually runs over. @return 0, or -1. */
int wifi_rssi_socket_iface(int sock, char* iface, size_t capacity);

#endif
