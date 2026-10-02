#ifndef BT_LINK_H
#define BT_LINK_H

#include <stdint.h>

/* Bluetooth LE link between two entities: an LE L2CAP connection-oriented
 * channel on a SOCK_STREAM socket, so it reads and writes like a TCP socket
 * (SST's header-then-body reads work, and messages larger than one LE frame
 * are segmented). Linux/BlueZ only; needs root (advertising and raw HCI). */

#define BT_LINK_DEFAULT_PSM 0x80 /* LE dynamic PSMs are 0x80..0xff */

/* Advertises (connectable, undirected) until one peer connects on psm.
 * @return the connected socket, or -1. */
int bt_link_accept(unsigned psm);

/* Connects to the peer's public LE address ("AA:BB:CC:DD:EE:FF") on psm.
 * @return the connected socket, or -1. */
int bt_link_connect(const char* peer, unsigned psm);

/* 1 if sock is a Bluetooth socket, else 0. */
int bt_link_is_bluetooth(int sock);

/* This controller's RSSI (dBm) for the LE link that carries sock.
 * @return 0, or -1 if it can't be read. */
int bt_link_read_rssi(int sock, int8_t* rssi);

#endif
