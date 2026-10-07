#ifndef BT_ADV_RADIO_H
#define BT_ADV_RADIO_H

#include "ble_adv_rssi.h"

/* ble_adv_radio on this host's Bluetooth controller through raw HCI
 * (BlueZ; needs CAP_NET_ADMIN): non-connectable advertising of the tag as
 * manufacturer-specific data, and passive scanning that reports each
 * received advertising packet carrying it with that packet's RSSI. Works
 * alongside an LE connection on the same controller (Raspberry Pi 4). */
typedef struct bt_adv_radio bt_adv_radio;

bt_adv_radio* bt_adv_radio_open(void);
void bt_adv_radio_bind(bt_adv_radio* radio, ble_adv_radio* out);
/* Stops any advertising or scanning it started. */
void bt_adv_radio_close(bt_adv_radio* radio);

#endif
