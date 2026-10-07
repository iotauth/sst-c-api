/* BLE advertising/scanning radio over raw HCI; see bt_adv_radio.h. */
#include "bt_adv_radio.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../physical_com/freshness.h"

#define HCI_TIMEOUT_MS 1000
/* Legacy non-connectable advertising may not be faster than 100 ms. */
#define ADV_INTERVAL 0x00A0 /* x 0.625 ms */
/* Continuous scanning: window = interval = 10 ms. */
#define SCAN_INTERVAL 0x0010
/* AD structure: length | 0xFF (manufacturer data) | company 0xFFFF (the
 * Bluetooth SIG's ID reserved for testing) | tag. */
#define AD_SIZE (4 + BLE_ADV_RSSI_TAG_SIZE)

struct bt_adv_radio {
    int dd;
    int advertising, scanning;
    struct hci_filter scan_filter;
};

/* @return 0 when the controller accepted the command, else -1. */
static int le_cmd(int dd, uint16_t ocf, void* param, int plen) {
    uint8_t status = 0xff;
    struct hci_request rq = {.ogf = OGF_LE_CTL,
                             .ocf = ocf,
                             .cparam = param,
                             .clen = plen,
                             .rparam = &status,
                             .rlen = 1};
    return hci_send_req(dd, &rq, HCI_TIMEOUT_MS) < 0 || status ? -1 : 0;
}

static void ad_bytes(const unsigned char* tag, uint8_t* ad) {
    ad[0] = AD_SIZE - 1;
    ad[1] = 0xff;
    ad[2] = 0xff;
    ad[3] = 0xff;
    memcpy(ad + 4, tag, BLE_ADV_RSSI_TAG_SIZE);
}

static int stop_advertising(void* ctx) {
    bt_adv_radio* r = ctx;
    le_set_advertise_enable_cp off = {0};
    int rc = le_cmd(r->dd, OCF_LE_SET_ADVERTISE_ENABLE, &off, sizeof(off));
    int was = r->advertising;
    r->advertising = 0;
    return was ? rc : 0;
}

static int advertise(void* ctx, const unsigned char* tag) {
    bt_adv_radio* r = ctx;
    /* Parameters and data change only while advertising is off; it may
     * already be off ("command disallowed"). */
    stop_advertising(r);
    le_set_advertising_parameters_cp p;
    memset(&p, 0, sizeof(p));
    p.min_interval = htobs(ADV_INTERVAL);
    p.max_interval = htobs(ADV_INTERVAL);
    p.advtype = 0x03; /* ADV_NONCONN_IND */
    p.chan_map = 0x07;
    le_set_advertising_data_cp d;
    memset(&d, 0, sizeof(d));
    ad_bytes(tag, d.data);
    d.length = AD_SIZE;
    le_set_advertise_enable_cp on = {1};
    if (le_cmd(r->dd, OCF_LE_SET_ADVERTISING_PARAMETERS, &p, sizeof(p)) ||
        le_cmd(r->dd, OCF_LE_SET_ADVERTISING_DATA, &d, sizeof(d)) ||
        le_cmd(r->dd, OCF_LE_SET_ADVERTISE_ENABLE, &on, sizeof(on))) {
        fprintf(stderr, "Bluetooth: could not start advertising.\n");
        return -1;
    }
    r->advertising = 1;
    return 0;
}

static int scan_stop(void* ctx) {
    bt_adv_radio* r = ctx;
    le_set_scan_enable_cp off = {0, 0};
    int rc = le_cmd(r->dd, OCF_LE_SET_SCAN_ENABLE, &off, sizeof(off));
    int was = r->scanning;
    r->scanning = 0;
    return was ? rc : 0;
}

static int scan_begin(void* ctx) {
    bt_adv_radio* r = ctx;
    scan_stop(r); /* may already be off */
    le_set_scan_parameters_cp sp;
    memset(&sp, 0, sizeof(sp));
    sp.type = 0x00; /* passive: the advertising packets are the samples */
    sp.interval = htobs(SCAN_INTERVAL);
    sp.window = htobs(SCAN_INTERVAL);
    le_set_scan_enable_cp on = {1, 0}; /* every packet, no duplicate filter */
    if (le_cmd(r->dd, OCF_LE_SET_SCAN_PARAMETERS, &sp, sizeof(sp)) ||
        le_cmd(r->dd, OCF_LE_SET_SCAN_ENABLE, &on, sizeof(on)) ||
        /* hci_send_req sets its own filter while it waits; take LE meta
         * events again after it. */
        setsockopt(r->dd, SOL_HCI, HCI_FILTER, &r->scan_filter,
                   sizeof(r->scan_filter))) {
        fprintf(stderr, "Bluetooth: could not start scanning.\n");
        return -1;
    }
    r->scanning = 1;
    return 0;
}

/* The first report in an LE Advertising Report event that carries `tag`.
 * @return 1 with its RSSI, else 0. */
static int find_tag(const uint8_t* buf, int len, const unsigned char* tag,
                    int8_t* rssi) {
    /* packet type | event code | length | subevent | report count */
    if (len < 5 || buf[0] != HCI_EVENT_PKT || buf[1] != EVT_LE_META_EVENT ||
        buf[3] != EVT_LE_ADVERTISING_REPORT)
        return 0;
    uint8_t expected[AD_SIZE];
    ad_bytes(tag, expected);
    int off = 5;
    for (unsigned k = 0; k < buf[4]; ++k) {
        /* event type | address type | address(6) | data length | data |
         * RSSI */
        if (off + 9 > len) return 0;
        int dlen = buf[off + 8];
        if (off + 9 + dlen + 1 > len) return 0;
        const uint8_t* data = buf + off + 9;
        /* The tag's AD structure, anywhere in the data. */
        for (int i = 0; i + AD_SIZE <= dlen; i += data[i] + 1) {
            if (data[i] == 0) break;
            if (!memcmp(data + i, expected, AD_SIZE)) {
                *rssi = (int8_t)data[dlen];
                return 1;
            }
        }
        off += 9 + dlen + 1;
    }
    return 0;
}

static int scan_next(void* ctx, const unsigned char* tag, uint64_t deadline_us,
                     int8_t* rssi) {
    bt_adv_radio* r = ctx;
    for (;;) {
        uint64_t now;
        if (freshness_now_us(&now)) return -1;
        if (now >= deadline_us) return 0;
        uint64_t wait_ms = (deadline_us - now + 999) / 1000;
        struct pollfd p = {.fd = r->dd, .events = POLLIN};
        int n = poll(&p, 1, wait_ms > 1000 ? 1000 : (int)wait_ms);
        if (n < 0 && errno != EINTR) return -1;
        if (n <= 0) continue;
        uint8_t buf[HCI_MAX_EVENT_SIZE];
        ssize_t got = read(r->dd, buf, sizeof(buf));
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return -1;
        }
        if (find_tag(buf, (int)got, tag, rssi)) return 1;
    }
}

bt_adv_radio* bt_adv_radio_open(void) {
    int dev = hci_get_route(NULL);
    int dd = dev < 0 ? -1 : hci_open_dev(dev);
    if (dd < 0) {
        perror("Bluetooth: no usable HCI device (is it unblocked and up?)");
        return NULL;
    }
    bt_adv_radio* r = calloc(1, sizeof(*r));
    if (!r) {
        hci_close_dev(dd);
        return NULL;
    }
    r->dd = dd;
    hci_filter_clear(&r->scan_filter);
    hci_filter_set_ptype(HCI_EVENT_PKT, &r->scan_filter);
    hci_filter_set_event(EVT_LE_META_EVENT, &r->scan_filter);
    return r;
}

void bt_adv_radio_bind(bt_adv_radio* r, ble_adv_radio* out) {
    out->ctx = r;
    out->advertise = advertise;
    out->stop_advertising = stop_advertising;
    out->scan_begin = scan_begin;
    out->scan_next = scan_next;
    out->scan_stop = scan_stop;
}

void bt_adv_radio_close(bt_adv_radio* r) {
    if (!r) return;
    if (r->advertising) stop_advertising(r);
    if (r->scanning) scan_stop(r);
    hci_close_dev(r->dd);
    free(r);
}
