#include "bt_link.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HCI_TIMEOUT_MS 1000
#define CONNECT_TIMEOUT_S 10
/* Above the default 672, so one SST message never exceeds a single write. */
#define LINK_MTU 8192
#define RSSI_UNAVAILABLE 127

static int hci_le_cmd(int dd, uint16_t ocf, void* param, int plen) {
    uint8_t status = 0;
    struct hci_request rq = {.ogf = OGF_LE_CTL,
                             .ocf = ocf,
                             .cparam = param,
                             .clen = plen,
                             .rparam = &status,
                             .rlen = 1};
    if (hci_send_req(dd, &rq, HCI_TIMEOUT_MS) < 0) return -1;
    return status ? -status : 0;
}

/* Connectable undirected advertising every 100 ms on all three channels.
 * The initiator connects by address, so no advertising data is needed. */
static int advertise(int enable) {
    int dev = hci_get_route(NULL);
    int dd = dev < 0 ? -1 : hci_open_dev(dev);
    if (dd < 0) {
        perror("Bluetooth: no usable HCI device (is it unblocked and up?)");
        return -1;
    }
    int rc = 0;
    if (enable) {
        le_set_advertising_parameters_cp p;
        memset(&p, 0, sizeof(p));
        p.min_interval = htobs(0x00A0); /* 0.625 ms units */
        p.max_interval = htobs(0x00A0);
        p.advtype = 0x00; /* ADV_IND */
        p.own_bdaddr_type = LE_PUBLIC_ADDRESS;
        p.chan_map = 0x07;
        rc = hci_le_cmd(dd, OCF_LE_SET_ADVERTISING_PARAMETERS, &p, sizeof(p));
        if (rc)
            fprintf(stderr,
                    "Bluetooth: LE Set Advertising Parameters failed (%d)\n",
                    rc);
    }
    if (!rc) {
        le_set_advertise_enable_cp e = {.enable = (uint8_t)enable};
        rc = hci_le_cmd(dd, OCF_LE_SET_ADVERTISE_ENABLE, &e, sizeof(e));
        /* Disabling fails harmlessly once a connection already stopped it. */
        if (rc && enable)
            fprintf(stderr, "Bluetooth: LE Set Advertise Enable failed (%d)\n",
                    rc);
    }
    hci_close_dev(dd);
    return enable ? rc : 0;
}

/* BT_MODE is only accepted once the socket is bound to an LE address type;
 * without it the initiator's channel stays in basic mode (seen on 6.18: it
 * then sends frames without the LE SDU length header, which the peer
 * drops). */
static int le_socket(unsigned psm) {
    int sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_L2CAP);
    if (sock < 0) {
        perror("Bluetooth: L2CAP socket");
        return -1;
    }
    struct sockaddr_l2 addr;
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(psm);
    addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
    bacpy(&addr.l2_bdaddr, BDADDR_ANY);
    uint8_t mode = BT_MODE_LE_FLOWCTL;
    uint16_t mtu = LINK_MTU;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) ||
        setsockopt(sock, SOL_BLUETOOTH, BT_MODE, &mode, sizeof(mode)) ||
        setsockopt(sock, SOL_BLUETOOTH, BT_RCVMTU, &mtu, sizeof(mtu))) {
        perror("Bluetooth: L2CAP bind/mode/MTU");
        close(sock);
        return -1;
    }
    return sock;
}

int bt_link_accept(unsigned psm) {
    int ls = le_socket(psm);
    if (ls < 0) return -1;
    if (listen(ls, 1)) {
        perror("Bluetooth: L2CAP listen");
        close(ls);
        return -1;
    }
    if (advertise(1)) {
        close(ls);
        return -1;
    }
    int sock = accept(ls, NULL, NULL);
    advertise(0); /* the controller already stops on connection */
    close(ls);
    if (sock < 0) perror("Bluetooth: L2CAP accept");
    return sock;
}

int bt_link_connect(const char* peer, unsigned psm) {
    struct sockaddr_l2 addr;
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(psm);
    addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
    if (!peer || str2ba(peer, &addr.l2_bdaddr)) {
        fprintf(stderr, "Bluetooth: bad peer address %s\n",
                peer ? peer : "(none)");
        return -1;
    }
    int sock = le_socket(0);
    if (sock < 0) return -1;
    /* The send timeout bounds the kernel's scan-then-connect; cleared after,
     * so the session socket blocks like a TCP one. */
    struct timeval tv = {.tv_sec = CONNECT_TIMEOUT_S}, none = {0};
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) ||
        connect(sock, (struct sockaddr*)&addr, sizeof(addr)) ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &none, sizeof(none))) {
        perror("Bluetooth: L2CAP connect");
        close(sock);
        return -1;
    }
    return sock;
}

int bt_link_is_bluetooth(int sock) {
    struct sockaddr_l2 addr;
    socklen_t len = sizeof(addr);
    return sock >= 0 && !getsockname(sock, (struct sockaddr*)&addr, &len) &&
           addr.l2_family == AF_BLUETOOTH;
}

int bt_link_read_rssi(int sock, int8_t* rssi) {
    struct l2cap_conninfo ci;
    socklen_t len = sizeof(ci);
    if (getsockopt(sock, SOL_L2CAP, L2CAP_CONNINFO, &ci, &len)) {
        perror("Bluetooth: L2CAP_CONNINFO");
        return -1;
    }
    int dev = hci_get_route(NULL);
    int dd = dev < 0 ? -1 : hci_open_dev(dev);
    if (dd < 0) {
        perror("Bluetooth: no usable HCI device");
        return -1;
    }
    /* On an LE link this is absolute dBm (on BR/EDR it would only be
     * relative to the golden receive range). */
    int rc = hci_read_rssi(dd, ci.hci_handle, rssi, HCI_TIMEOUT_MS) < 0 ||
                     *rssi == RSSI_UNAVAILABLE
                 ? -1
                 : 0;
    hci_close_dev(dd);
    if (rc) fprintf(stderr, "Bluetooth: HCI Read RSSI failed\n");
    return rc;
}
