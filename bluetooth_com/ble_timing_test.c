/*
 * Standalone BLE connection-based timing test between two Raspberry Pis,
 * independent of SST (uses a fixed shared test key so the HMAC verifies).
 *
 * The responder advertises and accepts an LE L2CAP channel (bt_link.c); the
 * initiator connects by address, drives the connection interval down to the
 * requested value, and reads back the negotiated interval. They then run the
 * authenticated nonce->HMAC response-time exchange of ble_timing.c and each
 * verifier reports its own RTT distribution. This measures the BLE
 * connection-based challenge--response RTT (for the Direct/Relay comparison);
 * it is NOT the RSSI mechanism, which is kept as the baseline.
 *
 * Usage (root: advertising + raw HCI need CAP_NET_ADMIN):
 *   ble_timing_test --role responder
 *   ble_timing_test --role initiator --peer D8:3A:DD:2B:3A:03
 * Options: --rounds N (20) --psm N (0x80) --interval-units U (6 = 7.5 ms)
 *          --deadline-us US (0 = measure only) --recv-timeout-us US (2000000)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ble_timing.h"
#include "bt_link.h"

/* Fixed 32-byte test MAC key shared by both roles (standalone test only; the
 * real mechanism binds to the SST session MAC key). */
static void test_key(session_key_t* k) {
    memset(k, 0, sizeof(*k));
    for (unsigned i = 0; i < MAC_KEY_SIZE; ++i) k->mac_key[i] = (unsigned char)(0x5a ^ i);
    k->mac_key_size = MAC_KEY_SIZE;
}

int main(int argc, char** argv) {
    int initiator = -1;
    const char* peer = NULL;
    unsigned rounds = 20, psm = BT_LINK_DEFAULT_PSM;
    unsigned interval_units = 6; /* 6 * 1.25 ms = 7.5 ms */
    unsigned long long deadline_us = 0, recv_timeout_us = 2000000ULL, prover_delay_us = 0;
    for (int i = 1; i < argc; ++i) {
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(argv[i], "--role") && v)
            initiator = !strcmp(v, "initiator") ? 1 : !strcmp(v, "responder") ? 0 : -1;
        else if (!strcmp(argv[i], "--peer") && v) peer = v;
        else if (!strcmp(argv[i], "--rounds") && v) rounds = (unsigned)atoi(v);
        else if (!strcmp(argv[i], "--psm") && v) psm = (unsigned)strtoul(v, NULL, 0);
        else if (!strcmp(argv[i], "--interval-units") && v) interval_units = (unsigned)atoi(v);
        else if (!strcmp(argv[i], "--deadline-us") && v) deadline_us = strtoull(v, NULL, 10);
        else if (!strcmp(argv[i], "--recv-timeout-us") && v) recv_timeout_us = strtoull(v, NULL, 10);
        else if (!strcmp(argv[i], "--prover-delay-us") && v) prover_delay_us = strtoull(v, NULL, 10);
        else { fprintf(stderr, "bad arg: %s\n", argv[i]); return 1; }
        if (v) ++i;
    }
    if (initiator < 0 || (initiator && !peer) || rounds < 1 ||
        rounds > BLE_TIMING_MAX_ROUNDS || psm < 0x80 || psm > 0xff) {
        fprintf(stderr,
                "Usage: %s --role initiator|responder [--peer BDADDR]\n"
                "  [--rounds N] [--psm N] [--interval-units U]\n"
                "  [--deadline-us US] [--recv-timeout-us US]\n",
                argv[0]);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    int sock;
    if (initiator) {
        printf("LOG: connecting to %s on LE PSM 0x%02x...\n", peer, psm);
        sock = bt_link_connect(peer, psm);
    } else {
        printf("LOG: advertising; waiting on LE PSM 0x%02x...\n", psm);
        sock = bt_link_accept(psm);
    }
    if (sock < 0) return 1;
    printf("LOG: connected\n");

    uint16_t got = 0;
    if (initiator) {
        if (ble_timing_request_interval(sock, (uint16_t)interval_units, &got) == 0)
            printf("LOG: BLE CONN INTERVAL requested_units=%u negotiated_units=%u "
                   "requested_ms=%.2f negotiated_ms=%.2f\n",
                   interval_units, got, interval_units * 1.25, got * 1.25);
        else
            printf("LOG: BLE CONN INTERVAL requested_units=%u negotiated=unknown "
                   "(update/readback failed)\n", interval_units);
    }

    session_key_t key;
    test_key(&key);
    ble_timing_config cfg = {
        .mode = deadline_us ? BLE_TIMING_MODE_ENFORCE : BLE_TIMING_MODE_MEASURE,
        .rounds = rounds,
        .deadline_us = deadline_us,
        .recv_timeout_us = recv_timeout_us,
        .prover_delay_us = prover_delay_us,
    };
    ble_timing_result res;
    int rc = ble_timing_run(sock, &key, initiator, initiator ? "initiator" : "responder",
                            &cfg, &res);

    /* Print the verifier's own per-round RTTs (CSV-ish) for distribution. */
    printf("LOG: BLE TIMING TEST: role=%s rc=%d valid=%u within=%u "
           "min_us=%llu median_us=%llu max_us=%llu\n",
           initiator ? "initiator" : "responder", rc, res.valid,
           res.within_deadline, (unsigned long long)res.min_rtt_us,
           (unsigned long long)res.median_rtt_us, (unsigned long long)res.max_rtt_us);
    for (unsigned i = 0; i < res.valid && i < BLE_TIMING_MAX_ROUNDS; ++i)
        printf("RTT_US,%u,%llu\n", i, (unsigned long long)res.rtt_us[i]);

    close(sock);
    return rc < 0 ? 1 : 0;
}
