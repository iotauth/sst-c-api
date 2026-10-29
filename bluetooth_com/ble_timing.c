/* Authenticated BLE connection response-time check; see ble_timing.h.
 * The challenge/response exchange mirrors wifi_timing.c (a connected stream
 * socket + session MAC key), with a BLE-specific domain label and wire tag,
 * plus a helper to drive the LE connection interval down and read it back. */
#include "ble_timing.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../physical_com/freshness.h"
#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

/* Wire messages, each one plaintext frame on the BLE L2CAP socket (LE round):
 *   challenge: 'B' 'L' 'C' VER | dir(1) | round(2) | nonce(16)
 *   response : 'B' 'L' 'R' VER | dir(1) | round(2) | tag(16)                */
#define BT_VER 1
#define BT_HDR 4
#define BT_CHAL_SIZE (BT_HDR + 1 + 2 + BLE_TIMING_NONCE_SIZE)
#define BT_RESP_SIZE (BT_HDR + 1 + 2 + BLE_TIMING_TAG_SIZE)
static const unsigned char BT_LABEL[] = "IoTAuth ble timing v1";

static int write_all(int fd, const unsigned char* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int read_exact(int fd, unsigned char* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1; /* includes EAGAIN/EWOULDBLOCK: the receive timed out */
        }
        if (r == 0) return -1; /* peer closed */
        off += (size_t)r;
    }
    return 0;
}

/* tag = HMAC-SHA-256(session MAC key, label | dir | round | nonce)[:16]. */
static int bt_tag(const session_key_t* key, unsigned dir, unsigned round,
                  const unsigned char nonce[BLE_TIMING_NONCE_SIZE],
                  unsigned char tag[BLE_TIMING_TAG_SIZE]) {
    unsigned char in[sizeof(BT_LABEL) - 1 + 1 + 2 + BLE_TIMING_NONCE_SIZE];
    unsigned char digest[32];
    size_t n = 0;
    memcpy(in + n, BT_LABEL, sizeof(BT_LABEL) - 1);
    n += sizeof(BT_LABEL) - 1;
    in[n++] = (unsigned char)dir;
    in[n++] = (unsigned char)(round & 0xff);
    in[n++] = (unsigned char)((round >> 8) & 0xff);
    memcpy(in + n, nonce, BLE_TIMING_NONCE_SIZE);
    n += BLE_TIMING_NONCE_SIZE;
    unsigned dl = 0;
    int ok = HMAC(EVP_sha256(), key->mac_key, key->mac_key_size, in, n, digest,
                  &dl) != NULL &&
             dl == sizeof(digest);
    if (ok) memcpy(tag, digest, BLE_TIMING_TAG_SIZE);
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok ? 0 : -1;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* This side, as prover for `dir`: answer each challenge, optionally after an
 * artificial delay (used to emulate a relay that adds `delay_us` round-trip). */
static int prove_dir(int sock, const session_key_t* key, unsigned dir,
                     unsigned rounds, uint64_t delay_us) {
    for (unsigned i = 1; i <= rounds; ++i) {
        unsigned char chal[BT_CHAL_SIZE], resp[BT_RESP_SIZE];
        if (read_exact(sock, chal, sizeof(chal))) return -1;
        if (chal[0] != 'B' || chal[1] != 'L' || chal[2] != 'C' ||
            chal[3] != BT_VER)
            return -1;
        unsigned r_dir = chal[BT_HDR];
        unsigned r_round = chal[BT_HDR + 1] | (chal[BT_HDR + 2] << 8);
        if (r_dir != dir || r_round != i) return -1;
        resp[0] = 'B'; resp[1] = 'L'; resp[2] = 'R'; resp[3] = BT_VER;
        resp[BT_HDR] = (unsigned char)dir;
        resp[BT_HDR + 1] = (unsigned char)(i & 0xff);
        resp[BT_HDR + 2] = (unsigned char)((i >> 8) & 0xff);
        if (bt_tag(key, dir, i, chal + BT_HDR + 3, resp + BT_HDR + 3))
            return -1;
        for (uint64_t left = delay_us; left > 0;) {  /* usleep bounded to <1e6 */
            useconds_t chunk = left > 500000 ? 500000 : (useconds_t)left;
            usleep(chunk); left -= chunk;
        }
        if (write_all(sock, resp, sizeof(resp))) return -1;
    }
    return 0;
}

/* This side, as verifier for `dir`: challenge and time each response. */
static void verify_dir(int sock, const session_key_t* key, unsigned dir,
                       const ble_timing_config* c, const char* role_name,
                       ble_timing_result* out, int* aborted) {
    for (unsigned i = 1; i <= c->rounds; ++i) {
        unsigned char chal[BT_CHAL_SIZE], resp[BT_RESP_SIZE],
            expect[BLE_TIMING_TAG_SIZE];
        chal[0] = 'B'; chal[1] = 'L'; chal[2] = 'C'; chal[3] = BT_VER;
        chal[BT_HDR] = (unsigned char)dir;
        chal[BT_HDR + 1] = (unsigned char)(i & 0xff);
        chal[BT_HDR + 2] = (unsigned char)((i >> 8) & 0xff);
        if (RAND_bytes(chal + BT_HDR + 3, BLE_TIMING_NONCE_SIZE) != 1) {
            *aborted = 1; return;
        }
        uint64_t t0 = 0, t1 = 0, rtt = 0;
        const char* failure = "none";
        int valid = 0, within = 0;
        if (freshness_now_us(&t0) || write_all(sock, chal, sizeof(chal))) {
            failure = "io"; *aborted = 1;
        } else if (read_exact(sock, resp, sizeof(resp))) {
            failure = "timeout"; *aborted = 1;
        } else {
            freshness_now_us(&t1);
            rtt = t1 - t0;
            unsigned r_dir = resp[BT_HDR];
            unsigned r_round = resp[BT_HDR + 1] | (resp[BT_HDR + 2] << 8);
            if (resp[0] != 'B' || resp[1] != 'L' || resp[2] != 'R' ||
                resp[3] != BT_VER || r_dir != dir || r_round != i) {
                failure = "mismatch"; *aborted = 1;
            } else if (bt_tag(key, dir, i, chal + BT_HDR + 3, expect) ||
                       CRYPTO_memcmp(expect, resp + BT_HDR + 3,
                                     BLE_TIMING_TAG_SIZE)) {
                failure = "auth"; *aborted = 1;
            } else {
                valid = 1;
                out->valid++;
                if (out->rounds_completed < BLE_TIMING_MAX_ROUNDS)
                    out->rtt_us[out->rounds_completed] = rtt;
                within = c->deadline_us && rtt <= c->deadline_us;
                if (c->deadline_us && within) out->within_deadline++;
                if (c->deadline_us && !within) failure = "late";
            }
        }
        out->rounds_completed++;
        if (c->deadline_us)
            SST_print_log(
                "BLE TIMING round=%u dir=%u role=verifier mode=%s "
                "response_time_us=%llu response_valid=%d within_deadline=%d "
                "deadline_us=%llu failure=%s",
                i, dir,
                c->mode == BLE_TIMING_MODE_ENFORCE ? "enforce" : "measure",
                (unsigned long long)rtt, valid, within,
                (unsigned long long)c->deadline_us, failure);
        else
            SST_print_log(
                "BLE TIMING round=%u dir=%u role=verifier mode=measure "
                "response_time_us=%llu response_valid=%d within_deadline=null "
                "deadline_us=null failure=%s",
                i, dir, (unsigned long long)rtt, valid, failure);
        (void)role_name;
        if (*aborted) return;
    }
}

int ble_timing_run(int sock, const session_key_t* key, int initiator,
                   const char* role_name, const ble_timing_config* c,
                   ble_timing_result* r) {
    if (sock < 0 || !key || !c || !r) return -1;
    if (c->rounds < 1 || c->rounds > BLE_TIMING_MAX_ROUNDS ||
        c->recv_timeout_us == 0)
        return -1;
    memset(r, 0, sizeof(*r));

    session_ctl_timeout saved;
    unsigned tmo_ms = (unsigned)((c->recv_timeout_us + 999) / 1000);
    if (session_ctl_timeout_set(sock, tmo_ms, &saved)) return -1;

    int aborted = 0;
    if (initiator) {
        verify_dir(sock, key, BLE_TIMING_DIR_REQUESTER_VERIFIES, c, role_name,
                   r, &aborted);
        if (!aborted &&
            prove_dir(sock, key, BLE_TIMING_DIR_TARGET_VERIFIES, c->rounds, c->prover_delay_us))
            aborted = 1;
    } else {
        if (prove_dir(sock, key, BLE_TIMING_DIR_REQUESTER_VERIFIES, c->rounds, c->prover_delay_us))
            aborted = 1;
        if (!aborted)
            verify_dir(sock, key, BLE_TIMING_DIR_TARGET_VERIFIES, c, role_name,
                       r, &aborted);
    }
    session_ctl_timeout_restore(sock, &saved);

    if (r->valid) {
        uint64_t sorted[BLE_TIMING_MAX_ROUNDS];
        unsigned n = r->rounds_completed < BLE_TIMING_MAX_ROUNDS
                         ? r->rounds_completed
                         : BLE_TIMING_MAX_ROUNDS;
        unsigned m = r->valid < n ? r->valid : n;
        memcpy(sorted, r->rtt_us, m * sizeof(uint64_t));
        qsort(sorted, m, sizeof(uint64_t), cmp_u64);
        if (m) {
            r->min_rtt_us = sorted[0];
            r->max_rtt_us = sorted[m - 1];
            r->median_rtt_us = m % 2 ? sorted[m / 2]
                                     : (sorted[m / 2 - 1] + sorted[m / 2]) / 2;
        }
    }

    int rc;
    if (aborted) {
        rc = -1;
        r->local_pass = 0;
    } else if (c->mode == BLE_TIMING_MODE_ENFORCE) {
        r->local_pass =
            r->valid == c->rounds && r->within_deadline == c->rounds;
        rc = r->local_pass ? 1 : 0;
    } else {
        r->local_pass = 1;
        rc = 1;
    }
    SST_print_log(
        "BLE TIMING: role=%s mode=%s rounds=%u valid=%u within_deadline=%u "
        "min_us=%llu median_us=%llu max_us=%llu deadline_us=%llu result=%s",
        initiator ? "initiator" : "responder",
        c->mode == BLE_TIMING_MODE_ENFORCE ? "enforce" : "measure", c->rounds,
        r->valid, r->within_deadline, (unsigned long long)r->min_rtt_us,
        (unsigned long long)r->median_rtt_us, (unsigned long long)r->max_rtt_us,
        (unsigned long long)c->deadline_us,
        rc == 1 ? "PASS" : rc == 0 ? "FAIL" : "ABORT");
    return rc;
}

/* ---- LE connection interval request + readback (central side) ---- */

int ble_timing_request_interval(int sock, uint16_t want_units,
                                uint16_t* got_units) {
    if (sock < 0 || !got_units) return -1;
    struct l2cap_conninfo ci;
    socklen_t len = sizeof(ci);
    if (getsockopt(sock, SOL_L2CAP, L2CAP_CONNINFO, &ci, &len)) {
        perror("BLE timing: L2CAP_CONNINFO");
        return -1;
    }
    uint16_t handle = ci.hci_handle;

    int dev = hci_get_route(NULL);
    int dd = dev < 0 ? -1 : hci_open_dev(dev);
    if (dd < 0) {
        perror("BLE timing: no usable HCI device");
        return -1;
    }

    /* Capture LE Meta events on a copy filter so we can read the negotiated
     * interval from LE Connection Update Complete. */
    struct hci_filter nf, of;
    socklen_t olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        hci_close_dev(dd);
        return -1;
    }
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);
    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        hci_close_dev(dd);
        return -1;
    }

    le_connection_update_cp cp;
    memset(&cp, 0, sizeof(cp));
    cp.handle = handle;
    cp.min_interval = htobs(want_units);
    cp.max_interval = htobs(want_units);
    cp.latency = htobs(0);
    cp.supervision_timeout = htobs(0x00C8); /* 2 s */
    cp.min_ce_length = htobs(0);
    cp.max_ce_length = htobs(0);

    int rc = -1;
    if (hci_send_cmd(dd, OGF_LE_CTL, OCF_LE_CONN_UPDATE, sizeof(cp), &cp) < 0) {
        perror("BLE timing: LE Connection Update");
        goto out;
    }

    /* Wait (bounded) for LE Connection Update Complete for our handle. */
    for (int tries = 0; tries < 50; ++tries) {
        unsigned char buf[HCI_MAX_EVENT_SIZE];
        struct timeval tv = {.tv_sec = 2};
        setsockopt(dd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int n = read(dd, buf, sizeof(buf));
        if (n < (1 + HCI_EVENT_HDR_SIZE + 1)) {
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            break;
        }
        /* buf[0]=HCI_EVENT_PKT, [1]=event code, [2]=plen, [3]=LE subevent */
        unsigned char* body = buf + (1 + HCI_EVENT_HDR_SIZE);
        if (buf[1] != EVT_LE_META_EVENT) continue;
        if (body[0] != EVT_LE_CONN_UPDATE_COMPLETE) continue;
        evt_le_connection_update_complete* ev =
            (evt_le_connection_update_complete*)(body + 1);
        if (btohs(ev->handle) != handle) continue;
        if (ev->status == 0) {
            *got_units = btohs(ev->interval);
            rc = 0;
        }
        break;
    }

out:
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
    hci_close_dev(dd);
    return rc;
}
