/* Authenticated Wi-Fi response-time check; see wifi_timing.h. */
#include "wifi_timing.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../physical_com/freshness.h"
#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

/* Wire messages, each sent as one plaintext frame on the measurement socket
 * (little-endian round):
 *   challenge: 'W' 'T' 'C' VER | dir(1) | round(2) | nonce(16)
 *   response : 'W' 'T' 'R' VER | dir(1) | round(2) | tag(16)                */
#define WT_VER 1
#define WT_HDR 4
#define WT_CHAL_SIZE (WT_HDR + 1 + 2 + WIFI_TIMING_NONCE_SIZE)
#define WT_RESP_SIZE (WT_HDR + 1 + 2 + WIFI_TIMING_TAG_SIZE)
static const unsigned char WT_LABEL[] = "IoTAuth wifi timing v1";

/* Writes exactly `n` bytes. @return 0, or -1 on error. */
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

/* Reads exactly `n` bytes. @return 0, or -1 on timeout (SO_RCVTIMEO), EOF or
 * error. */
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
static int wt_tag(const session_key_t* key, unsigned dir, unsigned round,
                  const unsigned char nonce[WIFI_TIMING_NONCE_SIZE],
                  unsigned char tag[WIFI_TIMING_TAG_SIZE]) {
    unsigned char in[sizeof(WT_LABEL) - 1 + 1 + 2 + WIFI_TIMING_NONCE_SIZE];
    unsigned char digest[32];
    size_t n = 0;
    memcpy(in + n, WT_LABEL, sizeof(WT_LABEL) - 1);
    n += sizeof(WT_LABEL) - 1;
    in[n++] = (unsigned char)dir;
    in[n++] = (unsigned char)(round & 0xff);
    in[n++] = (unsigned char)((round >> 8) & 0xff);
    memcpy(in + n, nonce, WIFI_TIMING_NONCE_SIZE);
    n += WIFI_TIMING_NONCE_SIZE;
    unsigned dl = 0;
    int ok = HMAC(EVP_sha256(), key->mac_key, key->mac_key_size, in, n, digest,
                  &dl) != NULL &&
             dl == sizeof(digest);
    if (ok) memcpy(tag, digest, WIFI_TIMING_TAG_SIZE);
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok ? 0 : -1;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* This side, as prover for `dir`: answer each challenge immediately. */
static int prove_dir(int sock, const session_key_t* key, unsigned dir,
                     unsigned rounds) {
    for (unsigned i = 1; i <= rounds; ++i) {
        unsigned char chal[WT_CHAL_SIZE], resp[WT_RESP_SIZE];
        if (read_exact(sock, chal, sizeof(chal))) return -1;
        if (chal[0] != 'W' || chal[1] != 'T' || chal[2] != 'C' ||
            chal[3] != WT_VER)
            return -1;
        unsigned r_dir = chal[WT_HDR];
        unsigned r_round = chal[WT_HDR + 1] | (chal[WT_HDR + 2] << 8);
        if (r_dir != dir || r_round != i) return -1;
        resp[0] = 'W'; resp[1] = 'T'; resp[2] = 'R'; resp[3] = WT_VER;
        resp[WT_HDR] = (unsigned char)dir;
        resp[WT_HDR + 1] = (unsigned char)(i & 0xff);
        resp[WT_HDR + 2] = (unsigned char)((i >> 8) & 0xff);
        if (wt_tag(key, dir, i, chal + WT_HDR + 3, resp + WT_HDR + 3) ||
            write_all(sock, resp, sizeof(resp)))
            return -1;
    }
    return 0;
}

/* This side, as verifier for `dir`: challenge and time each response.
 * Logs each round. Sets *aborted on a mismatch/auth/IO/timeout failure. */
static void verify_dir(int sock, const session_key_t* key, unsigned dir,
                       const wifi_timing_config* c, const char* role_name,
                       const char* iface, const char* local_addr,
                       const char* peer_addr, wifi_timing_result* out,
                       int* aborted) {
    for (unsigned i = 1; i <= c->rounds; ++i) {
        unsigned char chal[WT_CHAL_SIZE], resp[WT_RESP_SIZE],
            expect[WIFI_TIMING_TAG_SIZE];
        chal[0] = 'W'; chal[1] = 'T'; chal[2] = 'C'; chal[3] = WT_VER;
        chal[WT_HDR] = (unsigned char)dir;
        chal[WT_HDR + 1] = (unsigned char)(i & 0xff);
        chal[WT_HDR + 2] = (unsigned char)((i >> 8) & 0xff);
        if (RAND_bytes(chal + WT_HDR + 3, WIFI_TIMING_NONCE_SIZE) != 1) {
            *aborted = 1; return;
        }
        uint64_t t0 = 0, t1 = 0;
        const char* failure = "none";
        int valid = 0, within = 0;
        uint64_t rtt = 0;
        if (freshness_now_us(&t0) || write_all(sock, chal, sizeof(chal))) {
            failure = "io"; *aborted = 1;
        } else if (read_exact(sock, resp, sizeof(resp))) {
            failure = "timeout"; *aborted = 1; /* no/late response or IO */
        } else {
            freshness_now_us(&t1);
            rtt = t1 - t0;
            unsigned r_dir = resp[WT_HDR];
            unsigned r_round = resp[WT_HDR + 1] | (resp[WT_HDR + 2] << 8);
            if (resp[0] != 'W' || resp[1] != 'T' || resp[2] != 'R' ||
                resp[3] != WT_VER || r_dir != dir || r_round != i) {
                failure = "mismatch"; *aborted = 1;
            } else if (wt_tag(key, dir, i, chal + WT_HDR + 3, expect) ||
                       CRYPTO_memcmp(expect, resp + WT_HDR + 3,
                                     WIFI_TIMING_TAG_SIZE)) {
                failure = "auth"; *aborted = 1;
            } else {
                valid = 1;
                out->valid++;
                if (out->rounds_completed < WIFI_TIMING_MAX_ROUNDS)
                    out->rtt_us[out->rounds_completed] = rtt;
                within = c->deadline_us && rtt <= c->deadline_us;
                if (c->deadline_us && within) out->within_deadline++;
                if (c->deadline_us && !within) failure = "late";
            }
        }
        out->rounds_completed++;
        if (c->deadline_us)
            SST_print_log(
                "WIFI TIMING round=%u dir=%u role=verifier mode=%s "
                "interface=%s local=%s peer=%s response_time_us=%llu "
                "response_valid=%d within_deadline=%d deadline_us=%llu "
                "failure=%s",
                i, dir,
                c->mode == WIFI_TIMING_MODE_ENFORCE ? "enforce" : "measure",
                iface, local_addr, peer_addr, (unsigned long long)rtt, valid,
                within, (unsigned long long)c->deadline_us, failure);
        else
            SST_print_log(
                "WIFI TIMING round=%u dir=%u role=verifier mode=measure "
                "interface=%s local=%s peer=%s response_time_us=%llu "
                "response_valid=%d within_deadline=null deadline_us=null "
                "failure=%s",
                i, dir, iface, local_addr, peer_addr, (unsigned long long)rtt,
                valid, failure);
        (void)role_name;
        if (*aborted) return;
    }
}

int wifi_timing_run(int sock, const session_key_t* key, int initiator,
                    const char* role_name, const char* iface,
                    const char* local_addr, const char* peer_addr,
                    const wifi_timing_config* c, wifi_timing_result* r) {
    if (sock < 0 || !key || !c || !r) return -1;
    if (c->rounds < 1 || c->rounds > WIFI_TIMING_MAX_ROUNDS ||
        c->recv_timeout_us == 0)
        return -1;
    memset(r, 0, sizeof(*r));

    /* Bound every receive on the measurement socket for the whole exchange.
     * The receive timeout must exceed any response time we still want to
     * record in measure mode; it is distinct from the acceptance deadline. */
    session_ctl_timeout saved;
    unsigned tmo_ms = (unsigned)((c->recv_timeout_us + 999) / 1000);
    if (session_ctl_timeout_set(sock, tmo_ms, &saved)) return -1;

    int aborted = 0;
    if (initiator) {
        verify_dir(sock, key, WIFI_TIMING_DIR_REQUESTER_VERIFIES, c, role_name,
                   iface, local_addr, peer_addr, r, &aborted);
        if (!aborted &&
            prove_dir(sock, key, WIFI_TIMING_DIR_TARGET_VERIFIES, c->rounds))
            aborted = 1;
    } else {
        if (prove_dir(sock, key, WIFI_TIMING_DIR_REQUESTER_VERIFIES, c->rounds))
            aborted = 1;
        if (!aborted)
            verify_dir(sock, key, WIFI_TIMING_DIR_TARGET_VERIFIES, c, role_name,
                       iface, local_addr, peer_addr, r, &aborted);
    }
    session_ctl_timeout_restore(sock, &saved);

    if (r->valid) {
        uint64_t sorted[WIFI_TIMING_MAX_ROUNDS];
        unsigned n = r->rounds_completed < WIFI_TIMING_MAX_ROUNDS
                         ? r->rounds_completed
                         : WIFI_TIMING_MAX_ROUNDS;
        /* only the valid ones were stored, in order, up to n */
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
    } else if (c->mode == WIFI_TIMING_MODE_ENFORCE) {
        /* Simple rule: every required round valid and within the deadline. */
        r->local_pass =
            r->valid == c->rounds && r->within_deadline == c->rounds;
        rc = r->local_pass ? 1 : 0;
    } else {
        /* Measure mode never fails the overall outcome; every round was valid
         * (any invalid response already aborted above). */
        r->local_pass = 1;
        rc = 1;
    }
    SST_print_log(
        "WIFI TIMING: role=%s mode=%s rounds=%u valid=%u within_deadline=%u "
        "min_us=%llu median_us=%llu max_us=%llu deadline_us=%llu result=%s",
        initiator ? "initiator" : "responder",
        c->mode == WIFI_TIMING_MODE_ENFORCE ? "enforce" : "measure", c->rounds,
        r->valid, r->within_deadline, (unsigned long long)r->min_rtt_us,
        (unsigned long long)r->median_rtt_us, (unsigned long long)r->max_rtt_us,
        (unsigned long long)c->deadline_us,
        rc == 1 ? "PASS" : rc == 0 ? "FAIL" : "ABORT");
    return rc;
}
