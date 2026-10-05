#include "ultrasonic_echo.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

/* TCP control messages (inside SST secure messages):
 * 'U' 'E' version type | body. */
#define MSG_INIT 1
#define MSG_READY 2
#define MSG_CHALLENGE 3
#define MSG_DONE 4
#define MSG_HEADER 4
/* INIT/READY: key_id | max_response_us | response_timeout_ms. */
#define MSG_PARAMS_SIZE (MSG_HEADER + SESSION_KEY_ID_SIZE + 4 + 4)
/* CHALLENGE: direction | nonce. */
#define MSG_CHALLENGE_SIZE (MSG_HEADER + 1 + ULTRASONIC_ECHO_NONCE_SIZE)
/* DONE: direction | verifier's verdict (informational for the prover). */
#define MSG_DONE_SIZE (MSG_HEADER + 1 + 1)
/* Every control wait spans at most the peer's audio setup or one full
 * verifier listening window, so this bounds each TCP read beyond that. */
#define CONTROL_SLACK_MS 15000u
/* Before the second direction's capture starts, lets the first prover's
 * playback and room reverberation die away. Outside any timed window. */
#define TURNAROUND_MS 300u

uint64_t ultrasonic_echo_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

const char* ultrasonic_echo_failure_name(ultrasonic_echo_failure f) {
    switch (f) {
        case ULTRASONIC_ECHO_OK:
            return "none";
        case ULTRASONIC_ECHO_NOT_RUN:
            return "not_run";
        case ULTRASONIC_ECHO_NO_RESPONSE:
            return "no_acoustic_response";
        case ULTRASONIC_ECHO_BAD_PAYLOAD:
            return "malformed_payload";
        case ULTRASONIC_ECHO_BAD_MAC:
            return "bad_mac";
        case ULTRASONIC_ECHO_LATE:
            return "too_late";
        case ULTRASONIC_ECHO_KEY_EXPIRED:
            return "key_expired";
        case ULTRASONIC_ECHO_ABORTED:
            return "aborted";
    }
    return "unknown";
}

int ultrasonic_echo_config_valid(const ultrasonic_echo_config* c) {
    return c && c->max_response_us >= 1 &&
           c->max_response_us <= ULTRASONIC_ECHO_MAX_RESPONSE_US_LIMIT &&
           c->response_timeout_ms >= 1 &&
           c->response_timeout_ms <= ULTRASONIC_ECHO_TIMEOUT_MS_LIMIT &&
           (uint64_t)c->response_timeout_ms * 1000u >= c->max_response_us;
}

/* HMAC-SHA256 with the session's MAC key over direction | nonce, truncated. */
int ultrasonic_echo_tag(const session_key_t* key, unsigned direction,
                        const unsigned char nonce[ULTRASONIC_ECHO_NONCE_SIZE],
                        unsigned char tag[ULTRASONIC_ECHO_TAG_SIZE]) {
    unsigned char input[1 + ULTRASONIC_ECHO_NONCE_SIZE], digest[32];
    if (!key || !nonce || !tag ||
        (direction != ULTRASONIC_ECHO_DIR_REQUESTER_VERIFIES &&
         direction != ULTRASONIC_ECHO_DIR_TARGET_VERIFIES))
        return -1;
    input[0] = (unsigned char)direction;
    memcpy(input + 1, nonce, ULTRASONIC_ECHO_NONCE_SIZE);
    unsigned dl = 0;
    int ok = HMAC(EVP_sha256(), key->mac_key, key->mac_key_size, input,
                  sizeof(input), digest, &dl) != NULL &&
             dl == sizeof(digest);
    if (ok) memcpy(tag, digest, ULTRASONIC_ECHO_TAG_SIZE);
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok ? 0 : -1;
}

static void put32(unsigned char* p, unsigned v) {
    for (int i = 3; i >= 0; --i) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}

static void header(unsigned char* m, unsigned char type) {
    m[0] = 'U';
    m[1] = 'E';
    m[2] = ULTRASONIC_ECHO_VERSION;
    m[3] = type;
}

static int send_msg(SST_session_ctx_t* s, unsigned char* m, unsigned len) {
    return session_ctl_send(s, m, len);
}

/* Reads exactly one secure message, which must be `len` bytes of `type`;
 * anything else (timeout, EOF, wrong type/size/order) aborts the run. */
static int recv_msg(SST_session_ctx_t* s, unsigned char type,
                    unsigned char* out, unsigned len) {
    unsigned char prefix[MSG_HEADER];
    header(prefix, type);
    return session_ctl_recv(s, prefix, sizeof(prefix), out, len,
                            "Ultrasound echo");
}

static void params_msg(unsigned char* m, unsigned char type,
                       const session_key_t* k,
                       const ultrasonic_echo_config* c) {
    header(m, type);
    memcpy(m + MSG_HEADER, k->key_id, SESSION_KEY_ID_SIZE);
    put32(m + MSG_HEADER + SESSION_KEY_ID_SIZE, c->max_response_us);
    put32(m + MSG_HEADER + SESSION_KEY_ID_SIZE + 4, c->response_timeout_ms);
}

/* This side challenges its peer and times the acoustic answer. A wrong,
 * late or missing answer is a completed (failed) direction; only TCP or
 * audio-device failures abort. */
static int run_verifier(SST_session_ctx_t* s, const ultrasonic_echo_config* c,
                        const ultrasonic_echo_audio* a, unsigned dir,
                        ultrasonic_echo_result* r) {
    unsigned char nonce[ULTRASONIC_ECHO_NONCE_SIZE], msg[MSG_CHALLENGE_SIZE];
    unsigned char heard[256], expected[ULTRASONIC_ECHO_TAG_SIZE];
    unsigned char done[MSG_DONE_SIZE];
    r->direction = dir;
    /* Capture is ready before the challenge exists, so a fast answer can't
     * be missed; nothing is flushed after the challenge goes out. */
    if (a->rx_begin(a->ctx)) {
        SST_print_error("Ultrasound echo: could not start audio capture.");
        return -1;
    }
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return -1;
    header(msg, MSG_CHALLENGE);
    msg[MSG_HEADER] = (unsigned char)dir;
    memcpy(msg + MSG_HEADER + 1, nonce, sizeof(nonce));
    uint64_t start = ultrasonic_echo_now_us();
    if (send_msg(s, msg, sizeof(msg))) return -1;
    int n = a->rx_until(a->ctx, heard, sizeof(heard),
                        start + (uint64_t)c->response_timeout_ms * 1000u);
    uint64_t end = ultrasonic_echo_now_us();
    if (n < 0) {
        SST_print_error("Ultrasound echo: audio capture failed.");
        return -1;
    }
    if (n == 0) {
        r->failure = ULTRASONIC_ECHO_NO_RESPONSE;
    } else {
        r->decoded = 1;
        r->elapsed_us = end - start;
        if (n != ULTRASONIC_ECHO_PAYLOAD_SIZE ||
            heard[0] != ULTRASONIC_ECHO_VERSION || heard[1] != dir) {
            r->failure = ULTRASONIC_ECHO_BAD_PAYLOAD;
        } else if (ultrasonic_echo_tag(&s->s_key, dir, nonce, expected) ||
                   CRYPTO_memcmp(expected, heard + 2,
                                 ULTRASONIC_ECHO_TAG_SIZE)) {
            r->failure = ULTRASONIC_ECHO_BAD_MAC;
        } else {
            r->response_valid = 1;
            r->verified_at_us = end;
            r->timing_accepted = r->elapsed_us <= c->max_response_us;
            r->failure =
                r->timing_accepted ? ULTRASONIC_ECHO_OK : ULTRASONIC_ECHO_LATE;
        }
    }
    OPENSSL_cleanse(expected, sizeof(expected));
    header(done, MSG_DONE);
    done[MSG_HEADER] = (unsigned char)dir;
    done[MSG_HEADER + 1] =
        (unsigned char)(r->response_valid && r->timing_accepted);
    return send_msg(s, done, sizeof(done));
}

static int run_prover(SST_session_ctx_t* s, const ultrasonic_echo_audio* a,
                      unsigned dir, unsigned delay_ms,
                      ultrasonic_echo_result* r) {
    unsigned char msg[MSG_CHALLENGE_SIZE], done[MSG_DONE_SIZE];
    unsigned char payload[ULTRASONIC_ECHO_PAYLOAD_SIZE];
    if (recv_msg(s, MSG_CHALLENGE, msg, sizeof(msg)) || msg[MSG_HEADER] != dir)
        return -1;
    payload[0] = ULTRASONIC_ECHO_VERSION;
    payload[1] = (unsigned char)dir;
    if (ultrasonic_echo_tag(&s->s_key, dir, msg + MSG_HEADER + 1, payload + 2))
        return -1;
    if (delay_ms) session_ctl_sleep_ms(delay_ms);
    if (a->tx(a->ctx, payload, sizeof(payload))) {
        SST_print_error("Ultrasound echo: audio playback failed.");
        return -1;
    }
    if (recv_msg(s, MSG_DONE, done, sizeof(done)) || done[MSG_HEADER] != dir ||
        done[MSG_HEADER + 1] > 1)
        return -1;
    r->peer_reported_pass = done[MSG_HEADER + 1];
    return 0;
}

int ultrasonic_echo_run(SST_session_ctx_t* session,
                        const ultrasonic_echo_config* config, int initiator,
                        const ultrasonic_echo_audio* audio,
                        unsigned prover_delay_ms, ultrasonic_echo_result* r) {
    unsigned char mine[MSG_PARAMS_SIZE], theirs[MSG_PARAMS_SIZE];
    session_ctl_timeout saved = {0};
    int status = -1;
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    r->failure = ULTRASONIC_ECHO_NOT_RUN;
    if (!session || session->sock < 0 ||
        !ultrasonic_echo_config_valid(config) || !audio || !audio->rx_begin ||
        !audio->rx_until || !audio->tx ||
        session->s_key.mac_key_size != MAC_KEY_SIZE)
        return -1;
    if (!session_key_fresh(&session->s_key)) {
        r->failure = ULTRASONIC_ECHO_KEY_EXPIRED;
        return -1;
    }
    if (session_ctl_timeout_set(session->sock,
                                config->response_timeout_ms + CONTROL_SLACK_MS,
                                &saved))
        goto done;

    /* Both sides opened their audio before getting here, so READY also
     * means the responder is ready to play and capture. No timed nonce is
     * revealed yet. */
    params_msg(mine, initiator ? MSG_INIT : MSG_READY, &session->s_key, config);
    if (initiator) {
        if (send_msg(session, mine, sizeof(mine)) ||
            recv_msg(session, MSG_READY, theirs, sizeof(theirs)))
            goto done;
    } else if (recv_msg(session, MSG_INIT, theirs, sizeof(theirs))) {
        goto done;
    }
    if (memcmp(mine + MSG_HEADER, theirs + MSG_HEADER,
               sizeof(mine) - MSG_HEADER)) {
        SST_print_error(
            "Ultrasound echo: peer's session key ID or echo parameters "
            "differ from this side's Auth plan.");
        goto done;
    }
    if (!initiator && send_msg(session, mine, sizeof(mine))) goto done;

    for (unsigned dir = ULTRASONIC_ECHO_DIR_REQUESTER_VERIFIES;
         dir <= ULTRASONIC_ECHO_DIR_TARGET_VERIFIES; ++dir) {
        int verifier =
            (dir == ULTRASONIC_ECHO_DIR_REQUESTER_VERIFIES) == (initiator != 0);
        if (verifier) {
            if (dir == ULTRASONIC_ECHO_DIR_TARGET_VERIFIES)
                session_ctl_sleep_ms(TURNAROUND_MS);
            if (run_verifier(session, config, audio, dir, r)) goto done;
        } else if (run_prover(session, audio, dir, prover_delay_ms, r)) {
            goto done;
        }
    }
    r->local_pass = r->response_valid && r->timing_accepted &&
                    session_key_fresh(&session->s_key);
    if (r->response_valid && r->timing_accepted && !r->local_pass)
        r->failure = ULTRASONIC_ECHO_KEY_EXPIRED;
    status = r->local_pass;
done:
    if (status < 0) {
        r->local_pass = 0;
        if (r->failure == ULTRASONIC_ECHO_OK ||
            r->failure == ULTRASONIC_ECHO_NOT_RUN)
            r->failure = ULTRASONIC_ECHO_ABORTED;
    }
    session_ctl_timeout_restore(session->sock, &saved);
    return status;
}
