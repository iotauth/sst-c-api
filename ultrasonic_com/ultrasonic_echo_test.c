/* Portable test for the mutual acoustic keyed echo: real SST secure messages
 * over a socketpair, with the acoustic link simulated by a datagram
 * socketpair. Checks protocol logic only, not audio timing or real relays. */
#include "ultrasonic_echo.h"

#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../ir_com/ir_hk.h"

typedef struct {
    int air; /* this endpoint's end of the simulated acoustic link */
    int corrupt, silent, fail_tx, shutdown_after_tx;
    const unsigned char* replay; /* play this instead of the real answer */
    unsigned char played[ULTRASONIC_ECHO_PAYLOAD_SIZE];
    int played_count;
} mock_audio;

typedef struct {
    SST_session_ctx_t session;
    ultrasonic_echo_config config;
    mock_audio audio;
    int initiator, rc;
    unsigned delay_ms;
    ultrasonic_echo_result result;
} endpoint;

static int rx_begin(void* ctx) {
    mock_audio* m = ctx;
    unsigned char junk[256];
    while (recv(m->air, junk, sizeof(junk), MSG_DONTWAIT) > 0) {
    }
    return 0;
}
static int rx_until(void* ctx, unsigned char* buf, unsigned capacity,
                    uint64_t deadline_us) {
    mock_audio* m = ctx;
    uint64_t now = ultrasonic_echo_now_us();
    if (now >= deadline_us) return 0;
    struct pollfd p = {.fd = m->air, .events = POLLIN};
    int ready = poll(&p, 1, (int)((deadline_us - now + 999) / 1000));
    if (ready <= 0) return 0;
    ssize_t n = recv(m->air, buf, capacity, 0);
    return n > 0 ? (int)n : 0;
}
static int tx(void* ctx, const unsigned char* buf, unsigned len) {
    endpoint* e = ctx;
    mock_audio* m = &e->audio;
    unsigned char out[ULTRASONIC_ECHO_PAYLOAD_SIZE];
    assert(len == sizeof(out));
    memcpy(out, m->replay ? m->replay : buf, len);
    if (m->corrupt) out[len - 1] ^= 1;
    memcpy(m->played, out, len);
    m->played_count++;
    if (m->fail_tx) return -1;
    if (!m->silent) assert(send(m->air, out, len, 0) == (ssize_t)len);
    if (m->shutdown_after_tx) shutdown(e->session.sock, SHUT_RDWR);
    return 0;
}

/* tx needs the endpoint (to drop its TCP session), so every callback gets
 * the endpoint as ctx. */
static int rx_begin_e(void* ctx) { return rx_begin(&((endpoint*)ctx)->audio); }
static int rx_until_e(void* ctx, unsigned char* buf, unsigned capacity,
                      uint64_t deadline_us) {
    return rx_until(&((endpoint*)ctx)->audio, buf, capacity, deadline_us);
}

static void* run_endpoint(void* ctx) {
    endpoint* e = ctx;
    ultrasonic_echo_audio io = {e, rx_begin_e, rx_until_e, tx};
    e->rc = ultrasonic_echo_run(&e->session, &e->config, e->initiator, &io,
                                e->delay_ms, &e->result);
    /* An aborting side must not leave its peer waiting on TCP. */
    if (e->rc < 0) shutdown(e->session.sock, SHUT_RDWR);
    return NULL;
}

static void init(endpoint e[2]) {
    memset(e, 0, sizeof(endpoint) * 2);
    int ctrl[2], air[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, ctrl) == 0);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, air) == 0);
    for (int i = 0; i < 2; ++i) {
        session_key_t* k = &e[i].session.s_key;
        memset(k->key_id, 7, SESSION_KEY_ID_SIZE);
        memset(k->mac_key, 42, MAC_KEY_SIZE);
        memset(k->cipher_key, 9, 16);
        k->mac_key_size = MAC_KEY_SIZE;
        k->cipher_key_size = 16;
        k->enc_mode = AES_128_CBC;
        k->abs_validity = UINT64_MAX;
        e[i].session.sock = ctrl[i];
        e[i].audio.air = air[i];
        e[i].initiator = i == 0;
        e[i].config = (ultrasonic_echo_config){200000, 500};
    }
}
static void finish(endpoint e[2]) {
    for (int i = 0; i < 2; ++i) {
        close(e[i].session.sock);
        close(e[i].audio.air);
    }
}
static void exchange(endpoint e[2]) {
    pthread_t t[2];
    for (int i = 0; i < 2; ++i)
        assert(pthread_create(&t[i], NULL, run_endpoint, &e[i]) == 0);
    for (int i = 0; i < 2; ++i) pthread_join(t[i], NULL);
}

static void plan_tests(void) {
    const char* fmt =
        "{\"requester\":\"net1.robot1\",\"targets\":[%s],\"requiredChecks\":"
        "[\"CO_LOCATION\"],\"verificationPlan\":{\"CO_LOCATION\":{"
        "\"topology\":\"%s\",\"selectedMethod\":{\"method\":\"%s\","
        "\"parameters\":{%s}}}}}";
    const char* ok = "\"max_response_us\":2000000,\"response_timeout_ms\":5000";
    char plan[1024];
    ultrasonic_echo_config c;
    ultrasonic_echo_identity id;
    snprintf(plan, sizeof(plan), fmt, "\"net1.locker1\"", "MUTUAL",
             "ULTRASOUND", ok);
    assert(ultrasonic_echo_plan_config(plan, &c, &id) == 1);
    assert(c.max_response_us == 2000000 && c.response_timeout_ms == 5000);
    assert(!strcmp(id.requester, "net1.robot1") &&
           !strcmp(id.target, "net1.locker1"));
    /* The IR/LiFi parsers reject this plan, so the dispatcher must accept
     * an ULTRASOUND selection in spite of their -1. */
    ir_hk_config ir;
    assert(ir_hk_plan_config(plan, &ir) == -1);
    for (size_t i = 0; i < strlen(plan); ++i) {
        char saved = plan[i];
        plan[i] = 0;
        assert(ultrasonic_echo_plan_config(plan, &c, &id) == -1);
        plan[i] = saved;
    }
    const char* bad_params[] = {
        /* the old catalog entry, not to be reinterpreted */
        "\"rounds\":64,\"max_delay_us\":2000",
        "\"max_response_us\":2000000,\"response_timeout_ms\":5000,"
        "\"rounds\":64",
        "\"max_response_us\":2000000,\"response_timeout_ms\":5000,"
        "\"max_delay_us\":2000",
        "\"max_response_us\":2000000.5,\"response_timeout_ms\":5000",
        "\"max_response_us\":2e6,\"response_timeout_ms\":5000",
        "\"max_response_us\":\"2000000\",\"response_timeout_ms\":5000",
        "\"max_response_us\":-1,\"response_timeout_ms\":5000",
        "\"max_response_us\":0,\"response_timeout_ms\":5000",
        "\"max_response_us\":2000000,\"response_timeout_ms\":0",
        "\"max_response_us\":6000001,\"response_timeout_ms\":6000",
        "\"max_response_us\":60000001,\"response_timeout_ms\":60000",
        "\"max_response_us\":2000000,\"response_timeout_ms\":60001",
        "\"max_response_us\":99999999999999999999,\"response_timeout_ms\":1",
        "\"max_response_us\":2000000",
        "\"response_timeout_ms\":5000",
        "\"max_response_us\":1,\"max_response_us\":2,"
        "\"response_timeout_ms\":5000"};
    for (unsigned i = 0; i < sizeof(bad_params) / sizeof(bad_params[0]); ++i) {
        snprintf(plan, sizeof(plan), fmt, "\"net1.locker1\"", "MUTUAL",
                 "ULTRASOUND", bad_params[i]);
        assert(ultrasonic_echo_plan_config(plan, &c, &id) == -1);
    }
    /* Exactly the timeout's worth of acceptance is allowed. */
    snprintf(plan, sizeof(plan), fmt, "\"net1.locker1\"", "MUTUAL",
             "ULTRASOUND",
             "\"max_response_us\":5000000,\"response_timeout_ms\":5000");
    assert(ultrasonic_echo_plan_config(plan, &c, &id) == 1);
    const char* bad_targets[] = {"", "\"net1.locker1\",\"net1.locker2\"",
                                 "\"\"", "\"net1\\\\locker1\"", "1"};
    for (unsigned i = 0; i < sizeof(bad_targets) / sizeof(bad_targets[0]);
         ++i) {
        snprintf(plan, sizeof(plan), fmt, bad_targets[i], "MUTUAL",
                 "ULTRASOUND", ok);
        assert(ultrasonic_echo_plan_config(plan, &c, &id) == -1);
    }
    snprintf(plan, sizeof(plan), fmt, "\"net1.locker1\"", "LOCAL", "ULTRASOUND",
             ok);
    assert(ultrasonic_echo_plan_config(plan, &c, &id) == -1);
    snprintf(plan, sizeof(plan), fmt, "\"net1.locker1\"", "MUTUAL", "IR", ok);
    assert(ultrasonic_echo_plan_config(plan, &c, &id) == -1);
    snprintf(plan, sizeof(plan), fmt, "\"net1.locker1\"", "MUTUAL", "DUMMY",
             "");
    assert(ultrasonic_echo_plan_config(plan, &c, &id) == 0);
    assert(ultrasonic_echo_plan_config(
               "{\"requiredChecks\":[],\"verificationPlan\":{}}", &c, &id) ==
           0);
    assert(ultrasonic_echo_plan_config("{\"requiredChecks\":[\"CO_LOCATION\"],"
                                       "\"verificationPlan\":{}}",
                                       &c, &id) == -1);
    snprintf(plan, sizeof(plan),
             "{\"targets\":[\"net1.locker1\"],\"requiredChecks\":"
             "[\"CO_LOCATION\"],\"verificationPlan\":{\"CO_LOCATION\":{"
             "\"topology\":\"MUTUAL\",\"selectedMethod\":{\"method\":"
             "\"ULTRASOUND\",\"parameters\":{%s}}}}}",
             ok);
    assert(ultrasonic_echo_plan_config(plan, &c, &id) == -1); /* requester */
}

static void tag_tests(void) {
    endpoint e[2];
    init(e);
    unsigned char nonce[ULTRASONIC_ECHO_NONCE_SIZE] = {1, 2, 3};
    unsigned char a[16], b[16];
    const session_key_t* k = &e[0].session.s_key;
    assert(!ultrasonic_echo_tag(k, 1, nonce, a));
    assert(!ultrasonic_echo_tag(k, 1, nonce, b) && !memcmp(a, b, 16));
    assert(!ultrasonic_echo_tag(k, 2, nonce, b) && memcmp(a, b, 16));
    unsigned char other_nonce[ULTRASONIC_ECHO_NONCE_SIZE] = {1, 2, 4};
    assert(!ultrasonic_echo_tag(k, 1, other_nonce, b) && memcmp(a, b, 16));
    session_key_t other = *k;
    other.mac_key[0] ^= 1;
    assert(!ultrasonic_echo_tag(&other, 1, nonce, b) && memcmp(a, b, 16));
    assert(ultrasonic_echo_tag(k, 3, nonce, b) == -1);
    finish(e);
}

static void assert_pass(const endpoint* e, unsigned dir) {
    assert(e->rc == 1 && e->result.local_pass && e->result.response_valid &&
           e->result.timing_accepted && e->result.direction == dir &&
           e->result.failure == ULTRASONIC_ECHO_OK &&
           e->result.elapsed_us <= e->config.max_response_us &&
           e->result.verified_at_us != 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    plan_tests();
    tag_tests();
    endpoint e[2];

    /* Both directions pass, each verdict reported to the peer, and the SST
     * session (sequence numbers included) still works afterwards. */
    init(e);
    exchange(e);
    assert_pass(&e[0], 1);
    assert_pass(&e[1], 2);
    assert(e[0].result.peer_reported_pass && e[1].result.peer_reported_pass);
    assert(e[0].audio.played_count == 1 && e[1].audio.played_count == 1);
    unsigned char old_answer[ULTRASONIC_ECHO_PAYLOAD_SIZE];
    memcpy(old_answer, e[1].audio.played, sizeof(old_answer));
    unsigned char buf[MAX_SECURE_COMM_MSG_LENGTH];
    assert(send_secure_message("after echo", 10, &e[0].session) == 0);
    assert(read_secure_message(buf, &e[1].session) == 10 &&
           !memcmp(buf, "after echo", 10));
    assert(send_secure_message("reply", 5, &e[1].session) == 0);
    assert(read_secure_message(buf, &e[0].session) == 5);
    finish(e);

    /* Fresh nonces: the locker's answer differs run to run, and replaying
     * a previous run's answer fails while the other direction passes. */
    init(e);
    e[1].audio.replay = old_answer;
    exchange(e);
    assert(e[0].rc == 0 && e[0].result.decoded &&
           e[0].result.failure == ULTRASONIC_ECHO_BAD_MAC &&
           !e[0].result.response_valid);
    assert_pass(&e[1], 2);
    assert(!e[1].result.peer_reported_pass);
    finish(e);

    /* A forged tag fails, in either direction independently. */
    for (int prover = 0; prover < 2; ++prover) {
        init(e);
        e[prover].audio.corrupt = 1;
        exchange(e);
        endpoint* verifier = &e[1 - prover];
        assert(verifier->rc == 0 &&
               verifier->result.failure == ULTRASONIC_ECHO_BAD_MAC);
        assert_pass(&e[prover], prover == 0 ? 1 : 2);
        finish(e);
    }

    /* The robot playing the locker's direction-1 answer back in direction
     * 2 (as if relaying it) fails on the direction byte. */
    init(e);
    e[0].audio.replay = e[1].audio.played;
    exchange(e);
    assert(e[1].rc == 0 && e[1].result.failure == ULTRASONIC_ECHO_BAD_PAYLOAD);
    assert_pass(&e[0], 1);
    finish(e);

    /* A valid but late answer: response_valid, not timing_accepted. */
    init(e);
    e[1].delay_ms = 300;
    exchange(e);
    assert(e[0].rc == 0 && e[0].result.response_valid &&
           !e[0].result.timing_accepted &&
           e[0].result.failure == ULTRASONIC_ECHO_LATE &&
           e[0].result.elapsed_us > e[0].config.max_response_us);
    assert_pass(&e[1], 2);
    finish(e);

    /* No answer within the timeout: bounded failure, second direction still
     * runs (and the late arrival doesn't leak into it). */
    init(e);
    e[1].delay_ms = 700;
    uint64_t t0 = ultrasonic_echo_now_us();
    exchange(e);
    assert(e[0].rc == 0 && e[0].result.failure == ULTRASONIC_ECHO_NO_RESPONSE &&
           !e[0].result.decoded);
    assert_pass(&e[1], 2);
    assert(ultrasonic_echo_now_us() - t0 < 5000000);
    finish(e);
    init(e);
    e[1].audio.silent = 1;
    exchange(e);
    assert(e[0].rc == 0 && e[0].result.failure == ULTRASONIC_ECHO_NO_RESPONSE);
    assert_pass(&e[1], 2);
    finish(e);

    /* Audio device failure on the prover aborts both sides promptly. */
    init(e);
    e[1].audio.fail_tx = 1;
    t0 = ultrasonic_echo_now_us();
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[0].result.local_pass &&
           e[1].result.failure == ULTRASONIC_ECHO_ABORTED);
    assert(ultrasonic_echo_now_us() - t0 < 5000000);
    finish(e);

    /* TCP dropped after the first answer: no hang, no PASS. */
    init(e);
    e[1].audio.shutdown_after_tx = 1;
    t0 = ultrasonic_echo_now_us();
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[0].result.local_pass &&
           !e[1].result.local_pass);
    assert(ultrasonic_echo_now_us() - t0 < 5000000);
    finish(e);

    /* Parameter or key-ID disagreement stops before any nonce is sent. */
    init(e);
    e[1].config.max_response_us = 100000;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[0].audio.played_count &&
           !e[1].audio.played_count);
    finish(e);
    init(e);
    e[1].session.s_key.key_id[0] ^= 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[1].audio.played_count);
    finish(e);

    /* An expired key never starts. */
    init(e);
    e[0].session.s_key.abs_validity = 0;
    exchange(e);
    assert(e[0].rc == -1 &&
           e[0].result.failure == ULTRASONIC_ECHO_KEY_EXPIRED && e[1].rc == -1);
    finish(e);

    puts(
        "Ultrasound echo: plan, tag binding, mutual pass, replay, forgery, "
        "direction, late, no-response, audio/TCP failure, "
        "mismatch and post-echo messaging tests passed.");
    return 0;
}
