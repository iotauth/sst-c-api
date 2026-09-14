#include "../ir_com/ir_hk.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct {
    unsigned kind, len;
    uint64_t tick;
    unsigned char data[IR_HK_CONTROL_SIZE];
} packet;
typedef struct {
    int fd, initiator, rc;
    unsigned bits_sent, controls_sent, flip, delay, corrupt_control, guard;
    unsigned stop_after_bits;
    uint64_t now;
    unsigned char ready[IR_HK_CONTROL_SIZE];
    const unsigned char* replay;
    ir_hk_config config;
    session_key_t key;
    ir_hk_result result;
} endpoint;
static int write_packet(endpoint* e, const packet* p) {
    const unsigned char* b = (const unsigned char*)p;
    size_t left = sizeof(*p);
    while (left) {
        ssize_t n = write(e->fd, b, left);
        if (n <= 0) return -1;
        b += n;
        left -= (size_t)n;
    }
    return 0;
}
static int read_packet(endpoint* e, packet* p, unsigned kind, unsigned len) {
    unsigned char* b = (unsigned char*)p;
    size_t left = sizeof(*p);
    while (left) {
        ssize_t n = read(e->fd, b, left);
        if (n <= 0) return -1;
        b += n;
        left -= (size_t)n;
    }
    if (p->kind != kind || p->len != len) return -1;
    if (e->now < p->tick) e->now = p->tick;
    e->now += 100;
    return 0;
}
static int send_control(void* ctx, const unsigned char* p, unsigned n) {
    endpoint* e = ctx;
    packet v = {.kind = 1, .len = n, .tick = e->now};
    memcpy(v.data, p, n);
    if (p[4] == 2) {
        memcpy(e->ready, p, n);
        if (e->replay) memcpy(v.data, e->replay, n);
    }
    if (++e->controls_sent == e->corrupt_control) v.data[54] ^= 1;
    return write_packet(e, &v);
}
static int recv_control(void* ctx, unsigned char* p, unsigned n) {
    packet v;
    if (read_packet(ctx, &v, 1, n)) return -1;
    memcpy(p, v.data, n);
    return 0;
}
static int send_bit(void* ctx, unsigned char bit, uint32_t* end) {
    endpoint* e = ctx;
    if (e->stop_after_bits && e->bits_sent == e->stop_after_bits) return -1;
    int response = e->initiator ? e->bits_sent % 2 == 1 : e->bits_sent % 2 == 0;
    if (response && e->bits_sent / 2 < e->flip) bit ^= 1;
    if (response && e->bits_sent / 2 < e->delay) e->now += 1100;
    e->now += 300;
    ++e->bits_sent;
    *end = (uint32_t)e->now;
    packet v = {.kind = 2, .len = 1, .tick = e->now, .data = {bit}};
    return write_packet(e, &v);
}
static int recv_bit(void* ctx, unsigned char* bit, uint32_t* end) {
    endpoint* e = ctx;
    packet v;
    if (read_packet(e, &v, 2, 1)) return -1;
    *bit = v.data[0];
    *end = (uint32_t)e->now;
    return 0;
}
static void pause_us(void* ctx, unsigned us) {
    endpoint* e = ctx;
    if (us == IR_HK_READY_GUARD_US) e->guard++;
    e->now += us;
}
static void* run(void* ctx) {
    endpoint* e = ctx;
    ir_hk_io io = {e, send_control, recv_control, send_bit, recv_bit, pause_us};
    e->rc = ir_hk_run(&e->key, &e->config, e->initiator, &io, &e->result);
    shutdown(e->fd, SHUT_WR);
    return NULL;
}
static void init(endpoint e[2], unsigned rounds) {
    memset(e, 0, sizeof(endpoint) * 2);
    for (int i = 0; i < 2; ++i) {
        e[i].initiator = i == 0;
        e[i].config = (ir_hk_config){rounds, 800000, 1000};
        e[i].key.mac_key_size = MAC_KEY_SIZE;
        e[i].key.abs_validity = UINT64_MAX;
        memset(e[i].key.mac_key, 42, MAC_KEY_SIZE);
        memset(e[i].key.key_id, 17, SESSION_KEY_ID_SIZE);
        /* Exercise uint32 timer wrap without relying on wall-clock timing. */
        e[i].now = UINT32_MAX - 1000ULL;
    }
}
static void exchange(endpoint e[2]) {
    int sockets[2];
    pthread_t threads[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    for (int i = 0; i < 2; ++i) {
        e[i].fd = sockets[i];
        struct timeval timeout = {.tv_sec = 2};
        assert(setsockopt(sockets[i], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                          sizeof(timeout)) == 0);
        assert(pthread_create(&threads[i], NULL, run, &e[i]) == 0);
    }
    for (int i = 0; i < 2; ++i) {
        pthread_join(threads[i], NULL);
        close(sockets[i]);
    }
}
static void plan_tests(void) {
    const char* fmt =
        "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{\"CO_"
        "LOCATION\":{\"topology\":\"MUTUAL\",\"selectedMethod\":{\"method\":"
        "\"IR\",\"parameters\":{%s}}}}}";
    char plan[1024];
    ir_hk_config c;
    snprintf(plan, sizeof(plan), fmt,
             "\"rounds\":32,\"success_threshold\":0.8,\"max_delay_us\":1000");
    assert(ir_hk_plan_config(plan, &c) == 1 && ir_hk_required(&c) == 26);
    const char* bad[] = {
        "\"rounds\":31,\"success_threshold\":0.8,\"max_delay_us\":1000",
        "\"rounds\":32,\"success_threshold\":0,\"max_delay_us\":1000",
        "\"rounds\":32,\"success_threshold\":1.1,\"max_delay_us\":1000",
        "\"rounds\":32,\"success_threshold\":0.8000001,\"max_delay_us\":1000",
        "\"rounds\":32,\"success_threshold\":\"0.8\",\"max_delay_us\":1000",
        "\"rounds\":32,\"success_threshold\":0.8,\"max_delay_us\":-1",
        "\"rounds\":32,\"rounds\":64,\"success_threshold\":0.8,\"max_delay_"
        "us\":1000",
        "\"rounds\":32,\"max_delay_us\":1000"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(plan, sizeof(plan), fmt, bad[i]);
        assert(ir_hk_plan_config(plan, &c) == -1);
    }
    assert(ir_hk_plan_config(
               "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{}}",
               &c) == -1);
    assert(ir_hk_plan_config("{\"requiredChecks\":[],\"verificationPlan\":{}}",
                             &c) == 0);
    assert(ir_hk_plan_config("", &c) == -1);
    assert(ir_hk_plan_config("{", &c) == -1);
    snprintf(plan, sizeof(plan), fmt,
             "\"rounds\":128,\"success_threshold\":1,\"max_delay_us\":1000");
    assert(ir_hk_plan_config(plan, &c) == 1 && ir_hk_required(&c) == 128);
    /* Every truncated prefix must fail, including midway through strings. */
    for (size_t i = 0; i < strlen(plan); ++i) {
        char saved = plan[i];
        plan[i] = 0;
        assert(ir_hk_plan_config(plan, &c) == -1);
        plan[i] = saved;
    }
}
int main(void) {
    signal(SIGPIPE, SIG_IGN);
    plan_tests();
    endpoint e[2];
    unsigned char old_ready[IR_HK_CONTROL_SIZE];
    for (unsigned n = 32; n <= 128; n *= 2) {
        init(e, n);
        exchange(e);
        for (int i = 0; i < 2; ++i) {
            assert(e[i].rc == 1 && e[i].result.successes == n);
            assert(e[i].bits_sent == 2 * n && e[i].controls_sent == 2);
        }
        assert(e[0].guard == 1 && e[1].guard == 0);
    }
    init(e, 32);
    exchange(e);
    memcpy(old_ready, e[1].ready, sizeof(old_ready));
    init(e, 32);
    exchange(e);
    assert(memcmp(old_ready + 22, e[1].ready + 22, 32));
    for (int direction = 0; direction < 2; ++direction) {
        init(e, 32);
        e[direction].flip = 6;
        exchange(e);
        assert(e[0].rc == 1 && e[1].rc == 1 &&
               e[1 - direction].result.successes == 26);
        init(e, 32);
        e[direction].flip = 7;
        exchange(e);
        assert(e[0].rc == 0 && e[1].rc == 0 &&
               e[1 - direction].result.successes == 25);
        init(e, 32);
        e[direction].delay = 7;
        exchange(e);
        assert(e[0].rc == 0 && e[1].rc == 0 &&
               e[1 - direction].result.successes == 25);
        assert(e[1 - direction].result.correct[0] &&
               e[1 - direction].result.rtt_us[0] > 1000);
    }
    init(e, 32);
    e[1].config.rounds = 64;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[0].bits_sent &&
           !e[1].bits_sent);
    init(e, 32);
    e[1].key.mac_key[0] ^= 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);
    init(e, 32);
    e[1].key.key_id[0] ^= 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);
    init(e, 32);
    e[0].key.abs_validity = 0;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[0].bits_sent);
    init(e, 32);
    e[0].stop_after_bits =
        61; /* Enough successes so far, but not all N rounds. */
    exchange(e);
    assert(e[0].result.successes >= 26 && e[0].rc == -1 && e[1].rc == -1);
    for (unsigned control = 1; control <= 2; ++control) {
        init(e, 32);
        e[0].corrupt_control = control;
        exchange(e);
        assert(e[0].rc == -1 && e[1].rc == -1);
        init(e, 32);
        e[1].corrupt_control = control;
        exchange(e);
        assert(e[0].rc ==
               -1); /* Sender cannot know its last packet was tampered. */
    }
    init(e, 32);
    e[1].replay = old_ready;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1 && !e[0].bits_sent);
    puts(
        "IR HK: mutual rounds, threshold boundaries, delays, wrap, config/key "
        "mismatch, MAC and replay tests passed.");
    return 0;
}
