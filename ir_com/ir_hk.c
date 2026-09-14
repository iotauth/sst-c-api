#include "ir_hk.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <time.h>

int ir_hk_config_valid(const ir_hk_config* c) {
    return c && (c->rounds == 32 || c->rounds == 64 || c->rounds == 128) &&
           c->threshold_ppm > 0 && c->threshold_ppm <= 1000000 &&
           c->max_delay_us > 0 && c->max_delay_us <= 1000000;
}
unsigned ir_hk_required(const ir_hk_config* c) {
    return ir_hk_config_valid(c)
               ? (c->rounds * c->threshold_ppm + 999999) / 1000000
               : 0;
}
static int key_fresh(const session_key_t* key) {
    time_t now = time(NULL);
    return now >= 0 && (uint64_t)now * 1000 < key->abs_validity;
}
static int mac(const session_key_t* key, const unsigned char* data,
               unsigned len, unsigned char out[IR_HK_TAG_SIZE]) {
    unsigned n = 0;
    return HMAC(EVP_sha256(), key->mac_key, (int)key->mac_key_size, data, len,
                out, &n) &&
                   n == IR_HK_TAG_SIZE
               ? 0
               : -1;
}
static unsigned char bit_at(const unsigned char* p, unsigned i) {
    return (p[i / 8] >> (i % 8)) & 1;
}
static int recv_bit(const ir_hk_io* io, unsigned char* bit, uint32_t* end) {
    return io->recv_bit(io->ctx, bit, end) || *bit > 1 ? -1 : 0;
}
static int score(const ir_hk_io* io, const ir_hk_config* c, ir_hk_result* r,
                 unsigned i, uint32_t sent, unsigned char expected) {
    unsigned char bit;
    uint32_t received;
    if (recv_bit(io, &bit, &received)) return -1;
    r->rtt_us[i] = received - sent;
    r->correct[i] = bit == expected;
    r->successes += r->correct[i] && r->rtt_us[i] <= c->max_delay_us;
    r->completed++;
    return 0;
}

/* Derives both provers' response registers and this side's own challenge
 * sequence from the two nonces exchanged in INIT/READY. Freshness of the
 * derived material comes entirely from these nonces (each freshly random
 * per run) -- rounds/threshold/max_delay don't need to be folded in here,
 * since both sides already got them (matching, by construction) from
 * Auth's persisted plan, not from each other over IR. */
static int derive(const session_key_t* key, const unsigned char* nonce_a,
                  const unsigned char* nonce_b, unsigned char reg[2][2][16],
                  unsigned char challenges[16]) {
    unsigned char input[8 + IR_HK_NONCE_SIZE * 2 + 2], digest[32];
    memcpy(input, "IHK-REG1", 8);
    memcpy(input + 8, nonce_a, IR_HK_NONCE_SIZE);
    memcpy(input + 8 + IR_HK_NONCE_SIZE, nonce_b, IR_HK_NONCE_SIZE);
    for (unsigned role = 0; role < 2; ++role) {
        for (unsigned bit = 0; bit < 2; ++bit) {
            input[8 + IR_HK_NONCE_SIZE * 2] = (unsigned char)role;
            input[8 + IR_HK_NONCE_SIZE * 2 + 1] = (unsigned char)bit;
            if (mac(key, input, sizeof(input), digest)) return -1;
            memcpy(reg[role][bit], digest, 16);
        }
    }
    OPENSSL_cleanse(digest, sizeof(digest));
    return RAND_bytes(challenges, 16) == 1 ? 0 : -1;
}

int ir_hk_run(const session_key_t* key, const ir_hk_config* c, int initiator,
              const ir_hk_io* io, ir_hk_result* r) {
    unsigned char nonce_a[IR_HK_NONCE_SIZE], nonce_b[IR_HK_NONCE_SIZE];
    unsigned char reg[2][2][16] = {{{0}}}, challenges[16] = {0};
    unsigned char peer_challenge = 0, challenge;
    uint32_t sent = 0, ignored;
    int status = -1;
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!ir_hk_config_valid(c) || !key || !key_fresh(key) ||
        key->mac_key_size != MAC_KEY_SIZE || !io || !io->send_control ||
        !io->recv_control || !io->send_bit || !io->recv_bit || !io->pause_us)
        return -1;
    r->required = ir_hk_required(c);

    if (initiator) {
        unsigned char init_msg[IR_HK_INIT_SIZE], ready_msg[IR_HK_READY_SIZE];
        init_msg[0] = 1;
        memcpy(init_msg + 1, key->key_id, SESSION_KEY_ID_SIZE);
        if (RAND_bytes(nonce_a, IR_HK_NONCE_SIZE) != 1) goto done;
        memcpy(init_msg + 1 + SESSION_KEY_ID_SIZE, nonce_a, IR_HK_NONCE_SIZE);
        if (mac(key, init_msg, 1 + SESSION_KEY_ID_SIZE + IR_HK_NONCE_SIZE,
                init_msg + 1 + SESSION_KEY_ID_SIZE + IR_HK_NONCE_SIZE))
            goto done;
        if (io->send_control(io->ctx, init_msg, sizeof(init_msg))) goto done;

        if (io->recv_control(io->ctx, ready_msg, sizeof(ready_msg)) ||
            ready_msg[0] != 2)
            goto done;
        memcpy(nonce_b, ready_msg + 1, IR_HK_NONCE_SIZE);
        {
            /* READY's tag binds nonce_a too (known locally, not resent) so a
             * captured old READY can't be replayed against a new INIT. */
            unsigned char mac_input[1 + IR_HK_NONCE_SIZE + IR_HK_NONCE_SIZE];
            unsigned char tag[IR_HK_TAG_SIZE];
            memcpy(mac_input, ready_msg, 1 + IR_HK_NONCE_SIZE);
            memcpy(mac_input + 1 + IR_HK_NONCE_SIZE, nonce_a,
                   IR_HK_NONCE_SIZE);
            if (mac(key, mac_input, sizeof(mac_input), tag) ||
                CRYPTO_memcmp(tag, ready_msg + 1 + IR_HK_NONCE_SIZE,
                              IR_HK_TAG_SIZE))
                goto done;
        }
        if (derive(key, nonce_a, nonce_b, reg, challenges)) goto done;
        io->pause_us(io->ctx, IR_HK_READY_GUARD_US);
        challenge = bit_at(challenges, 0);
        if (io->send_bit(io->ctx, challenge, &sent)) goto done;
        for (unsigned i = 0; i < c->rounds; ++i) {
            if (score(io, c, r, i, sent, bit_at(reg[1][challenge], i)) ||
                recv_bit(io, &peer_challenge, &ignored) ||
                io->send_bit(io->ctx, bit_at(reg[0][peer_challenge], i),
                             &ignored))
                goto done;
            if (i + 1 < c->rounds) {
                io->pause_us(io->ctx, IR_HK_INTER_BIT_US);
                challenge = bit_at(challenges, i + 1);
                if (io->send_bit(io->ctx, challenge, &sent)) goto done;
            }
        }
    } else {
        unsigned char init_msg[IR_HK_INIT_SIZE], ready_msg[IR_HK_READY_SIZE];
        if (io->recv_control(io->ctx, init_msg, sizeof(init_msg)) ||
            init_msg[0] != 1 ||
            memcmp(init_msg + 1, key->key_id, SESSION_KEY_ID_SIZE))
            goto done;
        {
            unsigned char tag[IR_HK_TAG_SIZE];
            if (mac(key, init_msg, 1 + SESSION_KEY_ID_SIZE + IR_HK_NONCE_SIZE,
                    tag) ||
                CRYPTO_memcmp(
                    tag, init_msg + 1 + SESSION_KEY_ID_SIZE + IR_HK_NONCE_SIZE,
                    IR_HK_TAG_SIZE))
                goto done;
        }
        memcpy(nonce_a, init_msg + 1 + SESSION_KEY_ID_SIZE, IR_HK_NONCE_SIZE);
        if (RAND_bytes(nonce_b, IR_HK_NONCE_SIZE) != 1) goto done;
        if (derive(key, nonce_a, nonce_b, reg, challenges)) goto done;

        ready_msg[0] = 2;
        memcpy(ready_msg + 1, nonce_b, IR_HK_NONCE_SIZE);
        {
            unsigned char mac_input[1 + IR_HK_NONCE_SIZE + IR_HK_NONCE_SIZE];
            memcpy(mac_input, ready_msg, 1 + IR_HK_NONCE_SIZE);
            memcpy(mac_input + 1 + IR_HK_NONCE_SIZE, nonce_a,
                   IR_HK_NONCE_SIZE);
            if (mac(key, mac_input, sizeof(mac_input),
                    ready_msg + 1 + IR_HK_NONCE_SIZE))
                goto done;
        }
        if (io->send_control(io->ctx, ready_msg, sizeof(ready_msg)))
            goto done;

        for (unsigned i = 0; i < c->rounds; ++i) {
            if (recv_bit(io, &peer_challenge, &ignored) ||
                io->send_bit(io->ctx, bit_at(reg[1][peer_challenge], i),
                             &ignored))
                goto done;
            io->pause_us(io->ctx, IR_HK_INTER_BIT_US);
            challenge = bit_at(challenges, i);
            if (io->send_bit(io->ctx, challenge, &sent) ||
                score(io, c, r, i, sent, bit_at(reg[0][challenge], i)))
                goto done;
        }
    }
    r->local_pass = r->successes >= r->required && key_fresh(key);
    status = r->local_pass;
done:
    OPENSSL_cleanse(reg, sizeof(reg));
    OPENSSL_cleanse(challenges, sizeof(challenges));
    OPENSSL_cleanse(nonce_a, sizeof(nonce_a));
    OPENSSL_cleanse(nonce_b, sizeof(nonce_b));
    return status;
}
