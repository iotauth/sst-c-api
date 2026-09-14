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
static void put32(unsigned char* p, unsigned v) {
    for (int i = 3; i >= 0; --i) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}
static int mac(const session_key_t* key, const unsigned char* data,
               unsigned len, unsigned char out[32]) {
    unsigned n = 0;
    return HMAC(EVP_sha256(), key->mac_key, (int)key->mac_key_size, data, len,
                out, &n) &&
                   n == 32
               ? 0
               : -1;
}
static int sign_control(const session_key_t* key, unsigned char* p,
                        unsigned type) {
    p[4] = (unsigned char)type;
    return mac(key, p, 54, p + 54);
}
static int receive_control(const session_key_t* key, const ir_hk_io* io,
                           const unsigned char* expected, unsigned char* p,
                           unsigned type, unsigned prefix) {
    unsigned char tag[32];
    if (io->recv_control(io->ctx, p, IR_HK_CONTROL_SIZE) || p[4] != type ||
        memcmp(p, expected, 4) || memcmp(p + 5, expected + 5, prefix - 5) ||
        mac(key, p, 54, tag) || CRYPTO_memcmp(tag, p + 54, 32))
        return -1;
    return 0;
}
static int derive(const session_key_t* key, const unsigned char* control,
                  unsigned char reg[2][2][16], unsigned char challenges[16]) {
    unsigned char input[64] = {0}, digest[32];
    /* Separate KDF domain from control MACs and separate prover directions. */
    memcpy(input, "IHK-REG1", 8);
    memcpy(input + 8, control + 5, 49);
    for (unsigned role = 0; role < 2; ++role) {
        for (unsigned bit = 0; bit < 2; ++bit) {
            input[57] = (unsigned char)role;
            input[58] = (unsigned char)bit;
            if (mac(key, input, 59, digest)) return -1;
            memcpy(reg[role][bit], digest, 16);
        }
    }
    OPENSSL_cleanse(digest, sizeof(digest));
    return RAND_bytes(challenges, 16) == 1 ? 0 : -1;
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
int ir_hk_run(const session_key_t* key, const ir_hk_config* c, int initiator,
              const ir_hk_io* io, ir_hk_result* r) {
    unsigned char control[IR_HK_CONTROL_SIZE] = {0}, peer[IR_HK_CONTROL_SIZE];
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
    memcpy(control, "IHK1", 4);
    memcpy(control + 5, key->key_id, SESSION_KEY_ID_SIZE);
    control[13] = (unsigned char)c->rounds;
    put32(control + 14, c->threshold_ppm);
    put32(control + 18, c->max_delay_us);
    if (initiator) {
        if (RAND_bytes(control + 22, 16) != 1 ||
            sign_control(key, control, 1) ||
            io->send_control(io->ctx, control, sizeof(control)) ||
            receive_control(key, io, control, peer, 2, 38))
            goto done;
        memcpy(control, peer, sizeof(control));
        if (derive(key, control, reg, challenges)) goto done;
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
        if (receive_control(key, io, control, peer, 1, 22)) goto done;
        /* INIT's responder nonce must be empty, preventing ambiguous formats.
         */
        for (unsigned i = 38; i < 54; ++i)
            if (peer[i]) goto done;
        memcpy(control, peer, sizeof(control));
        if (RAND_bytes(control + 38, 16) != 1 ||
            derive(key, control, reg, challenges) ||
            sign_control(key, control, 2) ||
            io->send_control(io->ctx, control, sizeof(control)))
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
    /* Slow, authenticated completion: no side reports mutual PASS before
     * receiving the peer's decision bound to this exact nonce pair/config. */
    if (initiator) {
        if (sign_control(key, control, r->local_pass ? 3 : 4) ||
            io->send_control(io->ctx, control, sizeof(control)))
            goto done;
    }
    /* Type 5/6 is responder PASS/FAIL; type 3/4 is initiator PASS/FAIL. */
    {
        unsigned char tag[32];
        unsigned pass_type = initiator ? 5 : 3;
        if (io->recv_control(io->ctx, peer, sizeof(peer)) ||
            (peer[4] != pass_type && peer[4] != pass_type + 1) ||
            memcmp(peer, control, 4) || memcmp(peer + 5, control + 5, 49) ||
            mac(key, peer, 54, tag) || CRYPTO_memcmp(tag, peer + 54, 32))
            goto done;
        r->peer_pass = peer[4] == pass_type;
    }
    if (!initiator && (sign_control(key, control, r->local_pass ? 5 : 6) ||
                       io->send_control(io->ctx, control, sizeof(control))))
        goto done;
    status = r->local_pass && r->peer_pass && key_fresh(key);
done:
    OPENSSL_cleanse(reg, sizeof(reg));
    OPENSSL_cleanse(challenges, sizeof(challenges));
    return status;
}
