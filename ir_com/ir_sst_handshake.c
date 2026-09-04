// SST handshake (SKEY_HANDSHAKE_1/2/3) carried over infrared via
// pigpio-driven 38kHz bursts, instead of a TCP socket. Linux/pigpio only,
// and requires root at runtime (pigpio needs direct GPIO access).
//
// Reuses the same TX_GPIO/RX_GPIO wiring and pulse-width encoding
// (short/long/sync burst durations and their decode thresholds) as
// ir_test.c's distance-bounding protocol, but frames a one-way,
// variable-length byte stream (sync marker, then a 1-byte length header,
// then that many payload bytes) instead of ir_test.c's fixed-round
// challenge-response exchange.
//
// Compilation (from ir_com/):
//   gcc -I../.. ir_sst_handshake.c ... -lpigpio -lrt -lm -lpthread

#include "ir_sst_handshake.h"

#include <pigpio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "../src/c_common.h"
#include "../src/c_crypto.h"
#include "../src/c_secure_comm.h"

#define IR_TX_GPIO 27
#define IR_RX_GPIO 14
#define IR_ACTIVE_LEVEL 0
#define IR_BIT_THRESHOLD_US 450    // pulse width < this = bit 0, else bit 1
#define IR_SYNC_THRESHOLD_US 1500  // pulse width > this = start-of-frame marker
// Settle time before each pulse. Cheap 38kHz IR receiver modules have an
// AGC/hold-time after a burst ends, so back-to-back pulses without this gap
// would be missed or merged.
#define IR_INTER_BIT_GAP_US 50000
#define IR_MAX_PAYLOAD 255  // fits in the 1-byte length header

static int wave_short = -1;  // bit 0 (300us burst)
static int wave_long = -1;   // bit 1 (600us burst)
static int wave_sync = -1;   // start-of-frame marker (2000us burst)

// Builds a 38kHz carrier pulse wave of specified duration (us). Mirrors
// ir_test.c's build_38khz_burst_wave().
static int build_38khz_burst_wave(int gpio, int burst_us) {
    const int half_period_us = 13;  // approx 38.46 kHz
    int cycles = burst_us / (2 * half_period_us);
    int pulse_count = cycles * 2;

    gpioPulse_t* pulses = calloc((size_t)pulse_count, sizeof(gpioPulse_t));
    if (!pulses) return -1;

    for (int i = 0; i < cycles; i++) {
        pulses[2 * i].gpioOn = 1u << gpio;
        pulses[2 * i].gpioOff = 0;
        pulses[2 * i].usDelay = half_period_us;

        pulses[2 * i + 1].gpioOn = 0;
        pulses[2 * i + 1].gpioOff = 1u << gpio;
        pulses[2 * i + 1].usDelay = half_period_us;
    }

    gpioWaveAddGeneric(pulse_count, pulses);
    free(pulses);

    return gpioWaveCreate();
}

static int ir_init(void) {
    if (gpioInitialise() < 0) {
        SST_print_error("gpioInitialise() failed. Try running with sudo.");
        return -1;
    }
    gpioSetMode(IR_TX_GPIO, PI_OUTPUT);
    gpioWrite(IR_TX_GPIO, 0);
    gpioSetMode(IR_RX_GPIO, PI_INPUT);
    gpioSetPullUpDown(IR_RX_GPIO, PI_PUD_UP);

    gpioWaveClear();
    wave_short = build_38khz_burst_wave(IR_TX_GPIO, 300);
    wave_long = build_38khz_burst_wave(IR_TX_GPIO, 600);
    wave_sync = build_38khz_burst_wave(IR_TX_GPIO, 2000);
    if (wave_short < 0 || wave_long < 0 || wave_sync < 0) {
        SST_print_error("Failed to create IR waves.");
        gpioTerminate();
        return -1;
    }
    return 0;
}

static void ir_deinit(void) {
    gpioWrite(IR_TX_GPIO, 0);
    gpioTerminate();
}

static void ir_tx_pulse(int wave) {
    gpioDelay(IR_INTER_BIT_GAP_US);
    gpioWaveTxSend(wave, PI_WAVE_MODE_ONE_SHOT);
    while (gpioWaveTxBusy()) {
        // tight loop
    }
}

static void ir_tx_byte(unsigned char b) {
    for (int bit = 7; bit >= 0; bit--) {
        int v = (b >> bit) & 1;
        ir_tx_pulse(v ? wave_long : wave_short);
    }
}

// Sends buf over IR: a sync marker, then a 1-byte length header, then the
// payload bytes, each byte as 8 sequential 38kHz bursts (short = bit 0,
// long = bit 1). @return 0 on success, -1 on error.
static int ir_tx_buf(const unsigned char* buf, int len) {
    if (len <= 0 || len > IR_MAX_PAYLOAD) {
        SST_print_error(
            "ir_tx_buf(): payload of %d bytes exceeds the %d-byte cap.", len,
            IR_MAX_PAYLOAD);
        return -1;
    }
    gpioWaveTxSend(wave_sync, PI_WAVE_MODE_ONE_SHOT);
    while (gpioWaveTxBusy()) {
        // tight loop
    }
    ir_tx_byte((unsigned char)len);
    for (int i = 0; i < len; i++) {
        ir_tx_byte(buf[i]);
    }
    return 0;
}

// Waits for a sync marker, then decodes a 1-byte length header followed by
// that many payload bytes, one bit per IR pulse. @return decoded byte
// length (>0) on success, 0 on timeout waiting for a sync marker, -1 on a
// framing error.
static int ir_rx_buf(unsigned char* out_buf, int out_buf_size,
                     double timeout_sec) {
    struct timeval loop_start, now;
    gettimeofday(&loop_start, NULL);

    int have_sync = 0;
    int byte_val = 0, bit_count = 0;
    int expected_len = -1, received_bytes = 0;

    while (1) {
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - loop_start.tv_sec) +
                         (now.tv_usec - loop_start.tv_usec) / 1000000.0;
        if (timeout_sec > 0 && elapsed > timeout_sec) {
            return 0;
        }

        if (gpioRead(IR_RX_GPIO) != IR_ACTIVE_LEVEL) {
            gpioDelay(100);
            continue;
        }

        uint32_t rx_start_tick = gpioTick();
        while (gpioRead(IR_RX_GPIO) == IR_ACTIVE_LEVEL) {
            // tight loop for high timing precision during the pulse
        }
        uint32_t pulse_width = gpioTick() - rx_start_tick;

        if (pulse_width > IR_SYNC_THRESHOLD_US) {
            have_sync = 1;
            byte_val = 0;
            bit_count = 0;
            expected_len = -1;
            received_bytes = 0;
            continue;
        }
        if (!have_sync) {
            continue;
        }

        int bit = (pulse_width < IR_BIT_THRESHOLD_US) ? 0 : 1;
        byte_val = (byte_val << 1) | bit;
        if (++bit_count < 8) {
            continue;
        }

        if (expected_len < 0) {
            expected_len = byte_val;
            if (expected_len <= 0 || expected_len > out_buf_size) {
                SST_print_error(
                    "ir_rx_buf(): declared length %d out of range (cap %d).",
                    expected_len, out_buf_size);
                return -1;
            }
        } else {
            out_buf[received_bytes++] = (unsigned char)byte_val;
        }
        byte_val = 0;
        bit_count = 0;

        if (expected_len >= 0 && received_bytes == expected_len) {
            return received_bytes;
        }
    }
}

SST_session_ctx_t* secure_connect_to_server_via_ir(session_key_t* s_key) {
    if (ir_init() < 0) {
        return NULL;
    }

    unsigned char entity_nonce[HS_NONCE_SIZE];
    unsigned int hs1_length;
    unsigned char* hs1 = parse_handshake_1(s_key, entity_nonce, &hs1_length);
    if (hs1 == NULL) {
        SST_print_error("Failed parse_handshake_1().");
        ir_deinit();
        return NULL;
    }

    unsigned char hs2[256];
    int hs2_length = 0;
    // At IR_INTER_BIT_GAP_US=50ms/bit, an 80-byte handshake2 (81 bytes with
    // its length header, 648 bits) takes ~32s to transmit on its own -- so
    // the wait here needs real headroom on top of that, not just a
    // "network RTT"-scale timeout.
    const double HS2_TIMEOUT_SEC = 60.0;
    const int MAX_RETRIES = 5;
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        SST_print_log(
            "IR handshake: broadcasting handshake1 (attempt %d/%d, %u "
            "bytes)...",
            attempt + 1, MAX_RETRIES, hs1_length);
        if (ir_tx_buf(hs1, hs1_length) < 0) {
            free(hs1);
            ir_deinit();
            return NULL;
        }
        hs2_length = ir_rx_buf(hs2, sizeof(hs2), HS2_TIMEOUT_SEC);
        if (hs2_length > 0) {
            break;
        } else if (hs2_length < 0) {
            free(hs1);
            ir_deinit();
            return NULL;
        }
        SST_print_log("IR handshake: timed out waiting for handshake2, retrying...");
    }
    free(hs1);
    if (hs2_length <= 0) {
        SST_print_error("IR handshake: no handshake2 received after %d attempts.",
                        MAX_RETRIES);
        ir_deinit();
        return NULL;
    }
    SST_print_log("IR handshake: received handshake2 (%d bytes).", hs2_length);

    unsigned int hs3_length;
    unsigned char* hs3 = check_handshake_2_send_handshake_3(
        hs2, hs2_length, entity_nonce, s_key, &hs3_length);
    if (hs3 == NULL) {
        SST_print_error("Failed check_handshake_2_send_handshake_3().");
        ir_deinit();
        return NULL;
    }
    SST_print_log("IR handshake: broadcasting handshake3 (%u bytes)...", hs3_length);
    if (ir_tx_buf(hs3, hs3_length) < 0) {
        free(hs3);
        ir_deinit();
        return NULL;
    }
    free(hs3);

    update_validity(s_key);
    SST_session_ctx_t* session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->sock = -1;
    session_ctx->sent_seq_num = 0;
    session_ctx->received_seq_num = 0;
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));

    ir_deinit();
    return session_ctx;
}

SST_session_ctx_t* server_secure_comm_setup_via_ir(
    SST_ctx_t* ctx, session_key_list_t* existing_s_key_list) {
    if (ir_init() < 0) {
        return NULL;
    }

    unsigned char hs1[256];
    int hs1_length = 0;
    SST_print_log("IR handshake: listening for handshake1 (Ctrl+C to stop)...");
    while (hs1_length <= 0) {
        hs1_length = ir_rx_buf(hs1, sizeof(hs1), 0);
        if (hs1_length < 0) {
            ir_deinit();
            return NULL;
        }
    }
    SST_print_log("IR handshake: received handshake1 (%d bytes).", hs1_length);

    if (hs1_length <= SESSION_KEY_ID_SIZE) {
        SST_print_error("IR handshake: handshake1 too short (%d bytes).", hs1_length);
        ir_deinit();
        return NULL;
    }
    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    memcpy(target_session_key_id, hs1, SESSION_KEY_ID_SIZE);

    session_key_t* s_key =
        get_session_key_by_ID(target_session_key_id, ctx, existing_s_key_list);
    if (s_key == NULL) {
        SST_print_error("Failed to get_session_key_by_ID().");
        ir_deinit();
        return NULL;
    }

    unsigned char server_nonce[HS_NONCE_SIZE];
    unsigned int hs2_length;
    unsigned char* hs2 = check_handshake1_send_handshake2(
        hs1, (unsigned int)hs1_length, server_nonce, s_key, &hs2_length);
    if (hs2 == NULL) {
        SST_print_error("Failed check_handshake1_send_handshake2().");
        ir_deinit();
        return NULL;
    }
    SST_print_log("IR handshake: broadcasting handshake2 (%u bytes)...", hs2_length);
    if (ir_tx_buf(hs2, hs2_length) < 0) {
        free(hs2);
        ir_deinit();
        return NULL;
    }
    free(hs2);

    unsigned char hs3[256];
    // Same headroom reasoning as HS2_TIMEOUT_SEC in
    // secure_connect_to_server_via_ir(): an ~80-byte handshake3 alone takes
    // ~32s to transmit at this bit rate.
    int hs3_length = ir_rx_buf(hs3, sizeof(hs3), 60.0);
    if (hs3_length <= 0) {
        SST_print_error("IR handshake: no handshake3 received.");
        ir_deinit();
        return NULL;
    }
    SST_print_log("IR handshake: received handshake3 (%d bytes).", hs3_length);

    // Verify handshake3: decrypt and check the reply nonce matches
    // server_nonce (mirrors the inline check in server_secure_comm_setup()'s
    // socket path).
    unsigned int decrypted_length;
    unsigned char* decrypted = NULL;
    if (symmetric_decrypt_authenticate(
            hs3, (unsigned int)hs3_length, s_key->mac_key, MAC_KEY_SIZE,
            s_key->cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
            s_key->enc_mode, s_key->no_hmac, &decrypted, &decrypted_length) < 0) {
        SST_print_error("Failed symmetric_decrypt_authenticate() on handshake3.");
        ir_deinit();
        return NULL;
    }
    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);
    if (strncmp((const char*)hs.reply_nonce, (const char*)server_nonce, HS_NONCE_SIZE) != 0) {
        SST_print_error("IR handshake: peer NOT verified, nonce did NOT match.");
        ir_deinit();
        return NULL;
    }
    SST_print_log("IR handshake: peer authenticated, nonce matched!");

    update_validity(s_key);
    SST_session_ctx_t* session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->sock = -1;
    session_ctx->sent_seq_num = 0;
    session_ctx->received_seq_num = 0;
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));

    ir_deinit();
    return session_ctx;
}
