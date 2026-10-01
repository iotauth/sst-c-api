// SST handshake (SKEY_HANDSHAKE_1/2/3) carried over visible light, plus the
// pigpio adapter for the mutual LiFi HK check. Linux/pigpio only, and
// requires root at runtime (pigpio needs direct GPIO access). pigpio does not
// support the Pi 5.
//
// Physical layer, as validated by lifi_test.c on the bench: the LED is ON
// at idle (mark) and a symbol is a DARK interval of a given width. The
// TEMT6000 is non-inverting, so the sensor pin reads 0 for the duration of a
// pulse and 1 otherwise. There is no carrier and no demodulating receiver,
// which changes three things relative to ../ir_com/ir_sst_handshake.c:
//
//  * The line is only at mark while the PEER's LED is lit, so "dark for
//    longer than any symbol" means the peer is off/misaligned, not a frame.
//    The receiver waits that out instead of failing, and both sides keep
//    their LED lit across every phase (handshake -> HK).
//  * The sensor falls slower than it rises, so every dark symbol is received
//    NARROWER than sent (~180 us less on the recorded 600/1200 us run:
//    600 -> ~420 us, 1200 -> ~1020 us). The IR 300/600 us symbols would both
//    decode as 0, and 350/890 us mostly failed (short bits arrive at the
//    glitch floor). 600/1200 us ran 224/224 clean on the bench; the
//    thresholds are derived from them the same way lifi_test.c does
//    (split at the midpoint, glitch floor at half the short width).
//  * No AGC: the per-bit settle gap only has to cover the sensor's own
//    recovery, so byte framing runs ~25x faster than IR's 25 ms/bit.
//
// Symbols are one-shot pigpio waves (dark for the width, then relight), like
// the IR bursts, so their widths are DMA-timed rather than exposed to
// scheduler jitter, and "TX finished" is observed the same way
// (gpioWaveTxBusy() clearing) for the RTT measurement.
//
// Compilation (from lifi_com/):
//   gcc -I../.. lifi_sst_handshake.c ... -lpigpio -lrt -lm -lpthread

#include "lifi_sst_handshake.h"

#include <pigpio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/c_common.h"
#include "../src/c_crypto.h"
#include "../src/c_secure_comm.h"
#include "lifi_hk.h"

// Dark widths as sent (the bench-validated lifi_test.c settings).
// Received widths come back ~180 us narrower (see above).
#define LIFI_SHORT_US 600            // bit 0
#define LIFI_LONG_US 1200            // bit 1
#define LIFI_SYNC_US 2000            // start-of-frame marker
#define LIFI_BIT_THRESHOLD_US 900    // received width < this = bit 0, else 1
#define LIFI_SYNC_THRESHOLD_US 1500  // received width > this = sync marker
#define LIFI_MIN_WIDTH_US 300        // narrower than this is a glitch
// Dark this long is not a symbol: the peer's LED is off or the sensor no
// longer sees it. The receiver resets and waits for light to return.
#define LIFI_LINE_LOST_US 10000
// Settle time before each pulse of the byte framing, so the peer's sensor has
// relit and its receive loop is back to waiting for an edge. The sensor's
// rise time plus polling slack is a few hundred us, so this is deliberately
// generous (not bench-tuned): an 80-byte handshake message is still ~4 s,
// against ~32 s for IR. Lower it once the handshake is known to work.
#define LIFI_INTER_BIT_GAP_US 5000
// Lead before a control message so the peer has entered frame RX. Longer
// than IR's 25 ms because both sides re-init pigpio (~100 ms) between the
// handshake and the HK phase, and a LiFi INIT frame is only ~0.8 s long, so
// a missed sync marker is not recovered by the frame's own duration. Paid
// twice per run.
#define LIFI_CONTROL_LEAD_US 250000
#define LIFI_MAX_PAYLOAD 255  // fits in the 1-byte length header

static int tx_gpio = 23, rx_gpio = 22, led_active_low = 0;
static int wave_short = -1, wave_long = -1, wave_sync = -1;

void lifi_configure(int tx, int rx, int active_low) {
    tx_gpio = tx;
    rx_gpio = rx;
    led_active_low = active_low;
}

static void tx_level(int logical) {
    gpioWrite(tx_gpio, led_active_low ? !logical : logical);
}

// Builds a one-shot wave that holds the LED dark for width_us and then relights
// it. Two pulses: the dark hold, then a 1 us "light" pulse so the wave ends
// with the LED back at mark.
static int build_dark_pulse_wave(unsigned width_us) {
    uint32_t bit = 1u << tx_gpio;
    uint32_t light_on = led_active_low ? 0 : bit,
             light_off = led_active_low ? bit : 0;
    gpioPulse_t pulses[2] = {
        {.gpioOn = light_off, .gpioOff = light_on, .usDelay = width_us},
        {.gpioOn = light_on, .gpioOff = light_off, .usDelay = 1}};
    gpioWaveAddGeneric(2, pulses);
    return gpioWaveCreate();
}

static int lifi_init(void) {
    if (gpioInitialise() < 0) {
        SST_print_error("gpioInitialise() failed. Try running with sudo.");
        return -1;
    }
    // Level first, then mode, so the LED never glitches dark on (re)init --
    // the peer may already be listening and would see a false symbol.
    tx_level(1);
    gpioSetMode(tx_gpio, PI_OUTPUT);
    tx_level(1);
    gpioSetMode(rx_gpio, PI_INPUT);
    gpioSetPullUpDown(rx_gpio, PI_PUD_OFF);  // module has its own 10k load

    gpioWaveClear();
    wave_short = build_dark_pulse_wave(LIFI_SHORT_US);
    wave_long = build_dark_pulse_wave(LIFI_LONG_US);
    wave_sync = build_dark_pulse_wave(LIFI_SYNC_US);
    if (wave_short < 0 || wave_long < 0 || wave_sync < 0) {
        SST_print_error("Failed to create LiFi waves.");
        gpioTerminate();
        return -1;
    }
    return 0;
}

// Leaves the LED lit: the peer's line must stay at mark between phases.
static void lifi_deinit(void) {
    gpioWaveTxStop();
    tx_level(1);
    gpioTerminate();
}

static int lifi_send_wave(int wave) {
    uint32_t start = gpioTick();
    if (gpioWaveTxSend(wave, PI_WAVE_MODE_ONE_SHOT) < 0) return -1;
    while (gpioWaveTxBusy()) {
        if ((uint32_t)(gpioTick() - start) > 10000) return -1;
    }
    return 0;
}

static int lifi_tx_byte(unsigned char b) {
    for (int bit = 7; bit >= 0; bit--) {
        gpioDelay(LIFI_INTER_BIT_GAP_US);
        if (lifi_send_wave((b >> bit) & 1 ? wave_long : wave_short)) return -1;
    }
    return 0;
}

// Sends buf over light: a sync marker, then a 1-byte length header, then the
// payload bytes, each byte as 8 sequential dark pulses (short = bit 0, long =
// bit 1). Same framing as ir_tx_buf(). @return 0 on success, -1 on error.
static int lifi_tx_buf(const unsigned char* buf, int len) {
    if (len <= 0 || len > LIFI_MAX_PAYLOAD) {
        SST_print_error(
            "lifi_tx_buf(): payload of %d bytes exceeds the %d-byte cap.", len,
            LIFI_MAX_PAYLOAD);
        return -1;
    }
    if (lifi_send_wave(wave_sync) || lifi_tx_byte((unsigned char)len))
        return -1;
    for (int i = 0; i < len; i++) {
        if (lifi_tx_byte(buf[i])) return -1;
    }
    return 0;
}

// Waits for a sync marker, then decodes a 1-byte length header followed by
// that many payload bytes, one bit per dark pulse. A dark interval longer
// than LIFI_LINE_LOST_US is the peer's LED being off, not data: the partial
// frame is dropped and decoding resumes once light returns. @return decoded
// byte length (>0) on success, 0 on timeout, -1 on a framing error.
static int lifi_rx_buf(unsigned char* out_buf, int out_buf_size,
                       double timeout_sec) {
    uint32_t loop_start = gpioTick();
    int have_sync = 0, byte_val = 0, bit_count = 0;
    int expected_len = -1, received_bytes = 0, reported_dark = 0;

    while (1) {
        double elapsed = (uint32_t)(gpioTick() - loop_start) / 1000000.0;
        if (timeout_sec > 0 && elapsed > timeout_sec) return 0;

        if (gpioRead(rx_gpio) != 0) {
            gpioDelay(100);
            continue;
        }

        uint32_t rx_start_tick = gpioTick();
        int line_lost = 0;
        while (gpioRead(rx_gpio) == 0) {
            if ((uint32_t)(gpioTick() - rx_start_tick) > LIFI_LINE_LOST_US) {
                line_lost = 1;
                break;
            }
        }
        if (line_lost) {
            if (!reported_dark) {
                SST_print_log(
                    "LiFi: sensor dark > %u us; waiting for the peer's LED "
                    "(peer not running, misaligned, or too dim).",
                    LIFI_LINE_LOST_US);
                reported_dark = 1;
            }
            while (gpioRead(rx_gpio) == 0) {
                elapsed = (uint32_t)(gpioTick() - loop_start) / 1000000.0;
                if (timeout_sec > 0 && elapsed > timeout_sec) return 0;
                gpioDelay(1000);
            }
            SST_print_log("LiFi: light is back; listening.");
            have_sync = 0;
            continue;
        }
        uint32_t pulse_width = gpioTick() - rx_start_tick;

        if (pulse_width > LIFI_SYNC_THRESHOLD_US) {
            have_sync = 1;
            byte_val = 0;
            bit_count = 0;
            expected_len = -1;
            received_bytes = 0;
            continue;
        }
        if (!have_sync || pulse_width < LIFI_MIN_WIDTH_US) continue;

        int bit = (pulse_width < LIFI_BIT_THRESHOLD_US) ? 0 : 1;
        byte_val = (byte_val << 1) | bit;
        if (++bit_count < 8) continue;

        if (expected_len < 0) {
            expected_len = byte_val;
            if (expected_len <= 0 || expected_len > out_buf_size) {
                SST_print_error(
                    "lifi_rx_buf(): declared length %d out of range (cap %d).",
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

// Confirms the sensor sees the peer's lit LED before we start. Not fatal on
// its own -- lifi_rx_buf() waits for light -- but the most common bench
// failure, so worth one clear line up front.
static void report_idle_level(void) {
    int high = 0, samples = 100;
    for (int i = 0; i < samples; i++) {
        high += gpioRead(rx_gpio);
        gpioDelay(2000);
    }
    SST_print_log(
        "LiFi: tx=GPIO%d rx=GPIO%d led=%s; idle sensor level %s "
        "(%d%% high).",
        tx_gpio, rx_gpio, led_active_low ? "active-low" : "active-high",
        high > samples / 2 ? "HIGH" : "LOW", high * 100 / samples);
    if (high <= samples / 2) {
        SST_print_log(
            "LiFi: sensor does not see a lit LED: check alignment, that the "
            "peer is running, and that the room is dim.");
    }
}

static SST_session_ctx_t* new_session_ctx(session_key_t* s_key) {
    update_validity(s_key);
    SST_session_ctx_t* session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->sock = -1;
    session_ctx->sent_seq_num = 0;
    session_ctx->received_seq_num = 0;
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
    return session_ctx;
}

SST_session_ctx_t* secure_connect_to_server_via_lifi(session_key_t* s_key) {
    if (lifi_init() < 0) {
        return NULL;
    }
    report_idle_level();

    unsigned char entity_nonce[HS_NONCE_SIZE];
    unsigned int hs1_length;
    unsigned char* hs1 = parse_handshake_1(s_key, entity_nonce, &hs1_length);
    if (hs1 == NULL) {
        SST_print_error("Failed parse_handshake_1().");
        lifi_deinit();
        return NULL;
    }

    unsigned char hs2[256];
    int hs2_length = 0;
    // An 80-byte handshake2 is ~650 symbols at ~6 ms each, i.e. ~4 s on the
    // wire; the wait allows for the peer's Auth round trip too.
    const double HS2_TIMEOUT_SEC = 15.0;
    const int MAX_RETRIES = 5;
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        SST_print_log(
            "LiFi handshake: sending handshake1 (attempt %d/%d, %u bytes)...",
            attempt + 1, MAX_RETRIES, hs1_length);
        if (lifi_tx_buf(hs1, hs1_length) < 0) {
            free(hs1);
            lifi_deinit();
            return NULL;
        }
        hs2_length = lifi_rx_buf(hs2, sizeof(hs2), HS2_TIMEOUT_SEC);
        if (hs2_length > 0) {
            break;
        } else if (hs2_length < 0) {
            free(hs1);
            lifi_deinit();
            return NULL;
        }
        SST_print_log(
            "LiFi handshake: timed out waiting for handshake2, retrying...");
    }
    free(hs1);
    if (hs2_length <= 0) {
        SST_print_error(
            "LiFi handshake: no handshake2 received after %d attempts.",
            MAX_RETRIES);
        lifi_deinit();
        return NULL;
    }
    SST_print_log("LiFi handshake: received handshake2 (%d bytes).",
                  hs2_length);

    unsigned int hs3_length;
    unsigned char* hs3 = check_handshake_2_send_handshake_3(
        hs2, hs2_length, entity_nonce, s_key, &hs3_length);
    if (hs3 == NULL) {
        SST_print_error("Failed check_handshake_2_send_handshake_3().");
        lifi_deinit();
        return NULL;
    }
    SST_print_log("LiFi handshake: sending handshake3 (%u bytes)...",
                  hs3_length);
    if (lifi_tx_buf(hs3, hs3_length) < 0) {
        free(hs3);
        lifi_deinit();
        return NULL;
    }
    free(hs3);

    SST_session_ctx_t* session_ctx = new_session_ctx(s_key);
    lifi_deinit();
    return session_ctx;
}

SST_session_ctx_t* server_secure_comm_setup_via_lifi(
    SST_ctx_t* ctx, session_key_list_t* existing_s_key_list) {
    if (lifi_init() < 0) {
        return NULL;
    }
    report_idle_level();

    unsigned char hs1[256];
    int hs1_length = 0;
    SST_print_log(
        "LiFi handshake: listening for handshake1 (Ctrl+C to stop)...");
    while (hs1_length <= 0) {
        hs1_length = lifi_rx_buf(hs1, sizeof(hs1), 0);
        if (hs1_length < 0) {
            lifi_deinit();
            return NULL;
        }
    }
    SST_print_log("LiFi handshake: received handshake1 (%d bytes).",
                  hs1_length);

    if (hs1_length <= SESSION_KEY_ID_SIZE) {
        SST_print_error("LiFi handshake: handshake1 too short (%d bytes).",
                        hs1_length);
        lifi_deinit();
        return NULL;
    }
    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    memcpy(target_session_key_id, hs1, SESSION_KEY_ID_SIZE);

    session_key_t* s_key =
        get_session_key_by_ID(target_session_key_id, ctx, existing_s_key_list);
    if (s_key == NULL) {
        SST_print_error("Failed to get_session_key_by_ID().");
        lifi_deinit();
        return NULL;
    }

    unsigned char server_nonce[HS_NONCE_SIZE];
    unsigned int hs2_length;
    unsigned char* hs2 = check_handshake1_send_handshake2(
        hs1, (unsigned int)hs1_length, server_nonce, s_key, &hs2_length);
    if (hs2 == NULL) {
        SST_print_error("Failed check_handshake1_send_handshake2().");
        lifi_deinit();
        return NULL;
    }
    SST_print_log("LiFi handshake: sending handshake2 (%u bytes)...",
                  hs2_length);
    if (lifi_tx_buf(hs2, hs2_length) < 0) {
        free(hs2);
        lifi_deinit();
        return NULL;
    }
    free(hs2);

    unsigned char hs3[256];
    int hs3_length = lifi_rx_buf(hs3, sizeof(hs3), 15.0);
    if (hs3_length <= 0) {
        SST_print_error("LiFi handshake: no handshake3 received.");
        lifi_deinit();
        return NULL;
    }
    SST_print_log("LiFi handshake: received handshake3 (%d bytes).",
                  hs3_length);

    // Verify handshake3: decrypt and check the reply nonce matches
    // server_nonce (mirrors the inline check in server_secure_comm_setup()'s
    // socket path).
    unsigned int decrypted_length;
    unsigned char* decrypted = NULL;
    if (symmetric_decrypt_authenticate(
            hs3, (unsigned int)hs3_length, s_key->mac_key, MAC_KEY_SIZE,
            s_key->cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
            s_key->enc_mode, s_key->no_hmac, &decrypted,
            &decrypted_length) < 0) {
        SST_print_error(
            "Failed symmetric_decrypt_authenticate() on handshake3.");
        lifi_deinit();
        return NULL;
    }
    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);
    if (strncmp((const char*)hs.reply_nonce, (const char*)server_nonce,
                HS_NONCE_SIZE) != 0) {
        SST_print_error(
            "LiFi handshake: peer NOT verified, nonce did NOT match.");
        lifi_deinit();
        return NULL;
    }
    SST_print_log("LiFi handshake: peer authenticated, nonce matched!");

    SST_session_ctx_t* session_ctx = new_session_ctx(s_key);
    lifi_deinit();
    return session_ctx;
}

/* The HK adapter shares the handshake's wiring and prebuilt waves. Slow
 * controls use byte framing; rapid response bits bypass the byte encoder's
 * settle delay. No logging/allocation/crypto in a round. */
static int hk_send_control(void* ctx, const unsigned char* p, unsigned n) {
    (void)ctx;
    gpioDelay(LIFI_CONTROL_LEAD_US); /* Give peer time to enter frame RX. */
    return lifi_tx_buf(p, (int)n);
}
static int hk_recv_control(void* ctx, unsigned char* p, unsigned n) {
    (void)ctx;
    return lifi_rx_buf(p, (int)n, 60.0) == (int)n ? 0 : -1;
}
static int hk_send_bit(void* ctx, unsigned char bit, uint32_t* end) {
    (void)ctx;
    if (gpioWaveTxSend(bit ? wave_long : wave_short, PI_WAVE_MODE_ONE_SHOT) < 0)
        return -1;
    uint32_t start = gpioTick();
    while (gpioWaveTxBusy()) {
        if ((uint32_t)(gpioTick() - start) > 10000) return -1;
    }
    *end = gpioTick();
    return 0;
}
static int hk_recv_bit(void* ctx, unsigned char* bit, uint32_t* end) {
    (void)ctx;
    uint32_t start = gpioTick();
    while (gpioRead(rx_gpio) != 0) {
        if ((uint32_t)(gpioTick() - start) > 1100000) return -1;
    }
    uint32_t pulse = gpioTick();
    while (gpioRead(rx_gpio) == 0) {
        /* Longer than a sync marker is not a bit: peer LED lost, or a
         * merged symbol. Abort the run rather than guess. */
        if ((uint32_t)(gpioTick() - pulse) > LIFI_SYNC_THRESHOLD_US) return -1;
    }
    *end = gpioTick();
    uint32_t width = *end - pulse;
    /* Reject glitches, rather than treating every dip as a bit. */
    if (width < LIFI_MIN_WIDTH_US) return -1;
    *bit = width < LIFI_BIT_THRESHOLD_US ? 0 : 1;
    return 0;
}
static void hk_pause(void* ctx, unsigned us) {
    (void)ctx;
    gpioDelay(us);
}
int lifi_hk_run_gpio(const session_key_t* key, const lifi_hk_config* config,
                     int initiator, lifi_hk_result* result) {
    if (lifi_init()) return -1;
    lifi_hk_io io = {NULL,        hk_send_control, hk_recv_control,
                     hk_send_bit, hk_recv_bit,     hk_pause};
    int rc = lifi_hk_run(key, config, initiator, &io, result);
    lifi_deinit();
    return rc;
}
