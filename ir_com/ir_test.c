// ir_test.c
// IR distance-bounding test (Hancke-Kuhn protocol), combined into a single
// binary that can play either side, selected with --role at runtime:
//   --role initiator   Sends the sync pulse and challenges, measures RTT.
//   --role responder   Waits for challenges, decodes and replies immediately.
// Compile: gcc -O2 -Wall -pthread -o ir_test ir_test.c -lpigpio -lrt -lm
// Run:     sudo ./ir_test --role initiator
//          sudo ./ir_test --role responder

#include <pigpio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define TX_GPIO 27
#define RX_GPIO 14
#define ACTIVE_LEVEL 0

// Hancke-Kuhn Protocol Parameters
#define GAP_MS 50 // Settle time between rounds

// Shared 32-byte secret (256 bits)
static const uint8_t secret[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

static volatile int running = 1;

static void on_sigint(int sig)
{
    (void)sig;
    running = 0;
}

// Pre-created waves
static int wave_short = -1;
static int wave_long = -1;
static int wave_sync_32 = -1;
static int wave_sync_64 = -1;
static int wave_sync_128 = -1;

// Builds a 38kHz carrier pulse wave of specified duration (us)
static int build_38khz_burst_wave(int gpio, int burst_us)
{
    const int half_period_us = 13; // approx 38.46 kHz
    int cycles = burst_us / (2 * half_period_us);
    int pulse_count = cycles * 2;

    gpioPulse_t *pulses = calloc((size_t)pulse_count, sizeof(gpioPulse_t));
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

    int wave_id = gpioWaveCreate();
    return wave_id;
}

static int get_bit(const uint8_t *reg, int bit_idx)
{
    int byte_idx = bit_idx / 8;
    int bit_pos = bit_idx % 8;
    return (reg[byte_idx] >> (7 - bit_pos)) & 1;
}

// ---- Initiator: sends the sync pulse and challenges, measures RTT. ----

static void run_initiator_round(int num_rounds, int sync_wave)
{
    printf("\n=========================================\n");
    printf("=== Starting %d-Round Test ===\n", num_rounds);
    printf("=========================================\n");
    printf("Sending Sync pulse to reset responder...\n");

    // Send Sync pulse
    gpioWaveTxSend(sync_wave, PI_WAVE_MODE_ONE_SHOT);
    while (gpioWaveTxBusy()) {
        gpioDelay(100);
    }
    gpioDelay(200000); // Wait 200ms for responder to settle

    // Split 32-byte secret into two 16-byte registers
    const uint8_t *R0 = secret;
    const uint8_t *R1 = secret + 16;

    printf("Starting fast exchange...\n");
    printf("round,challenge,expected,response,rtt_us,pulse_us,result\n");

    int successful_rounds = 0;
    uint32_t rtt_sum = 0;

    uint32_t fast_start = gpioTick();

    for (int i = 0; running && i < num_rounds; i++) {
        // 1. Generate challenge bit
        int challenge = rand() & 1;
        int expected = get_bit((challenge == 0) ? R0 : R1, i);

        // 2. Clear any RX line noise
        gpioDelay(100);

        // 3. Send challenge wave
        int tx_wave = (challenge == 0) ? wave_short : wave_long;
        gpioWaveTxSend(tx_wave, PI_WAVE_MODE_ONE_SHOT);

        // Wait for transmission to end (to start RTT measurement from end of TX)
        while (gpioWaveTxBusy()) {
            // tight loop
        }
        uint32_t end_tx_tick = gpioTick();

        // 4. Wait for responder's reply start (falling edge on RX)
        uint32_t wait_start = gpioTick();
        int timed_out = 0;
        uint32_t rx_start_tick = 0;

        while (gpioRead(RX_GPIO) != ACTIVE_LEVEL) {
            if ((gpioTick() - wait_start) > 50000) { // 50ms timeout
                timed_out = 1;
                break;
            }
        }

        if (!timed_out) {
            rx_start_tick = gpioTick();

            // Wait for responder's reply to end (rising edge on RX)
            while (gpioRead(RX_GPIO) == ACTIVE_LEVEL) {
                if ((gpioTick() - rx_start_tick) > 50000) {
                    timed_out = 1;
                    break;
                }
            }
        }
        uint32_t rx_end_tick = gpioTick();

        if (timed_out) {
            printf("%d,%d,%d,TIMEOUT,0,0,FAIL\n", i, challenge, expected);
            fflush(stdout);
        } else {
            uint32_t rtt = rx_start_tick - end_tx_tick;
            uint32_t pulse_width = rx_end_tick - rx_start_tick;
            int response = (pulse_width < 450) ? 0 : 1;
            int matches = (response == expected);

            if (matches) {
                successful_rounds++;
                rtt_sum += rtt;
            }

            printf("%d,%d,%d,%d,%u,%u,%s\n",
                   i, challenge, expected, response, rtt, pulse_width,
                   matches ? "SUCCESS" : "FAIL");
            fflush(stdout);
        }

        // Sleep to let AGC recover before next round
        gpioDelay(GAP_MS * 1000);
    }

    uint32_t fast_end = gpioTick();
    uint32_t total_time_us = fast_end - fast_start;

    printf("\n--- %d-Round Summary ---\n", num_rounds);
    printf("Successful Rounds:  %d/%d\n", successful_rounds, num_rounds);
    printf("Total Elapsed Time: %u us (%.2f ms)\n", total_time_us, (double)total_time_us / 1000.0);
    if (successful_rounds > 0) {
        printf("Average RTT:        %.2f us\n", (double)rtt_sum / successful_rounds);
    }
}

static void run_initiator(void)
{
    run_initiator_round(32, wave_sync_32);
    gpioDelay(2000000); // Wait 2 seconds before next test

    if (running) {
        run_initiator_round(64, wave_sync_64);
        gpioDelay(2000000); // Wait 2 seconds before next test
    }

    if (running) {
        run_initiator_round(128, wave_sync_128);
    }
}

// ---- Responder: waits for challenges, decodes and replies immediately. ----

static void run_responder(void)
{
    // Split 32-byte secret into two 16-byte registers
    const uint8_t *R0 = secret;
    const uint8_t *R1 = secret + 16;

    printf("Waiting for Sync pulse or fast challenges...\n");

    int fast_phase = 0;
    int round_idx = 0;
    int expected_rounds = 128;

    while (running) {
        // Wait for RX pin to go LOW (start of pulse)
        while (running && gpioRead(RX_GPIO) != ACTIVE_LEVEL) {
            gpioDelay(100); // 100us sleep to save CPU when idle
        }

        if (!running) break;

        uint32_t rx_start_tick = gpioTick();

        // Wait for RX pin to go HIGH (end of pulse)
        while (gpioRead(RX_GPIO) == ACTIVE_LEVEL) {
            // Tight loop for high timing precision during transmission
        }
        uint32_t rx_end_tick = gpioTick();

        uint32_t pulse_width = rx_end_tick - rx_start_tick;

        // Check for Sync pulse (duration > 1500us)
        if (pulse_width > 1500) {
            int num_rounds = 128;
            if (pulse_width < 2500) {
                num_rounds = 32;
            } else if (pulse_width < 3500) {
                num_rounds = 64;
            } else {
                num_rounds = 128;
            }

            printf("\n--- New Session Started ---\n");
            printf("Sync pulse detected (width: %u us). Set expected rounds to %d.\n", pulse_width, num_rounds);
            fflush(stdout);

            round_idx = 0;
            expected_rounds = num_rounds;
            fast_phase = 1;
            continue;
        }

        // If not in fast phase, ignore short/long pulses
        if (!fast_phase) {
            continue;
        }

        // Decode challenge bit
        int challenge = (pulse_width < 450) ? 0 : 1;

        // Lookup response bit from R0 or R1
        int response = get_bit((challenge == 0) ? R0 : R1, round_idx);

        // Send response immediately
        int tx_wave = (response == 0) ? wave_short : wave_long;
        gpioWaveTxSend(tx_wave, PI_WAVE_MODE_ONE_SHOT);

        // Wait for transmission to end
        while (gpioWaveTxBusy()) {
            // Tight loop
        }

        round_idx++;
        if (round_idx >= expected_rounds) {
            printf("Completed %d rounds of fast exchange. Going back to idle.\n", expected_rounds);
            fflush(stdout);
            fast_phase = 0;
        }
    }
}

int main(int argc, char *argv[])
{
    const char *role = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[i + 1];
            i++;
        }
    }

    int is_initiator;
    if (role && strcmp(role, "initiator") == 0) {
        is_initiator = 1;
    } else if (role && strcmp(role, "responder") == 0) {
        is_initiator = 0;
    } else {
        fprintf(stderr, "Usage: %s --role initiator|responder\n", argv[0]);
        return 1;
    }

    signal(SIGINT, on_sigint);

    if (gpioInitialise() < 0) {
        fprintf(stderr, "gpioInitialise failed. Try running with sudo.\n");
        return 1;
    }

    gpioSetMode(TX_GPIO, PI_OUTPUT);
    gpioWrite(TX_GPIO, 0);

    gpioSetMode(RX_GPIO, PI_INPUT);
    gpioSetPullUpDown(RX_GPIO, PI_PUD_UP);

    // Clean up any waves from previous runs
    gpioWaveClear();

    // Pre-build waves
    wave_short = build_38khz_burst_wave(TX_GPIO, 300); // 300us (Bit 0)
    wave_long  = build_38khz_burst_wave(TX_GPIO, 600); // 600us (Bit 1)
    wave_sync_32  = build_38khz_burst_wave(TX_GPIO, 2000); // 2000us (Sync 32 rounds)
    wave_sync_64  = build_38khz_burst_wave(TX_GPIO, 3000); // 3000us (Sync 64 rounds)
    wave_sync_128 = build_38khz_burst_wave(TX_GPIO, 4000); // 4000us (Sync 128 rounds)

    if (wave_short < 0 || wave_long < 0 || wave_sync_32 < 0 || wave_sync_64 < 0 || wave_sync_128 < 0) {
        fprintf(stderr, "Failed to create waves\n");
        gpioTerminate();
        return 1;
    }

    printf("%s started. TX GPIO=%d, RX GPIO=%d\n", is_initiator ? "Initiator" : "Responder", TX_GPIO, RX_GPIO);

    if (is_initiator) {
        run_initiator();
    } else {
        run_responder();
    }

    gpioWrite(TX_GPIO, 0);
    gpioTerminate();
    return 0;
}
