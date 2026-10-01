// lifi_test.c
// Challenge/response RTT test over visible light, modelled on
// ../ir_com/ir_test.c (Hancke-Kuhn shaped: one-bit challenge, one-bit
// response looked up in a register, round-trip time measured). Same fixed
// shared secret, same 32/64/128 round sessions, same CSV output, so results
// are directly comparable with the IR numbers. One binary plays either side:
//   sudo ./lifi_test --role initiator   # sends sync + challenges, times RTT
//   sudo ./lifi_test --role responder   # decodes challenges, replies at once
//   sudo ./lifi_test --role loopback    # one Pi, LED at own sensor: measures
//                                          # the sensor's rise/fall latency and
//                                          # the narrowest dark pulse it passes
//
// Physical layer is where this differs from IR. There is no 38 kHz carrier
// and no demodulating receiver: the LED is ON at idle (mark, as in the UART
// link) and a symbol is a DARK interval of a given width. The TEMT6000 is
// non-inverting, so the sensor reads 0 for the duration of a pulse and 1
// otherwise. Widths default to the IR values (300 us = bit 0, 600 us =
// bit 1, 2000/3000/4000 us sync = 32/64/128 rounds) but are options. The
// defaults are the settings that ran 224/224 clean on the pi42/pi43 pair
// (600/1200 us, 50 ms gap). The TEMT6000 falls slower than it rises, so every
// dark symbol arrives ~180 us narrower than sent; at the IR 300/600 widths
// both bits land below a 450 us threshold, and 350/890 mostly failed. Run
// loopback first on a new sensor.
//
// What RTT means here: light covers a metre and back in 6.7 ns, below the
// 1 us tick resolution, so RTT does NOT measure distance the way the
// ultrasonic echo test does. It measures sensor rise time + the responder's
// software latency + scheduling jitter. Its use is the same as for IR:
// establish the honest RTT distribution, then reject anything slower (a
// relay through another channel). Read the summary as a latency budget, not
// as metres.
//
// Options: --tx-gpio N (23)  --rx-gpio N (22)   BCM numbers; pi42 wiring.
//                                                pi43 is the reverse (22/23).
//          --led-active-low    LED lights on GPIO LOW (KS0016 between its +
//                              rail and S). Default is active HIGH: KS0032
//                              with R tied to GND and V driven from the GPIO.
//          --short-us N (600)  --long-us N (1200)  bit 0 / bit 1 dark widths
//          --gap-ms N (50)     pause between rounds
//          --timeout-ms N (50) how long the initiator waits for a response
//          --rounds N          32, 64 or 128; default runs all three in turn
//          --count N (20)      loopback iterations
//
// Compile: gcc -O2 -Wall -o lifi_test lifi_test.c -lpigpio -lrt -lpthread

#include <pigpio.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int tx_gpio = 23, rx_gpio = 22, led_active_low = 0;
static unsigned short_us = 600, long_us = 1200;
static unsigned gap_ms = 50, timeout_ms = 50;
static volatile int running = 1;

// Sync pulse widths are fixed so the responder can tell them from data bits
// whatever --long-us is (it must stay below LIFI_SYNC_THRESHOLD_US).
#define SYNC_THRESHOLD_US 1500
#define SYNC_32_US 2000
#define SYNC_64_US 3000
#define SYNC_128_US 4000
#define MAX_ROUNDS 128

// Same 32-byte secret as ir_test.c: R0 is the first half, R1 the second.
static const uint8_t secret[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
    0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

static void on_sigint(int sig) {
    (void)sig;
    running = 0;
}

static int get_bit(const uint8_t* reg, int bit_idx) {
    return (reg[bit_idx / 8] >> (7 - bit_idx % 8)) & 1;
}

// ---- Physical layer: dark pulses on a lit LED, level reads on the sensor --

static void tx_level(int logical) {
    gpioWrite(tx_gpio, led_active_low ? !logical : logical);
}

static void spin_until(uint32_t t) {
    while ((int32_t)(gpioTick() - t) < 0) {
    }
}

// Holds the LED dark for width_us, then relights it. Returns the tick at
// which the LED was relit, i.e. the end of the symbol.
static uint32_t tx_pulse(unsigned width_us) {
    uint32_t t = gpioTick();
    tx_level(0);
    spin_until(t + width_us);
    tx_level(1);
    return gpioTick();
}

// Busy-polls the sensor until it reads `level`. On success stores the tick
// at which it did and returns 0; returns -1 if timeout_us passes first.
static int wait_level(int level, uint32_t timeout_us, uint32_t* at) {
    uint32_t start = gpioTick();
    while (gpioRead(rx_gpio) != level) {
        if (gpioTick() - start > timeout_us) return -1;
    }
    *at = gpioTick();
    return 0;
}

static unsigned decode_threshold(void) { return (short_us + long_us) / 2; }

// A dark interval narrower than this is a glitch, not a symbol.
static unsigned min_valid_width(void) { return short_us / 2; }

// Same diagnostic as lifi_bitbang.c. Both roles expect HIGH here: at idle
// the peer's LED is on (or, in loopback, our own).
static void report_idle_level(void) {
    int high = 0, samples = 200;
    for (int i = 0; i < samples; i++) {
        high += gpioRead(rx_gpio);
        gpioDelay(5000);
    }
    printf("idle sensor level over 1s: %s (%d%% high)\n",
           high > samples / 2 ? "HIGH" : "LOW", high * 100 / samples);
    if (high <= samples / 2) {
        printf("  sensor does not see a lit LED at idle: check alignment, "
               "that the peer is running, and that the room is dim\n");
    }
}

// ---- Initiator: sends the sync pulse and challenges, measures RTT. ----

static void run_initiator_round(int num_rounds, unsigned sync_us) {
    printf("\n=========================================\n");
    printf("==== Starting %d-Round Test ====\n", num_rounds);
    printf("=========================================\n");
    printf("Sending sync pulse (%u us) to reset responder...\n", sync_us);
    tx_pulse(sync_us);
    gpioDelay(200000);  // 200 ms for the responder to settle

    const uint8_t* R0 = secret;
    const uint8_t* R1 = secret + 16;
    unsigned threshold = decode_threshold();
    uint32_t timeout_us = timeout_ms * 1000;

    printf("Starting fast exchange...\n");
    // recovery_us: time after our own pulse ended until our sensor read
    // light again. Should be ~0 when the peer's LED alone is enough to hold
    // the sensor high; if it grows, our own LED is what was lighting the
    // sensor and the link is marginal.
    printf("round,challenge,expected,response,rtt_us,pulse_us,recovery_us,"
           "result\n");

    int successful_rounds = 0;
    uint32_t rtt_sum = 0, rtt_min = UINT32_MAX, rtt_max = 0;
    uint32_t fast_start = gpioTick();

    for (int i = 0; running && i < num_rounds; i++) {
        int challenge = rand() & 1;
        int expected = get_bit(challenge == 0 ? R0 : R1, i);
        uint32_t t;

        // Line must be at mark (peer lit, sensor high) before we challenge.
        if (wait_level(1, 5000, &t) < 0) {
            printf("%d,%d,%d,LINE_LOW,0,0,0,FAIL\n", i, challenge, expected);
            fflush(stdout);
            gpioDelay(gap_ms * 1000);
            continue;
        }

        // RTT is measured from the end of our own pulse, as in ir_test.c.
        uint32_t end_tx_tick = tx_pulse(challenge ? long_us : short_us);

        uint32_t idle_tick, rx_start_tick, rx_end_tick;
        int timed_out = wait_level(1, timeout_us, &idle_tick) < 0 ||
                        wait_level(0, timeout_us, &rx_start_tick) < 0 ||
                        wait_level(1, timeout_us, &rx_end_tick) < 0;

        if (timed_out) {
            printf("%d,%d,%d,TIMEOUT,0,0,0,FAIL\n", i, challenge, expected);
        } else {
            uint32_t rtt = rx_start_tick - end_tx_tick;
            uint32_t pulse_width = rx_end_tick - rx_start_tick;
            uint32_t recovery = idle_tick - end_tx_tick;
            int response = pulse_width < threshold ? 0 : 1;
            int matches = response == expected;
            if (matches) {
                successful_rounds++;
                rtt_sum += rtt;
                if (rtt < rtt_min) rtt_min = rtt;
                if (rtt > rtt_max) rtt_max = rtt;
            }
            printf("%d,%d,%d,%d,%u,%u,%u,%s\n", i, challenge, expected,
                   response, rtt, pulse_width, recovery,
                   matches ? "SUCCESS" : "FAIL");
        }
        fflush(stdout);
        gpioDelay(gap_ms * 1000);
    }

    uint32_t total_time_us = gpioTick() - fast_start;
    printf("\n--- %d-Round Summary ---\n", num_rounds);
    printf("Successful Rounds:  %d/%d\n", successful_rounds, num_rounds);
    printf("Total Elapsed Time: %u us (%.2f ms)\n", total_time_us,
           total_time_us / 1000.0);
    if (successful_rounds > 0) {
        printf("RTT min/avg/max:    %u / %.2f / %u us\n", rtt_min,
               (double)rtt_sum / successful_rounds, rtt_max);
        printf("(light flight time is ~6.7 ns per metre round trip; the RTT "
               "above is sensor + software latency)\n");
    }
}

static void run_initiator(int rounds) {
    if (rounds == 32 || rounds == 0) run_initiator_round(32, SYNC_32_US);
    if (rounds == 0 && running) gpioDelay(2000000);
    if (rounds == 64 || (rounds == 0 && running))
        run_initiator_round(64, SYNC_64_US);
    if (rounds == 0 && running) gpioDelay(2000000);
    if (rounds == 128 || (rounds == 0 && running))
        run_initiator_round(128, SYNC_128_US);
}

// ---- Responder: waits for challenges, decodes and replies immediately. ----

static void run_responder(void) {
    const uint8_t* R0 = secret;
    const uint8_t* R1 = secret + 16;
    unsigned threshold = decode_threshold();
    unsigned min_width = min_valid_width();

    // Logged only after a session, so printing never sits inside a round.
    static uint32_t seen_width[MAX_ROUNDS];
    static uint8_t seen_challenge[MAX_ROUNDS], sent_response[MAX_ROUNDS];

    printf("Waiting for sync pulse or fast challenges...\n");

    int fast_phase = 0, round_idx = 0, expected_rounds = 0;

    while (running) {
        // Idle: sleep-poll to save CPU. In a session: spin, so the start of
        // a challenge is caught within a few microseconds.
        while (running && gpioRead(rx_gpio) != 0) {
            if (!fast_phase) gpioDelay(100);
        }
        if (!running) break;
        uint32_t rx_start_tick = gpioTick();

        uint32_t rx_end_tick;
        if (wait_level(1, 2 * SYNC_128_US, &rx_end_tick) < 0) {
            // Dark far longer than any symbol: peer LED off, or ambient
            // dropped. Wait for light to come back before listening again.
            printf("line held low > %u us; waiting for it to return\n",
                   2 * SYNC_128_US);
            fflush(stdout);
            while (running && gpioRead(rx_gpio) == 0) gpioDelay(1000);
            fast_phase = 0;
            continue;
        }
        uint32_t pulse_width = rx_end_tick - rx_start_tick;

        if (pulse_width > SYNC_THRESHOLD_US) {
            expected_rounds = pulse_width < 2500 ? 32
                              : pulse_width < 3500 ? 64
                                                   : 128;
            printf("\n--- New Session Started ---\n");
            printf("Sync pulse detected (width: %u us). Expecting %d "
                   "rounds.\n",
                   pulse_width, expected_rounds);
            fflush(stdout);
            round_idx = 0;
            fast_phase = 1;
            continue;
        }
        if (!fast_phase || pulse_width < min_width) continue;

        int challenge = pulse_width < threshold ? 0 : 1;
        int response = get_bit(challenge == 0 ? R0 : R1, round_idx);
        tx_pulse(response ? long_us : short_us);

        seen_width[round_idx] = pulse_width;
        seen_challenge[round_idx] = (uint8_t)challenge;
        sent_response[round_idx] = (uint8_t)response;
        round_idx++;

        // Our own pulse may have dipped our own sensor; let it settle so
        // that is never mistaken for the next challenge. The initiator
        // waits gap_ms before challenging again, so there is time.
        uint32_t t;
        wait_level(1, 5000, &t);
        gpioDelay(200);

        if (round_idx >= expected_rounds) {
            printf("Completed %d rounds. Widths as received:\n",
                   expected_rounds);
            printf("round,rx_width_us,challenge,response\n");
            for (int i = 0; i < expected_rounds; i++) {
                printf("%d,%u,%u,%u\n", i, seen_width[i], seen_challenge[i],
                       sent_response[i]);
            }
            printf("Back to idle.\n");
            fflush(stdout);
            fast_phase = 0;
        }
    }
}

// ---- Loopback: one Pi, LED pointed at its own sensor. ----
//
// Measures the two numbers the two-Pi RTT is built from: how long after the
// LED changes the sensor's digital level follows (fall = light->dark, rise =
// dark->light), and how faithfully a dark pulse of a given width comes back.
// A pulse that returns much narrower or wider than sent, or not at all, sets
// the lower bound on usable --short-us and on the link's bit period.

static void run_loopback(int count) {
    uint32_t t;
    if (wait_level(1, 100000, &t) < 0) {
        printf("sensor never reads light with the LED on: nothing to "
               "measure\n");
        return;
    }

    printf("\n--- Edge latency, %d iterations ---\n", count);
    printf("iter,fall_us,rise_us\n");
    uint32_t fall_sum = 0, rise_sum = 0, fall_max = 0, rise_max = 0;
    int ok = 0;
    for (int i = 0; running && i < count; i++) {
        uint32_t t0 = gpioTick();
        tx_level(0);
        uint32_t fell;
        int f = wait_level(0, 20000, &fell);
        gpioDelay(2000);  // fully dark before relighting
        uint32_t t1 = gpioTick();
        tx_level(1);
        uint32_t rose;
        int r = wait_level(1, 20000, &rose);
        if (f < 0 || r < 0) {
            printf("%d,%s,%s\n", i, f < 0 ? "TIMEOUT" : "-",
                   r < 0 ? "TIMEOUT" : "-");
        } else {
            uint32_t fall = fell - t0, rise = rose - t1;
            printf("%d,%u,%u\n", i, fall, rise);
            fall_sum += fall;
            rise_sum += rise;
            if (fall > fall_max) fall_max = fall;
            if (rise > rise_max) rise_max = rise;
            ok++;
        }
        fflush(stdout);
        gpioDelay(gap_ms * 1000);
    }
    if (ok) {
        printf("fall avg/max: %.1f / %u us   rise avg/max: %.1f / %u us\n",
               (double)fall_sum / ok, fall_max, (double)rise_sum / ok,
               rise_max);
    }

    // Width fidelity: send each width, measure the dark interval the sensor
    // reports. The sensor's own fall/rise asymmetry shows up as a constant
    // offset; a width that comes back as TIMEOUT never went below threshold.
    static const unsigned widths[] = {50,  100, 150, 200, 300,
                                      450, 600, 1000, 2000};
    printf("\n--- Pulse width fidelity ---\n");
    printf("sent_us,seen_us,delta_us\n");
    for (size_t w = 0; running && w < sizeof widths / sizeof *widths; w++) {
        uint32_t fell = 0, rose;
        int f = -1;
        uint32_t t0 = gpioTick();
        tx_level(0);
        // Relight on time whether or not the sensor has followed yet.
        while ((int32_t)(gpioTick() - (t0 + widths[w])) < 0) {
            if (f < 0 && gpioRead(rx_gpio) == 0) {
                fell = gpioTick();
                f = 0;
            }
        }
        tx_level(1);
        // A slow sensor may still dip after the LED is already back on.
        if (f < 0) f = wait_level(0, 5000, &fell);
        int r = f < 0 ? -1 : wait_level(1, 20000, &rose);
        if (f < 0 || r < 0) {
            printf("%u,TIMEOUT,-\n", widths[w]);
        } else {
            uint32_t seen = rose - fell;
            printf("%u,%u,%d\n", widths[w], seen, (int)seen - (int)widths[w]);
        }
        fflush(stdout);
        gpioDelay(gap_ms * 1000);
    }
}

int main(int argc, char* argv[]) {
    const char* role = NULL;
    int rounds = 0, count = 20;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--role") && i + 1 < argc)
            role = argv[++i];
        else if (!strcmp(argv[i], "--tx-gpio") && i + 1 < argc)
            tx_gpio = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rx-gpio") && i + 1 < argc)
            rx_gpio = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--led-active-low"))
            led_active_low = 1;
        else if (!strcmp(argv[i], "--short-us") && i + 1 < argc)
            short_us = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--long-us") && i + 1 < argc)
            long_us = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--gap-ms") && i + 1 < argc)
            gap_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc)
            timeout_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rounds") && i + 1 < argc)
            rounds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--count") && i + 1 < argc)
            count = atoi(argv[++i]);
        else
            role = NULL;
    }
    int is_initiator = role && !strcmp(role, "initiator");
    int is_responder = role && !strcmp(role, "responder");
    int is_loopback = role && !strcmp(role, "loopback");
    if (!(is_initiator || is_responder || is_loopback) ||
        !(rounds == 0 || rounds == 32 || rounds == 64 || rounds == 128) ||
        short_us == 0 || long_us <= short_us || long_us >= SYNC_THRESHOLD_US) {
        fprintf(stderr,
                "Usage: sudo %s --role initiator|responder|loopback "
                "[--tx-gpio N] [--rx-gpio N] [--led-active-low] "
                "[--short-us N] [--long-us N] [--gap-ms N] [--timeout-ms N] "
                "[--rounds 32|64|128] [--count N]\n"
                "  0 < short-us < long-us < %u\n",
                argv[0], SYNC_THRESHOLD_US);
        return 1;
    }

    signal(SIGINT, on_sigint);
    srand((unsigned)time(NULL));

    if (gpioInitialise() < 0) {
        fprintf(stderr, "gpioInitialise() failed (run with sudo?)\n");
        return 1;
    }
    gpioSetMode(tx_gpio, PI_OUTPUT);
    tx_level(1);  // idle = mark = LED on
    gpioSetMode(rx_gpio, PI_INPUT);
    gpioSetPullUpDown(rx_gpio, PI_PUD_OFF);  // module has its own 10k load

    printf("%s: tx=GPIO%d rx=GPIO%d led=%s bit0=%u us bit1=%u us "
           "(threshold %u us)\n",
           role, tx_gpio, rx_gpio, led_active_low ? "active-low" : "active-high",
           short_us, long_us, decode_threshold());
    gpioDelay(100000);  // let the sensor settle on the lit LED
    report_idle_level();

    if (is_initiator)
        run_initiator(rounds);
    else if (is_responder)
        run_responder();
    else
        run_loopback(count);

    tx_level(1);
    gpioTerminate();
    return 0;
}