// lifi_bitbang.c
// Minimal LiFi data-transfer test: bit-bangs 8N1 serial over an LED and a
// phototransistor with plain gpioWrite()/gpioRead() and delays. No SST, no
// Auth, no framing, no CRC -- just bytes out one side, bytes in the other.
//
//   sudo ./lifi_bitbang loopback          # one Pi, LED pointed at own sensor
//   sudo ./lifi_bitbang tx                # two Pis: this side sends...
//   sudo ./lifi_bitbang rx                # ...this side prints what arrives
//
// Options: --bps N (100)  bits per second; 10 makes the LED visibly blink
//          --tx-gpio N (22)  --rx-gpio N (27)   BCM numbers
//          --led-active-high   LED lights on GPIO HIGH (default: active low,
//                              i.e. KS0016 driven straight from 3V3)
//          --msg "text"        what to send (default "hello over light")
//
// Compile: gcc -O2 -Wall -o lifi_bitbang lifi_bitbang.c -lpigpio -lrt -lpthread
//
// Optical convention: LIGHT = 1 (mark, idle), DARK = 0 (space). The TEMT6000
// is non-inverting so gpioRead() on the sensor pin IS the logical level.

#include <pigpio.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tx_gpio = 22, rx_gpio = 27, led_active_low = 1;
static unsigned bit_us = 10000;  // 100 bps
static volatile int running = 1;

static void on_sigint(int sig) {
    (void)sig;
    running = 0;
}

// ---- TX: one byte = start(0), 8 data bits LSB first, stop(1) ----------

static void tx_level(int logical) {
    gpioWrite(tx_gpio, led_active_low ? !logical : logical);
}

static void tx_byte(unsigned char b) {
    uint32_t t = gpioTick();
    tx_level(0);  // start bit
    for (int i = 0; i < 8; i++) {
        t += bit_us;
        while ((int32_t)(gpioTick() - t) < 0) {
        }
        tx_level((b >> i) & 1);
    }
    t += bit_us;
    while ((int32_t)(gpioTick() - t) < 0) {
    }
    tx_level(1);  // stop bit; line stays at mark until the next byte
    t += bit_us;
    while ((int32_t)(gpioTick() - t) < 0) {
    }
}

// ---- RX: wait for a falling edge, sample each bit at its centre --------

// Returns the byte, or -1 on a framing error (stop bit not high). Blocks
// until a start bit arrives or `running` is cleared (then returns -2).
static int rx_byte(void) {
    while (gpioRead(rx_gpio) == 1) {
        if (!running) return -2;
        gpioDelay(bit_us / 20 ? bit_us / 20 : 1);
    }
    uint32_t t = gpioTick() + bit_us / 2;  // centre of the start bit
    while ((int32_t)(gpioTick() - t) < 0) {
    }
    if (gpioRead(rx_gpio) != 0) return -1;  // glitch, not a real start bit
    unsigned char b = 0;
    for (int i = 0; i < 8; i++) {
        t += bit_us;
        while ((int32_t)(gpioTick() - t) < 0) {
        }
        if (gpioRead(rx_gpio)) b |= 1u << i;
    }
    t += bit_us;
    while ((int32_t)(gpioTick() - t) < 0) {
    }
    if (gpioRead(rx_gpio) != 1) return -1;  // stop bit missing
    return b;
}

static void* rx_loop(void* arg) {
    (void)arg;
    while (running) {
        int b = rx_byte();
        if (b == -2) break;
        if (b < 0) {
            printf("  [framing error]\n");
            continue;
        }
        printf("  rx: 0x%02x '%c'\n", b, (b >= 0x20 && b < 0x7F) ? b : '.');
        fflush(stdout);
    }
    return NULL;
}

// Reports what the sensor sees while nothing is being sent. Interpreting it:
// peer LED on (idle) or loopback -> should be HIGH; peer LED off/absent and
// still HIGH -> ambient light is pinning the input; loopback and LOW -> LED
// too dim or misaligned.
static void report_idle_level(void) {
    int high = 0, samples = 200;
    for (int i = 0; i < samples; i++) {
        high += gpioRead(rx_gpio);
        gpioDelay(5000);
    }
    printf("idle sensor level over 1s: %s (%d%% high)\n",
           high > samples / 2 ? "HIGH" : "LOW", high * 100 / samples);
}

int main(int argc, char* argv[]) {
    const char* role = argc > 1 ? argv[1] : "";
    const char* msg = "hello over light";
    unsigned bps = 100;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--bps") && i + 1 < argc)
            bps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--tx-gpio") && i + 1 < argc)
            tx_gpio = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rx-gpio") && i + 1 < argc)
            rx_gpio = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--led-active-high"))
            led_active_low = 0;
        else if (!strcmp(argv[i], "--msg") && i + 1 < argc)
            msg = argv[++i];
        else
            role = "";
    }
    int is_tx = !strcmp(role, "tx"), is_rx = !strcmp(role, "rx"),
        is_loop = !strcmp(role, "loopback");
    if (!(is_tx || is_rx || is_loop) || bps == 0) {
        fprintf(stderr,
                "Usage: sudo %s tx|rx|loopback [--bps N] [--tx-gpio N] "
                "[--rx-gpio N] [--led-active-high] [--msg text]\n",
                argv[0]);
        return 1;
    }
    bit_us = 1000000 / bps;

    if (gpioInitialise() < 0) {
        fprintf(stderr, "gpioInitialise() failed (run with sudo?)\n");
        return 1;
    }
    signal(SIGINT, on_sigint);
    gpioSetMode(tx_gpio, PI_OUTPUT);
    tx_level(1);  // idle = mark = LED on
    gpioSetMode(rx_gpio, PI_INPUT);
    gpioSetPullUpDown(rx_gpio, PI_PUD_OFF);  // module has its own 10k load
    printf("%s: tx=GPIO%d rx=GPIO%d %u bps (%u us/bit) led=%s\n", role, tx_gpio,
           rx_gpio, bps, bit_us, led_active_low ? "active-low" : "active-high");

    pthread_t rx_thread;
    if (is_rx || is_loop) {
        report_idle_level();
    }
    if (is_loop) {
        pthread_create(&rx_thread, NULL, rx_loop, NULL);
    }

    if (is_rx) {
        printf("listening (Ctrl+C to stop)...\n");
        rx_loop(NULL);
    } else {
        for (int n = 1; running; n++) {
            printf("tx [%d]: %s\n", n, msg);
            fflush(stdout);
            for (const char* p = msg; *p; p++) tx_byte((unsigned char)*p);
            tx_byte('\n');
            // Pause so the receiver's output is readable per message.
            for (int i = 0; i < 100 && running; i++) gpioDelay(10000);
        }
    }

    if (is_loop) pthread_join(rx_thread, NULL);
    tx_level(1);
    gpioTerminate();
    return 0;
}
