#ifndef PHYSICAL_PRESENCE_OPTIONS_H
#define PHYSICAL_PRESENCE_OPTIONS_H
#include <stdlib.h>
#include <string.h>

#include "../../src/c_common.h"
#include "hk_check.h"
#ifdef HAVE_LIFI_TRANSPORT
#include "../../lifi_com/lifi_sst_handshake.h"
#endif

/* Command line shared by robot and locker. */
typedef struct {
    const char* config_path;
    const char* comm_type; /* tcp, ir, lifi, ultrasound or bluetooth */
    const char* bt_peer;   /* robot: the Locker's public LE address */
    int lifi_tx_gpio, lifi_rx_gpio, lifi_led_active_low;
    /* Everything the CO_LOCATION check needs; the caller fills in
     * local_name and expected_peer once it knows them. */
    co_location_options co;
} physical_options;

static void physical_options_usage(const char* program, int robot) {
    SST_print_error_exit(
        "Usage: %s <config_file_path> "
        "[--comm_type tcp|ir|lifi|ultrasound|bluetooth] "
        "[--mic <alsa_device>] [--spk <alsa_device>] %s"
        "[--require-ir-hk | --require-lifi-hk | --require-ultrasound-echo "
        "| --require-ble-rssi | --require-uwb] [--uwb-dev <serial_port>] "
        "[--ultrasound-echo-test-delay-ms N] "
        "[--lifi-tx-gpio N] [--lifi-rx-gpio N] [--lifi-led-active-low]",
        program, robot ? "[--bt-peer <bdaddr>] " : "");
}

/* Parses argv (unknown arguments are ignored) and applies the LiFi wiring,
 * which both the LiFi handshake and a LiFi HK check use. */
static void physical_options_parse(int argc, char* argv[], int robot,
                                   physical_options* o) {
    static const struct {
        const char* flag;
        const char* method;
    } require_flags[] = {{"--require-ir-hk", "IR"},
                         {"--require-lifi-hk", "LIFI"},
                         {"--require-ultrasound-echo", "ULTRASOUND"},
                         {"--require-ble-rssi", "BLE_RSSI"},
                         {"--require-uwb", "UWB"}};
    memset(o, 0, sizeof(*o));
    o->comm_type = "tcp";
    o->lifi_tx_gpio = 23;
    o->lifi_rx_gpio = 22;
    o->co.mic_device = "plughw:1,0";
    o->co.spk_device = "plughw:2,0";
    if (argc < 2) physical_options_usage(argv[0], robot);
    o->config_path = argv[1];
    for (int i = 2; i < argc; i++) {
        const char* a = argv[i];
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        int takes_value = 1;
        for (size_t k = 0; k < sizeof(require_flags) / sizeof(*require_flags);
             ++k) {
            if (!strcmp(a, require_flags[k].flag))
                o->co.require_method = require_flags[k].method;
        }
        if (!strcmp(a, "--lifi-led-active-low")) {
            o->lifi_led_active_low = 1;
        }
        if (!v) continue;
        if (!strcmp(a, "--comm_type"))
            o->comm_type = v;
        else if (!strcmp(a, "--mic"))
            o->co.mic_device = v;
        else if (!strcmp(a, "--spk"))
            o->co.spk_device = v;
        else if (!strcmp(a, "--uwb-dev"))
            o->co.uwb_device = v;
        else if (robot && !strcmp(a, "--bt-peer"))
            o->bt_peer = v;
        else if (!strcmp(a, "--ultrasound-echo-test-delay-ms"))
            o->co.echo_test_delay_ms = (unsigned)atoi(v);
        else if (!strcmp(a, "--lifi-tx-gpio"))
            o->lifi_tx_gpio = atoi(v);
        else if (!strcmp(a, "--lifi-rx-gpio"))
            o->lifi_rx_gpio = atoi(v);
        else
            takes_value = 0;
        if (takes_value) i++;
    }
#ifdef HAVE_LIFI_TRANSPORT
    lifi_configure(o->lifi_tx_gpio, o->lifi_rx_gpio, o->lifi_led_active_low);
#endif
}

/* TCP and Bluetooth leave a real socket for secure messaging afterwards;
 * the IR, LiFi and ultrasound handshake adapters do not (yet). */
static int physical_options_has_socket(const physical_options* o) {
    return !strcmp(o->comm_type, "tcp") || !strcmp(o->comm_type, "bluetooth");
}

#endif
