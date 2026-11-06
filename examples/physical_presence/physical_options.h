#ifndef PHYSICAL_PRESENCE_OPTIONS_H
#define PHYSICAL_PRESENCE_OPTIONS_H
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../physical_com/freshness.h"
#include "../../physical_com/session_ctl.h"
#include "../../src/c_common.h"
#include "benchmark.h"
#include "hk_check.h"
#ifdef HAVE_LIFI_TRANSPORT
#include "../../lifi_com/lifi_sst_handshake.h"
#endif

/* Command line shared by robot and locker. */
typedef struct {
    const char* config_path;
    const char* comm_type; /* tcp, ir, lifi, ultrasound, bluetooth or wifi */
    const char* bt_peer;   /* robot: the Locker's public LE address */
    const char* wifi_peer; /* robot: the Locker's address on the Wi-Fi link */
    /* The measurement Wi-Fi link, used by the WIFI_RSSI proximity check and
     * independent of --comm_type. When wifi_link_script is set, the endpoint
     * brings the dongle link up itself (locker=AP, robot=station) and runs the
     * proximity check over a dedicated socket on it. */
    const char* wifi_link_script; /* path to wifi_com/wifi_link.sh, NULL = off */
    int wifi_link_minutes;        /* link auto-down timer, passed to the script */
    int wifi_measure_port;        /* measurement socket port on the link */
    char wifi_creds_file[64];     /* temp creds file for the link, "" if none */
    int lifi_tx_gpio, lifi_rx_gpio, lifi_led_active_low;
    /* Experiments only: a pause after verification, before the action
     * gate, so the evidence ages by it. Never changes a bound or skips a
     * check. */
    unsigned action_test_delay_ms;
    /* QR robot--locker discovery: the robot scans the locker's QR with its
     * camera (only if Auth's plan grants it "Camera"); the locker shows its own
     * ID as a QR on the framebuffer. */
    int scan_qr; /* robot */
    int show_qr; /* locker */
    /* Locker-side target-local temperature check: serial device of the ESP32
     * thermometer that streams "TEMP=<c>" (see temp_sensor.h). */
    const char* temp_dev;
    /* --benchmark: one measured run of the protected operation only (no
     * GRIP_ITEM, no messaging after the gate), recorded as JSON. */
    int benchmark;
    const char* benchmark_run_id;
    const char* benchmark_output;
    /* Everything the CO_LOCATION check needs; the caller fills in
     * local_name and expected_peer once it knows them. */
    co_location_options co;
} physical_options;

static void physical_options_usage(const char* program, int robot) {
    SST_print_error_exit(
        "Usage: %s <config_file_path> "
        "[--comm_type tcp|ir|lifi|ultrasound|bluetooth|wifi] "
        "[--mic <alsa_device>] [--spk <alsa_device>] %s"
        "[--require-ir-hk | --require-lifi-hk | --require-ultrasound-echo "
        "| --require-ambient-audio | --require-ble-rssi | --require-wifi-rssi "
        "| --require-uwb | --require-uwb-position | --require-qr] "
        "[--uwb-dev <serial_port>] "
        "[--uwb-anchor-dev <serial_port> (locker, repeatable)] "
        "[--temp-dev <serial_port> (locker)] "
        "[--wifi-iface <iface>] "
        "[--scan-qr (robot)] [--show-qr (locker)] "
        "[--ultrasound-echo-test-delay-ms N] [--action-test-delay-ms N] "
        "[--benchmark --benchmark-run-id ID --benchmark-output FILE] "
        "[--lifi-tx-gpio N] [--lifi-rx-gpio N] [--lifi-led-active-low]",
        program, robot ? "[--bt-peer <bdaddr>] [--wifi-peer <ip>] " : "");
}

#define ACTION_TEST_DELAY_MS_LIMIT 3600000UL

/* A decimal number of milliseconds in 0..ACTION_TEST_DELAY_MS_LIMIT.
 * @return 0, or -1 for anything else (sign, junk, overflow). */
static int parse_delay_ms(const char* v, unsigned* out) {
    char* end;
    if (!v || *v < '0' || *v > '9') return -1;
    errno = 0;
    unsigned long n = strtoul(v, &end, 10);
    if (errno || *end || n > ACTION_TEST_DELAY_MS_LIMIT) return -1;
    *out = (unsigned)n;
    return 0;
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
                         {"--require-ambient-audio", "AMBIENT_AUDIO"},
                         {"--require-ble-rssi", "BLE_RSSI"},
                         {"--require-wifi-rssi", "WIFI_RSSI"},
                         {"--require-uwb", "UWB"},
                         {"--require-uwb-position", "UWB_POSITION"},
                         {"--require-qr", "QR"}};
    memset(o, 0, sizeof(*o));
    o->comm_type = "tcp";
    o->lifi_tx_gpio = 23;
    o->lifi_rx_gpio = 22;
    o->co.mic_device = "plughw:1,0";
    o->co.spk_device = "plughw:2,0";
    o->co.wifi_iface = "wlan1";
    o->co.wifi_timing_mode = WIFI_TIMING_MODE_DISABLED;
    o->co.wifi_timing_rounds = 20;
    o->co.wifi_timing_deadline_us = 0;
    o->co.wifi_timing_recv_timeout_us = 500000;
    o->co.wifi_measure_sock = -1;
    o->co.ble_timing_mode = BLE_TIMING_MODE_DISABLED;
    o->co.ble_timing_rounds = 20;
    o->co.ble_timing_deadline_us = 0; /* set from measured BLE RTTs, not Wi-Fi's */
    o->co.ble_timing_recv_timeout_us = 2000000;
    o->co.ble_timing_psm = BT_LINK_DEFAULT_PSM;
    o->co.ble_timing_interval_units = 6; /* 6 * 1.25 ms = 7.5 ms (requested) */
    o->co.ble_measure_sock = -1;
    o->co.ble_timing_negotiated_units = 0;
    o->temp_dev = "/dev/ttyUSB0";
    o->wifi_peer = "192.168.77.1";
    o->wifi_link_script = NULL;
    o->wifi_link_minutes = 15;
    o->wifi_measure_port = 21101;
    if (argc < 2) physical_options_usage(argv[0], robot);
    o->config_path = argv[1];
    for (int i = 2; i < argc; i++) {
        /* A trailing delay flag without a value is an error, not a no-op. */
        if (!strcmp(argv[i], "--action-test-delay-ms") && i + 1 >= argc)
            physical_options_usage(argv[0], robot);
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
        /* Relay experiment: IR/LiFi HK control over the TCP session. */
        if (!strcmp(a, "--hk-control-tcp")) o->co.hk_control_over_tcp = 1;
        if (!strcmp(a, "--scan-qr")) o->scan_qr = 1;
        if (!strcmp(a, "--show-qr")) o->show_qr = 1;
        if (!strcmp(a, "--benchmark")) o->benchmark = 1;
        if (!v) continue;
        if (!strcmp(a, "--comm_type"))
            o->comm_type = v;
        else if (!strcmp(a, "--mic"))
            o->co.mic_device = v;
        else if (!strcmp(a, "--spk"))
            o->co.spk_device = v;
        else if (!strcmp(a, "--uwb-dev"))
            o->co.uwb_device = v;
        else if (!strcmp(a, "--uwb-anchor-dev")) {
            /* Repeatable (locker): one anchor serial port per use, in the plan's
             * anchor-coordinate order. */
            if (o->co.uwb_anchor_count < UWB_LOCATE_MAX_ANCHORS)
                o->co.uwb_anchor_devices[o->co.uwb_anchor_count++] = v;
        }
        else if (!strcmp(a, "--temp-dev"))
            o->temp_dev = v;
        else if (robot && !strcmp(a, "--bt-peer"))
            o->bt_peer = v;
        else if (robot && !strcmp(a, "--wifi-peer"))
            o->wifi_peer = v;
        else if (!strcmp(a, "--wifi-iface"))
            o->co.wifi_iface = v;
        else if (!strcmp(a, "--wifi-link-script"))
            o->wifi_link_script = v;
        else if (!strcmp(a, "--wifi-link-minutes"))
            o->wifi_link_minutes = atoi(v);
        else if (!strcmp(a, "--wifi-measure-port"))
            o->wifi_measure_port = atoi(v);
        else if (!strcmp(a, "--wifi-timing-mode"))
            o->co.wifi_timing_mode =
                !strcmp(v, "enforce")   ? WIFI_TIMING_MODE_ENFORCE
                : !strcmp(v, "measure") ? WIFI_TIMING_MODE_MEASURE
                                        : WIFI_TIMING_MODE_DISABLED;
        else if (!strcmp(a, "--wifi-timing-rounds"))
            o->co.wifi_timing_rounds = (unsigned)atoi(v);
        else if (!strcmp(a, "--wifi-timing-deadline-us"))
            o->co.wifi_timing_deadline_us = (uint64_t)strtoull(v, NULL, 10);
        else if (!strcmp(a, "--wifi-timing-recv-timeout-us"))
            o->co.wifi_timing_recv_timeout_us = (uint64_t)strtoull(v, NULL, 10);
        else if (!strcmp(a, "--ble-timing-mode"))
            o->co.ble_timing_mode =
                !strcmp(v, "enforce")   ? BLE_TIMING_MODE_ENFORCE
                : !strcmp(v, "measure") ? BLE_TIMING_MODE_MEASURE
                                        : BLE_TIMING_MODE_DISABLED;
        else if (!strcmp(a, "--ble-timing-rounds"))
            o->co.ble_timing_rounds = (unsigned)atoi(v);
        else if (!strcmp(a, "--ble-timing-deadline-us"))
            o->co.ble_timing_deadline_us = (uint64_t)strtoull(v, NULL, 10);
        else if (!strcmp(a, "--ble-timing-recv-timeout-us"))
            o->co.ble_timing_recv_timeout_us = (uint64_t)strtoull(v, NULL, 10);
        else if (!strcmp(a, "--ble-timing-psm"))
            o->co.ble_timing_psm = (unsigned)strtoul(v, NULL, 0);
        else if (!strcmp(a, "--ble-timing-interval-units"))
            o->co.ble_timing_interval_units = (unsigned)atoi(v);
        else if (!strcmp(a, "--ultrasound-echo-test-delay-ms"))
            o->co.echo_test_delay_ms = (unsigned)atoi(v);
        else if (!strcmp(a, "--action-test-delay-ms")) {
            if (parse_delay_ms(v, &o->action_test_delay_ms))
                physical_options_usage(argv[0], robot);
        } else if (!strcmp(a, "--benchmark-run-id"))
            o->benchmark_run_id = v;
        else if (!strcmp(a, "--benchmark-output"))
            o->benchmark_output = v;
        else if (!strcmp(a, "--lifi-tx-gpio"))
            o->lifi_tx_gpio = atoi(v);
        else if (!strcmp(a, "--lifi-rx-gpio"))
            o->lifi_rx_gpio = atoi(v);
        else
            takes_value = 0;
        if (takes_value) i++;
    }
    /* A benchmark run needs its ID and output, an ID safe in file names
     * and JSON, and no experimental delays: they would be measured. */
    if (o->benchmark &&
        (!o->benchmark_run_id || !o->benchmark_output ||
         !*o->benchmark_run_id ||
         strspn(o->benchmark_run_id,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789._-") != strlen(o->benchmark_run_id) ||
         o->action_test_delay_ms || o->co.echo_test_delay_ms))
        physical_options_usage(argv[0], robot);
#ifdef HAVE_LIFI_TRANSPORT
    lifi_configure(o->lifi_tx_gpio, o->lifi_rx_gpio, o->lifi_led_active_low);
#endif
}

/* True when this run requires the WIFI_RSSI proximity check (so the
 * measurement Wi-Fi link must be prepared, whatever the handshake transport). */
static int physical_requires_wifi_rssi(const physical_options* o) {
    return o->co.require_method && !strcmp(o->co.require_method, "WIFI_RSSI");
}

/* The measurement Wi-Fi link settings Auth provisions for WIFI_RSSI, carried in
 * the plan separately from the handshakeTransport (CO_LOCATION -> WIFI_RSSI
 * parameters: peer_host, peer_port, ssid, password). */
typedef struct {
    char host[INET_ADDRSTRLEN];
    int port;
    char ssid[64];
    char password[80];
} wifi_measure_cfg;

/* Parses the plan's WIFI_RSSI measurement settings. host/port fall back to the
 * given defaults; ssid/password are Auth-provisioned per execution and have no
 * fallback. @return 0 when ssid and password are both present, else -1 (the
 * caller must fail rather than run with stale or default credentials). */
static int physical_wifi_measure_parse(const char* challenge,
                                       const char* fallback_host,
                                       int fallback_port,
                                       wifi_measure_cfg* out) {
    char port_str[16] = {0};
    memset(out, 0, sizeof(*out));
    snprintf(out->host, sizeof(out->host), "%s",
             fallback_host ? fallback_host : "");
    out->port = fallback_port;
    /* WIFI_RSSI is a PROXIMITY/MUTUAL method; its Auth-provisioned ssid/password
     * live in the selected method's parameters in the verification plan. */
    plan_json j;
    int params = -1;
    if (plan_check(challenge, "PROXIMITY", "WIFI_RSSI", "MUTUAL", &j, &params) !=
            1 ||
        params < 0)
        return -1;
    int host = plan_json_field(&j, params, "peer_host");
    if (host >= 0) plan_json_name(&j, host, out->host, sizeof(out->host));
    int port = plan_json_field(&j, params, "peer_port");
    if (port >= 0 && plan_json_name(&j, port, port_str, sizeof(port_str)) == 0)
        out->port = atoi(port_str);
    if (plan_json_name(&j, plan_json_field(&j, params, "ssid"), out->ssid,
                       sizeof(out->ssid)) != 0 ||
        plan_json_name(&j, plan_json_field(&j, params, "password"),
                       out->password, sizeof(out->password)) != 0 ||
        !out->ssid[0] || !out->password[0])
        return -1;
    return 0;
}

/* Writes a root-only credentials file for wifi_link.sh (SSID/PASSPHRASE), so
 * the passphrase never reaches a command line. @return 0 and the path in
 * out_path, or -1. */
static int physical_wifi_write_creds(const char* ssid, const char* password,
                                     char* out_path, size_t n) {
    char tmpl[] = "/tmp/wifi_creds.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    fchmod(fd, S_IRUSR | S_IWUSR);
    FILE* f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    fprintf(f, "SSID=%s\nPASSPHRASE=%s\n", ssid, password);
    if (fclose(f)) {
        unlink(tmpl);
        return -1;
    }
    snprintf(out_path, n, "%s", tmpl);
    return 0;
}

/* AP-ready signal over the authenticated SST session (session-bound). */
#define PHYS_WIFI_READY_PREFIX {'W', 'R', 'D', 'Y'}
static int physical_wifi_send_ready(SST_session_ctx_t* session) {
    unsigned char msg[] = PHYS_WIFI_READY_PREFIX;
    return session_ctl_send(session, msg, sizeof(msg));
}
static int physical_wifi_wait_ready(SST_session_ctx_t* session,
                                    unsigned timeout_ms) {
    static const unsigned char prefix[] = PHYS_WIFI_READY_PREFIX;
    unsigned char msg[sizeof(prefix)];
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock, timeout_ms, &saved)) return -1;
    int rc = session_ctl_recv(session, prefix, sizeof(prefix), msg, sizeof(msg),
                              "wifi ready");
    session_ctl_timeout_restore(session->sock, &saved);
    return rc;
}

/* Locker: after the handshake, start the measurement AP with the Auth-provided
 * credentials, listen, signal the robot, and accept its measurement socket.
 * Sets o->co.wifi_measure_sock and o->wifi_creds_file. @return 0 or -1. */
static int physical_wifi_measure_setup_locker(physical_options* o,
                                              SST_session_ctx_t* session) {
    wifi_measure_cfg cfg;
    if (physical_wifi_measure_parse(session->s_key.challenge, NULL,
                                    o->wifi_measure_port, &cfg)) {
        SST_print_error("WIFI RSSI: plan has no measurement Wi-Fi credentials.");
        return -1;
    }
    if (!o->wifi_link_script) {
        SST_print_error("WIFI RSSI: no --wifi-link-script to start the AP.");
        return -1;
    }
    if (physical_wifi_write_creds(cfg.ssid, cfg.password, o->wifi_creds_file,
                                  sizeof(o->wifi_creds_file))) {
        SST_print_error("WIFI RSSI: could not stage the AP credentials file.");
        return -1;
    }
    memset(cfg.password, 0, sizeof(cfg.password));
    /* Relay experiment: a pre-standing measurement AP (brought up out of band so
     * the relay station stays associated across trials) is reused instead of
     * being torn down and rebuilt each run. Unset in normal operation. */
    if (getenv("PHYS_WIFI_REUSE_AP")) {
        SST_print_log("WIFI RSSI: reusing pre-standing measurement AP "
                      "(PHYS_WIFI_REUSE_AP set); not restarting it.");
    } else {
        SST_print_log("WIFI RSSI: starting measurement AP (ssid=%s) via %s",
                      cfg.ssid, o->wifi_link_script);
        if (wifi_measure_link_up(o->wifi_link_script, 1, o->wifi_link_minutes,
                                 o->wifi_creds_file)) {
            SST_print_error("WIFI RSSI: failed to start the measurement AP.");
            return -1;
        }
    }
    int serv = -1;
    if (wifi_measure_listen(o->co.wifi_iface, cfg.port, &serv)) {
        SST_print_error("WIFI RSSI: failed to listen on %s:%d.",
                        o->co.wifi_iface, cfg.port);
        return -1;
    }
    SST_print_log("WIFI RSSI: measurement link listening on %s:%d; signaling "
                  "the robot.",
                  o->co.wifi_iface, cfg.port);
    if (physical_wifi_send_ready(session)) {
        SST_print_error("WIFI RSSI: failed to send the AP-ready signal.");
        close(serv);
        return -1;
    }
    char peer_ip[16];
    int msock = wifi_measure_accept(serv, peer_ip, sizeof(peer_ip));
    close(serv);
    if (msock < 0) {
        SST_print_error("WIFI RSSI: failed to accept the measurement link.");
        return -1;
    }
    SST_print_log("WIFI RSSI: measurement link accepted from %s", peer_ip);
    o->co.wifi_measure_sock = msock;
    return 0;
}

/* Robot: after the handshake, wait for the locker's AP-ready signal, join the
 * measurement AP with the Auth-provided credentials, and connect the
 * measurement socket. Sets o->co.wifi_measure_sock and o->wifi_creds_file.
 * @return 0 or -1. */
static int physical_wifi_measure_setup_robot(physical_options* o,
                                             SST_session_ctx_t* session) {
    wifi_measure_cfg cfg;
    if (physical_wifi_measure_parse(session->s_key.challenge, o->wifi_peer,
                                    o->wifi_measure_port, &cfg)) {
        SST_print_error("WIFI RSSI: plan has no measurement Wi-Fi credentials.");
        return -1;
    }
    if (!o->wifi_link_script) {
        SST_print_error("WIFI RSSI: no --wifi-link-script to join the AP.");
        return -1;
    }
    SST_print_log("WIFI RSSI: waiting for the locker's AP-ready signal.");
    if (physical_wifi_wait_ready(session, 60000)) {
        SST_print_error("WIFI RSSI: no AP-ready signal from the locker.");
        return -1;
    }
    if (physical_wifi_write_creds(cfg.ssid, cfg.password, o->wifi_creds_file,
                                  sizeof(o->wifi_creds_file))) {
        SST_print_error("WIFI RSSI: could not stage the station credentials.");
        return -1;
    }
    memset(cfg.password, 0, sizeof(cfg.password));
    SST_print_log("WIFI RSSI: joining measurement AP (ssid=%s) via %s",
                  cfg.ssid, o->wifi_link_script);
    if (wifi_measure_link_up(o->wifi_link_script, 0, o->wifi_link_minutes,
                             o->wifi_creds_file)) {
        SST_print_error("WIFI RSSI: failed to join the measurement AP.");
        return -1;
    }
    char peer_ip[16];
    int msock = wifi_measure_connect(cfg.host, cfg.port, 50, peer_ip,
                                     sizeof(peer_ip));
    if (msock < 0) {
        SST_print_error("WIFI RSSI: failed to connect to %s:%d.", cfg.host,
                        cfg.port);
        return -1;
    }
    SST_print_log("WIFI RSSI: measurement link connected to %s:%d (peer %s)",
                  cfg.host, cfg.port, peer_ip);
    o->co.wifi_measure_sock = msock;
    return 0;
}

/* Closes the measurement socket and removes the credentials file. */
static void physical_wifi_measure_cleanup(physical_options* o) {
    if (o->co.wifi_measure_sock >= 0) {
        close(o->co.wifi_measure_sock);
        o->co.wifi_measure_sock = -1;
    }
    if (o->wifi_creds_file[0]) {
        unlink(o->wifi_creds_file);
        o->wifi_creds_file[0] = '\0';
    }
}

/* True when this run requires BLE_RSSI with a timing mode other than disabled,
 * so the separate BLE L2CAP measurement link must be established before the
 * check. RSSI-only BLE_RSSI (disabled) needs no measurement link. */
static int physical_requires_ble_timing(const physical_options* o) {
    return o->co.require_method && !strcmp(o->co.require_method, "BLE_RSSI") &&
           o->co.ble_timing_mode != BLE_TIMING_MODE_DISABLED;
}

/* BLE-measurement-link coordination over the authenticated control session,
 * analogous to the Wi-Fi AP-ready handshake: the locker starts advertising and
 * accepting an LE L2CAP channel and signals the robot; the robot then connects
 * to the locker's LE address. The BLE link is kept separate from the
 * handshake/control transport, so a relay bridging it adds its forwarding delay
 * to the timing exchange. Establishing the link is not itself proximity or peer
 * authentication; only the authenticated timing exchange over it counts. */
#ifdef HAVE_BT_TRANSPORT
#define PHYS_BLE_READY_PREFIX {'B', 'R', 'D', 'Y'}
static int physical_ble_send_ready(SST_session_ctx_t* session) {
    unsigned char msg[] = PHYS_BLE_READY_PREFIX;
    return session_ctl_send(session, msg, sizeof(msg));
}
static int physical_ble_wait_ready(SST_session_ctx_t* session,
                                   unsigned timeout_ms) {
    static const unsigned char prefix[] = PHYS_BLE_READY_PREFIX;
    unsigned char msg[sizeof(prefix)];
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock, timeout_ms, &saved)) return -1;
    int rc = session_ctl_recv(session, prefix, sizeof(prefix), msg, sizeof(msg),
                              "ble ready");
    session_ctl_timeout_restore(session->sock, &saved);
    return rc;
}
#endif

/* Locker: signal the robot over the control session, then advertise and accept
 * the BLE L2CAP measurement link. Sets o->co.ble_measure_sock. @return 0/-1. */
static int physical_ble_measure_setup_locker(physical_options* o,
                                             SST_session_ctx_t* session) {
#ifndef HAVE_BT_TRANSPORT
    (void)o;
    (void)session;
    SST_print_error("BLE timing needs BlueZ support (HAVE_BT_TRANSPORT).");
    return -1;
#else
    SST_print_log(
        "BLE RSSI: advertising BLE L2CAP measurement link on PSM 0x%02x; "
        "signaling the robot.",
        o->co.ble_timing_psm);
    if (physical_ble_send_ready(session)) {
        SST_print_error("BLE RSSI: failed to send the BLE-ready signal.");
        return -1;
    }
    int sock = bt_link_accept(o->co.ble_timing_psm);
    if (sock < 0) {
        SST_print_error("BLE RSSI: failed to accept the BLE measurement link.");
        return -1;
    }
    SST_print_log("BLE RSSI: BLE measurement link accepted.");
    o->co.ble_measure_sock = sock;
    return 0;
#endif
}

/* Robot: wait for the locker's BLE-ready signal, connect the BLE L2CAP
 * measurement link to the locker's LE address (--bt-peer), request the
 * connection interval, and record the negotiated value. @return 0/-1. */
static int physical_ble_measure_setup_robot(physical_options* o,
                                            SST_session_ctx_t* session) {
#ifndef HAVE_BT_TRANSPORT
    (void)o;
    (void)session;
    SST_print_error("BLE timing needs BlueZ support (HAVE_BT_TRANSPORT).");
    return -1;
#else
    if (!o->bt_peer) {
        SST_print_error(
            "BLE RSSI: timing needs the locker's LE address (--bt-peer).");
        return -1;
    }
    SST_print_log("BLE RSSI: waiting for the locker's BLE-ready signal.");
    if (physical_ble_wait_ready(session, 60000)) {
        SST_print_error("BLE RSSI: no BLE-ready signal from the locker.");
        return -1;
    }
    int sock = -1;
    for (int attempt = 0; attempt < 20 && sock < 0; ++attempt) {
        sock = bt_link_connect(o->bt_peer, o->co.ble_timing_psm);
        if (sock < 0) session_ctl_sleep_ms(500);
    }
    if (sock < 0) {
        SST_print_error(
            "BLE RSSI: failed to connect the BLE measurement link to %s.",
            o->bt_peer);
        return -1;
    }
    SST_print_log("BLE RSSI: BLE measurement link connected to %s.", o->bt_peer);
    uint16_t got = 0;
    if (ble_timing_request_interval(
            sock, (uint16_t)o->co.ble_timing_interval_units, &got) == 0) {
        o->co.ble_timing_negotiated_units = got;
        SST_print_log(
            "BLE RSSI: conn interval requested_units=%u negotiated_units=%u "
            "requested_ms=%.2f negotiated_ms=%.2f",
            o->co.ble_timing_interval_units, got,
            o->co.ble_timing_interval_units * 1.25, got * 1.25);
    } else {
        o->co.ble_timing_negotiated_units = 0;
        SST_print_log(
            "BLE RSSI: conn interval requested_units=%u negotiated=unknown "
            "(update/readback failed)",
            o->co.ble_timing_interval_units);
    }
    o->co.ble_measure_sock = sock;
    return 0;
#endif
}

/* Closes the BLE measurement link. */
static void physical_ble_measure_cleanup(physical_options* o) {
    if (o->co.ble_measure_sock >= 0) {
        close(o->co.ble_measure_sock);
        o->co.ble_measure_sock = -1;
    }
}

/* Starts the benchmark record for this endpoint's protected action, once
 * SST is initialized and before anything is measured. */
static void physical_benchmark_init(benchmark_trace* b,
                                    const physical_options* o,
                                    const SST_ctx_t* ctx, int robot) {
    memset(b, 0, sizeof(*b));
    if (!o->benchmark) return;
    b->enabled = 1;
    b->run_id = o->benchmark_run_id;
    b->output = o->benchmark_output;
    b->role = robot ? "requester" : "locker";
    b->action = robot ? "RETRIEVE_ITEM" : "LOCKER_OPEN";
    b->handshake_transport = o->comm_type;
    b->dist_key_loaded_at_init = ctx->dist_key.cipher_key_size != 0;
    b->perm_dist_key_mode = (int)ctx->config.perm_dist_key_mode;
    SST_print_log("BENCHMARK: run_id=%s role=%s output=%s", b->run_id, b->role,
                  b->output);
}

/* TCP, Wi-Fi (TCP over the direct link) and Bluetooth leave a real socket
 * for secure messaging afterwards; the IR, LiFi and ultrasound handshake
 * adapters do not (yet). */
static int physical_options_has_socket(const physical_options* o) {
    return !strcmp(o->comm_type, "tcp") || !strcmp(o->comm_type, "wifi") ||
           !strcmp(o->comm_type, "bluetooth");
}

/* Test stand-in for the protected action: records that it would have
 * started; no motor, latch or other actuator is driven. */
static void simulated_action_start(void* action) {
    SST_print_log(
        "SIMULATED_ACTION_STARTED: action=%s (test callback, no actuator)",
        (const char*)action);
}

/* The last step before `action` starts: the optional experimental delay,
 * then the action gate over every check the key's plan requires, which
 * starts the (simulated) action immediately on ALLOW. Exits on DENY, except
 * in a benchmark run (`bench` enabled), where the gate starts the benchmark
 * callback instead and the caller records the decision. */
static gate_decision physical_action_gate(const physical_options* o,
                                          const session_key_t* key,
                                          const char* action,
                                          const action_evidence* evidence,
                                          benchmark_trace* bench) {
    if (o->action_test_delay_ms) {
        SST_print_log(
            "ACTION_GATE: TEST ONLY: action_test_delay_ms=%u before gating %s.",
            o->action_test_delay_ms, action);
        session_ctl_sleep_ms(o->action_test_delay_ms);
    }
    if (bench && bench->enabled) {
        bench->decision = action_gate_run(key, action, evidence, NULL,
                                          bench_action_callback, bench,
                                          &bench->gate);
        bench->gate_ran = 1;
        return bench->decision;
    }
    if (action_gate_run(key, action, evidence, NULL, simulated_action_start,
                        (void*)action, NULL) != GATE_ALLOW) {
        SST_print_error_exit("%s denied by the action gate.", action);
    }
    return GATE_ALLOW;
}

#endif
