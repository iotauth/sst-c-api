#ifndef PHYSICAL_PRESENCE_HK_CHECK_H
#define PHYSICAL_PRESENCE_HK_CHECK_H
#include <string.h>

#include "../../physical_com/hk.h"
#include "../../physical_com/rssi_check.h"
#include "../../ultrasonic_com/ultrasonic_echo.h"
#include "../../uwb_com/uwb_cli_dev.h"
#include "../../wifi_com/wifi_rssi.h"
#ifdef HAVE_BT_TRANSPORT
#include "../../bluetooth_com/bt_link.h"
#endif
#ifdef HAVE_IR_TRANSPORT
#include "../../ir_com/ir_sst_handshake.h"
#endif
#ifdef HAVE_LIFI_TRANSPORT
#include "../../lifi_com/lifi_sst_handshake.h"
#endif
#ifdef HAVE_GGWAVE_TRANSPORT
#include "../../ultrasonic_com/ultrasonic_audio.h"
#endif

typedef struct {
    /* NULL, "IR", "LIFI", "ULTRASOUND", "BLE_RSSI", "WIFI_RSSI" or "UWB":
     * when set, a
     * plan that selects anything else (including DUMMY) fails, so a stale
     * catalog cannot make an intended hardware test appear successful. Never
     * overrides Auth. */
    const char* require_method;
    const char* mic_device; /* ALSA devices for the ultrasound echo */
    const char* spk_device;
    const char* local_name;      /* this entity's own name */
    const char* expected_peer;   /* initiator: the target it asked Auth for */
    unsigned echo_test_delay_ms; /* timing tests only: delays our answers */
    const char* uwb_device;      /* UWB board's serial port, NULL: auto */
    const char* wifi_iface;      /* the Wi-Fi dongle's direct link */
} co_location_options;

/* One CO_LOCATION method's settings, as read from Auth's plan. */
typedef union {
    hk_config hk;
    struct {
        ultrasonic_echo_config config;
        ultrasonic_echo_identity identity;
    } echo;
    rssi_config rssi; /* BLE_RSSI and WIFI_RSSI */
    uwb_range_config uwb;
} co_location_config;

static const char* run_result_name(int rc) {
    return rc == 1 ? "PASS" : rc == 0 ? "FAIL" : "ABORT";
}

static const char* peer_report_name(int reported, int pass) {
    return !reported ? "NONE" : pass ? "PASS" : "FAIL";
}

/* IR and LiFi: the shared timed bit exchange over each medium's GPIOs. */
static int verify_hk(SST_session_ctx_t* session, int initiator,
                     const hk_medium* medium, const hk_config* c) {
    unsigned required = hk_required(c);
    SST_print_log(
        "%s HK: role=%s rounds=%u required=%u threshold=%.6f max_delay_us=%u",
        medium->method, initiator ? "initiator" : "responder", c->rounds,
        required, c->threshold_ppm / 1000000.0, c->max_delay_us);
    int (*run_gpio)(const session_key_t*, const hk_config*, int, hk_result*) =
        NULL;
#ifdef HAVE_IR_TRANSPORT
    if (medium == &HK_IR) run_gpio = ir_hk_run_gpio;
#endif
#ifdef HAVE_LIFI_TRANSPORT
    if (medium == &HK_LIFI) run_gpio = lifi_hk_run_gpio;
#endif
    if (!run_gpio) {
        SST_print_error(
            "Auth requires %s HK, but this build has no pigpio support.",
            medium->name);
        return 0;
    }
    hk_result r = {0};
    int rc = run_gpio(&session->s_key, c, initiator, &r);
    /* Print only after the complete exchange, never inside timed rounds. */
    for (unsigned i = 0; i < r.completed; ++i) {
        SST_print_log("%s HK round=%u correct=%u complete_rtt_us=%u timely=%u",
                      medium->method, i + 1, r.correct[i], r.rtt_us[i],
                      r.rtt_us[i] <= c->max_delay_us);
    }
    SST_print_log("%s HK: successes=%u/%u required=%u local=%s result=%s",
                  medium->method, r.successes, c->rounds, required,
                  r.local_pass ? "PASS" : "FAIL", run_result_name(rc));
    return rc == 1;
}

/* Auth's plan names both parties; each side checks that against what it
 * already knows before binding its MACs to those names. */
static int verify_ultrasound_echo(SST_session_ctx_t* session, int initiator,
                                  const co_location_options* o,
                                  const ultrasonic_echo_config* c,
                                  const ultrasonic_echo_identity* id) {
    int names_ok = initiator ? !strcmp(id->requester, o->local_name) &&
                                   o->expected_peer &&
                                   !strcmp(id->target, o->expected_peer)
                             : !strcmp(id->target, o->local_name);
    if (!names_ok) {
        SST_print_error(
            "Ultrasound echo: Auth plan names requester=%s target=%s, which "
            "doesn't match this %s (%s).",
            id->requester, id->target, initiator ? "requester" : "target",
            o->local_name);
        return 0;
    }
    SST_print_log(
        "ULTRASOUND ECHO: role=%s requester=%s target=%s max_response_us=%u "
        "response_timeout_ms=%u mic=%s spk=%s",
        initiator ? "initiator" : "responder", id->requester, id->target,
        c->max_response_us, c->response_timeout_ms, o->mic_device,
        o->spk_device);
    if (o->echo_test_delay_ms) {
        SST_print_log(
            "ULTRASOUND ECHO: TEST ONLY: delaying this side's acoustic answer "
            "by %u ms.",
            o->echo_test_delay_ms);
    }
#ifdef HAVE_GGWAVE_TRANSPORT
    if (session->sock < 0) {
        SST_print_error(
            "Ultrasound echo needs the TCP SST session; use --comm_type tcp.");
        return 0;
    }
    /* Opened before the INIT/READY exchange, outside any timed window. */
    ultrasonic_audio* audio =
        ultrasonic_audio_open(o->mic_device, o->spk_device);
    if (!audio) return 0;
    ultrasonic_echo_audio io;
    ultrasonic_audio_bind(audio, &io);
    ultrasonic_echo_result r;
    int rc = ultrasonic_echo_run(session, c, initiator, &io,
                                 o->echo_test_delay_ms, &r);
    ultrasonic_audio_close(audio);
    /* Print only after the complete exchange, never inside timed windows. */
    SST_print_log(
        "ULTRASOUND ECHO: verified direction=%u (%s) decoded=%d "
        "response_valid=%d elapsed_us=%llu max_response_us=%u timely=%d "
        "verified_at_us=%llu failure=%s",
        r.direction,
        r.direction == ULTRASONIC_ECHO_DIR_REQUESTER_VERIFIES
            ? "requester verifies target"
        : r.direction == ULTRASONIC_ECHO_DIR_TARGET_VERIFIES
            ? "target verifies requester"
            : "none",
        r.decoded, r.response_valid, (unsigned long long)r.elapsed_us,
        c->max_response_us, r.timing_accepted,
        (unsigned long long)r.verified_at_us,
        ultrasonic_echo_failure_name(r.failure));
    SST_print_log("ULTRASOUND ECHO: local=%s peer_reported=%s result=%s",
                  r.local_pass ? "PASS" : "FAIL",
                  r.peer_reported_pass ? "PASS" : "FAIL", run_result_name(rc));
    return rc == 1;
#else
    (void)session;
    SST_print_error(
        "Auth requires the ultrasound echo, but this build has no "
        "ggwave/ALSA support.");
    return 0;
#endif
}

#ifdef HAVE_BT_TRANSPORT
static int read_link_rssi(void* sock, int8_t* rssi) {
    return bt_link_read_rssi(*(const int*)sock, rssi);
}
#endif

static int read_wifi_rssi(void* iface, int8_t* rssi) {
    return wifi_rssi_read(iface, rssi);
}

/* Both RSSI methods sample the link that carries this session, from this
 * side's own radio. `name` is the log prefix ("BLE RSSI", "WIFI RSSI"). */
static int run_rssi_check(SST_session_ctx_t* session, int initiator,
                          const char* name, const rssi_config* c,
                          rssi_reader read, void* reader_ctx) {
    rssi_result r;
    int rc = rssi_run(session, c, initiator, read, reader_ctx, &r);
    SST_print_log(
        "%s: samples=%u median_rssi_dbm=%.1f min_rssi_dbm=%d local=%s", name,
        r.samples, r.median_rssi_dbm, c->min_rssi_dbm,
        r.local_pass ? "PASS" : "FAIL");
    SST_print_log("%s: peer_median_rssi_dbm=%d peer_reported=%s result=%s",
                  name, r.peer_median_rssi_dbm,
                  peer_report_name(r.peer_reported, r.peer_reported_pass),
                  run_result_name(rc));
    return rc == 1;
}

static void log_rssi_role(const char* name, int initiator,
                          const rssi_config* c) {
    SST_print_log("%s: role=%s min_rssi_dbm=%d samples=%u interval_ms=%u", name,
                  initiator ? "initiator" : "responder", c->min_rssi_dbm,
                  c->samples, c->interval_ms);
}

/* Samples the RSSI of the Bluetooth link that carries this session. */
static int verify_ble_rssi(SST_session_ctx_t* session, int initiator,
                           const rssi_config* c) {
    log_rssi_role("BLE RSSI", initiator, c);
#ifdef HAVE_BT_TRANSPORT
    if (!bt_link_is_bluetooth(session->sock)) {
        SST_print_error(
            "BLE RSSI needs the Bluetooth SST session; use --comm_type "
            "bluetooth.");
        return 0;
    }
    return run_rssi_check(session, initiator, "BLE RSSI", c, read_link_rssi,
                          &session->sock);
#else
    (void)session;
    SST_print_error(
        "Auth requires the BLE RSSI check, but this build has no BlueZ "
        "support.");
    return 0;
#endif
}

/* Samples the RSSI of the direct Wi-Fi link that carries this session: the
 * session's socket must run over the dongle, or its RSSI says nothing about
 * the authenticated peer. */
static int verify_wifi_rssi(SST_session_ctx_t* session, int initiator,
                            const co_location_options* o,
                            const rssi_config* c) {
    log_rssi_role("WIFI RSSI", initiator, c);
    char iface[32];
    if (session->sock < 0 ||
        wifi_rssi_socket_iface(session->sock, iface, sizeof(iface)) ||
        strcmp(iface, o->wifi_iface)) {
        SST_print_error(
            "WIFI RSSI needs the SST session on the %s link; use --comm_type "
            "wifi.",
            o->wifi_iface);
        return 0;
    }
    return run_rssi_check(session, initiator, "WIFI RSSI", c, read_wifi_rssi,
                          (void*)o->wifi_iface);
}

/* Ranges with the peer's UWB board over this session's TCP socket. */
static int verify_uwb(SST_session_ctx_t* session, int initiator,
                      const co_location_options* o, const uwb_range_config* c) {
    SST_print_log(
        "UWB RANGE: role=%s max_distance_cm=%u samples=%u timeout_ms=%u",
        initiator ? "initiator" : "responder", c->max_distance_cm, c->samples,
        c->timeout_ms);
    if (session->sock < 0) {
        SST_print_error(
            "UWB ranging needs the TCP SST session; use --comm_type tcp.");
        return 0;
    }
    uwb_cli* cli = uwb_cli_open(o->uwb_device);
    if (!cli) return 0;
    uwb_range_radio radio;
    uwb_cli_bind(cli, &radio);
    uwb_range_result r;
    int rc = uwb_range_run(session, c, initiator, &radio, &r);
    uwb_cli_close(cli);
    SST_print_log(
        "UWB RANGE: samples=%u/%u median_cm=%d max_distance_cm=%u local=%s",
        r.samples, c->samples, r.median_cm, c->max_distance_cm,
        r.local_pass ? "PASS" : "FAIL");
    SST_print_log("UWB RANGE: peer_median_cm=%d peer_reported=%s result=%s",
                  r.peer_median_cm,
                  peer_report_name(r.peer_reported, r.peer_reported_pass),
                  run_result_name(rc));
    return rc == 1;
}

/* Every CO_LOCATION method an endpoint can run: how to read its settings
 * from the plan (1 selected, 0 absent/DUMMY, -1 malformed or another
 * method), and how to run it once selected. */
typedef struct {
    const char* id;
    int (*select)(const char* plan, co_location_config* c);
    int (*verify)(SST_session_ctx_t* session, int initiator,
                  const co_location_options* o, const co_location_config* c);
} co_location_method;

static int select_ir(const char* plan, co_location_config* c) {
    return hk_plan_config(plan, &HK_IR, &c->hk);
}
static int select_lifi(const char* plan, co_location_config* c) {
    return hk_plan_config(plan, &HK_LIFI, &c->hk);
}
static int select_echo(const char* plan, co_location_config* c) {
    return ultrasonic_echo_plan_config(plan, &c->echo.config,
                                       &c->echo.identity);
}
static int select_ble(const char* plan, co_location_config* c) {
    return rssi_plan_config(plan, "BLE_RSSI", &c->rssi);
}
static int select_wifi(const char* plan, co_location_config* c) {
    return rssi_plan_config(plan, "WIFI_RSSI", &c->rssi);
}
static int select_uwb(const char* plan, co_location_config* c) {
    return uwb_range_plan_config(plan, &c->uwb);
}
static int run_ir(SST_session_ctx_t* s, int initiator,
                  const co_location_options* o, const co_location_config* c) {
    (void)o;
    return verify_hk(s, initiator, &HK_IR, &c->hk);
}
static int run_lifi(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c) {
    (void)o;
    return verify_hk(s, initiator, &HK_LIFI, &c->hk);
}
static int run_echo(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c) {
    return verify_ultrasound_echo(s, initiator, o, &c->echo.config,
                                  &c->echo.identity);
}
static int run_ble(SST_session_ctx_t* s, int initiator,
                   const co_location_options* o, const co_location_config* c) {
    (void)o;
    return verify_ble_rssi(s, initiator, &c->rssi);
}
static int run_wifi(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c) {
    return verify_wifi_rssi(s, initiator, o, &c->rssi);
}
static int run_uwb(SST_session_ctx_t* s, int initiator,
                   const co_location_options* o, const co_location_config* c) {
    return verify_uwb(s, initiator, o, &c->uwb);
}

static const co_location_method CO_LOCATION_METHODS[] = {
    {"IR", select_ir, run_ir},
    {"LIFI", select_lifi, run_lifi},
    {"ULTRASOUND", select_echo, run_echo},
    {"BLE_RSSI", select_ble, run_ble},
    {"WIFI_RSSI", select_wifi, run_wifi},
    {"UWB", select_uwb, run_uwb},
};

/* Called after handshake for every transport; Auth's verificationPlan alone
 * decides which CO_LOCATION method runs. Never substitute DUMMY when the
 * selected medium is unavailable. */
static int verify_co_location(SST_session_ctx_t* session, int initiator,
                              const co_location_options* opts) {
    const co_location_method* selected = NULL;
    co_location_config config;
    int malformed = 0;
    for (size_t i = 0;
         i < sizeof(CO_LOCATION_METHODS) / sizeof(*CO_LOCATION_METHODS); ++i) {
        co_location_config c;
        int rc = CO_LOCATION_METHODS[i].select(session->s_key.challenge, &c);
        if (rc == 1 && !selected) {
            selected = &CO_LOCATION_METHODS[i];
            config = c;
        }
        /* Each parser returns -1 for the others' methods. */
        malformed |= rc < 0;
    }
    if (!selected && malformed) {
        SST_print_error("Invalid or unsupported Auth CO_LOCATION plan.");
        return 0;
    }
    if (opts->require_method &&
        (!selected || strcmp(selected->id, opts->require_method))) {
        SST_print_error("%s required for this run, but Auth selected %s.",
                        opts->require_method,
                        selected ? selected->id : "a different plan");
        return 0;
    }
    if (!selected) {
        SST_print_log(
            "CO_LOCATION: no IR/LiFi/ultrasound/BLE/Wi-Fi/UWB check selected "
            "(absent or demo DUMMY).");
        return 1;
    }
    return selected->verify(session, initiator, opts, &config);
}
#endif
