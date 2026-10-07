#ifndef PHYSICAL_PRESENCE_HK_CHECK_H
#define PHYSICAL_PRESENCE_HK_CHECK_H
#include <string.h>

#include "../../bluetooth_com/ble_adv_rssi.h"
#include "../../physical_com/freshness.h"
#include "../../physical_com/hk.h"
#include "../../physical_com/rssi_check.h"
#include "../../ultrasonic_com/ultrasonic_echo.h"
#include "../../uwb_com/uwb_cli_dev.h"
#include "../../wifi_com/wifi_rssi.h"
#ifdef HAVE_BT_TRANSPORT
#include "../../bluetooth_com/bt_adv_radio.h"
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
    rssi_config rssi; /* WIFI_RSSI */
    ble_adv_rssi_config ble;
    uwb_range_config uwb;
} co_location_config;

static const char* run_result_name(int rc) {
    return rc == 1 ? "PASS" : rc == 0 ? "FAIL" : "ABORT";
}

static const char* peer_report_name(int reported, int pass) {
    return !reported ? "NONE" : pass ? "PASS" : "FAIL";
}

/* A method's run result (1 pass, 0 completed without passing, -1 aborted)
 * and its own observation interval, as freshness evidence. A lower bound of
 * 0 means it was never taken, so the observation time is unknown. */
static void set_evidence(physical_evidence* ev, int rc,
                         uint64_t observed_not_before_us,
                         uint64_t collection_completed_us) {
    ev->complete = rc >= 0;
    ev->local_pass = rc == 1;
    ev->observation_time_known =
        observed_not_before_us != 0 && collection_completed_us != 0;
    ev->observed_not_before_us = observed_not_before_us;
    ev->collection_completed_us = collection_completed_us;
}

/* IR and LiFi: the shared timed bit exchange over each medium's GPIOs. */
static int verify_hk(SST_session_ctx_t* session, int initiator,
                     const hk_medium* medium, const hk_config* c,
                     physical_evidence* ev) {
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
        return -1;
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
    set_evidence(ev, rc, r.observed_not_before_us, r.collection_completed_us);
    return rc;
}

/* Auth's plan names both parties; each side checks that against what it
 * already knows before binding its MACs to those names. */
static int verify_ultrasound_echo(SST_session_ctx_t* session, int initiator,
                                  const co_location_options* o,
                                  const ultrasonic_echo_config* c,
                                  const ultrasonic_echo_identity* id,
                                  physical_evidence* ev) {
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
        return -1;
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
        return -1;
    }
    /* Opened before the INIT/READY exchange, outside any timed window. */
    ultrasonic_audio* audio =
        ultrasonic_audio_open(o->mic_device, o->spk_device);
    if (!audio) return -1;
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
    set_evidence(ev, rc, r.observed_not_before_us, r.collection_completed_us);
    return rc;
#else
    (void)session;
    (void)ev;
    SST_print_error(
        "Auth requires the ultrasound echo, but this build has no "
        "ggwave/ALSA support.");
    return -1;
#endif
}

/* The Wi-Fi peer, as wifi_fresh_sampler's radio. */
typedef struct {
    const char* iface;
    char peer_ip[16];
} wifi_peer;
static int read_wifi_station(void* ctx, wifi_station_info* out) {
    return wifi_station_read(((const wifi_peer*)ctx)->iface, out);
}
static int probe_wifi_peer(void* ctx) {
    const wifi_peer* p = ctx;
    return wifi_probe_peer(p->iface, p->peer_ip);
}
static int read_fresh_wifi_rssi(void* sampler, int8_t* rssi) {
    return wifi_fresh_sample(sampler, rssi);
}

/* Both RSSI methods sample the link that carries this session, from this
 * side's own radio. `name` is the log prefix ("BLE RSSI", "WIFI RSSI").
 * `observed_not_before_us` precedes every sampled frame, or is 0 when the
 * reader cannot tell: then the evidence has no known observation time and a
 * strict freshness gate denies it, even when the RSSI check itself passed. */
static int run_rssi_check(SST_session_ctx_t* session, int initiator,
                          const char* name, const rssi_config* c,
                          rssi_reader read, void* reader_ctx,
                          uint64_t observed_not_before_us,
                          physical_evidence* ev) {
    rssi_result r;
    int rc = rssi_run(session, c, initiator, read, reader_ctx, &r);
    uint64_t done_us = 0;
    freshness_now_us(&done_us);
    set_evidence(ev, rc, observed_not_before_us, done_us);
    SST_print_log(
        "%s: samples=%u median_rssi_dbm=%.1f min_rssi_dbm=%d local=%s", name,
        r.samples, r.median_rssi_dbm, c->min_rssi_dbm,
        r.local_pass ? "PASS" : "FAIL");
    SST_print_log("%s: peer_median_rssi_dbm=%d peer_reported=%s result=%s",
                  name, r.peer_median_rssi_dbm,
                  peer_report_name(r.peer_reported, r.peer_reported_pass),
                  run_result_name(rc));
    if (!observed_not_before_us) {
        SST_print_log(
            "%s: observation time of the cached RSSI is unknown; a strict "
            "freshness gate will not accept it.",
            name);
    }
    return rc;
}

static void log_rssi_role(const char* name, int initiator,
                          const rssi_config* c) {
    SST_print_log("%s: role=%s min_rssi_dbm=%d samples=%u interval_ms=%u", name,
                  initiator ? "initiator" : "responder", c->min_rssi_dbm,
                  c->samples, c->interval_ms);
}

/* BLE RSSI from advertising packets that answer a fresh challenge over this
 * session (ble_adv_rssi.h): each sample is a packet the peer sent after this
 * side's challenge, so the challenge time bounds every observation. Uses
 * this host's controller next to the session's own BLE connection. */
static int verify_ble_rssi(SST_session_ctx_t* session, int initiator,
                           const ble_adv_rssi_config* c,
                           physical_evidence* ev) {
    SST_print_log(
        "BLE RSSI: role=%s min_rssi_dbm=%d samples=%u timeout_ms=%u "
        "(advertising challenge)",
        initiator ? "initiator" : "responder", c->min_rssi_dbm, c->samples,
        c->timeout_ms);
#ifdef HAVE_BT_TRANSPORT
    if (session->sock < 0) {
        SST_print_error(
            "BLE RSSI needs a socket-backed SST session; use --comm_type "
            "bluetooth.");
        return -1;
    }
    bt_adv_radio* bt = bt_adv_radio_open();
    if (!bt) return -1;
    ble_adv_radio radio;
    bt_adv_radio_bind(bt, &radio);
    ble_adv_rssi_result r;
    int rc = ble_adv_rssi_run(session, c, initiator, &radio, &r);
    bt_adv_radio_close(bt);
    SST_print_log(
        "BLE RSSI: samples=%u/%u median_rssi_dbm=%.1f min_rssi_dbm=%d local=%s",
        r.samples, c->samples, r.median_rssi_dbm, c->min_rssi_dbm,
        r.local_pass ? "PASS" : "FAIL");
    SST_print_log("BLE RSSI: peer_median_rssi_dbm=%d peer_reported=%s result=%s",
                  r.peer_median_rssi_dbm,
                  peer_report_name(r.peer_reported, r.peer_reported_pass),
                  run_result_name(rc));
    set_evidence(ev, rc, r.observed_not_before_us, r.collection_completed_us);
    return rc;
#else
    (void)session;
    (void)ev;
    SST_print_error(
        "Auth requires the BLE RSSI check, but this build has no BlueZ "
        "support.");
    return -1;
#endif
}

/* Samples the RSSI of the direct Wi-Fi link that carries this session: the
 * session's socket must run over the dongle, or its RSSI says nothing about
 * the authenticated peer. The driver's RSSI is a cached value, so every
 * sample comes from wifi_fresh_sampler: only RSSI of frames the peer sent
 * after the sampler began, which makes that start the observation time's
 * lower bound. */
static int verify_wifi_rssi(SST_session_ctx_t* session, int initiator,
                            const co_location_options* o, const rssi_config* c,
                            physical_evidence* ev) {
    log_rssi_role("WIFI RSSI", initiator, c);
    char iface[32];
    if (session->sock < 0 ||
        wifi_rssi_socket_iface(session->sock, iface, sizeof(iface)) ||
        strcmp(iface, o->wifi_iface)) {
        SST_print_error(
            "WIFI RSSI needs the SST session on the %s link; use --comm_type "
            "wifi.",
            o->wifi_iface);
        return -1;
    }
    wifi_peer peer = {o->wifi_iface, {0}};
    wifi_fresh_sampler sampler = {&peer, read_wifi_station, probe_wifi_peer,
                                  0};
    uint64_t observed_not_before_us;
    if (wifi_rssi_socket_peer(session->sock, peer.peer_ip,
                              sizeof(peer.peer_ip)) ||
        freshness_now_us(&observed_not_before_us) ||
        wifi_fresh_begin(&sampler)) {
        SST_print_error("WIFI RSSI: could not read the peer's link state.");
        return -1;
    }
    return run_rssi_check(session, initiator, "WIFI RSSI", c,
                          read_fresh_wifi_rssi, &sampler,
                          observed_not_before_us, ev);
}

/* Ranges with the peer's UWB board over this session's TCP socket. */
static int verify_uwb(SST_session_ctx_t* session, int initiator,
                      const co_location_options* o, const uwb_range_config* c,
                      physical_evidence* ev) {
    SST_print_log(
        "UWB RANGE: role=%s max_distance_cm=%u samples=%u timeout_ms=%u",
        initiator ? "initiator" : "responder", c->max_distance_cm, c->samples,
        c->timeout_ms);
    if (session->sock < 0) {
        SST_print_error(
            "UWB ranging needs the TCP SST session; use --comm_type tcp.");
        return -1;
    }
    uwb_cli* cli = uwb_cli_open(o->uwb_device);
    if (!cli) return -1;
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
    set_evidence(ev, rc, r.observed_not_before_us, r.collection_completed_us);
    return rc;
}

/* Every CO_LOCATION method an endpoint can run: how to read its settings
 * from the plan (1 selected, 0 absent/DUMMY, -1 malformed or another
 * method), and how to run it once selected (1 pass, 0 fail, -1 aborted,
 * with its evidence). */
typedef struct {
    const char* id;
    int (*select)(const char* plan, co_location_config* c);
    int (*verify)(SST_session_ctx_t* session, int initiator,
                  const co_location_options* o, const co_location_config* c,
                  physical_evidence* ev);
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
    return ble_adv_rssi_plan_config(plan, &c->ble);
}
static int select_wifi(const char* plan, co_location_config* c) {
    return rssi_plan_config(plan, "WIFI_RSSI", &c->rssi);
}
static int select_uwb(const char* plan, co_location_config* c) {
    return uwb_range_plan_config(plan, &c->uwb);
}
static int run_ir(SST_session_ctx_t* s, int initiator,
                  const co_location_options* o, const co_location_config* c,
                  physical_evidence* ev) {
    (void)o;
    return verify_hk(s, initiator, &HK_IR, &c->hk, ev);
}
static int run_lifi(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c,
                    physical_evidence* ev) {
    (void)o;
    return verify_hk(s, initiator, &HK_LIFI, &c->hk, ev);
}
static int run_echo(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c,
                    physical_evidence* ev) {
    return verify_ultrasound_echo(s, initiator, o, &c->echo.config,
                                  &c->echo.identity, ev);
}
static int run_ble(SST_session_ctx_t* s, int initiator,
                   const co_location_options* o, const co_location_config* c,
                   physical_evidence* ev) {
    (void)o;
    return verify_ble_rssi(s, initiator, &c->ble, ev);
}
static int run_wifi(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c,
                    physical_evidence* ev) {
    return verify_wifi_rssi(s, initiator, o, &c->rssi, ev);
}
static int run_uwb(SST_session_ctx_t* s, int initiator,
                   const co_location_options* o, const co_location_config* c,
                   physical_evidence* ev) {
    return verify_uwb(s, initiator, o, &c->uwb, ev);
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
 * selected medium is unavailable. The result goes into this operation's
 * `evidence` (any earlier CO_LOCATION evidence is dropped first); only the
 * action gate decides whether it still allows the action.
 * @return 1 when the selected method passed here, 0 otherwise (including
 * an absent or DUMMY check, which leaves no evidence). */
static int verify_co_location(SST_session_ctx_t* session, int initiator,
                              const co_location_options* opts,
                              action_evidence* evidence) {
    const co_location_method* selected = NULL;
    co_location_config config;
    int malformed = 0;
    action_evidence_invalidate(evidence, "CO_LOCATION");
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
            "(absent or demo DUMMY); no evidence recorded.");
        return 0;
    }
    physical_evidence ev = {0};
    int rc = selected->verify(session, initiator, opts, &config, &ev);
    SST_print_log(
        "CO_LOCATION evidence: method=%s complete=%d local_pass=%d "
        "observation_time_known=%d observed_not_before_us=%llu "
        "collection_completed_us=%llu",
        selected->id, ev.complete, ev.local_pass, ev.observation_time_known,
        (unsigned long long)ev.observed_not_before_us,
        (unsigned long long)ev.collection_completed_us);
    if (action_evidence_record(evidence, "CO_LOCATION", selected->id, &ev)) {
        SST_print_error("CO_LOCATION: could not store the evidence.");
        return 0;
    }
    return rc == 1;
}
#endif
