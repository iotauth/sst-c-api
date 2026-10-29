#ifndef PHYSICAL_PRESENCE_HK_CHECK_H
#define PHYSICAL_PRESENCE_HK_CHECK_H
#include <stdarg.h>
#include <string.h>

#include "../../ambient_audio_com/ambient_audio.h"
#include "../../bluetooth_com/ble_adv_rssi.h"
#include "../../physical_com/freshness.h"
#include "../../physical_com/hk.h"
#include "../../physical_com/rssi_check.h"
#include "../../ultrasonic_com/ultrasonic_echo.h"
#include "../../uwb_com/uwb_cli_dev.h"
#include "../../wifi_com/wifi_rssi.h"
#include "../../wifi_com/wifi_timing.h"
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
#ifdef HAVE_AMBIENT_AUDIO
#include "../../ambient_audio_com/ambient_audio_device.h"
#endif

typedef struct {
    /* NULL, "IR", "LIFI", "ULTRASOUND", "AMBIENT_AUDIO", "BLE_RSSI",
     * "WIFI_RSSI" or "UWB":
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
    /* IR/LiFi only: send the HK preparation control messages (INIT/READY)
     * over the TCP session, keeping just the timed rounds optical. For the
     * relay experiment. 0 = all of HK over the optical link (default). */
    int hk_control_over_tcp;
    /* WIFI_RSSI only: an authenticated response-time challenge--response over
     * the Wi-Fi session, added after the RSSI sampling (see wifi_timing.h).
     * mode 0 = disabled (default, unchanged behavior). */
    int wifi_timing_mode;
    unsigned wifi_timing_rounds;
    uint64_t wifi_timing_deadline_us;
    uint64_t wifi_timing_recv_timeout_us;
    /* WIFI_RSSI only, set at run time (not from the plan): the measurement
     * Wi-Fi link's socket, separate from the handshake transport. The caller
     * brings the link up and establishes it (locker accepts, robot connects)
     * before the check. < 0 means no measurement link was set up. */
    int wifi_measure_sock;
    /* Benchmark only: when set, the selected method writes its own
     * observations here as one JSON object, after its exchange. */
    char* observations;
    size_t observations_size;
} co_location_options;

/* One CO_LOCATION method's settings, as read from Auth's plan. */
typedef union {
    hk_config hk;
    struct {
        ultrasonic_echo_config config;
        ultrasonic_echo_identity identity;
    } echo;
    struct {
        ambient_audio_config config;
        ambient_audio_identity identity;
    } ambient;
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

/* Appends to the benchmark's observations JSON, if it is being recorded.
 * Only ever called after an exchange has finished. */
static void obs_add(const co_location_options* o, size_t* off,
                    const char* fmt, ...) {
    if (!o->observations || *off >= o->observations_size) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(o->observations + *off, o->observations_size - *off, fmt,
                      ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= o->observations_size - *off) {
        o->observations[0] = 0; /* truncated JSON is worse than none */
        *off = o->observations_size;
        return;
    }
    *off += (size_t)n;
}

/* IR and LiFi: the shared timed bit exchange over each medium's GPIOs. */
static int verify_hk(SST_session_ctx_t* session, int initiator,
                     const co_location_options* o, const hk_medium* medium,
                     const hk_config* c, physical_evidence* ev) {
    unsigned required = hk_required(c);
    SST_print_log(
        "%s HK: role=%s rounds=%u required=%u threshold=%.6f max_delay_us=%u",
        medium->method, initiator ? "initiator" : "responder", c->rounds,
        required, c->threshold_ppm / 1000000.0, c->max_delay_us);
    int (*run_gpio)(const session_key_t*, const hk_config*, int, hk_result*,
                    SST_session_ctx_t*, int) = NULL;
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
    int rc = run_gpio(&session->s_key, c, initiator, &r, session,
                      o->hk_control_over_tcp);
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
    size_t off = 0;
    obs_add(o, &off,
            "{\"mechanism\": \"%s\", \"role\": \"%s\", \"rounds\": %u, "
            "\"completed_rounds\": %u, \"correct_and_timely\": %u, "
            "\"required\": %u, \"max_delay_us\": %u, "
            "\"success_threshold_ppm\": %u, \"inter_bit_us\": %u, "
            "\"rtt_us\": [",
            medium->method, initiator ? "initiator" : "responder", c->rounds,
            r.completed, r.successes, required, c->max_delay_us,
            c->threshold_ppm, medium->inter_bit_us);
    for (unsigned i = 0; i < r.completed; ++i)
        obs_add(o, &off, "%s%u", i ? ", " : "", r.rtt_us[i]);
    obs_add(o, &off, "], \"correct\": [");
    for (unsigned i = 0; i < r.completed; ++i)
        obs_add(o, &off, "%s%u", i ? ", " : "", r.correct[i]);
    obs_add(o, &off, "]}");
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
    size_t off = 0;
    obs_add(o, &off,
            "{\"mechanism\": \"ULTRASOUND\", \"role\": \"%s\", "
            "\"direction\": %u, \"decoded\": %s, \"response_valid\": %s, "
            "\"challenge_to_decode_us\": %llu, \"timing_accepted\": %s, "
            "\"max_response_us\": %u, \"response_timeout_ms\": %u, "
            "\"failure\": \"%s\", \"peer_reported_pass\": %s}",
            initiator ? "initiator" : "responder", r.direction,
            r.decoded ? "true" : "false", r.response_valid ? "true" : "false",
            (unsigned long long)r.elapsed_us,
            r.timing_accepted ? "true" : "false", c->max_response_us,
            c->response_timeout_ms, ultrasonic_echo_failure_name(r.failure),
            r.peer_reported_pass ? "true" : "false");
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

/* Sound-Proof-inspired passive co-location: both sides record the same
 * wall-clock window, exchange recordings over the session, and each compares
 * its own against the peer's with the Python ambient_audio tool. */
static int verify_ambient_audio(SST_session_ctx_t* session, int initiator,
                                const co_location_options* o,
                                const ambient_audio_config* c,
                                const ambient_audio_identity* id,
                                physical_evidence* ev) {
    int names_ok = initiator ? !strcmp(id->requester, o->local_name) &&
                                   o->expected_peer &&
                                   !strcmp(id->target, o->expected_peer)
                             : !strcmp(id->target, o->local_name);
    if (!names_ok) {
        SST_print_error(
            "Ambient audio: Auth plan names requester=%s target=%s, which "
            "doesn't match this %s (%s).",
            id->requester, id->target, initiator ? "requester" : "target",
            o->local_name);
        return -1;
    }
    SST_print_log(
        "AMBIENT AUDIO: role=%s requester=%s target=%s recording_ms=%u "
        "threshold_milli=%u max_lag_ms=%u min_power_dbfs=%d mic=%s",
        initiator ? "initiator" : "responder", id->requester, id->target,
        c->recording_ms, c->similarity_threshold_milli, c->max_lag_ms,
        c->min_power_dbfs, o->mic_device);
#ifdef HAVE_AMBIENT_AUDIO
    if (session->sock < 0) {
        SST_print_error(
            "Ambient audio needs the TCP SST session; use --comm_type tcp.");
        return -1;
    }
    ambient_audio_device* dev = ambient_audio_device_open(o->mic_device);
    if (!dev) return -1;
    ambient_audio_io io;
    ambient_audio_device_bind(dev, &io);
    ambient_audio_result r;
    int rc = ambient_audio_run(session, c, initiator, &io, &r);
    ambient_audio_device_close(dev);
    SST_print_log(
        "AMBIENT AUDIO: similarity_milli=%d inputs_valid=%d accepted=%d "
        "local_power_dbfs=%d peer_power_dbfs=%d failure=%s",
        r.similarity_milli, r.inputs_valid, r.accepted, r.local_power_dbfs,
        r.peer_power_dbfs, ambient_audio_failure_name(r.failure));
    SST_print_log("AMBIENT AUDIO: local=%s result=%s",
                  r.local_pass ? "PASS" : "FAIL", run_result_name(rc));
    set_evidence(ev, rc, r.observed_not_before_us, r.collection_completed_us);
    size_t off = 0;
    obs_add(o, &off,
            "{\"mechanism\": \"AMBIENT_AUDIO\", \"role\": \"%s\", "
            "\"recording_ms\": %u, \"similarity_milli\": %d, "
            "\"threshold_milli\": %u, \"max_lag_ms\": %u, "
            "\"min_power_dbfs\": %d, \"inputs_valid\": %s, \"accepted\": %s, "
            "\"local_power_dbfs\": %d, \"peer_power_dbfs\": %d, "
            "\"failure\": \"%s\"}",
            initiator ? "initiator" : "responder", c->recording_ms,
            r.similarity_milli, c->similarity_threshold_milli, c->max_lag_ms,
            c->min_power_dbfs, r.inputs_valid ? "true" : "false",
            r.accepted ? "true" : "false", r.local_power_dbfs,
            r.peer_power_dbfs, ambient_audio_failure_name(r.failure));
    return rc;
#else
    (void)session;
    (void)ev;
    SST_print_error(
        "Auth requires ambient audio, but this build has no ALSA support.");
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
                          physical_evidence* ev, rssi_result* out) {
    rssi_result r;
    int rc = rssi_run(session, c, initiator, read, reader_ctx, &r);
    *out = r;
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
                           const co_location_options* o,
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
    size_t off = 0;
    obs_add(o, &off,
            "{\"mechanism\": \"BLE_RSSI\", \"role\": \"%s\", "
            "\"required_reports\": %u, \"received_reports\": %u, "
            "\"median_rssi_dbm\": %.1f, \"min_rssi_dbm\": %d, "
            "\"timeout_ms\": %u, \"nominal_advertising_interval_ms\": 100, "
            "\"peer_reported\": %s, \"peer_reported_pass\": %s, "
            "\"peer_median_rssi_dbm\": %d}",
            initiator ? "initiator" : "responder", c->samples, r.samples,
            r.median_rssi_dbm, c->min_rssi_dbm, c->timeout_ms,
            r.peer_reported ? "true" : "false",
            r.peer_reported_pass ? "true" : "false", r.peer_median_rssi_dbm);
    return rc;
#else
    (void)session;
    (void)o;
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
    /* Proximity is measured on the dedicated Wi-Fi measurement link, which is
     * independent of the handshake transport (the handshake may have run over
     * TCP on another interface). The caller brought the link up and
     * established this socket (locker accepted, robot connected). */
    if (o->wifi_measure_sock < 0) {
        SST_print_error(
            "WIFI RSSI needs the measurement Wi-Fi link; none was set up.");
        return -1;
    }
    char miface[32];
    wifi_peer peer = {o->wifi_iface, {0}};
    if (wifi_rssi_socket_iface(o->wifi_measure_sock, miface, sizeof(miface)) ||
        strcmp(miface, o->wifi_iface) ||
        wifi_rssi_socket_peer(o->wifi_measure_sock, peer.peer_ip,
                              sizeof(peer.peer_ip))) {
        SST_print_error(
            "WIFI RSSI: the measurement socket is not on the %s link.",
            o->wifi_iface);
        return -1;
    }
    /* Make the two channels distinguishable in the logs. */
    char hiface[32] = "n/a", hpeer[16] = "n/a", mlocal[16] = "n/a";
    if (session->sock >= 0) {
        wifi_rssi_socket_iface(session->sock, hiface, sizeof(hiface));
        wifi_rssi_socket_peer(session->sock, hpeer, sizeof(hpeer));
    }
    wifi_iface_ipv4(o->wifi_iface, mlocal, sizeof(mlocal));
    SST_print_log(
        "WIFI RSSI: channels: handshake_interface=%s handshake_peer=%s "
        "measurement_interface=%s measurement_local=%s measurement_peer=%s",
        hiface, hpeer, miface, mlocal, peer.peer_ip);
    wifi_fresh_sampler sampler = {&peer, read_wifi_station, probe_wifi_peer,
                                  0};
    uint64_t observed_not_before_us;
    if (freshness_now_us(&observed_not_before_us) ||
        wifi_fresh_begin(&sampler)) {
        SST_print_error("WIFI RSSI: could not read the peer's link state.");
        return -1;
    }
    rssi_result r;
    /* RSSI medians are exchanged over the existing SST session (its control
     * channel); the sampling and the timing responses below are on the
     * measurement link. */
    int rc = run_rssi_check(session, initiator, "WIFI RSSI", c,
                            read_fresh_wifi_rssi, &sampler,
                            observed_not_before_us, ev, &r);
    /* Optional authenticated response-time check over the measurement Wi-Fi
     * link; in enforce mode it is ANDed with the RSSI outcome. */
    if (o->wifi_timing_mode != WIFI_TIMING_MODE_DISABLED) {
        wifi_timing_config tc = {o->wifi_timing_mode, o->wifi_timing_rounds,
                                 o->wifi_timing_deadline_us,
                                 o->wifi_timing_recv_timeout_us};
        wifi_timing_result tr;
        int trc = wifi_timing_run(o->wifi_measure_sock, &session->s_key,
                                  initiator,
                                  initiator ? "initiator" : "responder",
                                  o->wifi_iface, mlocal, peer.peer_ip, &tc, &tr);
        if (o->wifi_timing_mode == WIFI_TIMING_MODE_ENFORCE) {
            int combined =
                (rc < 0 || trc < 0) ? -1 : (rc == 1 && trc == 1) ? 1 : 0;
            uint64_t done_us = 0;
            freshness_now_us(&done_us);
            set_evidence(ev, combined, observed_not_before_us, done_us);
            rc = combined;
        }
    }
    size_t off = 0;
    obs_add(o, &off,
            "{\"mechanism\": \"WIFI_RSSI\", \"role\": \"%s\", "
            "\"interface\": \"%s\", \"required_samples\": %u, "
            "\"samples\": %u, \"median_rssi_dbm\": %.1f, "
            "\"min_rssi_dbm\": %d, \"interval_ms\": %u, \"probes\": %u, "
            "\"peer_reported\": %s, \"peer_reported_pass\": %s, "
            "\"peer_median_rssi_dbm\": %d}",
            initiator ? "initiator" : "responder", o->wifi_iface, c->samples,
            r.samples, r.median_rssi_dbm, c->min_rssi_dbm, c->interval_ms,
            sampler.probes, r.peer_reported ? "true" : "false",
            r.peer_reported_pass ? "true" : "false", r.peer_median_rssi_dbm);
    return rc;
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
    size_t off = 0;
    obs_add(o, &off,
            "{\"mechanism\": \"UWB\", \"role\": \"%s\", "
            "\"required_ranges\": %u, \"successful_ranges\": %u, "
            "\"median_cm\": %d, \"max_distance_cm\": %u, "
            "\"timeout_ms\": %u, \"peer_reported\": %s, "
            "\"peer_reported_pass\": %s, \"peer_median_cm\": %d}",
            initiator ? "initiator" : "responder", c->samples, r.samples,
            r.median_cm, c->max_distance_cm, c->timeout_ms,
            r.peer_reported ? "true" : "false",
            r.peer_reported_pass ? "true" : "false", r.peer_median_cm);
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
static int select_ambient(const char* plan, co_location_config* c) {
    return ambient_audio_plan_config(plan, &c->ambient.config,
                                     &c->ambient.identity);
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
    return verify_hk(s, initiator, o, &HK_IR, &c->hk, ev);
}
static int run_lifi(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c,
                    physical_evidence* ev) {
    return verify_hk(s, initiator, o, &HK_LIFI, &c->hk, ev);
}
static int run_echo(SST_session_ctx_t* s, int initiator,
                    const co_location_options* o, const co_location_config* c,
                    physical_evidence* ev) {
    return verify_ultrasound_echo(s, initiator, o, &c->echo.config,
                                  &c->echo.identity, ev);
}
static int run_ambient(SST_session_ctx_t* s, int initiator,
                       const co_location_options* o, const co_location_config* c,
                       physical_evidence* ev) {
    return verify_ambient_audio(s, initiator, o, &c->ambient.config,
                                &c->ambient.identity, ev);
}
static int run_ble(SST_session_ctx_t* s, int initiator,
                   const co_location_options* o, const co_location_config* c,
                   physical_evidence* ev) {
    return verify_ble_rssi(s, initiator, o, &c->ble, ev);
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
    {"AMBIENT_AUDIO", select_ambient, run_ambient},
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
