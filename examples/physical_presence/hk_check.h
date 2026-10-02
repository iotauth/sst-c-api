#ifndef PHYSICAL_PRESENCE_HK_CHECK_H
#define PHYSICAL_PRESENCE_HK_CHECK_H
#include <string.h>

#include "../../ir_com/ir_hk.h"
#include "../../lifi_com/lifi_hk.h"
#include "../../ultrasonic_com/ultrasonic_echo.h"
#ifdef HAVE_LIFI_TRANSPORT
#include "../../lifi_com/lifi_sst_handshake.h"
#endif
#ifdef HAVE_GGWAVE_TRANSPORT
#include "../../ultrasonic_com/ultrasonic_audio.h"
#endif

typedef struct {
    /* NULL, "IR", "LIFI" or "ULTRASOUND": when set, a plan that selects
     * anything else (including DUMMY) fails, so a stale catalog cannot make
     * an intended hardware test appear successful. Never overrides Auth. */
    const char* require_method;
    const char* mic_device; /* ALSA devices for the ultrasound echo */
    const char* spk_device;
    const char* local_name;      /* this entity's own name */
    const char* expected_peer;   /* initiator: the target it asked Auth for */
    unsigned echo_test_delay_ms; /* timing tests only: delays our answers */
} co_location_options;

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
    int rc = ultrasonic_echo_run(session, c, id, initiator, &io,
                                 o->echo_test_delay_ms, &r);
    ultrasonic_audio_close(audio);
    /* Print only after the complete exchange, never inside timed windows. */
    SST_print_log(
        "ULTRASOUND ECHO: verified direction=%u (%s) decoded=%d "
        "response_valid=%d elapsed_us=%llu max_response_us=%u timely=%d "
        "verified_at_us=%llu failure=%s",
        r.direction,
        r.direction == ULTRASONIC_ECHO_DIR_REQUESTER_VERIFIES ? "requester "
                                                                "verifies "
                                                                "target"
        : r.direction == ULTRASONIC_ECHO_DIR_TARGET_VERIFIES
            ? "target verifies requester"
            : "none",
        r.decoded, r.response_valid, (unsigned long long)r.elapsed_us,
        c->max_response_us, r.timing_accepted,
        (unsigned long long)r.verified_at_us,
        ultrasonic_echo_failure_name(r.failure));
    SST_print_log("ULTRASOUND ECHO: local=%s peer_reported=%s result=%s",
                  r.local_pass ? "PASS" : "FAIL",
                  r.peer_reported_pass ? "PASS" : "FAIL",
                  rc == 1   ? "PASS"
                  : rc == 0 ? "FAIL"
                            : "ABORT");
    return rc == 1;
#else
    (void)session;
    SST_print_error(
        "Auth requires the ultrasound echo, but this build has no "
        "ggwave/ALSA support.");
    return 0;
#endif
}

/* Called after handshake for every transport; Auth's verificationPlan alone
 * decides whether to run IR/LiFi HK or the ultrasound echo. Never
 * substitute DUMMY when the selected medium is unavailable. */
static int verify_co_location(SST_session_ctx_t* session, int initiator,
                              const co_location_options* opts) {
    const char* require_method = opts->require_method;
    ir_hk_config ir = {0};
    lifi_hk_config lifi = {0};
    ultrasonic_echo_config echo = {0};
    ultrasonic_echo_identity echo_id = {{0}, {0}};
    /* Each parser returns -1 for the others' methods, 0 for absent/DUMMY. */
    int ir_selected = ir_hk_plan_config(session->s_key.challenge, &ir);
    int lifi_selected = lifi_hk_plan_config(session->s_key.challenge, &lifi);
    int echo_selected =
        ultrasonic_echo_plan_config(session->s_key.challenge, &echo, &echo_id);
    const char* selected = ir_selected == 1     ? "IR"
                           : lifi_selected == 1 ? "LIFI"
                           : echo_selected == 1 ? "ULTRASOUND"
                                                : NULL;
    if (!selected &&
        (ir_selected < 0 || lifi_selected < 0 || echo_selected < 0)) {
        SST_print_error("Invalid or unsupported Auth CO_LOCATION plan.");
        return 0;
    }
    if (require_method && (!selected || strcmp(selected, require_method))) {
        SST_print_error("%s required for this run, but Auth selected %s.",
                        require_method,
                        selected ? selected : "a different plan");
        return 0;
    }
    if (!selected) {
        SST_print_log(
            "CO_LOCATION: no IR/LiFi/ultrasound check selected (absent or "
            "demo DUMMY).");
        return 1;
    }
    if (echo_selected == 1)
        return verify_ultrasound_echo(session, initiator, opts, &echo,
                                      &echo_id);
    unsigned rounds = ir_selected == 1 ? ir.rounds : lifi.rounds;
    unsigned required =
        ir_selected == 1 ? ir_hk_required(&ir) : lifi_hk_required(&lifi);
    unsigned threshold_ppm =
        ir_selected == 1 ? ir.threshold_ppm : lifi.threshold_ppm;
    unsigned max_delay_us =
        ir_selected == 1 ? ir.max_delay_us : lifi.max_delay_us;
    SST_print_log(
        "%s HK: role=%s rounds=%u required=%u threshold=%.6f max_delay_us=%u",
        selected, initiator ? "initiator" : "responder", rounds, required,
        threshold_ppm / 1000000.0, max_delay_us);

    /* Copied out of the medium-specific result so the report below is
     * shared; each medium's result lives only inside its own branch. */
    _Static_assert(IR_HK_MAX_ROUNDS == LIFI_HK_MAX_ROUNDS,
                   "shared report arrays assume equal round caps");
    unsigned completed = 0, successes = 0;
    uint32_t rtt_us[LIFI_HK_MAX_ROUNDS] = {0};
    unsigned char correct[LIFI_HK_MAX_ROUNDS] = {0};
    int local_pass = 0, rc = -1;
    if (ir_selected == 1) {
#ifdef HAVE_IR_TRANSPORT
        ir_hk_result result = {0};
        rc = ir_hk_run_gpio(&session->s_key, &ir, initiator, &result);
        completed = result.completed;
        successes = result.successes;
        local_pass = result.local_pass;
        memcpy(rtt_us, result.rtt_us, sizeof(rtt_us));
        memcpy(correct, result.correct, sizeof(correct));
#else
        SST_print_error(
            "Auth requires IR HK, but this build has no pigpio support.");
        return 0;
#endif
    } else {
#ifdef HAVE_LIFI_TRANSPORT
        lifi_hk_result result = {0};
        rc = lifi_hk_run_gpio(&session->s_key, &lifi, initiator, &result);
        completed = result.completed;
        successes = result.successes;
        local_pass = result.local_pass;
        memcpy(rtt_us, result.rtt_us, sizeof(rtt_us));
        memcpy(correct, result.correct, sizeof(correct));
#else
        SST_print_error(
            "Auth requires LiFi HK, but this build has no pigpio support.");
        return 0;
#endif
    }
    /* Print only after the complete exchange, never inside timed rounds. */
    for (unsigned i = 0; i < completed; ++i) {
        SST_print_log("%s HK round=%u correct=%u complete_rtt_us=%u timely=%u",
                      selected, i + 1, correct[i], rtt_us[i],
                      rtt_us[i] <= max_delay_us);
    }
    SST_print_log("%s HK: successes=%u/%u required=%u local=%s result=%s",
                  selected, successes, rounds, required,
                  local_pass ? "PASS" : "FAIL",
                  rc == 1   ? "PASS"
                  : rc == 0 ? "FAIL"
                            : "ABORT");
    return rc == 1;
}
#endif
