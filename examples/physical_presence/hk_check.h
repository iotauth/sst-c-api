#ifndef PHYSICAL_PRESENCE_HK_CHECK_H
#define PHYSICAL_PRESENCE_HK_CHECK_H
#include "../../ir_com/ir_hk.h"

/* Called after handshake for every transport; Auth's verificationPlan alone
 * decides whether to run IR. Never substitute DUMMY when IR is unavailable. */
static int verify_co_location(SST_session_ctx_t* session, int initiator,
                              int require_ir) {
    ir_hk_config config = {0};
    int selected = ir_hk_plan_config(session->s_key.challenge, &config);
    if (selected < 0) {
        SST_print_error("Invalid or unsupported Auth CO_LOCATION plan.");
        return 0;
    }
    if (!selected && require_ir) {
        SST_print_error(
            "IR HK required for this run, but Auth selected a different plan.");
        return 0;
    }
    if (!selected) {
        SST_print_log(
            "CO_LOCATION: no IR check selected (absent or demo DUMMY).");
        return 1;
    }
    SST_print_log(
        "IR HK: role=%s rounds=%u required=%u threshold=%.6f max_delay_us=%u",
        initiator ? "initiator" : "responder", config.rounds,
        ir_hk_required(&config), config.threshold_ppm / 1000000.0,
        config.max_delay_us);
#ifdef HAVE_IR_TRANSPORT
    ir_hk_result result = {0};
    int rc = ir_hk_run_gpio(&session->s_key, &config, initiator, &result);
    /* Print only after the complete exchange, never inside timed rounds. */
    for (unsigned i = 0; i < result.completed; ++i) {
        SST_print_log("IR HK round=%u correct=%u complete_rtt_us=%u timely=%u",
                      i + 1, result.correct[i], result.rtt_us[i],
                      result.rtt_us[i] <= config.max_delay_us);
    }
    SST_print_log(
        "IR HK: successes=%u/%u required=%u local=%s peer=%s result=%s",
        result.successes, config.rounds, result.required,
        result.local_pass ? "PASS" : "FAIL", result.peer_pass ? "PASS" : "FAIL",
        rc == 1   ? "PASS"
        : rc == 0 ? "FAIL"
                  : "ABORT");
    return rc == 1;
#else
    SST_print_error(
        "Auth requires IR HK, but this build has no pigpio support.");
    return 0;
#endif
}
#endif
