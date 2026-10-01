#ifndef PHYSICAL_PRESENCE_HK_CHECK_H
#define PHYSICAL_PRESENCE_HK_CHECK_H
#include <string.h>

#include "../../ir_com/ir_hk.h"
#include "../../lifi_com/lifi_hk.h"
#ifdef HAVE_LIFI_TRANSPORT
#include "../../lifi_com/lifi_sst_handshake.h"
#endif

/* Called after handshake for every transport; Auth's verificationPlan alone
 * decides whether to run IR or LiFi HK. Never substitute DUMMY when the
 * selected medium is unavailable.
 * @param require_method NULL, "IR" or "LIFI": when set, a plan that selects
 * anything else (including DUMMY) fails, so a stale catalog cannot make an
 * intended hardware test appear successful. */
static int verify_co_location(SST_session_ctx_t* session, int initiator,
                              const char* require_method) {
    ir_hk_config ir = {0};
    lifi_hk_config lifi = {0};
    /* Each parser returns -1 for the other's method, 0 for absent/DUMMY. */
    int ir_selected = ir_hk_plan_config(session->s_key.challenge, &ir);
    int lifi_selected = lifi_hk_plan_config(session->s_key.challenge, &lifi);
    const char* selected = ir_selected == 1     ? "IR"
                           : lifi_selected == 1 ? "LIFI"
                                                : NULL;
    if (!selected && (ir_selected < 0 || lifi_selected < 0)) {
        SST_print_error("Invalid or unsupported Auth CO_LOCATION plan.");
        return 0;
    }
    if (require_method && (!selected || strcmp(selected, require_method))) {
        SST_print_error("%s HK required for this run, but Auth selected %s.",
                        require_method,
                        selected ? selected : "a different plan");
        return 0;
    }
    if (!selected) {
        SST_print_log(
            "CO_LOCATION: no IR/LiFi check selected (absent or demo DUMMY).");
        return 1;
    }
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
