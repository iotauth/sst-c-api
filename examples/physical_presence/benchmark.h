#ifndef PHYSICAL_PRESENCE_BENCHMARK_H
#define PHYSICAL_PRESENCE_BENCHMARK_H
/* Opt-in latency benchmark for robot/locker (--benchmark): timestamps of one
 * RETRIEVE_ITEM (robot) or LOCKER_OPEN (locker) run on this endpoint's own
 * CLOCK_MONOTONIC, the action gate's report, and the selected mechanism's
 * observations, written as one JSON file per endpoint and run.
 *
 * Every timestamp comes from the same clock as the freshness gate
 * (freshness_now_us). Nothing here changes an observation time, a bound or
 * the gate's decision: the benchmark only reads clocks around the existing
 * calls and replaces the simulated action callback with one that reads the
 * clock first. A clock read that fails leaves its field unset (null) and
 * marks the run as a measurement error; nothing is filled in. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../physical_com/freshness.h"
#include "../../physical_com/plan_json.h"
#include "../../src/c_common.h"

#define BENCH_OBSERVATIONS_SIZE 8192
#define BENCH_MAX_CHECKS 12

/* One verification's own execution interval, on this endpoint's clock. Covers
 * both cooperative requirements (PROXIMITY, ...) and single-device checks
 * (TEMPERATURE_CHECK, HUMIDITY_CHECK, HUMAN_PRESENCE). start/end are 0 when not
 * recorded; completed is rc>=0, accepted is rc==1. */
typedef struct {
    char check[40];
    char method[40];
    const char* kind; /* "cooperative" or "single_device" */
    uint64_t start_us, end_us;
    int completed, accepted;
} bench_check_timing;

typedef struct {
    int enabled;
    const char* run_id;
    const char* output;
    const char* role;   /* "requester" or "locker" */
    const char* action; /* "RETRIEVE_ITEM" or "LOCKER_OPEN" */
    const char* handshake_transport;
    freshness_clock clock; /* NULL: freshness_now_us */
    int clock_error;
    /* 0 = not recorded (JSON null). */
    uint64_t authorization_start_us, authorization_end_us;
    uint64_t peer_handshake_start_us, peer_handshake_end_us;
    uint64_t cooperative_start_us, cooperative_end_us;
    /* Per-check execution intervals, in the order they ran. */
    bench_check_timing checks[BENCH_MAX_CHECKS];
    int check_count;
    uint64_t action_callback_start_us;
    int callback_started;
    int gate_ran;
    gate_decision decision;
    gate_report gate;
    const char* error_stage; /* first stage that failed, NULL if none */
    const char* stage;       /* the stage in progress, NULL when done */
    int written;
    const session_key_t* key;
    const action_evidence* evidence;
    /* Distribution-key state right after init_SST(), before any request. */
    int dist_key_loaded_at_init;
    int perm_dist_key_mode;
    char observations[BENCH_OBSERVATIONS_SIZE]; /* a JSON object, or "" */
} benchmark_trace;

/* Reads the benchmark clock into *field; a failed read leaves it 0 and
 * marks the run. A no-op when the benchmark is off. */
static void bench_mark(benchmark_trace* b, uint64_t* field) {
    if (!b || !b->enabled) return;
    uint64_t now;
    if ((b->clock ? b->clock : freshness_now_us)(&now) || now == 0) {
        b->clock_error = 1;
        return;
    }
    *field = now;
}

/* The protected action in benchmark mode: its first act is reading the
 * clock, so the end-to-end interval ends where the action would start. */
static void bench_action_callback(void* ctx) {
    benchmark_trace* b = ctx;
    bench_mark(b, &b->action_callback_start_us);
    b->callback_started = 1;
    SST_print_log(
        "SIMULATED_ACTION_STARTED: action=%s (benchmark callback, no "
        "actuator)",
        b->action);
}

/* Names the stage now running; a run that exits during it records it as
 * its error_stage. */
static void bench_stage(benchmark_trace* b, const char* stage) {
    if (b && b->enabled) b->stage = stage;
}

/* Starts timing one check (cooperative requirement or single-device check),
 * returning its slot index, or -1 when off/full. The slot's start is recorded
 * now; bench_check_end fills the rest. */
static int bench_check_begin(benchmark_trace* b, const char* check,
                             const char* method, const char* kind) {
    if (!b || !b->enabled || b->check_count >= BENCH_MAX_CHECKS) return -1;
    int i = b->check_count++;
    bench_check_timing* t = &b->checks[i];
    memset(t, 0, sizeof(*t));
    snprintf(t->check, sizeof(t->check), "%s", check ? check : "");
    snprintf(t->method, sizeof(t->method), "%s", method ? method : "");
    t->kind = kind;
    bench_mark(b, &t->start_us);
    return i;
}

/* Ends the check at `idx`: records its end time and outcome (completed = rc>=0,
 * accepted = rc==1). A no-op for idx<0. */
static void bench_check_end(benchmark_trace* b, int idx, int completed,
                            int accepted) {
    if (!b || !b->enabled || idx < 0 || idx >= b->check_count) return;
    bench_check_timing* t = &b->checks[idx];
    bench_mark(b, &t->end_us);
    t->completed = completed;
    t->accepted = accepted;
}

/* A value that may legitimately be 0, present only when `has`. */
static void json_opt_u64(FILE* f, const char* name, int has, uint64_t v,
                         int last) {
    if (has)
        fprintf(f, "  \"%s\": %llu%s\n", name, (unsigned long long)v,
                last ? "" : ",");
    else
        fprintf(f, "  \"%s\": null%s\n", name, last ? "" : ",");
}

/* A timestamp or duration: 0 means not recorded. */
static void json_u64(FILE* f, const char* name, uint64_t v, int last) {
    if (v)
        fprintf(f, "  \"%s\": %llu%s\n", name, (unsigned long long)v,
                last ? "" : ",");
    else
        fprintf(f, "  \"%s\": null%s\n", name, last ? "" : ",");
}

/* end - start when both were recorded on this clock and are ordered;
 * else 0 (null). `*bad` is set for a recorded but reversed pair. */
static uint64_t bench_span(uint64_t start, uint64_t end, int* bad) {
    if (!start || !end) return 0;
    if (end < start) {
        *bad = 1;
        return 0;
    }
    return end - start;
}

static void json_str(FILE* f, const char* name, const char* v, int last) {
    if (v)
        fprintf(f, "  \"%s\": \"%s\"%s\n", name, v, last ? "" : ",");
    else
        fprintf(f, "  \"%s\": null%s\n", name, last ? "" : ",");
}

/* The cooperative requirements, so the benchmark can summarize the first one
 * present for the legacy single-value fields; per-requirement data is in the
 * checks[] array. */
static const char* const BENCH_COOP_CHECKS[] = {
    "PROXIMITY", "POSITION_IN_REGION", "SHARED_ACOUSTIC_ENVIRONMENT"};
static int bench_is_coop(const char* check) {
    for (size_t i = 0; i < sizeof(BENCH_COOP_CHECKS) / sizeof(*BENCH_COOP_CHECKS);
         ++i)
        if (!strcmp(check, BENCH_COOP_CHECKS[i])) return 1;
    return 0;
}

/* The raw text of the first present cooperative requirement's
 * selectedMethod.parameters, or NULL. Auth's JSON, already tokenized. */
static int bench_plan_parameters(const char* plan, const char** start,
                                 int* len) {
    static plan_json j;
    if (!plan || plan_json_parse(plan, &j)) return -1;
    int checks = plan_json_field(&j, 0, "verificationPlan");
    if (checks < 0) return -1;
    for (size_t k = 0; k < sizeof(BENCH_COOP_CHECKS) / sizeof(*BENCH_COOP_CHECKS);
         ++k) {
        int co = plan_json_field(&j, checks, BENCH_COOP_CHECKS[k]);
        int sel = co < 0 ? -1 : plan_json_field(&j, co, "selectedMethod");
        int params = sel < 0 ? -1 : plan_json_field(&j, sel, "parameters");
        if (params >= 0 && j.t[params].type == '{') {
            *start = j.t[params].start;
            *len = (int)(j.t[params].end - j.t[params].start);
            return 0;
        }
    }
    return -1;
}

static const char* bench_outcome(const action_evidence* e) {
    if (!e) return NULL;
    for (unsigned i = 0; i < e->count; ++i) {
        if (!bench_is_coop(e->entries[i].check)) continue;
        const physical_evidence* ev = &e->entries[i].ev;
        return !ev->complete ? "ABORT" : ev->local_pass ? "PASS" : "FAIL";
    }
    return NULL; /* no cooperative requirement ran (or never got that far) */
}

/* Writes the run's JSON to b->output (via a temporary file, then rename).
 * @return 0, or -1. */
static int bench_write(benchmark_trace* b) {
    if (!b || !b->enabled) return 0;
    char tmp[1024];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", b->output) >= (int)sizeof(tmp))
        return -1;
    FILE* f = fopen(tmp, "w");
    if (!f) {
        SST_print_error("benchmark: cannot write %s", tmp);
        return -1;
    }
    int requester = !strcmp(b->role, "requester");
    int bad = 0;
    uint64_t auth = bench_span(b->authorization_start_us,
                               b->authorization_end_us, &bad);
    uint64_t hs = bench_span(b->peer_handshake_start_us,
                             b->peer_handshake_end_us, &bad);
    uint64_t coop =
        bench_span(b->cooperative_start_us, b->cooperative_end_us, &bad);
    /* Measured directly, never a sum of stages; only for the requester,
     * which runs the operation authorization. */
    uint64_t e2e = requester ? bench_span(b->authorization_start_us,
                                          b->action_callback_start_us, &bad)
                             : 0;

    freshness_plan plan;
    int plan_ok = b->key && !freshness_plan_parse(b->key->challenge, &plan);
    const freshness_check* co = NULL;
    for (unsigned i = 0; plan_ok && i < plan.count; ++i)
        if (!co && bench_is_coop(plan.checks[i].check)) co = &plan.checks[i];

    char key_id[2 * SESSION_KEY_ID_SIZE + 1] = {0};
    for (int i = 0; b->key && i < SESSION_KEY_ID_SIZE; ++i)
        snprintf(key_id + 2 * i, 3, "%02x", b->key->key_id[i]);

    fprintf(f, "{\n");
    json_str(f, "run_id", b->run_id, 0);
    json_str(f, "endpoint_role", b->role, 0);
    json_str(f, "action", b->action, 0);
    json_str(f, "selected_method", co ? co->method : NULL, 0);
    json_str(f, "handshake_transport", b->handshake_transport, 0);
    const char* ps;
    int pl;
    if (b->key && !bench_plan_parameters(b->key->challenge, &ps, &pl))
        fprintf(f, "  \"parameters\": %.*s,\n", pl, ps);
    else
        fprintf(f, "  \"parameters\": null,\n");
    json_u64(f, "freshness_bound_us",
             co ? (uint64_t)co->freshness_ms * 1000u : 0, 0);
    json_str(f, "session_key_id", b->key ? key_id : NULL, 0);
    fprintf(f, "  \"dist_key_loaded_at_init\": %s,\n",
            b->dist_key_loaded_at_init ? "true" : "false");
    fprintf(f, "  \"perm_dist_key_mode\": %d,\n", b->perm_dist_key_mode);

    json_u64(f, "authorization_start_us", b->authorization_start_us, 0);
    json_u64(f, "authorization_end_us", b->authorization_end_us, 0);
    json_u64(f, "peer_handshake_start_us", b->peer_handshake_start_us, 0);
    json_u64(f, "peer_handshake_end_us", b->peer_handshake_end_us, 0);
    json_u64(f, "cooperative_start_us", b->cooperative_start_us, 0);
    json_u64(f, "cooperative_end_us", b->cooperative_end_us, 0);
    json_u64(f, "gate_time_us", b->gate_ran ? b->gate.now_us : 0, 0);
    json_u64(f, "action_callback_start_us", b->action_callback_start_us, 0);
    json_u64(f, "authorization_latency_us", auth, 0);
    json_u64(f, "peer_handshake_latency_us", hs, 0);
    fprintf(f, "  \"local_verification_latency_us\": null,\n");
    json_u64(f, "cooperative_verification_latency_us", coop, 0);
    json_u64(f, "end_to_end_latency_us", e2e, 0);

    /* The CO_LOCATION evidence and its requirement's gate result. */
    const physical_evidence* ev = NULL;
    for (unsigned i = 0; b->evidence && i < b->evidence->count; ++i)
        if (!ev && bench_is_coop(b->evidence->entries[i].check))
            ev = &b->evidence->entries[i].ev;
    json_u64(f, "observed_not_before_us", ev ? ev->observed_not_before_us : 0,
             0);
    json_u64(f, "collection_completed_us",
             ev ? ev->collection_completed_us : 0, 0);
    if (ev)
        fprintf(f, "  \"observation_time_known\": %s,\n",
                ev->observation_time_known ? "true" : "false");
    else
        fprintf(f, "  \"observation_time_known\": null,\n");
    const char* verification = NULL;
    uint64_t age = 0;
    int has_age = 0;
    for (unsigned i = 0; b->gate_ran && i < b->gate.count; ++i) {
        if (verification || !bench_is_coop(b->gate.checks[i].plan.check))
            continue;
        verification =
            b->gate.checks[i].decision == GATE_ALLOW ? "PASS" : "FAIL";
        /* The gate computes an age only once the evidence passed and its
         * times are known and consistent. */
        has_age = b->gate.checks[i].decision == GATE_ALLOW ||
                  b->gate.checks[i].decision == GATE_STALE_EVIDENCE;
        age = b->gate.checks[i].age_us;
    }
    json_opt_u64(f, "evidence_age_us_at_gate", has_age, age, 0);

    json_str(f, "mechanism_outcome", bench_outcome(b->evidence), 0);
    json_str(f, "verification_result", verification, 0);
    json_str(f, "action_decision",
             !b->gate_ran ? NULL
             : b->decision == GATE_ALLOW ? "ALLOW"
                                         : "DENY",
             0);
    json_str(f, "denial_reason",
             b->gate_ran && b->decision != GATE_ALLOW
                 ? gate_decision_name(b->decision)
                 : NULL,
             0);
    fprintf(f, "  \"callback_started\": %s,\n",
            b->callback_started ? "true" : "false");
    fprintf(f, "  \"requirements\": [");
    for (unsigned i = 0; b->gate_ran && i < b->gate.count; ++i) {
        const physical_evidence* e = &b->gate.checks[i].ev;
        fprintf(f,
                "%s{\"check\": \"%s\", \"method\": \"%s\", "
                "\"freshness_bound_us\": %llu, \"evidence_present\": %s, "
                "\"observed_not_before_us\": %llu, "
                "\"conservative_age_us\": %llu, \"denial_reason\": %s%s%s}",
                i ? ", " : "", b->gate.checks[i].plan.check,
                b->gate.checks[i].plan.method,
                (unsigned long long)b->gate.checks[i].plan.freshness_ms * 1000u,
                b->gate.checks[i].present ? "true" : "false",
                (unsigned long long)e->observed_not_before_us,
                (unsigned long long)b->gate.checks[i].age_us,
                b->gate.checks[i].decision == GATE_ALLOW ? "" : "\"",
                b->gate.checks[i].decision == GATE_ALLOW
                    ? "null"
                    : gate_decision_name(b->gate.checks[i].decision),
                b->gate.checks[i].decision == GATE_ALLOW ? "" : "\"");
    }
    fprintf(f, "],\n");
    /* Per-check execution intervals, measured around each verification call on
     * this endpoint's clock. Cooperative requirements and single-device checks
     * are tagged by "kind"; durations null when an endpoint did not time. */
    fprintf(f, "  \"check_timings\": [");
    for (int i = 0; i < b->check_count; ++i) {
        const bench_check_timing* t = &b->checks[i];
        int tbad = 0;
        uint64_t dur = bench_span(t->start_us, t->end_us, &tbad);
        fprintf(f,
                "%s{\"check\": \"%s\", \"method\": \"%s\", \"kind\": \"%s\", "
                "\"start_us\": %llu, \"end_us\": %llu, \"duration_us\": ",
                i ? ", " : "", t->check, t->method, t->kind ? t->kind : "",
                (unsigned long long)t->start_us, (unsigned long long)t->end_us);
        if (dur)
            fprintf(f, "%llu", (unsigned long long)dur);
        else
            fprintf(f, "null");
        fprintf(f, ", \"completed\": %s, \"accepted\": %s}",
                t->completed ? "true" : "false",
                t->accepted ? "true" : "false");
    }
    fprintf(f, "],\n");
    fprintf(f, "  \"observations\": %s,\n",
            b->observations[0] ? b->observations : "null");
    json_str(f, "error_stage", b->error_stage, 0);
    json_str(f, "measurement_status",
             b->clock_error ? "clock_error"
             : bad          ? "inconsistent_timestamps"
                            : "ok",
             1);
    fprintf(f, "}\n");
    int rc = ferror(f) | fclose(f);
    if (rc || rename(tmp, b->output)) {
        SST_print_error("benchmark: cannot write %s", b->output);
        return -1;
    }
    b->written = 1;
    return 0;
}

/* The run's failures exit through SST_print_error_exit(); this still writes
 * the record then, naming the stage that was running. */
static benchmark_trace* bench_active;
static void bench_atexit(void) {
    benchmark_trace* b = bench_active;
    if (!b || !b->enabled || b->written) return;
    if (!b->error_stage) b->error_stage = b->stage ? b->stage : "setup";
    bench_write(b);
}
static void bench_arm(benchmark_trace* b) {
    if (!b->enabled) return;
    bench_active = b;
    atexit(bench_atexit);
}

#endif
