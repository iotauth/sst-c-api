/* Portable test for the physical-context freshness gate
 * (physical_com/freshness.h). Time is injected (now_us or a fake clock), so
 * nothing here depends on real sleeps. */
#include "../physical_com/freshness.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define T0 1000000000ull /* an arbitrary monotonic time, us */

static const char* plan2(unsigned co_ms, unsigned hp_ms, const char* hp_method) {
    static char plan[MAX_CHALLENGE_LENGTH];
    snprintf(plan, sizeof(plan),
             "{\"requester\":\"r\",\"requiredChecks\":[\"CO_LOCATION\","
             "\"HUMAN_PRESENCE\"],\"verificationPlan\":{\"CO_LOCATION\":{"
             "\"topology\":\"MUTUAL\",\"freshness_ms\":%u,\"selectedMethod\":{"
             "\"method\":\"UWB\",\"parameters\":{\"samples\":20}}},"
             "\"HUMAN_PRESENCE\":{\"topology\":\"LOCAL\",\"freshness_ms\":%u,"
             "\"selectedMethod\":{\"method\":\"%s\",\"parameters\":{}}}}}",
             co_ms, hp_ms, hp_method);
    return plan;
}

static const char* plan1(const char* freshness_ms) {
    static char plan[MAX_CHALLENGE_LENGTH];
    snprintf(plan, sizeof(plan),
             "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{"
             "\"CO_LOCATION\":{\"topology\":\"MUTUAL\",%s\"selectedMethod\":{"
             "\"method\":\"UWB\",\"parameters\":{}}}}}",
             freshness_ms);
    return plan;
}

static session_key_t key_with(const char* plan, unsigned char id) {
    session_key_t k;
    memset(&k, 0, sizeof(k));
    memset(k.key_id, id, SESSION_KEY_ID_SIZE);
    k.abs_validity = UINT64_MAX;
    snprintf(k.challenge, sizeof(k.challenge), "%s", plan);
    return k;
}

/* Passing evidence observed in [at, at + 1 ms]. */
static physical_evidence passing(uint64_t at) {
    return (physical_evidence){1, 1, 1, at, at + 1000};
}

static int started;
static void start(void* ctx) {
    (void)ctx;
    ++started;
}

static uint64_t fake_now;
static int fake_clock(uint64_t* now) {
    *now = fake_now;
    return 0;
}
static int broken_clock(uint64_t* now) {
    (void)now;
    return -1;
}

static void plan_tests(void) {
    freshness_plan p;
    assert(freshness_plan_parse(plan2(10000, 1000, "CAMERA"), &p) == 0);
    assert(p.count == 2 && !strcmp(p.checks[0].check, "CO_LOCATION") &&
           !strcmp(p.checks[0].method, "UWB") &&
           p.checks[0].freshness_ms == 10000 &&
           !strcmp(p.checks[1].method, "CAMERA") &&
           p.checks[1].freshness_ms == 1000);
    assert(freshness_plan_parse(plan1("\"freshness_ms\":1,"), &p) == 0 &&
           p.checks[0].freshness_ms == 1);
    assert(freshness_plan_parse(plan1("\"freshness_ms\":600000,"), &p) == 0);
    /* No required checks: a conventional authorization. */
    assert(freshness_plan_parse("", &p) == 0 && p.count == 0);
    assert(freshness_plan_parse(
               "{\"requiredChecks\":[],\"verificationPlan\":{}}", &p) == 0 &&
           p.count == 0);
    const char* bad_bounds[] = {"",
                                "\"freshness_ms\":0,",
                                "\"freshness_ms\":-1,",
                                "\"freshness_ms\":600001,",
                                "\"freshness_ms\":1000.5,",
                                "\"freshness_ms\":1e3,",
                                "\"freshness_ms\":\"1000\",",
                                "\"freshness_ms\":null,",
                                "\"freshness_ms\":99999999999999999999,",
                                "\"freshness_ms\":1000,\"freshness_ms\":1000,"};
    for (size_t i = 0; i < sizeof(bad_bounds) / sizeof(*bad_bounds); ++i)
        assert(freshness_plan_parse(plan1(bad_bounds[i]), &p) == -1);
    const char* bad_plans[] = {
        "{",
        "[]",
        "{\"verificationPlan\":{}}",
        /* required but no entry */
        "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{}}",
        /* required twice */
        "{\"requiredChecks\":[\"X\",\"X\"],\"verificationPlan\":{\"X\":{"
        "\"freshness_ms\":1,\"selectedMethod\":{\"method\":\"UWB\"}}}}",
        /* no selected method */
        "{\"requiredChecks\":[\"X\"],\"verificationPlan\":{\"X\":{"
        "\"freshness_ms\":1,\"selectedMethod\":null}}}",
        /* duplicate check entry */
        "{\"requiredChecks\":[\"X\"],\"verificationPlan\":{\"X\":{"
        "\"freshness_ms\":1,\"selectedMethod\":{\"method\":\"UWB\"}},\"X\":{"
        "\"freshness_ms\":1,\"selectedMethod\":{\"method\":\"UWB\"}}}}",
        "{\"requiredChecks\":[1],\"verificationPlan\":{}}",
    };
    for (size_t i = 0; i < sizeof(bad_plans) / sizeof(*bad_plans); ++i)
        assert(freshness_plan_parse(bad_plans[i], &p) == -1);
}

/* Evaluates RETRIEVE_ITEM under `k` with CO_LOCATION evidence `co` and,
 * when given, HUMAN_PRESENCE evidence `hp`. */
static gate_decision judge(const session_key_t* k, const physical_evidence* co,
                           const physical_evidence* hp, uint64_t now,
                           gate_report* r) {
    action_evidence e;
    assert(action_evidence_init(&e, "RETRIEVE_ITEM", k) == 0);
    if (co) assert(action_evidence_record(&e, "CO_LOCATION", "UWB", co) == 0);
    if (hp)
        assert(action_evidence_record(&e, "HUMAN_PRESENCE", "CAMERA", hp) == 0);
    return action_gate_evaluate(k, "RETRIEVE_ITEM", &e, now, r);
}

static void decision_tests(void) {
    session_key_t k = key_with(plan2(10000, 1000, "CAMERA"), 7);
    physical_evidence co = passing(T0), hp = passing(T0 + 5000000);
    gate_report r;

    /* All fresh. Exactly at a bound passes; one microsecond more is stale.
     * HUMAN_PRESENCE (1 s) is the binding bound here. */
    assert(judge(&k, &co, &hp, T0 + 5001000, &r) == GATE_ALLOW);
    assert(r.count == 2 && r.checks[0].age_us == 5001000 &&
           r.checks[1].age_us == 1000);
    assert(judge(&k, &co, &hp, T0 + 6000000, &r) == GATE_ALLOW);
    assert(judge(&k, &co, &hp, T0 + 6000001, &r) == GATE_STALE_EVIDENCE);
    assert(r.checks[0].decision == GATE_ALLOW &&
           r.checks[1].decision == GATE_STALE_EVIDENCE);

    /* The earlier check expired while the later one was collected. */
    hp = passing(T0 + 9999000);
    assert(judge(&k, &co, &hp, T0 + 10000000, &r) == GATE_ALLOW);
    assert(judge(&k, &co, &hp, T0 + 10000001, &r) == GATE_STALE_EVIDENCE);
    assert(r.checks[0].decision == GATE_STALE_EVIDENCE &&
           r.checks[1].decision == GATE_ALLOW);

    /* Any missing, failed, aborted or untimed check denies. */
    uint64_t now = T0 + 10000000;
    assert(judge(&k, &co, NULL, now, &r) == GATE_MISSING_EVIDENCE);
    assert(judge(&k, NULL, &hp, now, &r) == GATE_MISSING_EVIDENCE);
    physical_evidence bad = co;
    bad.local_pass = 0;
    assert(judge(&k, &bad, &hp, now, &r) == GATE_CHECK_FAILED);
    bad = co;
    bad.complete = 0;
    bad.local_pass = 0;
    assert(judge(&k, &bad, &hp, now, &r) == GATE_ABORTED);
    /* An RSSI-like reading: the check passed, but how old the value is
     * cannot be told, however recently it was read. */
    bad = passing(now - 1000);
    bad.observation_time_known = 0;
    assert(judge(&k, &bad, &hp, now, &r) == GATE_UNKNOWN_OBSERVATION_TIME);
    /* Inconsistent times: from the future, missing, or reversed. */
    bad = passing(now);
    assert(judge(&k, &bad, &hp, now, &r) == GATE_CLOCK_ERROR);
    bad = co;
    bad.observed_not_before_us = 0;
    assert(judge(&k, &bad, &hp, now, &r) == GATE_CLOCK_ERROR);
    bad = co;
    bad.collection_completed_us = co.observed_not_before_us - 1;
    assert(judge(&k, &bad, &hp, now, &r) == GATE_CLOCK_ERROR);

    /* Evidence from another method than the plan selects does not count. */
    action_evidence e;
    assert(action_evidence_init(&e, "RETRIEVE_ITEM", &k) == 0);
    assert(action_evidence_record(&e, "CO_LOCATION", "WIFI_RSSI", &co) == 0);
    assert(action_evidence_record(&e, "HUMAN_PRESENCE", "CAMERA", &hp) == 0);
    assert(action_gate_evaluate(&k, "RETRIEVE_ITEM", &e, now, &r) ==
           GATE_MISSING_EVIDENCE);

    /* A required DUMMY check can never pass: it has no evidence and none
     * can be recorded for it. */
    session_key_t dummy = key_with(plan2(10000, 1000, "DUMMY"), 7);
    assert(action_evidence_init(&e, "RETRIEVE_ITEM", &dummy) == 0);
    assert(action_evidence_record(&e, "HUMAN_PRESENCE", "DUMMY", &hp) == -1);
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &co) == 0);
    assert(action_gate_evaluate(&dummy, "RETRIEVE_ITEM", &e, now, &r) ==
           GATE_MISSING_EVIDENCE);

    /* No required checks: nothing to wait for. */
    session_key_t plain =
        key_with("{\"requiredChecks\":[],\"verificationPlan\":{}}", 7);
    assert(action_evidence_init(&e, "GRIP_ITEM", &plain) == 0);
    assert(action_gate_evaluate(&plain, "GRIP_ITEM", &e, now, &r) ==
           GATE_ALLOW);

    /* A malformed plan or bound never becomes "no checks". */
    session_key_t broken = key_with(plan1("\"freshness_ms\":0,"), 7);
    assert(action_evidence_init(&e, "RETRIEVE_ITEM", &broken) == 0);
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &co) == 0);
    assert(action_gate_evaluate(&broken, "RETRIEVE_ITEM", &e, now, &r) ==
           GATE_INVALID_PLAN);

    /* Authorization that expired since the checks also denies. */
    session_key_t expired = k;
    expired.abs_validity = 1;
    assert(judge(&expired, &co, &hp, now, &r) == GATE_AUTHORIZATION_EXPIRED);
}

static void context_tests(void) {
    session_key_t k = key_with(plan2(10000, 1000, "CAMERA"), 7);
    physical_evidence co = passing(T0), hp = passing(T0);
    uint64_t now = T0 + 2000;
    action_evidence e;
    assert(action_evidence_init(&e, "RETRIEVE_ITEM", &k) == 0);
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &co) == 0);
    assert(action_evidence_record(&e, "HUMAN_PRESENCE", "CAMERA", &hp) == 0);
    assert(action_gate_evaluate(&k, "RETRIEVE_ITEM", &e, now, NULL) ==
           GATE_ALLOW);
    /* Not for another action, nor another session key (operation). */
    assert(action_gate_evaluate(&k, "GRIP_ITEM", &e, now, NULL) ==
           GATE_CONTEXT_MISMATCH);
    session_key_t other = key_with(plan2(10000, 1000, "CAMERA"), 8);
    assert(action_gate_evaluate(&other, "RETRIEVE_ITEM", &e, now, NULL) ==
           GATE_CONTEXT_MISMATCH);
    /* A new operation under the same key starts with no evidence. */
    action_evidence next;
    assert(action_evidence_init(&next, "RETRIEVE_ITEM", &k) == 0);
    assert(action_gate_evaluate(&k, "RETRIEVE_ITEM", &next, now, NULL) ==
           GATE_MISSING_EVIDENCE);

    /* Re-verification: the earlier PASS is gone before the rerun, so a
     * failed or interrupted rerun cannot leave it behind. */
    action_evidence_invalidate(&e, "CO_LOCATION");
    assert(action_gate_evaluate(&k, "RETRIEVE_ITEM", &e, now, NULL) ==
           GATE_MISSING_EVIDENCE);
    physical_evidence failed = passing(T0 + 500);
    failed.local_pass = 0;
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &failed) == 0);
    assert(action_gate_evaluate(&k, "RETRIEVE_ITEM", &e, now, NULL) ==
           GATE_CHECK_FAILED);
    /* Recording again replaces, never accumulates. */
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &co) == 0);
    assert(e.count == 2);
    assert(action_gate_evaluate(&k, "RETRIEVE_ITEM", &e, now, NULL) ==
           GATE_ALLOW);
}

static void run_tests(void) {
    session_key_t k = key_with(plan1("\"freshness_ms\":1000,"), 7);
    physical_evidence co = passing(T0);
    action_evidence e;
    assert(action_evidence_init(&e, "RETRIEVE_ITEM", &k) == 0);
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &co) == 0);
    gate_report r;

    /* ALLOW starts the action exactly once, at the gate's own time. */
    started = 0;
    fake_now = T0 + 1000000;
    assert(action_gate_run(&k, "RETRIEVE_ITEM", &e, fake_clock, start, NULL,
                           &r) == GATE_ALLOW);
    assert(started == 1 && r.now_us == fake_now);

    /* Any delay before the gate (e.g. --action-test-delay-ms) counts
     * toward the age: one microsecond later it never starts. */
    started = 0;
    fake_now = T0 + 1000001;
    assert(action_gate_run(&k, "RETRIEVE_ITEM", &e, fake_clock, start, NULL,
                           &r) == GATE_STALE_EVIDENCE);
    assert(started == 0);

    /* An unreadable clock denies. */
    assert(action_gate_run(&k, "RETRIEVE_ITEM", &e, broken_clock, start, NULL,
                           &r) == GATE_CLOCK_ERROR);
    assert(started == 0);

    /* The real clock: fresh evidence passes, and the clock moves forward. */
    uint64_t a, b;
    assert(freshness_now_us(&a) == 0);
    co = passing(a);
    co.collection_completed_us = a;
    assert(action_evidence_record(&e, "CO_LOCATION", "UWB", &co) == 0);
    assert(action_gate_run(&k, "RETRIEVE_ITEM", &e, NULL, start, NULL, &r) ==
           GATE_ALLOW);
    assert(started == 1);
    assert(freshness_now_us(&b) == 0 && b >= a);
}

int main(void) {
    plan_tests();
    decision_tests();
    context_tests();
    run_tests();
    puts(
        "Freshness: plan parsing, bounds, denial reasons, context binding, "
        "re-verification and gate run tests passed.");
    return 0;
}
