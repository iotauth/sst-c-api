/* Portable test for the robot/locker benchmark record (benchmark.h): spans
 * come from one injected clock, the real action gate decides whether the
 * benchmark callback runs, and fields that do not apply stay null. */
#include "benchmark.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint64_t fake_now;
static int fake_fail;
static int fake_clock(uint64_t* now) {
    if (fake_fail) return -1;
    *now = fake_now;
    return 0;
}

static session_key_t key_with_bound(unsigned bound_ms) {
    session_key_t k;
    memset(&k, 0, sizeof(k));
    memset(k.key_id, 0xab, SESSION_KEY_ID_SIZE);
    k.abs_validity = UINT64_MAX;
    snprintf(k.challenge, sizeof(k.challenge),
             "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{"
             "\"CO_LOCATION\":{\"topology\":\"MUTUAL\",\"freshness_ms\":%u,"
             "\"selectedMethod\":{\"method\":\"UWB\",\"parameters\":{"
             "\"samples\":20,\"timeout_ms\":10000}}}}}",
             bound_ms);
    return k;
}

static char json[16384];
static const char* written(benchmark_trace* b) {
    assert(bench_write(b) == 0 && b->written);
    FILE* f = fopen(b->output, "r");
    assert(f);
    size_t n = fread(json, 1, sizeof(json) - 1, f);
    json[n] = 0;
    fclose(f);
    return json;
}

static void has(const char* text, const char* field) {
    if (!strstr(text, field)) {
        fprintf(stderr, "missing %s in\n%s", field, text);
        assert(0);
    }
}

/* One requester run on the fake clock: authorization 1000..1500,
 * handshake 1600..1900, cooperative 2000..5000 with evidence observed from
 * 2100, gate at `gate`. */
static gate_decision run(benchmark_trace* b, const session_key_t* k,
                         action_evidence* e, uint64_t gate, const char* role) {
    memset(b, 0, sizeof(*b));
    b->enabled = 1;
    b->run_id = "test-run";
    b->output = "benchmark_test_output.json";
    b->role = role;
    b->action = !strcmp(role, "requester") ? "RETRIEVE_ITEM" : "LOCKER_OPEN";
    b->handshake_transport = "tcp";
    b->clock = fake_clock;
    fake_now = 1000;
    if (!strcmp(role, "requester")) bench_mark(b, &b->authorization_start_us);
    fake_now = 1500;
    if (!strcmp(role, "requester")) bench_mark(b, &b->authorization_end_us);
    fake_now = 1600;
    bench_mark(b, &b->peer_handshake_start_us);
    fake_now = 1900;
    bench_mark(b, &b->peer_handshake_end_us);
    fake_now = 2000;
    bench_mark(b, &b->cooperative_start_us);
    assert(action_evidence_init(e, b->action, k) == 0);
    physical_evidence ev = {1, 1, 1, 2100, 4900};
    assert(action_evidence_record(e, "CO_LOCATION", "UWB", &ev) == 0);
    fake_now = 5000;
    bench_mark(b, &b->cooperative_end_us);
    b->key = k;
    b->evidence = e;
    fake_now = gate;
    /* The real gate, on the same clock; its callback reads that clock. */
    b->decision = action_gate_run(k, b->action, e, fake_clock,
                                  bench_action_callback, b, &b->gate);
    b->gate_ran = 1;
    return b->decision;
}

int main(void) {
    benchmark_trace b;
    action_evidence e;
    session_key_t k = key_with_bound(10); /* 10 ms = 10000 us */

    /* ALLOW: every span is end - start on one clock; end-to-end runs from
     * the authorization start to the callback, measured, not summed. */
    assert(run(&b, &k, &e, 12100, "requester") == GATE_ALLOW);
    assert(b.callback_started && b.action_callback_start_us == 12100);
    const char* j = written(&b);
    has(j, "\"authorization_latency_us\": 500,");
    has(j, "\"peer_handshake_latency_us\": 300,");
    has(j, "\"cooperative_verification_latency_us\": 3000,");
    has(j, "\"end_to_end_latency_us\": 11100,");
    has(j, "\"local_verification_latency_us\": null,");
    has(j, "\"gate_time_us\": 12100,");
    has(j, "\"evidence_age_us_at_gate\": 10000,");
    has(j, "\"freshness_bound_us\": 10000,");
    has(j, "\"parameters\": {\"samples\":20,\"timeout_ms\":10000},");
    has(j, "\"mechanism_outcome\": \"PASS\",");
    has(j, "\"verification_result\": \"PASS\",");
    has(j, "\"action_decision\": \"ALLOW\",");
    has(j, "\"denial_reason\": null,");
    has(j, "\"session_key_id\": \"abababababababab\",");
    has(j, "\"measurement_status\": \"ok\"");

    /* One microsecond past the bound: the mechanism passed, but the
     * evidence is stale, so the gate denies and the callback never runs. */
    assert(run(&b, &k, &e, 12101, "requester") == GATE_STALE_EVIDENCE);
    assert(!b.callback_started && b.action_callback_start_us == 0);
    j = written(&b);
    has(j, "\"mechanism_outcome\": \"PASS\",");
    has(j, "\"verification_result\": \"FAIL\",");
    has(j, "\"action_decision\": \"DENY\",");
    has(j, "\"denial_reason\": \"STALE_EVIDENCE\",");
    has(j, "\"action_callback_start_us\": null,");
    has(j, "\"end_to_end_latency_us\": null,");
    has(j, "\"callback_started\": false,");

    /* The locker runs no operation authorization: those spans are null,
     * not 0, even when its own action is allowed. */
    assert(run(&b, &k, &e, 6000, "locker") == GATE_ALLOW);
    j = written(&b);
    has(j, "\"authorization_latency_us\": null,");
    has(j, "\"end_to_end_latency_us\": null,");
    has(j, "\"cooperative_verification_latency_us\": 3000,");
    has(j, "\"action_callback_start_us\": 6000,");

    /* A failed clock read leaves the field null and marks the run. */
    memset(&b, 0, sizeof(b));
    b.enabled = 1;
    b.run_id = "test-run";
    b.output = "benchmark_test_output.json";
    b.role = "requester";
    b.action = "RETRIEVE_ITEM";
    b.clock = fake_clock;
    fake_now = 10;
    bench_mark(&b, &b.authorization_start_us);
    fake_fail = 1;
    bench_mark(&b, &b.authorization_end_us);
    fake_fail = 0;
    assert(b.clock_error && b.authorization_end_us == 0);
    j = written(&b);
    has(j, "\"authorization_end_us\": null,");
    has(j, "\"authorization_latency_us\": null,");
    has(j, "\"mechanism_outcome\": null,");
    has(j, "\"action_decision\": null,");
    has(j, "\"measurement_status\": \"clock_error\"");

    /* Reversed timestamps are never turned into a duration. */
    memset(&b, 0, sizeof(b));
    b.enabled = 1;
    b.run_id = "test-run";
    b.output = "benchmark_test_output.json";
    b.role = "requester";
    b.action = "RETRIEVE_ITEM";
    b.cooperative_start_us = 500;
    b.cooperative_end_us = 400;
    j = written(&b);
    has(j, "\"cooperative_verification_latency_us\": null,");
    has(j, "\"measurement_status\": \"inconsistent_timestamps\"");

    /* Off: no clock reads, nothing written. */
    memset(&b, 0, sizeof(b));
    bench_mark(&b, &b.authorization_start_us);
    assert(b.authorization_start_us == 0 && bench_write(&b) == 0);

    remove("benchmark_test_output.json");
    puts(
        "Benchmark: spans on one clock, gate-controlled callback, stale "
        "evidence, null locker spans, clock failure and reversed timestamps "
        "tests passed.");
    return 0;
}
