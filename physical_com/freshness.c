/* Physical-context freshness gate; see freshness.h. */
#include "freshness.h"

#include <string.h>
#include <time.h>

#include "plan_json.h"
#include "session_ctl.h"

int freshness_now_us(uint64_t* now_us) {
    struct timespec ts;
    if (!now_us || clock_gettime(CLOCK_MONOTONIC, &ts) || ts.tv_sec < 0 ||
        (uint64_t)ts.tv_sec > UINT64_MAX / 1000000u - 1)
        return -1;
    *now_us = (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
    return 0;
}

int freshness_plan_parse(const char* plan, freshness_plan* out) {
    if (!plan || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (!*plan) return 0;
    plan_json j;
    if (plan_json_parse(plan, &j)) return -1;
    int required = plan_json_field(&j, 0, "requiredChecks");
    int checks = plan_json_field(&j, 0, "verificationPlan");
    if (required < 0 || j.t[required].type != '[') return -1;
    for (int i = required + 1; i < j.t[required].next; i = j.t[i].next) {
        if (out->count == FRESHNESS_MAX_CHECKS) return -1;
        freshness_check* c = &out->checks[out->count];
        if (plan_json_name(&j, i, c->check, sizeof(c->check))) return -1;
        for (unsigned k = 0; k < out->count; ++k)
            if (!strcmp(out->checks[k].check, c->check)) return -1;
        int entry = plan_json_field(&j, checks, c->check);
        int selected = plan_json_field(&j, entry, "selectedMethod");
        long ms;
        if (entry < 0 || j.t[entry].type != '{' ||
            plan_json_int(&j, plan_json_field(&j, entry, "freshness_ms"), 1,
                          FRESHNESS_MAX_MS, &ms) ||
            plan_json_name(&j, plan_json_field(&j, selected, "method"),
                           c->method, sizeof(c->method)))
            return -1;
        c->freshness_ms = (unsigned)ms;
        out->count++;
    }
    return 0;
}

static int copy_name(char* out, const char* in) {
    if (!in || !*in || strlen(in) >= FRESHNESS_NAME_SIZE) return -1;
    strcpy(out, in);
    return 0;
}

int action_evidence_init(action_evidence* e, const char* action,
                         const session_key_t* key) {
    if (!e) return -1;
    memset(e, 0, sizeof(*e));
    if (!key || copy_name(e->action, action)) return -1;
    memcpy(e->key_id, key->key_id, SESSION_KEY_ID_SIZE);
    return 0;
}

void action_evidence_invalidate(action_evidence* e, const char* check) {
    if (!e || !check) return;
    for (unsigned i = 0; i < e->count; ++i) {
        if (strcmp(e->entries[i].check, check)) continue;
        e->entries[i] = e->entries[--e->count];
        memset(&e->entries[e->count], 0, sizeof(e->entries[e->count]));
        return;
    }
}

int action_evidence_record(action_evidence* e, const char* check,
                           const char* method, const physical_evidence* ev) {
    /* DUMMY stands in for an unimplemented sensor; it is never evidence. */
    if (!e || !ev || !method || !strcmp(method, "DUMMY")) return -1;
    action_evidence_invalidate(e, check);
    if (e->count == FRESHNESS_MAX_CHECKS) return -1;
    unsigned i = e->count;
    if (copy_name(e->entries[i].check, check) ||
        copy_name(e->entries[i].method, method)) {
        memset(&e->entries[i], 0, sizeof(e->entries[i]));
        return -1;
    }
    e->entries[i].ev = *ev;
    e->count++;
    return 0;
}

const char* gate_decision_name(gate_decision d) {
    switch (d) {
        case GATE_ALLOW:
            return "NONE";
        case GATE_MISSING_EVIDENCE:
            return "MISSING_EVIDENCE";
        case GATE_CHECK_FAILED:
            return "CHECK_FAILED";
        case GATE_ABORTED:
            return "ABORTED";
        case GATE_INVALID_PLAN:
            return "INVALID_PLAN";
        case GATE_UNKNOWN_OBSERVATION_TIME:
            return "UNKNOWN_OBSERVATION_TIME";
        case GATE_CLOCK_ERROR:
            return "CLOCK_ERROR";
        case GATE_STALE_EVIDENCE:
            return "STALE_EVIDENCE";
        case GATE_CONTEXT_MISMATCH:
            return "CONTEXT_MISMATCH";
        case GATE_AUTHORIZATION_EXPIRED:
            return "AUTHORIZATION_EXPIRED";
    }
    return "UNKNOWN";
}

/* One check's decision at now_us. */
static gate_decision judge(const action_evidence* e, const freshness_check* c,
                           uint64_t now_us, int* present,
                           physical_evidence* ev, uint64_t* age_us) {
    if (!strcmp(c->method, "DUMMY")) return GATE_MISSING_EVIDENCE;
    for (unsigned i = 0; i < e->count; ++i) {
        if (strcmp(e->entries[i].check, c->check)) continue;
        if (strcmp(e->entries[i].method, c->method))
            return GATE_MISSING_EVIDENCE;
        *present = 1;
        *ev = e->entries[i].ev;
        break;
    }
    if (!*present) return GATE_MISSING_EVIDENCE;
    if (!ev->complete) return GATE_ABORTED;
    if (!ev->local_pass) return GATE_CHECK_FAILED;
    if (!ev->observation_time_known) return GATE_UNKNOWN_OBSERVATION_TIME;
    if (!ev->observed_not_before_us ||
        ev->collection_completed_us < ev->observed_not_before_us ||
        ev->collection_completed_us > now_us)
        return GATE_CLOCK_ERROR;
    *age_us = now_us - ev->observed_not_before_us;
    return *age_us > (uint64_t)c->freshness_ms * 1000u ? GATE_STALE_EVIDENCE
                                                       : GATE_ALLOW;
}

gate_decision action_gate_evaluate(const session_key_t* key,
                                   const char* action, const action_evidence* e,
                                   uint64_t now_us, gate_report* r) {
    gate_report scratch;
    if (!r) r = &scratch;
    memset(r, 0, sizeof(*r));
    r->now_us = now_us;
    freshness_plan plan;
    if (!key || freshness_plan_parse(key->challenge, &plan))
        return r->decision = GATE_INVALID_PLAN;
    if (!e || !action || strcmp(e->action, action) ||
        memcmp(e->key_id, key->key_id, SESSION_KEY_ID_SIZE))
        return r->decision = GATE_CONTEXT_MISMATCH;
    if (!session_key_fresh(key)) return r->decision = GATE_AUTHORIZATION_EXPIRED;
    r->count = plan.count;
    for (unsigned i = 0; i < plan.count; ++i) {
        r->checks[i].plan = plan.checks[i];
        r->checks[i].decision =
            judge(e, &plan.checks[i], now_us, &r->checks[i].present,
                  &r->checks[i].ev, &r->checks[i].age_us);
        if (r->decision == GATE_ALLOW) r->decision = r->checks[i].decision;
    }
    return r->decision;
}

static const char* predicate_name(int present, const physical_evidence* ev) {
    return !present ? "NONE"
           : !ev->complete ? "ABORTED"
           : ev->local_pass ? "PASS"
                            : "FAIL";
}

static const char* freshness_name(gate_decision d) {
    return d == GATE_ALLOW            ? "PASS"
           : d == GATE_STALE_EVIDENCE ? "STALE"
           : d == GATE_UNKNOWN_OBSERVATION_TIME ? "UNKNOWN"
           : d == GATE_CLOCK_ERROR             ? "CLOCK_ERROR"
                                               : "NOT_EVALUATED";
}

static void log_report(const char* action, const gate_report* r) {
    for (unsigned i = 0; i < r->count; ++i) {
        const physical_evidence* ev = &r->checks[i].ev;
        SST_print_log(
            "ACTION_GATE check: action=%s check=%s selected_method=%s "
            "observation_time_known=%d observed_not_before_us=%llu "
            "collection_completed_us=%llu gate_time_us=%llu "
            "conservative_age_us=%llu freshness_bound_us=%llu predicate=%s "
            "freshness=%s denial_reason=%s",
            action, r->checks[i].plan.check, r->checks[i].plan.method,
            ev->observation_time_known,
            (unsigned long long)ev->observed_not_before_us,
            (unsigned long long)ev->collection_completed_us,
            (unsigned long long)r->now_us,
            (unsigned long long)r->checks[i].age_us,
            (unsigned long long)r->checks[i].plan.freshness_ms * 1000u,
            predicate_name(r->checks[i].present, ev),
            freshness_name(r->checks[i].decision),
            gate_decision_name(r->checks[i].decision));
    }
    SST_print_log("ACTION_GATE %s: action=%s required_checks=%u "
                  "gate_time_us=%llu action_result=%s denial_reason=%s",
                  r->decision == GATE_ALLOW ? "PASS" : "DENY", action,
                  r->count, (unsigned long long)r->now_us,
                  r->decision == GATE_ALLOW ? "STARTED" : "NOT_STARTED",
                  gate_decision_name(r->decision));
}

gate_decision action_gate_run(const session_key_t* key, const char* action,
                              const action_evidence* e, freshness_clock clock,
                              action_callback start, void* start_ctx,
                              gate_report* r) {
    gate_report scratch;
    if (!r) r = &scratch;
    uint64_t now = 0;
    int clock_failed = (clock ? clock : freshness_now_us)(&now) != 0;
    gate_decision d = action_gate_evaluate(key, action, e, now, r);
    if (clock_failed) d = r->decision = GATE_CLOCK_ERROR;
    if (d == GATE_ALLOW) {
        if (start)
            start(start_ctx);
        else
            d = r->decision = GATE_INVALID_PLAN; /* nothing to start */
    }
    /* Logged only after the start: nothing may sit between the decision
     * and the action. */
    log_report(action ? action : "(none)", r);
    return d;
}
