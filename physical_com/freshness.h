#ifndef PHYSICAL_FRESHNESS_H
#define PHYSICAL_FRESHNESS_H
#include <stdint.h>

#include "../src/c_api.h"

/* Physical-context freshness: a protected action may start only while the
 * physical evidence behind every check its plan requires is still young
 * enough. Auth's plan gives each required check a bound, freshness_ms; at
 * the moment the action would start, the gate requires for every one
 *     0 <= now - observed_not_before <= freshness_ms
 * where observed_not_before precedes every physical observation the check's
 * verdict used. Ages are therefore conservative (never under-estimated).
 *
 * All times are this endpoint's own CLOCK_MONOTONIC in microseconds; no peer
 * timestamp is ever used. CLOCK_MONOTONIC stops while the system is
 * suspended, so suspending between a check and its action is unsupported. */

#define FRESHNESS_MAX_MS 600000u /* same limit as Auth */
#define FRESHNESS_MAX_CHECKS 8
#define FRESHNESS_NAME_SIZE 32

/* @return 0 with *now_us set, or -1 when the clock cannot be read. */
int freshness_now_us(uint64_t* now_us);
typedef int (*freshness_clock)(uint64_t* now_us);

/* One check's local result, as the gate sees it. */
typedef struct {
    int complete;   /* the check ran to a verdict (0: aborted) */
    int local_pass; /* this side's own physical condition held */
    /* 1 only when observed_not_before_us is a guaranteed lower bound of
     * every observation used (e.g. not a cached RSSI of unknown age). */
    int observation_time_known;
    uint64_t observed_not_before_us;
    uint64_t collection_completed_us; /* for logs and consistency only */
} physical_evidence;

/* A required check as Auth's plan states it. */
typedef struct {
    char check[FRESHNESS_NAME_SIZE];  /* e.g. "CO_LOCATION" */
    char method[FRESHNESS_NAME_SIZE]; /* selectedMethod.method */
    unsigned freshness_ms;            /* 1..FRESHNESS_MAX_MS */
} freshness_check;

typedef struct {
    unsigned count;
    freshness_check checks[FRESHNESS_MAX_CHECKS];
} freshness_plan;

/* Reads every entry of `requiredChecks`, each of which must have a
 * verificationPlan entry with a selectedMethod.method and an integer
 * freshness_ms in range. An empty plan string means no required checks.
 * @return 0, or -1 when malformed (never "no checks"). */
int freshness_plan_parse(const char* plan, freshness_plan* out);

/* The evidence collected for one operation: one action under one session
 * key. Start a new one per operation, even when a key is reused, so
 * evidence never carries over to another operation, action or session. */
typedef struct {
    char action[FRESHNESS_NAME_SIZE];
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    unsigned count;
    struct {
        char check[FRESHNESS_NAME_SIZE];
        char method[FRESHNESS_NAME_SIZE];
        physical_evidence ev;
    } entries[FRESHNESS_MAX_CHECKS];
} action_evidence;

/* @return 0, or -1 for a bad action name. */
int action_evidence_init(action_evidence* e, const char* action,
                         const session_key_t* key);
/* Drops `check`'s evidence; call before (re)running it, so a failed rerun
 * cannot leave an earlier PASS behind. */
void action_evidence_invalidate(action_evidence* e, const char* check);
/* Stores `check`'s evidence from `method`, replacing any earlier one.
 * @return 0, or -1 when names are bad or the store is full. */
int action_evidence_record(action_evidence* e, const char* check,
                           const char* method, const physical_evidence* ev);

typedef enum {
    GATE_ALLOW = 0,
    GATE_MISSING_EVIDENCE,  /* no evidence from the selected method */
    GATE_CHECK_FAILED,      /* physical condition not met */
    GATE_ABORTED,           /* the check never reached a verdict */
    GATE_INVALID_PLAN,      /* plan or bound unusable */
    GATE_UNKNOWN_OBSERVATION_TIME,
    GATE_CLOCK_ERROR,       /* clock unreadable or inconsistent times */
    GATE_STALE_EVIDENCE,    /* older than the bound */
    GATE_CONTEXT_MISMATCH,  /* evidence of another operation */
    GATE_AUTHORIZATION_EXPIRED,
} gate_decision;

const char* gate_decision_name(gate_decision d);

typedef struct {
    gate_decision decision; /* the first denial in requiredChecks order */
    uint64_t now_us;        /* one gate time for every check */
    unsigned count;
    struct {
        freshness_check plan;
        int present;
        physical_evidence ev;
        uint64_t age_us; /* when computable */
        gate_decision decision;
    } checks[FRESHNESS_MAX_CHECKS];
} gate_report;

/* Pure decision at gate time now_us, against the plan in key->challenge.
 * Allows only when the key is still valid, `e` belongs to this action and
 * key, and every required check has complete, passing evidence from its
 * selected method with a known observation time no older than its bound
 * (equal to the bound passes; one microsecond more is stale). */
gate_decision action_gate_evaluate(const session_key_t* key,
                                   const char* action, const action_evidence* e,
                                   uint64_t now_us, gate_report* report);

typedef void (*action_callback)(void* ctx);

/* Reads `clock` (freshness_now_us when NULL), evaluates, and on ALLOW calls
 * `start` immediately, with nothing in between; then logs the decision for
 * every check. Never caches a decision: call it right before each start.
 * @return the decision; `start` ran exactly when it is GATE_ALLOW. */
gate_decision action_gate_run(const session_key_t* key, const char* action,
                              const action_evidence* e, freshness_clock clock,
                              action_callback start, void* start_ctx,
                              gate_report* report);

#endif
