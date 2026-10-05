/* Reads the ULTRASOUND CO_LOCATION method from Auth's verification plan
 * (see physical_com/plan_json.h). */
#include "../physical_com/plan_json.h"
#include "ultrasonic_echo.h"

int ultrasonic_echo_plan_config(const char* plan, ultrasonic_echo_config* c,
                                ultrasonic_echo_identity* id) {
    plan_json j;
    int params;
    if (!c || !id) return -1;
    int rc = plan_co_location(plan, "ULTRASOUND", &j, &params);
    if (rc != 1) return rc;
    if (params < 0 || j.t[params].type != '{') return -1;
    /* The old ULTRASOUND entry's round/delay fields are not echo settings;
     * a catalog still carrying them is rejected, not reinterpreted. */
    if (plan_json_field(&j, params, "rounds") != -1 ||
        plan_json_field(&j, params, "max_delay_us") != -1 ||
        plan_json_field(&j, params, "success_threshold") != -1)
        return -1;
    long response, timeout;
    if (plan_json_int(&j, plan_json_field(&j, params, "max_response_us"), 1,
                      ULTRASONIC_ECHO_MAX_RESPONSE_US_LIMIT, &response) ||
        plan_json_int(&j, plan_json_field(&j, params, "response_timeout_ms"), 1,
                      ULTRASONIC_ECHO_TIMEOUT_MS_LIMIT, &timeout))
        return -1;
    c->max_response_us = (unsigned)response;
    c->response_timeout_ms = (unsigned)timeout;
    /* A pairwise echo needs exactly one target, named by Auth. */
    int targets = plan_json_field(&j, 0, "targets");
    if (targets < 0 || j.t[targets].type != '[' ||
        targets + 1 >= j.t[targets].next ||
        j.t[targets + 1].next != j.t[targets].next)
        return -1;
    if (plan_json_name(&j, plan_json_field(&j, 0, "requester"), id->requester,
                       sizeof(id->requester)) ||
        plan_json_name(&j, targets + 1, id->target, sizeof(id->target)))
        return -1;
    return ultrasonic_echo_config_valid(c) ? 1 : -1;
}
