/* Reads the AMBIENT_AUDIO CO_LOCATION method from Auth's verification plan
 * (see physical_com/plan_json.h). */
#include "../physical_com/plan_json.h"
#include "ambient_audio.h"

int ambient_audio_plan_config(const char* plan, ambient_audio_config* c,
                              ambient_audio_identity* id) {
    plan_json j;
    int params;
    if (!c || !id) return -1;
    int rc = plan_co_location(plan, "AMBIENT_AUDIO", &j, &params);
    if (rc != 1) return rc;
    if (params < 0 || j.t[params].type != '{') return -1;
    long recording_ms, threshold_milli, max_lag_ms, min_power_dbfs;
    if (plan_json_int(&j, plan_json_field(&j, params, "recording_ms"), 1000,
                      AMBIENT_AUDIO_RECORDING_MS_LIMIT, &recording_ms) ||
        plan_json_int(&j, plan_json_field(&j, params, "similarity_threshold_milli"),
                      0, AMBIENT_AUDIO_THRESHOLD_MILLI_LIMIT, &threshold_milli) ||
        plan_json_int(&j, plan_json_field(&j, params, "max_lag_ms"), 0,
                      AMBIENT_AUDIO_MAX_LAG_MS_LIMIT, &max_lag_ms) ||
        plan_json_int(&j, plan_json_field(&j, params, "min_power_dbfs"), -120, 0,
                      &min_power_dbfs))
        return -1;
    c->recording_ms = (unsigned)recording_ms;
    c->similarity_threshold_milli = (unsigned)threshold_milli;
    c->max_lag_ms = (unsigned)max_lag_ms;
    c->min_power_dbfs = (int)min_power_dbfs;
    /* A pairwise comparison needs exactly one target, named by Auth. */
    int targets = plan_json_field(&j, 0, "targets");
    if (targets < 0 || j.t[targets].type != '[' ||
        targets + 1 >= j.t[targets].next ||
        j.t[targets + 1].next != j.t[targets].next)
        return -1;
    if (plan_json_name(&j, plan_json_field(&j, 0, "requester"), id->requester,
                       sizeof(id->requester)) ||
        plan_json_name(&j, targets + 1, id->target, sizeof(id->target)))
        return -1;
    return ambient_audio_config_valid(c) ? 1 : -1;
}
