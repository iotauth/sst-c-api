#include "verification_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

char* load_verification_policy(const char* path) {
    FILE* file = fopen(path, "rb");

    if (file == NULL) {
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    long size = ftell(file);

    if (size < 0) {
        fclose(file);
        return NULL;
    }

    rewind(file);

    char* buffer = malloc((size_t)size + 1);

    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(buffer, 1, (size_t)size, file);

    fclose(file);

    if (bytes_read != (size_t)size) {
        free(buffer);
        return NULL;
    }

    buffer[size] = '\0';

    return buffer;
}

int parse_verification_policy(const char* json, VerificationPolicy* policy) {
    if (json == NULL || policy == NULL) {
        return -1;
    }

    memset(policy, 0, sizeof(VerificationPolicy));

    cJSON* root = cJSON_Parse(json);

    if (root == NULL) {
        return -1;
    }

    int ret = -1;

    cJSON* verification =
        cJSON_GetObjectItemCaseSensitive(root, "verification");

    if (!cJSON_IsObject(verification)) {
        goto cleanup;
    }

    cJSON* type = cJSON_GetObjectItemCaseSensitive(verification, "type");
    cJSON* method = cJSON_GetObjectItemCaseSensitive(verification, "method");
    cJSON* ranging_method =
        cJSON_GetObjectItemCaseSensitive(verification, "ranging_method");

    if (!cJSON_IsString(type) || !cJSON_IsString(method) ||
        !cJSON_IsString(ranging_method)) {
        goto cleanup;
    }

    if (strcmp(type->valuestring, "location") != 0 ||
        strcmp(method->valuestring, "uwb") != 0 ||
        strcmp(ranging_method->valuestring, "ds_twr") != 0) {
        goto cleanup;
    }

    snprintf(policy->type, sizeof(policy->type), "%s", type->valuestring);

    snprintf(policy->method, sizeof(policy->method), "%s", method->valuestring);

    snprintf(policy->ranging_method, sizeof(policy->ranging_method), "%s",
             ranging_method->valuestring);

    /*
     * Parse UWB anchors.
     */
    cJSON* anchors = cJSON_GetObjectItemCaseSensitive(verification, "anchors");

    if (!cJSON_IsArray(anchors)) {
        goto cleanup;
    }

    int anchor_count = cJSON_GetArraySize(anchors);

    if (anchor_count <= 0 || anchor_count > MAX_ANCHORS) {
        goto cleanup;
    }

    policy->anchor_count = anchor_count;

    for (int i = 0; i < anchor_count; i++) {
        cJSON* anchor = cJSON_GetArrayItem(anchors, i);

        if (!cJSON_IsObject(anchor)) {
            goto cleanup;
        }

        cJSON* id = cJSON_GetObjectItemCaseSensitive(anchor, "id");
        cJSON* x = cJSON_GetObjectItemCaseSensitive(anchor, "x");
        cJSON* y = cJSON_GetObjectItemCaseSensitive(anchor, "y");

        if (!cJSON_IsNumber(id) || !cJSON_IsNumber(x) || !cJSON_IsNumber(y)) {
            goto cleanup;
        }

        policy->anchors[i].id = id->valueint;
        policy->anchors[i].x = x->valuedouble;
        policy->anchors[i].y = y->valuedouble;
    }

    /*
     * Parse required physical zone.
     */
    cJSON* required_zone =
        cJSON_GetObjectItemCaseSensitive(verification, "required_zone");

    if (!cJSON_IsObject(required_zone)) {
        goto cleanup;
    }

    cJSON* zone_name = cJSON_GetObjectItemCaseSensitive(required_zone, "name");
    cJSON* x_min = cJSON_GetObjectItemCaseSensitive(required_zone, "x_min");
    cJSON* x_max = cJSON_GetObjectItemCaseSensitive(required_zone, "x_max");
    cJSON* y_min = cJSON_GetObjectItemCaseSensitive(required_zone, "y_min");
    cJSON* y_max = cJSON_GetObjectItemCaseSensitive(required_zone, "y_max");

    if (!cJSON_IsString(zone_name) || !cJSON_IsNumber(x_min) ||
        !cJSON_IsNumber(x_max) || !cJSON_IsNumber(y_min) ||
        !cJSON_IsNumber(y_max)) {
        goto cleanup;
    }

    snprintf(policy->required_zone.name, sizeof(policy->required_zone.name),
             "%s", zone_name->valuestring);

    policy->required_zone.x_min = x_min->valuedouble;
    policy->required_zone.x_max = x_max->valuedouble;
    policy->required_zone.y_min = y_min->valuedouble;
    policy->required_zone.y_max = y_max->valuedouble;

    if (policy->required_zone.x_min > policy->required_zone.x_max ||
        policy->required_zone.y_min > policy->required_zone.y_max) {
        goto cleanup;
    }

    /*
     * Parse maximum permitted location error.
     */
    cJSON* max_error =
        cJSON_GetObjectItemCaseSensitive(verification, "max_error_m");

    if (!cJSON_IsNumber(max_error)) {
        goto cleanup;
    }

    policy->max_error_m = max_error->valuedouble;

    if (policy->max_error_m < 0.0) {
        goto cleanup;
    }

    double zone_width =
        policy->required_zone.x_max - policy->required_zone.x_min;
    double zone_height =
        policy->required_zone.y_max - policy->required_zone.y_min;

    if (2.0 * policy->max_error_m > zone_width ||
        2.0 * policy->max_error_m > zone_height) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    cJSON_Delete(root);
    return ret;
}

void free_verification_policy_json(char* policy_json) { free(policy_json); }
