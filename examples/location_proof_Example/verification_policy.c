#include "verification_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

char *load_verification_policy(const char *path){
    FILE *file = fopen(path, "rb");

    if(file == NULL){
        return NULL;
    }

    if(fseek(file, 0, SEEK_END) != 0){
        fclose(file);
        return NULL;
    }

    long size = ftell(file);

    if(size < 0){
        fclose(file);
        return NULL;
    }

    rewind(file);

    char *buffer = malloc((size_t)size + 1);

    if(buffer == NULL){
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(buffer, 1, (size_t)size, file);

    fclose(file);

    if(bytes_read != (size_t)size){
        free(buffer);
        return NULL;
    }

    buffer[size] = '\0';

    return buffer;
}
int parse_verification_policy(const char *json, VerificationPolicy *policy){
    if(json == NULL || policy == NULL){
        return -1;
    }
    memset(policy, 0, sizeof(VerificationPolicy));

    cJSON *root = cJSON_Parse(json);
    if(root == NULL){
        return -1;
    }

    cJSON *verification = cJSON_GetObjectItemCaseSensitive(root, "verification");

    if(!cJSON_IsObject(verification)){
        cJSON_Delete(root);
        return -1;
    }
        cJSON *type =
        cJSON_GetObjectItemCaseSensitive(
            verification,
            "type"
        );

    cJSON *method =
        cJSON_GetObjectItemCaseSensitive(
            verification,
            "method"
        );

    cJSON *ranging_method =
        cJSON_GetObjectItemCaseSensitive(
            verification,
            "ranging_method"
        );

    if (!cJSON_IsString(type) ||
        !cJSON_IsString(method) ||
        !cJSON_IsString(ranging_method)) {

        cJSON_Delete(root);
        return -1;
    }
        snprintf(
        policy->type,
        sizeof(policy->type),
        "%s",
        type->valuestring
    );

    snprintf(
        policy->method,
        sizeof(policy->method),
        "%s",
        method->valuestring
    );

    snprintf(
        policy->ranging_method,
        sizeof(policy->ranging_method),
        "%s",
        ranging_method->valuestring
    );
    cJSON_Delete(root);
    return 0;
}
void free_verification_policy(char *policy){
    free(policy);
}