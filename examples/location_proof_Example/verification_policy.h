#ifndef VERIFICATION_POLICY_H
#define VERIFICATION_POLICY_H
/**
 * Defines the location verification policy and the parsing interface
 * 
 *  Contains the structures used to represent verification requirements,
 * UWB anchor configs, authorized zones, and error margin
 * 
 */
#define MAX_ANCHORS 4

typedef struct {
    int id;
    double x;
    double y;
} AnchorConfig;

typedef struct {
    char name[32];
    double x_min;
    double x_max;
    double y_min;
    double y_max;
} ZoneConfig;

typedef struct {
    char type[32];
    char method[32];
    char ranging_method[32];
    AnchorConfig anchors[MAX_ANCHORS];
    int anchor_count;
    ZoneConfig required_zone;
    double max_error_m;
} VerificationPolicy;

char* load_verification_policy(const char* path);

int parse_verification_policy(const char* json, VerificationPolicy* policy);

void free_verification_policy(char* policy);

#endif
