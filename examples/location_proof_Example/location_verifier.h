#ifndef LOCATION_VERIFIER_H
#define LOCATION_VERIFIER_H
#include "protocol.h"
#include <stdbool.h>
#include "verification_policy.h"

bool verify_position_against_policy(
    double x, double y, const VerificationPolicy *policy
);

bool verify_location(Zone required_zone);
#endif 
