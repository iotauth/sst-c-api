#ifndef LOCATION_VERIFIER_H
#define LOCATION_VERIFIER_H

/**
 * Checks a claimed position against the required zone of a
 * VerificationPolicy.
 */

#include <stdbool.h>

#include "verification_policy.h"

bool verify_position_against_policy(double x, double y,
                                    const VerificationPolicy* policy);

#endif