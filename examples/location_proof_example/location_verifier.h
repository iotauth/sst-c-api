#ifndef LOCATION_VERIFIER_H
#define LOCATION_VERIFIER_H
#include <stdbool.h>
/**
 *Defines the structures and interfaces for representing verification
 * requirements, UWB anchor configurations, and authorized location zones.
 */
#include "protocol.h"
#include "verification_policy.h"

bool verify_position_against_policy(double x, double y,
                                    const VerificationPolicy* policy);

#endif
