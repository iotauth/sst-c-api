/**
 * Provides functionality for checking whether a Robot's position satisfies
 * the location requirements defined by a verification policy.
 */
#include "location_verifier.h"

#include <stddef.h>

bool verify_position_against_policy(double x, double y,
                                    const VerificationPolicy* policy) {
    if (policy == NULL) {
        return false;
    }
    bool inside_x =
        x >= policy->required_zone.x_min && x <= policy->required_zone.x_max;

    bool inside_y =
        y >= policy->required_zone.y_min && y <= policy->required_zone.y_max;

    return inside_x && inside_y;
}
