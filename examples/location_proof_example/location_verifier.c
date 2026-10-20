
#include "location_verifier.h"

#include <stddef.h>

bool verify_position_against_policy(double x, double y,
                                    const VerificationPolicy* policy) {
    if (policy == NULL) {
        return false;
    }
    double x_min = policy->required_zone.x_min + policy->max_error_m;
    double x_max = policy->required_zone.x_max - policy->max_error_m;
    double y_min = policy->required_zone.y_min + policy->max_error_m;
    double y_max = policy->required_zone.y_max - policy->max_error_m;

    bool inside_x = x >= x_min && x <= x_max;
    bool inside_y = y >= y_min && y <= y_max;

    return inside_x && inside_y;
}
