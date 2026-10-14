#include "location_verifier.h"
#include <stdio.h>

bool verify_location(Zone required_zone){
    /*
    1. Obtain UWB TWR ranges
    2. Trilateration
    3. Determine Current Zone
    4. Compare with zone input
    */
   Zone current_zone = ZONE_A;

    printf("Current zone: %d\n", current_zone);
    printf("Required zone: %d\n", required_zone);

    return current_zone == required_zone;

}

bool verify_position_against_policy(double x, double y, const VerificationPolicy *policy){
    if(policy == NULL){
        return false;
    }
    bool inside_x =
        x >= policy->required_zone.x_min &&
        x <= policy->required_zone.x_max;

    bool inside_y =
        y >= policy->required_zone.y_min &&
        y <= policy->required_zone.y_max;
    printf(
        "[LOCATION] Claimed position: (%.2f, %.2f)\n",
        x,
        y
    );

    printf(
        "[LOCATION] Required zone %s: "
        "x=[%.2f, %.2f], y=[%.2f, %.2f]\n",
        policy->required_zone.name,
        policy->required_zone.x_min,
        policy->required_zone.x_max,
        policy->required_zone.y_min,
        policy->required_zone.y_max
    );

    return inside_x && inside_y;
}