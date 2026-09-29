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