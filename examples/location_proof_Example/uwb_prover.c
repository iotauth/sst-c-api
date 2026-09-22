#include <stdio.h>
#include <string.h>

#include "location_context.h"

static LocationContext currentLocation;

int prover_init(void) { 

    memset(&currentLocation, 0, sizeof(LocationContext));

    currentLocation.valid = true;
    printf("Initialized Prover\n");
    
    return 0;
}

int prover_wait_for_challenge(void){
    return 0;
    //waits until verifier asks for proof
}
//hardcoded for now
//will alter to query UWB later to actually get location
LocationContext prover_get_location(void) { 
    currentLocation.zone = ZONE_RESTRICTED;
    currentLocation.x = 1.5f;
    currentLocation.y = 2.0f;
    currentLocation.timestamp = 4;
    printf("Sending location\n");
    return currentLocation;
}

//send the current location
void prover_send_location(LocationContext *ctx){
    printf("Shutting Down\n");
}

void prover_shutdown(){
    printf("Shutting Down\n");

}



