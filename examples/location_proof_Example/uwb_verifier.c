#include "uwb_prover.h"
#include "uwb_verifier.h"
#include <stdio.h>

int verifier_init(void){
    printf("Initializing Verifier\n");
    return 0;
}

LocationContext verifier_request_location(void){
    printf("Sending Location Request\n");
    return prover_get_location();
}

bool verifier_validate(LocationContext *ctx){
    if(!ctx -> valid){
        printf("Invalid Location\n");
        return false;
    }
    if(ctx->zone != ZONE_A && ctx->zone != ZONE_B){
        printf("Access Denied. Unauthorized Zone.\n");
        return false;
    }
    printf("Location Verified\n");
    switch(ctx->zone) {
        case ZONE_A:
            printf("ZONE_A\n");
            break;

        case ZONE_B:
            printf("ZONE_B\n");
            break;

        case ZONE_RESTRICTED:
            printf("ZONE_RESTRICTED\n");
            break;

        default:
            printf("UNKNOWN\n");
    }
    printf("%.2f ",ctx->x);
    printf("%.2f \n ",ctx->y);
    return true;
}

void verifier_shutdown(void){

    printf("Shutdown\n");
}



