#include "uwb_prover.h"
#include "uwb_verifier.h"

int main(void) {
    prover_init();
    verifier_init();

    LocationContext ctx = verifier_request_location();

    verifier_validate(&ctx);
    verifier_shutdown();
    prover_shutdown();
    return 0;
}