#ifndef UWB_VERIFIER_H
#define UWB_VERIFIER_H

#include <stdbool.h>

#include "location_context.h"

/*
 * Initialize the verifier.
 */
int verifier_init(void);

/*
 * Request a location from the prover.
 *
 * Version 1:
 * Uses a hardcoded provider.
 *
 * Future:
 * Sends a challenge over the
 * UWB communication channel.
 */
LocationContext verifier_request_location(void);

/*
 * Validate a received location.
 *
 * Version 1:
 * Checks only if the location
 * is marked valid.
 *
 * Future:
 * Verify freshness
 * Verify challenge/response
 * Verify zone
 */
bool verifier_validate(LocationContext *ctx);

/*
 * Shut down the verifier.
 */
void verifier_shutdown(void);

#endif