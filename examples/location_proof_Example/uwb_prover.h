#ifndef UWB_PROVER_H
#define UWB_PROVER_H

#include "location_context.h"

/*
 * Initialize the UWB prover.
 *
 * Future:
 * - Configure DW3110
 * - Initialize SPI
 * - Load configuration
 */
int prover_init(void);

/*
 * Returns the prover's current location.
 *
 * Version 1:
 * Returns a hardcoded LocationContext.
 *
 * Future:
 * Returns a location generated from
 * real UWB ranging.
 */
LocationContext prover_get_location(void);

/*
 * Shut down the prover.
 */
void prover_shutdown(void);

#endif