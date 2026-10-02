#ifndef UWB_CLI_DEV_H
#define UWB_CLI_DEV_H

#include "uwb_range.h"

/* A Qorvo DWM3001CDK running the DW3_QM33_SDK CLI firmware (FiRa INITF/
 * RESPF), driven over its nRF52 USB serial port (J20), as the radio for
 * uwb_range_run(). Both sides use initiator address 0 and responder
 * address 1; the session ID and vupper64 come from uwb_range_session. */
typedef struct uwb_cli uwb_cli;

/* device: a serial port path, or NULL for the single
 * /dev/serial/by-id/usb-Nordic_Semiconductor_nRF52_USB_Product_* port.
 * Stops any ranging left running. @return NULL on failure. */
uwb_cli* uwb_cli_open(const char* device);
void uwb_cli_close(uwb_cli* cli);
void uwb_cli_bind(uwb_cli* cli, uwb_range_radio* radio);

#endif
