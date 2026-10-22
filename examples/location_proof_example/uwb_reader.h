/**
 * Interface for reading UWB ranging measurements over serial
 */

#ifndef UWB_READER_H
#define UWB_READER_H

#include <termios.h>

#include "multilateration.h"
// just for rpi for now
#define UWB_SERIAL_DEVICE                                      \
    "/dev/serial/by-id/"                                       \
    "usb-Nordic_Semiconductor_nRF52_USB_Product_C0CD5133BBC8-" \
    "if00" #define UWB_BAUD_RATE B115200
#define UWB_ANCHOR_COUNT 4

/**
 * Opens the UWB tag's serial connection.
 *
 * @return File descriptor on success, -1 on failure.
 */
int uwb_open(void);

/**
 * Reads one complete set of four successful anchor measurements.
 *
 * Only the anchor ID and distance fields are populated. Anchor
 * coordinates will later come from the verification policy.
 *
 * @return true when four measurements were successfully collected.
 */
bool uwb_read_measurements(int fd,
                           AnchorMeasurement measurements[UWB_ANCHOR_COUNT]);

void uwb_close(int fd);

#endif