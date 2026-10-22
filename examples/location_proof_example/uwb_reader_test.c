/**
 * @file uwb_reader_test.c
 * @brief Standalone test for live UWB ranging and multilateration.
 */

#include "uwb_reader.h"

#include <stdio.h>
#include <stdlib.h>

#include "multilateration.h"

int main(void) {
    printf("Opening UWB device: %s\n", UWB_SERIAL_DEVICE);

    int fd = uwb_open();

    if (fd < 0) {
        return EXIT_FAILURE;
    }

    printf("UWB serial connection opened.\n");
    printf("Waiting for four-anchor measurement sets...\n\n");

    while (1) {
        AnchorMeasurement measurements[UWB_ANCHOR_COUNT] = {0};

        if (!uwb_read_measurements(fd, measurements)) {
            fprintf(stderr, "Failed to read UWB measurements.\n");
            uwb_close(fd);
            return EXIT_FAILURE;
        }

        /*
         * Physical anchor coordinates in meters:
         *
         * A3 (0.000, 0.200) -------- A4 (0.588, 0.200)
         *        |                          |
         *        |                          |
         * A1 (0.000, 0.000) -------- A2 (0.588, 0.000)
         */

        measurements[0].x = 0.000;
        measurements[0].y = 0.000;

        measurements[1].x = 0.588;
        measurements[1].y = 0.000;

        measurements[2].x = 0.000;
        measurements[2].y = 0.200;

        measurements[3].x = 0.588;
        measurements[3].y = 0.200;

        printf("UWB measurements:\n");

        for (int i = 0; i < UWB_ANCHOR_COUNT; i++) {
            printf("  Anchor %d: %.2f m\n", measurements[i].id,
                   measurements[i].distance);
        }

        Position position;

        if (!multilaterate(measurements, UWB_ANCHOR_COUNT, &position)) {
            fprintf(stderr, "Multilateration failed.\n\n");
            continue;
        }

        printf("Estimated position: (%.3f, %.3f) m\n\n", position.x,
               position.y);
    }

    uwb_close(fd);

    return EXIT_SUCCESS;
}