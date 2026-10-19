/**
 * @file uwb_reader_test.c
 * @brief Standalone test for live UWB serial ranging.
 */

#include <stdio.h>
#include <stdlib.h>

#include "uwb_reader.h"

int main(void)
{
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

        printf("UWB measurements:\n");

        for (int i = 0; i < UWB_ANCHOR_COUNT; i++) {
            printf(
                "  Anchor %d: %.2f m\n",
                measurements[i].id,
                measurements[i].distance
            );
        }

        printf("\n");
    }

    uwb_close(fd);

    return EXIT_SUCCESS;
}