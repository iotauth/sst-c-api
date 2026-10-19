#include "trilateration.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /*
     * Test geometry:
     *
     * A3 (0,2) -------- A4 (2,2)
     *    |                  |
     *    |      TAG         |
     *    |     (1,1)        |
     *    |                  |
     * A1 (0,0) -------- A2 (2,0)
     *
     * The tag is sqrt(2) meters from
     * every anchor.
     */

    AnchorMeasurement anchors[4] = {
        {.id = 1, .x = 0.0, .y = 0.0, .distance = 1.41421356},
        {.id = 2, .x = 2.0, .y = 0.0, .distance = 1.41421356},
        {.id = 3, .x = 0.0, .y = 2.0, .distance = 1.41421356},
        {.id = 4, .x = 2.0, .y = 2.0, .distance = 1.41421356}};

    Position position;

    printf("Running multilateration test...\n\n");

    printf("Anchor measurements:\n");

    for (int i = 0; i < 4; i++) {
        printf("  Anchor %d: position=(%.2f, %.2f), distance=%.3f m\n",
               anchors[i].id, anchors[i].x, anchors[i].y, anchors[i].distance);
    }

    printf("\n");

    if (!multilaterate(anchors, 4, &position)) {
        printf("ERROR: Multilateration failed\n");
        return EXIT_FAILURE;
    }

    printf("Estimated position: (%.3f, %.3f) m\n", position.x, position.y);

    /*
     * We know the expected answer for this test.
     */
    double expected_x = 1.0;
    double expected_y = 1.0;

    double error_x = position.x - expected_x;
    double error_y = position.y - expected_y;

    printf("Expected position:  (%.3f, %.3f) m\n", expected_x, expected_y);

    printf("Error:              (%.6f, %.6f) m\n", error_x, error_y);

    return EXIT_SUCCESS;
}