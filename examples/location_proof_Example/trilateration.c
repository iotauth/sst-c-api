#include "trilateration.h"

#include <math.h>
#include <stddef.h>

bool multilaterate(const AnchorMeasurement* anchors, int anchor_count,
                   Position* position) {
    if (anchors == NULL || position == NULL) {
        return false;
    }

    if (anchor_count < 3) {
        return false;
    }

    /*
     * Anchor 0 is used as the reference anchor.
     */
    double x1 = anchors[0].x;
    double y1 = anchors[0].y;
    double r1 = anchors[0].distance;

    /*
     * After subtracting the reference circle from
     * every other anchor circle, we get:
     *
     * A_i * x + B_i * y = C_i
     *
     * With 4 anchors, this gives 3 equations for
     * only 2 unknowns (x and y).
     *
     * We solve them using least squares.
     */

    double sum_AA = 0.0;
    double sum_AB = 0.0;
    double sum_BB = 0.0;

    double sum_AC = 0.0;
    double sum_BC = 0.0;

    for (int i = 1; i < anchor_count; i++) {
        double xi = anchors[i].x;
        double yi = anchors[i].y;
        double ri = anchors[i].distance;

        double A = 2.0 * (xi - x1);

        double B = 2.0 * (yi - y1);

        double C = (r1 * r1) - (ri * ri) - (x1 * x1) + (xi * xi) - (y1 * y1) +
                   (yi * yi);

        /*
         * Build A^T A and A^T b.
         *
         * [sum_AA sum_AB] [x]   [sum_AC]
         * [sum_AB sum_BB] [y] = [sum_BC]
         */

        sum_AA += A * A;
        sum_AB += A * B;
        sum_BB += B * B;

        sum_AC += A * C;
        sum_BC += B * C;
    }

    /*
     * Solve the 2x2 least-squares system.
     */
    double denominator = (sum_AA * sum_BB) - (sum_AB * sum_AB);

    /*
     * If this is approximately zero, the anchor
     * geometry does not provide enough independent
     * information for a reliable 2D position.
     */
    if (fabs(denominator) < 0.000001) {
        return false;
    }

    position->x = ((sum_AC * sum_BB) - (sum_AB * sum_BC)) / denominator;

    position->y = ((sum_AA * sum_BC) - (sum_AB * sum_AC)) / denominator;
    // returns only if valid coordinate
    return isfinite(position->x) && isfinite(position->y);
}
