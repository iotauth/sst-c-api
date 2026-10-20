#ifndef MULTILATERATION_H
#define MULTILATERATION_H

/**
 * Contains the anchor measurement and position structures used to estimate
 * a Robot's location from multiple UWB distance measurements.
 */

#include <stdbool.h>

typedef struct {
    int id;
    double x;
    double y;
    double distance;
} AnchorMeasurement;

typedef struct {
    double x;
    double y;
} Position;

bool multilaterate(const AnchorMeasurement* anchors, int anchor_count,
                   Position* position);

#endif