#ifndef TRILATERATION_H
#define TRILATERATION_H

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