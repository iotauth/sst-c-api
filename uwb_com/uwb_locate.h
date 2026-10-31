#ifndef UWB_LOCATE_H
#define UWB_LOCATE_H

#include <stdint.h>

#include "../src/c_api.h"
#include "uwb_range.h" /* uwb_range_session, uwb_range_radio */

/* UWB absolute-position check (CO_LOCATION method UWB_POSITION), run over the
 * TCP SST session after its handshake. Unlike the mutual UWB proximity check,
 * this localizes the requester: the target carries several fixed anchors (one
 * UWB radio each, at known coordinates) and the requester carries one tag.
 *
 * The target measures and judges: each of its anchors initiates FiRa DS-TWR
 * against the requester's tag (which responds), so the target obtains the
 * per-anchor distances on its own boards, trilaterates the requester's (x, y)
 * in the anchors' plane, and PASSES only when that position is within tolerance
 * of the expected point Auth put in the plan. The requester never measures or
 * judges; it takes the target's authenticated verdict as its own evidence. The
 * target thus verifies the position from its own observations rather than
 * trusting a value the requester computed.
 *
 * Each anchor uses a FiRa session ID and static-STS vupper64 derived from the
 * SST session key and the anchor index, so an anchor ranges only with a tag
 * holding the same session key.
 *
 * Portable: the radios are passed in, so this builds without the hardware. */

#define UWB_LOCATE_VERSION 1
#define UWB_LOCATE_MIN_ANCHORS 3
#define UWB_LOCATE_MAX_ANCHORS 4
#define UWB_LOCATE_COORD_LIMIT 100000 /* |x|,|y| bound, cm */
#define UWB_LOCATE_TOLERANCE_LIMIT 100000

typedef struct {
    int n_anchors;
    int anchor_x_cm[UWB_LOCATE_MAX_ANCHORS];
    int anchor_y_cm[UWB_LOCATE_MAX_ANCHORS];
    int expected_x_cm, expected_y_cm;
    unsigned tolerance_cm;    /* PASS when |solved - expected| <= this */
    unsigned samples;         /* successful ranges needed per anchor */
    unsigned timeout_ms;      /* to collect them, per anchor */
} uwb_locate_config;

typedef struct {
    int ranged[UWB_LOCATE_MAX_ANCHORS];  /* 1 when that anchor gave `samples` */
    int dist_cm[UWB_LOCATE_MAX_ANCHORS]; /* its median, if ranged */
    int solved;                          /* trilateration produced a point */
    int x_cm, y_cm;                      /* the solved position */
    int error_cm;                        /* its distance from expected */
    int local_pass;                      /* every anchor ranged and in range */
    /* CLOCK_MONOTONIC (freshness_now_us) just before the first anchor's
     * ranging started and once the last one stopped; 0 if not reached. */
    uint64_t observed_not_before_us, collection_completed_us;
} uwb_locate_result;

int uwb_locate_config_valid(const uwb_locate_config* c);
/* 1: CO_LOCATION selects UWB_POSITION (config filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int uwb_locate_plan_config(const char* plan, uwb_locate_config* c);
/* FiRa parameters for one anchor, from the session key and anchor index. */
int uwb_locate_session_params(const session_key_t* key, unsigned anchor_index,
                              uwb_range_session* out);
/* Least-squares trilateration of (x, y) from the anchors and `dist_cm`.
 * @return 0 and fills *x_cm,*y_cm, or -1 when the anchors are degenerate. */
int uwb_locate_trilaterate(const uwb_locate_config* c, const int* dist_cm,
                           int* x_cm, int* y_cm);

/* Requester side: responds over `tag_radio` to each anchor in turn while the
 * target ranges it, then takes the target's authenticated verdict and solved
 * position from the DONE report into *r (only `solved`, `local_pass`, `x_cm`,
 * `y_cm`, `error_cm` and the observation window are filled; this side does not
 * measure). @return 1 when the target reported a pass, 0 completed without one,
 * -1 aborted. */
int uwb_locate_run_tag(SST_session_ctx_t* session, const uwb_locate_config* c,
                       const uwb_range_radio* tag_radio, uwb_locate_result* r);
/* Target side: for each anchor, has the tag respond, ranges it over
 * anchor_radios[i], collects the per-anchor medians, trilaterates and judges,
 * then reports its verdict and solved position to the requester. @return 1
 * pass, 0 completed without passing, -1 aborted. */
int uwb_locate_run_anchors(SST_session_ctx_t* session,
                           const uwb_locate_config* c,
                           const uwb_range_radio* const* anchor_radios,
                           uwb_locate_result* r);
#endif
