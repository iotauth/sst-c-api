#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ambient_audio_device.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/c_common.h"

/* ALSA capture format, matching the Python tool's expectation. */
#define AMBIENT_RATE 48000

struct ambient_audio_device {
    char mic[64];
    char cmd[256]; /* Python compare command prefix */
};

ambient_audio_device* ambient_audio_device_open(const char* mic_device) {
    ambient_audio_device* d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    snprintf(d->mic, sizeof(d->mic), "%s",
             mic_device ? mic_device : "plughw:3,0");
    const char* cmd = getenv("AMBIENT_AUDIO_CMD");
    snprintf(d->cmd, sizeof(d->cmd), "%s",
             cmd && *cmd ? cmd : "python3 -m ambient_audio");
    return d;
}

void ambient_audio_device_close(ambient_audio_device* d) { free(d); }

/* Sleeps until the agreed wall-clock start, then records with arecord. The
 * observation lower bound is taken on CLOCK_MONOTONIC just before capture. */
static int device_record(void* ctx, uint64_t start_realtime_us,
                         unsigned duration_ms, const char* out_path,
                         uint64_t* observed_not_before_us) {
    ambient_audio_device* d = ctx;
    struct timespec target = {
        .tv_sec = (time_t)(start_realtime_us / 1000000u),
        .tv_nsec = (long)((start_realtime_us % 1000000u) * 1000u)};
    while (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &target, NULL) == EINTR)
        ;
    *observed_not_before_us = ambient_audio_now_us();
    unsigned seconds = duration_ms / 1000u;
    if (seconds == 0) seconds = 1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "arecord -D %s -f S16_LE -c 1 -r %d -d %u -t wav %s 2>/dev/null",
             d->mic, AMBIENT_RATE, seconds, out_path);
    int rc = system(cmd);
    if (rc != 0) {
        SST_print_error("Ambient audio: arecord failed (device %s).", d->mic);
        return -1;
    }
    return 0;
}

/* Runs the Python compare tool and reads its single result line:
 * "<score_milli> <valid> <accepted> <a_power_dbfs> <b_power_dbfs>". */
static int device_compare(void* ctx, const char* local_path,
                          const char* peer_path, const ambient_audio_config* cfg,
                          int* similarity_milli, int* inputs_valid, int* accepted,
                          int* local_power_dbfs, int* peer_power_dbfs) {
    ambient_audio_device* d = ctx;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "%s score %s %s --threshold %d.%03d --max-lag-ms %u "
             "--min-power-dbfs %d",
             d->cmd, local_path, peer_path,
             cfg->similarity_threshold_milli / 1000,
             cfg->similarity_threshold_milli % 1000, cfg->max_lag_ms,
             cfg->min_power_dbfs);
    FILE* p = popen(cmd, "r");
    if (!p) {
        SST_print_error("Ambient audio: could not run the compare tool.");
        return -1;
    }
    int score = -1, valid = 0, acc = 0, ap = 0, bp = 0;
    int parsed =
        fscanf(p, "%d %d %d %d %d", &score, &valid, &acc, &ap, &bp) == 5;
    int status = pclose(p);
    if (!parsed || status != 0) {
        SST_print_error("Ambient audio: compare tool did not return a result "
                        "(status %d).",
                        status);
        return -1;
    }
    *similarity_milli = score;
    *inputs_valid = valid ? 1 : 0;
    *accepted = acc ? 1 : 0;
    *local_power_dbfs = ap;
    *peer_power_dbfs = bp;
    return 0;
}

void ambient_audio_device_bind(ambient_audio_device* d, ambient_audio_io* io) {
    io->ctx = d;
    io->record = device_record;
    io->compare = device_compare;
}
