#include "ambient_audio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

/* TCP control messages (inside SST secure messages): 'A' 'A' version type.
 *  INIT/READY : key_id | recording_ms | threshold_milli | max_lag_ms |
 *               min_power_dbfs (cross-checked, so both sides share the plan).
 *  START      : start_realtime_us (the agreed capture start, initiator-chosen).
 *  AUDIO_BEGIN: total_bytes | chunk_count, announcing one recording transfer.
 *  AUDIO_DATA : one fixed-size chunk; the last is zero-padded and trimmed to
 *               total_bytes on receipt. */
#define MSG_INIT 1
#define MSG_READY 2
#define MSG_START 3
#define MSG_AUDIO_BEGIN 4
#define MSG_AUDIO_DATA 5
#define MSG_HEADER 4
#define MSG_PARAMS_SIZE (MSG_HEADER + SESSION_KEY_ID_SIZE + 4 + 4 + 4 + 4)
#define MSG_START_SIZE (MSG_HEADER + 8)
#define MSG_BEGIN_SIZE (MSG_HEADER + 4 + 4)
/* Plaintext secure messages carry at most MAX_PAYLOAD_LENGTH bytes. */
#define AUDIO_CHUNK 1000u
#define MSG_DATA_SIZE (MSG_HEADER + AUDIO_CHUNK)
/* A recording is mono 16-bit PCM at 48 kHz plus a small WAV header. */
#define AMBIENT_SAMPLE_RATE 48000u
#define AMBIENT_MAX_WAV_BYTES \
    (AMBIENT_AUDIO_RECORDING_MS_LIMIT / 1000u * AMBIENT_SAMPLE_RATE * 2u + 4096u)
/* Each read waits out at most the peer's capture window plus transfer slack. */
#define CONTROL_SLACK_MS 30000u

uint64_t ambient_audio_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

uint64_t ambient_audio_now_realtime_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

const char* ambient_audio_failure_name(ambient_audio_failure f) {
    switch (f) {
        case AMBIENT_AUDIO_OK:
            return "none";
        case AMBIENT_AUDIO_NOT_RUN:
            return "not_run";
        case AMBIENT_AUDIO_RECORD_FAILED:
            return "record_failed";
        case AMBIENT_AUDIO_EXCHANGE_FAILED:
            return "exchange_failed";
        case AMBIENT_AUDIO_COMPARE_FAILED:
            return "compare_failed";
        case AMBIENT_AUDIO_INVALID_INPUT:
            return "invalid_input";
        case AMBIENT_AUDIO_BELOW_THRESHOLD:
            return "below_threshold";
        case AMBIENT_AUDIO_KEY_EXPIRED:
            return "key_expired";
        case AMBIENT_AUDIO_ABORTED:
            return "aborted";
    }
    return "unknown";
}

int ambient_audio_config_valid(const ambient_audio_config* c) {
    return c && c->recording_ms >= 1000u &&
           c->recording_ms <= AMBIENT_AUDIO_RECORDING_MS_LIMIT &&
           c->similarity_threshold_milli <= AMBIENT_AUDIO_THRESHOLD_MILLI_LIMIT &&
           c->max_lag_ms <= AMBIENT_AUDIO_MAX_LAG_MS_LIMIT &&
           c->min_power_dbfs <= 0 && c->min_power_dbfs >= -120;
}

static void put32(unsigned char* p, unsigned v) {
    for (int i = 3; i >= 0; --i) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}

static unsigned get32(const unsigned char* p) {
    unsigned v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | p[i];
    return v;
}

static void put64(unsigned char* p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}

static uint64_t get64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

static void header(unsigned char* m, unsigned char type) {
    m[0] = 'A';
    m[1] = 'A';
    m[2] = AMBIENT_AUDIO_VERSION;
    m[3] = type;
}

static int send_msg(SST_session_ctx_t* s, unsigned char* m, unsigned len) {
    return session_ctl_send(s, m, len);
}

static int recv_msg(SST_session_ctx_t* s, unsigned char type, unsigned char* out,
                    unsigned len) {
    unsigned char prefix[MSG_HEADER];
    header(prefix, type);
    return session_ctl_recv(s, prefix, sizeof(prefix), out, len,
                            "Ambient audio");
}

static void params_msg(unsigned char* m, unsigned char type,
                       const session_key_t* k, const ambient_audio_config* c) {
    header(m, type);
    unsigned char* b = m + MSG_HEADER;
    memcpy(b, k->key_id, SESSION_KEY_ID_SIZE);
    b += SESSION_KEY_ID_SIZE;
    put32(b, c->recording_ms);
    put32(b + 4, c->similarity_threshold_milli);
    put32(b + 8, c->max_lag_ms);
    put32(b + 12, (unsigned)(int32_t)c->min_power_dbfs);
}

/* Reads the whole file into a freshly allocated buffer. @return 0 or -1. */
static int read_file(const char* path, unsigned char** out, unsigned* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END)) {
        fclose(f);
        return -1;
    }
    long n = ftell(f);
    if (n < 0 || n > (long)AMBIENT_MAX_WAV_BYTES || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return -1;
    }
    unsigned char* buf = malloc((size_t)n ? (size_t)n : 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (unsigned)n;
    return 0;
}

static int write_file(const char* path, const unsigned char* buf, unsigned len) {
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    size_t wrote = fwrite(buf, 1, len, f);
    if (fclose(f) || wrote != len) return -1;
    return 0;
}

/* Sends one recording as AUDIO_BEGIN followed by zero-padded fixed chunks. */
static int send_recording(SST_session_ctx_t* s, const char* path) {
    unsigned char* buf = NULL;
    unsigned len = 0;
    if (read_file(path, &buf, &len)) {
        SST_print_error("Ambient audio: could not read this side's recording.");
        return -1;
    }
    unsigned chunks = (len + AUDIO_CHUNK - 1) / AUDIO_CHUNK;
    if (chunks == 0) chunks = 1; /* always send at least an (empty) chunk */
    unsigned char begin[MSG_BEGIN_SIZE];
    header(begin, MSG_AUDIO_BEGIN);
    put32(begin + MSG_HEADER, len);
    put32(begin + MSG_HEADER + 4, chunks);
    int rc = send_msg(s, begin, sizeof(begin));
    for (unsigned i = 0; rc == 0 && i < chunks; ++i) {
        unsigned char msg[MSG_DATA_SIZE];
        header(msg, MSG_AUDIO_DATA);
        unsigned off = i * AUDIO_CHUNK;
        unsigned n = len > off ? len - off : 0;
        if (n > AUDIO_CHUNK) n = AUDIO_CHUNK;
        memcpy(msg + MSG_HEADER, buf + off, n);
        if (n < AUDIO_CHUNK) memset(msg + MSG_HEADER + n, 0, AUDIO_CHUNK - n);
        rc = send_msg(s, msg, sizeof(msg));
    }
    free(buf);
    return rc;
}

/* Receives one recording and writes exactly its announced length to `path`. */
static int recv_recording(SST_session_ctx_t* s, const char* path) {
    unsigned char begin[MSG_BEGIN_SIZE];
    if (recv_msg(s, MSG_AUDIO_BEGIN, begin, sizeof(begin))) return -1;
    unsigned len = get32(begin + MSG_HEADER);
    unsigned chunks = get32(begin + MSG_HEADER + 4);
    unsigned want = len ? (len + AUDIO_CHUNK - 1) / AUDIO_CHUNK : 1;
    if (len > AMBIENT_MAX_WAV_BYTES || chunks != want) {
        SST_print_error("Ambient audio: peer announced an implausible recording "
                        "(%u bytes, %u chunks).",
                        len, chunks);
        return -1;
    }
    unsigned char* buf = malloc((size_t)chunks * AUDIO_CHUNK);
    if (!buf) return -1;
    int rc = 0;
    for (unsigned i = 0; i < chunks; ++i) {
        unsigned char msg[MSG_DATA_SIZE];
        if (recv_msg(s, MSG_AUDIO_DATA, msg, sizeof(msg))) {
            rc = -1;
            break;
        }
        memcpy(buf + (size_t)i * AUDIO_CHUNK, msg + MSG_HEADER, AUDIO_CHUNK);
    }
    if (rc == 0 && write_file(path, buf, len)) {
        SST_print_error("Ambient audio: could not write the peer's recording.");
        rc = -1;
    }
    free(buf);
    return rc;
}

int ambient_audio_run(SST_session_ctx_t* session,
                      const ambient_audio_config* config, int initiator,
                      const ambient_audio_io* io, ambient_audio_result* r) {
    unsigned char mine[MSG_PARAMS_SIZE], theirs[MSG_PARAMS_SIZE];
    char local_path[64], peer_path[64];
    session_ctl_timeout saved = {0};
    int status = -1;
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    r->failure = AMBIENT_AUDIO_NOT_RUN;
    if (!session || session->sock < 0 || !ambient_audio_config_valid(config) ||
        !io || !io->record || !io->compare ||
        session->s_key.mac_key_size != MAC_KEY_SIZE)
        return -1;
    if (!session_key_fresh(&session->s_key)) {
        r->failure = AMBIENT_AUDIO_KEY_EXPIRED;
        return -1;
    }
    snprintf(local_path, sizeof(local_path), "/tmp/ambient_local_%d.wav",
             (int)getpid());
    snprintf(peer_path, sizeof(peer_path), "/tmp/ambient_peer_%d.wav",
             (int)getpid());
    if (session_ctl_timeout_set(
            session->sock, config->recording_ms + CONTROL_SLACK_MS, &saved))
        goto done;

    /* INIT/READY carries the plan parameters so both sides confirm they run
     * the same settings before capturing. */
    params_msg(mine, initiator ? MSG_INIT : MSG_READY, &session->s_key, config);
    if (initiator) {
        if (send_msg(session, mine, sizeof(mine)) ||
            recv_msg(session, MSG_READY, theirs, sizeof(theirs)))
            goto done;
    } else if (recv_msg(session, MSG_INIT, theirs, sizeof(theirs))) {
        goto done;
    }
    if (memcmp(mine + MSG_HEADER, theirs + MSG_HEADER,
               sizeof(mine) - MSG_HEADER)) {
        SST_print_error(
            "Ambient audio: peer's session key ID or parameters differ from "
            "this side's Auth plan.");
        goto done;
    }
    if (!initiator && send_msg(session, mine, sizeof(mine))) goto done;

    /* The initiator picks the shared capture start and announces it; both
     * sides then record the same wall-clock window. */
    uint64_t start_realtime_us;
    unsigned char start_msg[MSG_START_SIZE];
    if (initiator) {
        start_realtime_us = ambient_audio_now_realtime_us() +
                            (uint64_t)AMBIENT_AUDIO_START_DELAY_MS * 1000u;
        header(start_msg, MSG_START);
        put64(start_msg + MSG_HEADER, start_realtime_us);
        if (send_msg(session, start_msg, sizeof(start_msg))) goto done;
    } else {
        if (recv_msg(session, MSG_START, start_msg, sizeof(start_msg))) goto done;
        start_realtime_us = get64(start_msg + MSG_HEADER);
    }

    uint64_t observed_not_before_us = 0;
    if (io->record(io->ctx, start_realtime_us, config->recording_ms, local_path,
                   &observed_not_before_us)) {
        r->failure = AMBIENT_AUDIO_RECORD_FAILED;
        goto done;
    }
    r->observed_not_before_us = observed_not_before_us;

    /* Exchange recordings. The initiator sends first and then receives; the
     * responder receives first and then sends, so neither side blocks. */
    if (initiator) {
        if (send_recording(session, local_path) ||
            recv_recording(session, peer_path))
            goto exchange_failed;
    } else {
        if (recv_recording(session, peer_path) ||
            send_recording(session, local_path))
            goto exchange_failed;
    }

    if (io->compare(io->ctx, local_path, peer_path, config, &r->similarity_milli,
                    &r->inputs_valid, &r->accepted, &r->local_power_dbfs,
                    &r->peer_power_dbfs)) {
        r->failure = AMBIENT_AUDIO_COMPARE_FAILED;
        goto done;
    }
    r->collection_completed_us = ambient_audio_now_us();
    r->local_pass = r->accepted && session_key_fresh(&session->s_key);
    if (!r->inputs_valid)
        r->failure = AMBIENT_AUDIO_INVALID_INPUT;
    else if (!r->accepted)
        r->failure = AMBIENT_AUDIO_BELOW_THRESHOLD;
    else if (!r->local_pass)
        r->failure = AMBIENT_AUDIO_KEY_EXPIRED;
    else
        r->failure = AMBIENT_AUDIO_OK;
    status = r->local_pass;
    goto done;

exchange_failed:
    r->failure = AMBIENT_AUDIO_EXCHANGE_FAILED;
done:
    if (status < 0) {
        r->local_pass = 0;
        if (r->failure == AMBIENT_AUDIO_OK || r->failure == AMBIENT_AUDIO_NOT_RUN)
            r->failure = AMBIENT_AUDIO_ABORTED;
    }
    session_ctl_timeout_restore(session->sock, &saved);
    unlink(local_path);
    unlink(peer_path);
    return status;
}
