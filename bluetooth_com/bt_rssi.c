/* Mutual Bluetooth RSSI proximity check: plan parsing and the sampling and
 * report exchange over an SST session. */
#include "bt_rssi.h"

#include <stdlib.h>
#include <string.h>

#include "../physical_com/plan_json.h"
#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

int bt_rssi_config_valid(const bt_rssi_config* c) {
    return c && c->min_rssi_dbm >= BT_RSSI_MIN_DBM_LIMIT &&
           c->min_rssi_dbm <= BT_RSSI_MAX_DBM_LIMIT && c->samples >= 1 &&
           c->samples <= BT_RSSI_MAX_SAMPLES &&
           c->interval_ms <= BT_RSSI_MAX_INTERVAL_MS;
}

int bt_rssi_plan_config(const char* plan, bt_rssi_config* c) {
    plan_json j;
    int params;
    if (!c) return -1;
    int rc = plan_co_location(plan, "BLE_RSSI", &j, &params);
    if (rc != 1) return rc;
    if (params < 0 || j.t[params].type != '{') return -1;
    long min_rssi, samples, interval;
    if (plan_json_int(&j, plan_json_field(&j, params, "min_rssi_dbm"),
                      BT_RSSI_MIN_DBM_LIMIT, BT_RSSI_MAX_DBM_LIMIT,
                      &min_rssi) ||
        plan_json_int(&j, plan_json_field(&j, params, "samples"), 1,
                      BT_RSSI_MAX_SAMPLES, &samples) ||
        plan_json_int(&j, plan_json_field(&j, params, "interval_ms"), 0,
                      BT_RSSI_MAX_INTERVAL_MS, &interval))
        return -1;
    c->min_rssi_dbm = (int)min_rssi;
    c->samples = (unsigned)samples;
    c->interval_ms = (unsigned)interval;
    return bt_rssi_config_valid(c) ? 1 : -1;
}

/* REPORT, inside a secure message: 'B' 'R' version | pass | median (i8). */
#define REPORT_SIZE 5
/* Bounds the wait for the peer's report beyond its own sampling time. */
#define CONTROL_SLACK_MS 15000u

static int cmp_i8(const void* a, const void* b) {
    return *(const int8_t*)a - *(const int8_t*)b;
}

static int send_report(SST_session_ctx_t* s, const bt_rssi_result* r) {
    long m = r->median_rssi_dbm < 0 ? (long)(r->median_rssi_dbm - 0.5)
                                    : (long)(r->median_rssi_dbm + 0.5);
    unsigned char msg[REPORT_SIZE] = {'B', 'R', BT_RSSI_VERSION,
                                      (unsigned char)r->local_pass,
                                      (unsigned char)(int8_t)m};
    return session_ctl_send(s, msg, sizeof(msg));
}

static int recv_report(SST_session_ctx_t* s, bt_rssi_result* r) {
    static const unsigned char prefix[] = {'B', 'R', BT_RSSI_VERSION};
    unsigned char msg[REPORT_SIZE];
    if (session_ctl_recv(s, prefix, sizeof(prefix), msg, sizeof(msg),
                         "BLE RSSI") ||
        msg[3] > 1)
        return -1;
    r->peer_reported = 1;
    r->peer_reported_pass = msg[3];
    r->peer_median_rssi_dbm = (int8_t)msg[4];
    return 0;
}

int bt_rssi_run(SST_session_ctx_t* session, const bt_rssi_config* c,
                int initiator, bt_rssi_reader read_rssi, void* reader_ctx,
                bt_rssi_result* r) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!session || session->sock < 0 || !bt_rssi_config_valid(c) || !read_rssi)
        return -1;
    int8_t samples[BT_RSSI_MAX_SAMPLES];
    for (unsigned i = 0; i < c->samples; ++i) {
        if (i && c->interval_ms) session_ctl_sleep_ms(c->interval_ms);
        if (read_rssi(reader_ctx, &samples[i])) {
            SST_print_error("BLE RSSI: reading RSSI failed.");
            return -1;
        }
        r->samples = i + 1;
    }
    qsort(samples, c->samples, sizeof(*samples), cmp_i8);
    unsigned n = c->samples;
    r->median_rssi_dbm =
        n % 2 ? samples[n / 2] : (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
    r->local_pass = r->median_rssi_dbm >= c->min_rssi_dbm;

    /* The peer may still be sampling, for up to as long as this side did. */
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock,
                                c->samples * c->interval_ms + CONTROL_SLACK_MS,
                                &saved))
        return -1;
    int rc = initiator ? send_report(session, r) || recv_report(session, r)
                       : recv_report(session, r) || send_report(session, r);
    session_ctl_timeout_restore(session->sock, &saved);
    if (rc) return -1;
    return r->local_pass ? 1 : 0;
}
