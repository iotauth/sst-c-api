#ifndef PHYSICAL_PRESENCE_TEMP_SENSOR_H
#define PHYSICAL_PRESENCE_TEMP_SENSOR_H
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../../physical_com/freshness.h"
#include "../../physical_com/plan_json.h"
#include "../../src/c_common.h"

/* Locker-side local temperature verification. An ESP32 (flashed with
 * MicroPython) reads an analog thermistor on GPIO34 and streams "TEMP=<c>\n"
 * lines over USB serial (default /dev/ttyUSB0). This is a TARGET-LOCAL check:
 * Auth provisions the threshold in the plan's verificationPlan.TEMPERATURE_CHECK
 * but does not put it in requiredChecks, so only the endpoint with the sensor
 * (the locker) enforces it. Fails closed. */

/* Reads one "TEMP=<celsius>" line from the serial device into *out.
 * @return 0 on success, -1 on any error (open/timeout/ERR/parse). */
static int read_temperature_c(const char* dev, double* out) {
    int fd = open(dev, O_RDONLY | O_NOCTTY);
    if (fd < 0) return -1;
    struct termios t;
    if (tcgetattr(fd, &t)) {
        close(fd);
        return -1;
    }
    cfmakeraw(&t);
    cfsetispeed(&t, B115200);
    cfsetospeed(&t, B115200);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 10; /* 1 s inter-read timeout */
    tcsetattr(fd, TCSANOW, &t);

    char line[128];
    size_t len = 0;
    time_t start = time(NULL);
    int found = 0;
    double val = 0.0;
    while (!found && time(NULL) - start < 4) {
        char c;
        int n = read(fd, &c, 1);
        if (n != 1) continue;
        if (c == '\n' || len >= sizeof(line) - 1) {
            line[len] = '\0';
            char* p = strstr(line, "TEMP=");
            if (p) {
                p += 5;
                if (strncmp(p, "ERR", 3) != 0 && (*p == '-' || *p == '.' ||
                                                  (*p >= '0' && *p <= '9'))) {
                    val = atof(p);
                    found = 1;
                }
            }
            len = 0;
        } else if (c != '\r') {
            line[len++] = c;
        }
    }
    close(fd);
    if (!found) return -1;
    *out = val;
    return 0;
}

/* Runs the TEMPERATURE_CHECK target-local verification from Auth's plan.
 * Reads verificationPlan.TEMPERATURE_CHECK.selectedMethod from the plan with the
 * shared bounded tokenizer (so numeric parameters parse correctly).
 * @return 1 pass (or absent from the plan, i.e. not required), 0 fail. */
static int verify_temperature_local(const char* challenge, const char* dev) {
    plan_json j;
    char method[64] = {0};
    if (!challenge || plan_json_parse(challenge, &j)) {
        SST_print_error("TEMPERATURE_CHECK: could not parse the plan.");
        return 0;
    }
    int vp = plan_json_field(&j, 0, "verificationPlan");
    int tc = vp < 0 ? -1 : plan_json_field(&j, vp, "TEMPERATURE_CHECK");
    if (tc < 0) return 1; /* not in the plan: the action did not require it */
    int sm = plan_json_field(&j, tc, "selectedMethod");
    int params = sm < 0 ? -1 : plan_json_field(&j, sm, "parameters");
    long min_i = 0;
    if (sm < 0 || params < 0 ||
        plan_json_name(&j, plan_json_field(&j, sm, "method"), method,
                       sizeof(method))) {
        SST_print_error("TEMPERATURE_CHECK: plan has no selected method.");
        return 0;
    }
    if (strcmp(method, "THERMOMETER") != 0) {
        SST_print_error("TEMPERATURE_CHECK: method %s is not implemented.",
                        method);
        return 0;
    }
    if (plan_json_int(&j, plan_json_field(&j, params, "min_temperature_celsius"),
                      -120, 1000, &min_i)) {
        SST_print_error("TEMPERATURE_CHECK: plan has no min_temperature_celsius.");
        return 0;
    }
    double min_c = (double)min_i;
    uint64_t observed_us = 0;
    freshness_now_us(&observed_us);
    double temp_c = 0.0;
    if (read_temperature_c(dev, &temp_c) != 0) {
        SST_print_error(
            "TEMPERATURE_CHECK: could not read the thermometer on %s "
            "(fail-closed).",
            dev);
        return 0;
    }
    int pass = temp_c >= min_c;
    SST_print_log(
        "TEMPERATURE_CHECK: method=THERMOMETER temp_c=%.1f min_temperature_c=%.1f "
        "dev=%s observed_at_us=%llu local=%s",
        temp_c, min_c, dev, (unsigned long long)observed_us,
        pass ? "PASS" : "FAIL");
    return pass ? 1 : 0;
}

#endif
