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

/* Locker-side target-local environment checks read from an ESP32 (MicroPython)
 * that streams one line per second over USB serial, e.g. "TEMP=24.4 HUM=42"
 * (thermistor on GPIO34, DHT11 on GPIO4). Auth provisions each check's
 * threshold in the plan's verificationPlan but keeps it out of requiredChecks,
 * so only the endpoint with the sensor (the locker) enforces it. Fails closed. */

/* Reads one streamed line and parses the number after `prefix` (e.g. "TEMP=" or
 * "HUM="), into *out. @return 0 on success, -1 on error (open/timeout/ERR). */
static int read_esp_field(const char* dev, const char* prefix, double* out) {
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
            char* p = strstr(line, prefix);
            if (p) {
                p += strlen(prefix);
                if (strncmp(p, "ERR", 3) != 0 &&
                    (*p == '-' || *p == '.' || (*p >= '0' && *p <= '9'))) {
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

/* Generic target-local check: reads check `name` from the plan's
 * verificationPlan, confirms its selected method, reads the sensor value after
 * `prefix`, and requires value >= min (from parameter `param`).
 * @return 1 pass (or absent from the plan), 0 fail. */
static int verify_esp_local(const char* challenge, const char* dev,
                            const char* name, const char* method,
                            const char* param, const char* prefix,
                            const char* label, long min_bound, long max_bound) {
    plan_json j;
    char got_method[64] = {0};
    if (!challenge || plan_json_parse(challenge, &j)) {
        SST_print_error("%s: could not parse the plan.", name);
        return 0;
    }
    int vp = plan_json_field(&j, 0, "verificationPlan");
    int ck = vp < 0 ? -1 : plan_json_field(&j, vp, name);
    if (ck < 0) return 1; /* not in the plan: the action did not require it */
    int sm = plan_json_field(&j, ck, "selectedMethod");
    int params = sm < 0 ? -1 : plan_json_field(&j, sm, "parameters");
    long min_val = 0;
    if (sm < 0 || params < 0 ||
        plan_json_name(&j, plan_json_field(&j, sm, "method"), got_method,
                       sizeof(got_method))) {
        SST_print_error("%s: plan has no selected method.", name);
        return 0;
    }
    if (strcmp(got_method, method) != 0) {
        SST_print_error("%s: method %s is not implemented.", name, got_method);
        return 0;
    }
    if (plan_json_int(&j, plan_json_field(&j, params, param), min_bound,
                      max_bound, &min_val)) {
        SST_print_error("%s: plan has no %s.", name, param);
        return 0;
    }
    uint64_t observed_us = 0;
    freshness_now_us(&observed_us);
    double value = 0.0;
    if (read_esp_field(dev, prefix, &value) != 0) {
        SST_print_error("%s: could not read the sensor on %s (fail-closed).",
                        name, dev);
        return 0;
    }
    int pass = value >= (double)min_val;
    SST_print_log(
        "%s: method=%s %s=%.1f min=%ld dev=%s observed_at_us=%llu local=%s", name,
        method, label, value, min_val, dev, (unsigned long long)observed_us,
        pass ? "PASS" : "FAIL");
    return pass ? 1 : 0;
}

/* TEMPERATURE_CHECK (thermistor): value_c >= min_temperature_celsius. */
static int verify_temperature_local(const char* challenge, const char* dev) {
    return verify_esp_local(challenge, dev, "TEMPERATURE_CHECK", "THERMOMETER",
                            "min_temperature_celsius", "TEMP=", "temp_c", -120,
                            1000);
}

/* HUMIDITY_CHECK (DHT11): value_pct >= min_humidity. */
static int verify_humidity_local(const char* challenge, const char* dev) {
    return verify_esp_local(challenge, dev, "HUMIDITY_CHECK", "HUMIDITY",
                            "min_humidity", "HUM=", "humidity_pct", 0, 100);
}

#endif
