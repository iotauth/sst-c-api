#ifndef PHYSICAL_PRESENCE_QR_IO_H
#define PHYSICAL_PRESENCE_QR_IO_H
#include <stdio.h>
#include <string.h>

#include "../../src/c_common.h"

/* Camera QR scanning (robot) and framebuffer QR display (locker) for the
 * robot--locker discovery step, using command-line tools already on the Pi:
 *   scan:    rpicam-jpeg (capture) + zbarimg (decode)
 *   display: qrencode (render) + fbi (show on /dev/fb0)
 * These are Linux/Pi-only and fail gracefully (returning -1) elsewhere. */

/* True when Auth's plan grants `role` ("requester"/"target") capability `cap`,
 * read from the plan's effectiveCapabilities. This is how the robot confirms
 * Auth actually assigned it a camera before scanning. */
static int plan_grants_capability(const char* challenge, const char* role,
                                  const char* cap) {
    char caps[512], role_obj[512], quoted[64];
    if (extract_json_object_value(challenge, "effectiveCapabilities", caps,
                                  sizeof(caps)) != 0)
        return 0;
    if (extract_json_object_value(caps, role, role_obj, sizeof(role_obj)) != 0)
        return 0;
    snprintf(quoted, sizeof(quoted), "\"%s\"", cap);
    return strstr(role_obj, quoted) != NULL;
}

/* Captures one frame and decodes a QR, writing the payload to `out`. Retries a
 * few times, since a single frame can miss. @return 0 on success, -1 on error. */
static int qr_scan_entity_id(char* out, size_t n) {
    for (int attempt = 1; attempt <= 3; ++attempt) {
        if (system("rpicam-jpeg -o /tmp/robot_qr.jpg -t 1500 --width 1640 "
                   "--height 1232 --nopreview >/dev/null 2>&1") != 0) {
            SST_print_error("QR scan: camera capture failed (attempt %d/3).",
                            attempt);
            continue;
        }
        FILE* p =
            popen("zbarimg --quiet --raw /tmp/robot_qr.jpg 2>/dev/null", "r");
        if (!p) return -1;
        char buf[128] = {0};
        char* got = fgets(buf, sizeof(buf), p);
        pclose(p);
        if (got) {
            buf[strcspn(buf, "\r\n")] = '\0';
            if (buf[0]) {
                snprintf(out, n, "%s", buf);
                return 0;
            }
        }
        SST_print_log("QR scan: no code decoded (attempt %d/3); retrying.",
                      attempt);
    }
    return -1;
}

/* Renders `id` as a QR and shows it on the framebuffer via fbi, detached so the
 * caller keeps running. Needs framebuffer access (user in the `video` group).
 * @return 0 when the viewer was launched, -1 on error. */
static int qr_display_entity_id(const char* id) {
    char cmd[256];
    /* Entity names are controlled config values (e.g. net1.locker1); still, keep
     * this to simple identifier characters so it is safe inside the shell. */
    if (!id || id[0] == '\0' ||
        strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "0123456789._-") != strlen(id)) {
        SST_print_error("QR display: refusing to render unexpected id '%s'.",
                        id ? id : "(null)");
        return -1;
    }
    snprintf(cmd, sizeof(cmd),
             "qrencode -o /tmp/locker_qr.png -s 20 -m 4 '%s' >/dev/null 2>&1",
             id);
    if (system(cmd) != 0) {
        SST_print_error("QR display: qrencode failed for '%s'.", id);
        return -1;
    }
    /* fbi drives the console VT (/dev/tty1), which needs root -- as do the IR
     * and LiFi GPIO mechanisms. Passwordless sudo is assumed on the testbed. */
    system("sudo pkill -x fbi >/dev/null 2>&1");
    if (system("sudo setsid fbi -T 1 -d /dev/fb0 --noverbose "
               "/tmp/locker_qr.png </dev/null >/dev/null 2>&1 &") != 0) {
        SST_print_error(
            "QR display: fbi failed (framebuffer/VT permission?).");
        return -1;
    }
    SST_print_log("QR display: showing '%s' on the framebuffer.", id);
    return 0;
}

#endif
