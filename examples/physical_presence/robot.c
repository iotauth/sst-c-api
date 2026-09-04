#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "../../src/c_common.h"

#ifdef HAVE_GGWAVE_TRANSPORT
#include "../../ultrasonic_com/ggwave_sst_handshake.h"
#endif
#ifdef HAVE_IR_TRANSPORT
#include "../../ir_com/ir_sst_handshake.h"
#endif

// Executes one named check's selected verification method from the physical
// presence verification plan received from Auth (e.g. "HUMAN_PRESENCE" or
// "CO_LOCATION"), and reports whether it passed.
//
// This currently only supports the "DUMMY" method, which requires no real
// sensor/actuator interaction and always passes. Real physical mechanisms
// (ultrasonic/IR ranging, camera, thermometer) would be executed here in the
// same way once implemented; any other selected method is treated as not
// implemented and fails closed.
//
// This is separate from the handshake transport decision (which channel
// carries the SST handshake with a target entity, e.g. "TCP" for now):
// secure_connect_to_server() resolves that on its own from the same
// challenge, independently of the checks executed here.
// @param challenge The physical presence verification plan JSON (the whole
// plan, covering every required check).
// @param check_id The check to execute, e.g. "CO_LOCATION". If the plan has
// no such check, this is a no-op success (the action didn't require it).
// @return true if the check passed (or was absent from the plan), false if
// present but failed or its method is not implemented in this demo.
static bool execute_check(const char* challenge, const char* check_id) {
    char check_obj[512];
    if (extract_json_object_value(challenge, check_id, check_obj,
                                  sizeof(check_obj)) != 0) {
        // This check isn't part of the plan; the action didn't require it.
        return true;
    }
    SST_print_log("%s: selected verification method: %s", check_id, check_obj);

    char method[64] = {0};
    if (parse_json_string_value(check_obj, "method", method, sizeof(method)) !=
        0) {
        SST_print_error("%s: plan has no selected method.", check_id);
        return false;
    }

    if (strcmp(method, "DUMMY") == 0) {
        SST_print_log("%s: executing DUMMY method (no sensor required): PASS.",
                      check_id);
        return true;
    }

    SST_print_error(
        "%s: verification method %s is not implemented in this demo.", check_id,
        method);
    return false;
}

// Reads the target locker's entity ID via the robot's camera (e.g., a QR
// code on the locker). Camera-based scanning is not implemented here; this
// simply stands in for it and returns as if "net1.locker1" had been scanned.
// @return The scanned locker's entity name.
static const char* scan_locker_id_from_qr_code(void) { return "net1.locker1"; }

int main(int argc, char* argv[]) {
    const char* comm_type = "tcp";
    const char* mic_device = "plughw:1,0";
    const char* spk_device = "plughw:2,0";
    if (argc < 2) {
        SST_print_error_exit(
            "Usage: %s <config_file_path> [--comm_type tcp|ir|ultrasound] "
            "[--mic <alsa_device>] [--spk <alsa_device>]",
            argv[0]);
    }
    char* config_path = argv[1];
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--comm_type") == 0 && i + 1 < argc) {
            comm_type = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--mic") == 0 && i + 1 < argc) {
            mic_device = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--spk") == 0 && i + 1 < argc) {
            spk_device = argv[i + 1];
            i++;
        }
    }

    // Initialize SST context with configuration file
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    // Case 1: solo action, no target entity. Request authorization for
    // gripping an item on the floor (purpose index 0: "action":"GRIP_ITEM").
    // Runs first since it needs no peer entity to be reachable.
    session_key_list_t* grip_s_key_list =
        get_session_key_with_index(ctx, 0, NULL);
    if (grip_s_key_list == NULL) {
        SST_print_error_exit(
            "Failed get_session_key_with_index() for GRIP_ITEM.");
    }
    SST_print_log("Received authorization for GRIP_ITEM successfully!");

    if (!execute_check(grip_s_key_list->s_key[0].challenge, "HUMAN_PRESENCE")) {
        SST_print_error_exit(
            "Physical presence verification failed for GRIP_ITEM.");
    }
    SST_print_log("GRIP_ITEM authorized: robot may grip the item.");
    free_session_key_list_t(grip_s_key_list);

    // Case 2: interactive action, targeting a specific locker identified at
    // runtime (not known ahead of time, so it can't live in a static config
    // purpose slot). The purpose is built dynamically with the scanned ID.
    const char* target_locker = scan_locker_id_from_qr_code();
    SST_print_log("Scanned locker ID: %s", target_locker);

    char retrieve_purpose[MAX_PURPOSE_LENGTH + 1];
    snprintf(retrieve_purpose, sizeof(retrieve_purpose),
             "{\"action\":\"RETRIEVE_ITEM\",\"target\":\"%s\"}", target_locker);

    session_key_list_t* s_key_list =
        get_session_key_with_purpose(ctx, retrieve_purpose, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit(
            "Failed get_session_key_with_purpose() for RETRIEVE_ITEM.");
    }
    SST_print_log("Received session key for RETRIEVE_ITEM successfully!");

    // Execute each required check in the physical presence verification plan
    // locally, and proceed only when all of them pass (fail-closed). Which
    // handshake transport CO_LOCATION selected (and, for TCP, its connection
    // info) is resolved internally by secure_connect_to_server() below.
    const char* challenge = s_key_list->s_key[0].challenge;
    bool human_presence_ok = execute_check(challenge, "HUMAN_PRESENCE");
    bool co_location_ok = execute_check(challenge, "CO_LOCATION");
    if (!human_presence_ok || !co_location_ok) {
        SST_print_error_exit("Physical presence verification failed.");
    }

    // Securely connect to target Locker server. --comm_type picks the
    // transport for this robot<->Locker handshake only; the session key
    // itself was still obtained from Auth over TCP either way.
    SST_session_ctx_t* session_ctx = NULL;
    if (strcmp(comm_type, "tcp") == 0) {
        session_ctx = secure_connect_to_server(&s_key_list->s_key[0], ctx);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed secure_connect_to_server().");
        }
    } else if (strcmp(comm_type, "ultrasound") == 0) {
#ifdef HAVE_GGWAVE_TRANSPORT
        session_ctx = secure_connect_to_server_via_ggwave(
            &s_key_list->s_key[0], mic_device, spk_device);
        if (session_ctx == NULL) {
            SST_print_error_exit(
                "Failed secure_connect_to_server_via_ggwave().");
        }
        SST_print_log(
            "Robot: GGWAVE handshake with Locker succeeded. (Ongoing secure "
            "messaging over ultrasound is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no ggwave/ALSA support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type ultrasound.");
#endif
    } else if (strcmp(comm_type, "ir") == 0) {
#ifdef HAVE_IR_TRANSPORT
        session_ctx = secure_connect_to_server_via_ir(&s_key_list->s_key[0]);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed secure_connect_to_server_via_ir().");
        }
        SST_print_log(
            "Robot: IR handshake with Locker succeeded. (Ongoing secure "
            "messaging over IR is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no pigpio/IR support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type ir.");
#endif
    } else {
        SST_print_error_exit(
            "Unknown --comm_type '%s'. Expected tcp, ir, or ultrasound.",
            comm_type);
    }

    if (strcmp(comm_type, "tcp") == 0) {
        sleep(1);
        pthread_t thread;
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx);

        // Send secure messages to Locker
        int msg =
            send_secure_message("Robot: Hello Locker!",
                                strlen("Robot: Hello Locker!"), session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(1);

        msg = send_secure_message("Robot: Physical presence verified.",
                                  strlen("Robot: Physical presence verified."),
                                  session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(1);

        pthread_cancel(thread);
        pthread_join(thread, NULL);
    }
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return 0;
}
