#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "../../src/c_common.h"

// Executes the verification plan received from Auth for a physical presence
// check, and reports whether the requester is verified.
//
// This currently only supports the "DUMMY" verification method, which
// requires no real sensor/actuator interaction and always passes. Real
// mechanisms (e.g. ultrasonic/IR ranging, camera, thermometer) would be
// executed here in the same way.
// @param challenge The physical presence verification plan JSON received
// from Auth (session_key_t.challenge).
// @return true if the requester is verified, false otherwise.
static bool execute_verification_plan(const char* challenge) {
    if (challenge == NULL || strlen(challenge) == 0) {
        SST_print_log("No physical presence verification plan specified.");
        return true;
    }

    SST_print_log("Received verification plan: %s", challenge);

    char method[64] = {0};
    if (parse_json_string_value(challenge, "method", method,
                                sizeof(method)) != 0) {
        SST_print_error("Verification plan has no selected method.");
        return false;
    }

    if (strcmp(method, "DUMMY") == 0) {
        SST_print_log(
            "Executing DUMMY verification method (no sensor required): "
            "PASS.");
        return true;
    }

    SST_print_error("Unsupported verification method: %s", method);
    return false;
}

// Reads the target locker's entity ID via the robot's camera (e.g., a QR
// code on the locker). Camera-based scanning is not implemented here; this
// simply stands in for it and returns as if "net1.locker1" had been scanned.
// @return The scanned locker's entity name.
static const char* scan_locker_id_from_qr_code(void) {
    return "net1.locker1";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }
    char* config_path = argv[1];

    // Initialize SST context with configuration file
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    // Case 1: solo action, no target entity. Request authorization for
    // gripping an item on the floor (purpose index 0: "action":"GRIP_ITEM").
    // Runs first since it needs no peer entity to be reachable.
    session_key_list_t* grip_s_key_list = get_session_key_with_index(ctx, 0, NULL);
    if (grip_s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key_with_index() for GRIP_ITEM.");
    }
    SST_print_log("Received authorization for GRIP_ITEM successfully!");

    if (!execute_verification_plan(grip_s_key_list->s_key[0].challenge)) {
        SST_print_error_exit("Physical presence verification failed for GRIP_ITEM.");
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
        SST_print_error_exit("Failed get_session_key_with_purpose() for RETRIEVE_ITEM.");
    }
    SST_print_log("Received session key for RETRIEVE_ITEM successfully!");

    // Execute the physical presence verification plan locally, and proceed
    // only when verified (fail-closed).
    if (!execute_verification_plan(s_key_list->s_key[0].challenge)) {
        SST_print_error_exit("Physical presence verification failed.");
    }

    // Securely connect to target Locker server
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }

    sleep(1);
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread_read_one_each,
                   (void*)session_ctx);

    // Send secure messages to Locker
    int msg = send_secure_message("Robot: Hello Locker!",
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
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return 0;
}
