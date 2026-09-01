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
    // gripping an item on the floor (purpose index 1: "action":"GRIP_ITEM").
    // Runs first since it needs no peer entity to be reachable.
    session_key_list_t* grip_s_key_list = get_session_key_with_index(ctx, 1, NULL);
    if (grip_s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key_with_index() for GRIP_ITEM.");
    }
    SST_print_log("Received authorization for GRIP_ITEM successfully!");

    if (!execute_verification_plan(grip_s_key_list->s_key[0].challenge)) {
        SST_print_error_exit("Physical presence verification failed for GRIP_ITEM.");
    }
    SST_print_log("GRIP_ITEM authorized: robot may grip the item.");
    free_session_key_list_t(grip_s_key_list);

    // Case 2: interactive action, needs a session key to talk to the Locker.
    // Request session key from Auth server (purpose index 0: "group":"Lockers").
    session_key_list_t* s_key_list = get_session_key_with_index(ctx, 0, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key_with_index() for Locker.");
    }
    SST_print_log("Received session key for Locker successfully!");

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
