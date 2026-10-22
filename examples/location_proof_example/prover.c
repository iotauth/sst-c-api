#include <stdio.h>
#include <stdlib.h>

#include "../../src/c_api.h"
#include "protocol.h"

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 4) {
        SST_print_error_exit("Usage: %s <config_file_path> [x y]", argv[0]);
    }

    const char* config_path = argv[1];
    double x = 1.50;
    double y = 0.50;

    if (argc == 4) {
        x = strtod(argv[2], NULL);
        y = strtod(argv[3], NULL);
    }

    SST_ctx_t* ctx = init_SST(config_path);

    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    printf("[PROVER] SST initialized\n");

    session_key_list_t* s_key_list = get_session_key(ctx, NULL);

    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }

    printf("[PROVER] Received session key\n");

    /*
     * Establish secure SST connection
     * with the Resource.
     */
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);

    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }

    printf("[PROVER] Secure connection established\n");

    /*
     * Build action request.
     *
     * The Robot requests a MOVE action.
     * Location requirements are defined by the Resource policy.
     */
    ActionRequest request = {.msg_type = MSG_ACTION_REQUEST,
                             .action = ACTION_MOVE};

    printf("[PROVER] Sending MOVE request\n");

    int result =
        send_secure_message((char*)&request, sizeof(request), session_ctx);

    if (result < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }

    /*
     * Wait for the location request.
     */
    uint8_t message_type;

    if (read_exact_message(session_ctx, &message_type, sizeof(message_type),
                           "LocationRequest") != 0) {
        SST_print_error_exit("Failed to receive LocationRequest.");
    }

    if (message_type != MSG_LOCATION_REQUEST) {
        SST_print_error_exit("Unexpected message type.");
    }

    printf("[PROVER] Resource requested location\n");

    /*
     * Use the supplied prototype location.
     * This will later be replaced by UWB multilateration.
     */

    LocationResponse location_response = {
        .msg_type = MSG_LOCATION_RESPONSE, .x = x, .y = y};

    printf("[PROVER] Current position: (%.2f, %.2f)\n", location_response.x,
           location_response.y);

    result = send_secure_message((char*)&location_response,
                                 sizeof(location_response), session_ctx);

    if (result < 0) {
        SST_print_error_exit("Failed to send location response.");
    }

    printf("[PROVER] Location response sent\n");

    ActionResponse response;

    if (read_exact_message(session_ctx, &response, sizeof(response),
                           "ActionResponse") != 0) {
        SST_print_error_exit("Failed to receive ActionResponse.");
    }

    if (response.msg_type != MSG_ACTION_RESPONSE) {
        SST_print_error_exit("Unexpected message type.");
    }
    if (response.allowed) {
        printf("[PROVER] ACTION ALLOWED\n");
    } else {
        printf("[PROVER] ACTION DENIED\n");
    }

    /*
     * Cleanup.
     */
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}
