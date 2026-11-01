#include <stdio.h>
#include <stdlib.h>

#include "../../src/c_api.h"
#include "multilateration.h"
#include "protocol.h"
#include "uwb_reader.h"

#define ANCHOR_WIDTH_M 1.0668
#define ANCHOR_HEIGHT_M 0.5842

static void set_anchor_coordinates(
    AnchorMeasurement measurements[UWB_ANCHOR_COUNT]) {
    measurements[0].x = 0.0;
    measurements[0].y = 0.0;

    measurements[1].x = ANCHOR_WIDTH_M;
    measurements[1].y = 0.0;

    measurements[2].x = 0.0;
    measurements[2].y = ANCHOR_HEIGHT_M;

    measurements[3].x = ANCHOR_WIDTH_M;
    measurements[3].y = ANCHOR_HEIGHT_M;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    const char* config_path = argv[1];

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

    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);

    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }

    printf("[PROVER] Secure connection established\n");

    ActionRequest request = {.msg_type = MSG_ACTION_REQUEST,
                             .action = ACTION_MOVE};

    printf("[PROVER] Sending MOVE request\n");

    int result =
        send_secure_message((char*)&request, sizeof(request), session_ctx);

    if (result < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }

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
     * Open the UWB tag and collect one complete set
     * of measurements from A1-A4.
     */
    int uwb_fd = uwb_open();

    if (uwb_fd < 0) {
        SST_print_error_exit("Failed to open UWB device.");
    }

    printf("[PROVER] Collecting UWB measurements...\n");

    AnchorMeasurement measurements[UWB_ANCHOR_COUNT];

    if (!uwb_read_measurements(uwb_fd, measurements)) {
        uwb_close(uwb_fd);
        SST_print_error_exit("Failed to collect UWB measurements.");
    }

    uwb_close(uwb_fd);

    /*
     * uwb_read_measurements() provides anchor IDs and distances.
     * Supply the known physical coordinates of the testbed.
     */
    set_anchor_coordinates(measurements);

    printf("[PROVER] UWB measurements:\n");

    for (int i = 0; i < UWB_ANCHOR_COUNT; i++) {
        printf("  A%d: %.3f m\n", measurements[i].id,
               measurements[i].distance);
    }

    /*
     * Estimate the Robot's position using four-anchor
     * least-squares multilateration.
     */
    Position position;

    if (!multilaterate(measurements, UWB_ANCHOR_COUNT, &position)) {
        SST_print_error_exit("Multilateration failed.");
    }

    printf("[PROVER] Estimated position: (%.3f, %.3f) m\n", position.x,
           position.y);

    LocationResponse location_response = {
        .msg_type = MSG_LOCATION_RESPONSE,
        .x = position.x,
        .y = position.y};

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

    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}