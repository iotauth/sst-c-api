#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "location_verifier.h"
#include "protocol.h"
#include "verification_policy.h"

/* Must match entity.server.port.number in robot_arm.config. */
#define PORT_NUM 21100

int main(int argc, char* argv[]) {
    if (argc != 3) {
        SST_print_error_exit(
            "Usage: %s <config_file_path> <verification_policy_path>", argv[0]);
    }

    const char* config_path = argv[1];
    const char* policy_path = argv[2];

    SST_ctx_t* ctx = init_SST(config_path);

    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    char* verification_policy = load_verification_policy(policy_path);

    if (verification_policy == NULL) {
        SST_print_error_exit("Failed to load verification policy.");
    }

    VerificationPolicy policy;

    if (parse_verification_policy(verification_policy, &policy) != 0) {
        free_verification_policy_json(verification_policy);
        SST_print_error_exit("Failed to parse verification policy.");
    }

    printf("[RESOURCE] Verification policy loaded\n");

    int serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        SST_print_error_exit("socket() error in %s", __FILE__);
    }

    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        SST_print_error_exit("setsockopt() failed.");
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT_NUM);

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        SST_print_error_exit("bind() error in %s", __FILE__);
    }

    if (listen(serv_sock, 5) == -1) {
        SST_print_error_exit("listen() error in %s", __FILE__);
    }

    printf("[RESOURCE] Waiting for connection on port %d...\n", PORT_NUM);

    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);

    int clnt_sock =
        accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

    if (clnt_sock == -1) {
        SST_print_error_exit("accept() error in %s", __FILE__);
    }

    printf("[RESOURCE] TCP connection accepted\n");

    printf(
        "[RESOURCE] Parsed verification policy:\n"
        "  Type: %s\n"
        "  Method: %s\n"
        "  Ranging method: %s\n"
        "  Anchors: %d\n",
        policy.type, policy.method, policy.ranging_method, policy.anchor_count);

    for (int i = 0; i < policy.anchor_count; i++) {
        printf("  Anchor %d: (%.2f, %.2f)\n", policy.anchors[i].id,
               policy.anchors[i].x, policy.anchors[i].y);
    }

    printf(
        "  Required zone: %s\n"
        "  X bounds: %.2f - %.2f\n"
        "  Y bounds: %.2f - %.2f\n"
        "  Maximum error: %.2f m\n",
        policy.required_zone.name, policy.required_zone.x_min,
        policy.required_zone.x_max, policy.required_zone.y_min,
        policy.required_zone.y_max, policy.max_error_m);

    session_key_list_t* s_key_list = init_empty_session_key_list();

    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);

    if (session_ctx == NULL) {
        SST_print_error_exit("Failed server_secure_comm_setup().");
    }

    printf("[RESOURCE] Secure SST session established\n");

    ActionRequest request;

    if (read_exact_message(session_ctx, &request, sizeof(request),
                           "ActionRequest") != 0) {
        SST_print_error_exit("Failed to receive ActionRequest.");
    }

    if (request.msg_type != MSG_ACTION_REQUEST) {
        SST_print_error_exit("Unexpected message type.");
    }

    /* Only ACTION_MOVE is currently supported. */
    if (request.action != ACTION_MOVE) {
        printf("[RESOURCE] Unsupported action: %u\n", request.action);

        ActionResponse response = {.msg_type = MSG_ACTION_RESPONSE,
                                   .allowed = 0};

        int result = send_secure_message((char*)&response, sizeof(response),
                                         session_ctx);

        if (result < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }

        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        free_verification_policy_json(verification_policy);

        close(clnt_sock);
        close(serv_sock);

        free_SST_ctx_t(ctx);

        return EXIT_FAILURE;
    }

    printf("[RESOURCE] Received MOVE request\n");

    uint8_t location_request = MSG_LOCATION_REQUEST;

    int result = send_secure_message((char*)&location_request,
                                     sizeof(location_request), session_ctx);

    if (result < 0) {
        SST_print_error_exit("Failed to send location request.");
    }

    printf("[RESOURCE] Location requested\n");

    LocationResponse location_response;

    if (read_exact_message(session_ctx, &location_response,
                           sizeof(location_response),
                           "LocationResponse") != 0) {
        SST_print_error_exit("Failed to receive LocationResponse.");
    }

    if (location_response.msg_type != MSG_LOCATION_RESPONSE) {
        SST_print_error_exit("Unexpected message type.");
    }

    printf(
        "[RESOURCE] Robot claims position: "
        "(%.2f, %.2f)\n",
        location_response.x, location_response.y);

    bool allowed = verify_position_against_policy(location_response.x,
                                                  location_response.y, &policy);
    ActionResponse response = {.msg_type = MSG_ACTION_RESPONSE,
                               .allowed = allowed ? 1 : 0};
    if (allowed) {
        printf("[RESOURCE] Location verification successful at (%.2f, %.2f)\n",
               location_response.x, location_response.y);
        printf("[RESOURCE] Movement allowed\n");
    } else {
        printf("[RESOURCE] Location verification failed at (%.2f, %.2f)\n",
               location_response.x, location_response.y);
        printf("[RESOURCE] Movement denied\n");
    }

    result =
        send_secure_message((char*)&response, sizeof(response), session_ctx);

    if (result < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }

    printf("[RESOURCE] Response sent\n");

    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_verification_policy_json(verification_policy);
    close(clnt_sock);
    close(serv_sock);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}
