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
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    const char* config_path = argv[1];

    SST_ctx_t* ctx = init_SST(config_path);

    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

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

    printf("[RESOURCE] Waiting for connections on port %d...\n", PORT_NUM);

    int trial = 0;

    while (1) {
        struct sockaddr_in clnt_addr;
        socklen_t clnt_addr_size = sizeof(clnt_addr);

        int clnt_sock =
            accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

        if (clnt_sock == -1) {
            SST_print_error("accept() error.");
            continue;
        }

        trial++;

        printf("\n");
        printf("========================================\n");
        printf("[RESOURCE] TRIAL %d\n", trial);
        printf("========================================\n");

        session_key_list_t* s_key_list = init_empty_session_key_list();

        if (s_key_list == NULL) {
            close(clnt_sock);
            continue;
        }

        SST_session_ctx_t* session_ctx =
            server_secure_comm_setup(ctx, clnt_sock, s_key_list);

        if (session_ctx == NULL) {
            SST_print_error("Failed server_secure_comm_setup().");
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        printf("[RESOURCE] Secure SST session established\n");

        if (ctx->verification_policy_json == NULL) {
            SST_print_error("No verification policy received from Auth.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        VerificationPolicy policy;

        if (parse_verification_policy(ctx->verification_policy_json, &policy) !=
            0) {
            SST_print_error("Failed to parse verification policy from Auth.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        printf("[RESOURCE] Verification policy received from Auth\n");

        ActionRequest request;

        if (read_exact_message(session_ctx, &request, sizeof(request),
                               "ActionRequest") != 0) {
            SST_print_error("Failed to receive ActionRequest.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        if (request.msg_type != MSG_ACTION_REQUEST) {
            SST_print_error("Unexpected message type.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        if (request.action != ACTION_MOVE) {
            ActionResponse response = {.msg_type = MSG_ACTION_RESPONSE,
                                       .allowed = 0};

            send_secure_message((char*)&response, sizeof(response),
                                session_ctx);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        printf("[RESOURCE] MOVE request received\n");

        uint8_t location_request = MSG_LOCATION_REQUEST;

        int result = send_secure_message((char*)&location_request,
                                         sizeof(location_request), session_ctx);

        if (result < 0) {
            SST_print_error("Failed to send location request.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        LocationResponse location_response;

        if (read_exact_message(session_ctx, &location_response,
                               sizeof(location_response),
                               "LocationResponse") != 0) {
            SST_print_error("Failed to receive LocationResponse.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        if (location_response.msg_type != MSG_LOCATION_RESPONSE) {
            SST_print_error("Unexpected message type.");
            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);
            continue;
        }

        bool allowed =
            verify_position_against_policy(location_response.x,
                                           location_response.y, &policy);

        ActionResponse response = {.msg_type = MSG_ACTION_RESPONSE,
                                   .allowed = allowed ? 1 : 0};

        result =
            send_secure_message((char*)&response, sizeof(response), session_ctx);

        if (result < 0) {
            SST_print_error("Failed send_secure_message().");
        } else {
            printf("[RESOURCE] Position: (%.3f, %.3f) -> %s\n",
                   location_response.x, location_response.y,
                   allowed ? "ALLOW" : "DENY");
        }

        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        close(clnt_sock);

        printf("[RESOURCE] Trial %d complete\n", trial);
        printf("[RESOURCE] Waiting for next connection...\n");
    }

    close(serv_sock);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}