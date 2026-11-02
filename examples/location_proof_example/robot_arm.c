#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "location_verifier.h"
#include "multilateration.h"
#include "protocol.h"
#include "uwb_reader.h"
#include "verification_policy.h"

#define PORT_NUM 21100

static bool apply_policy_anchor_coordinates(
    AnchorMeasurement measurements[UWB_ANCHOR_COUNT],
    const VerificationPolicy* policy) {

    for (int i = 0; i < UWB_ANCHOR_COUNT; i++) {
        bool found = false;

        for (int j = 0; j < policy->anchor_count; j++) {
            if (measurements[i].id == policy->anchors[j].id) {
                measurements[i].x = policy->anchors[j].x;
                measurements[i].y = policy->anchors[j].y;

                found = true;
                break;
            }
        }

        if (!found) {
            return false;
        }
    }

    return true;
}

static double position_difference(
    double x1,
    double y1,
    double x2,
    double y2) {

    double dx = x1 - x2;
    double dy = y1 - y2;

    return sqrt(dx * dx + dy * dy);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit(
            "Usage: %s <config_file_path>",
            argv[0]);
    }

    const char* config_path = argv[1];

    SST_ctx_t* ctx = init_SST(config_path);

    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    int serv_sock = socket(PF_INET, SOCK_STREAM, 0);

    if (serv_sock == -1) {
        SST_print_error_exit("socket() failed.");
    }

    int on = 1;

    if (setsockopt(
            serv_sock,
            SOL_SOCKET,
            SO_REUSEADDR,
            &on,
            sizeof(on)) < 0) {

        SST_print_error_exit("setsockopt() failed.");
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT_NUM);

    if (bind(
            serv_sock,
            (struct sockaddr*)&serv_addr,
            sizeof(serv_addr)) == -1) {

        SST_print_error_exit("bind() failed.");
    }

    if (listen(serv_sock, 5) == -1) {
        SST_print_error_exit("listen() failed.");
    }

    printf(
        "[RESOURCE] Waiting for connections on port %d...\n",
        PORT_NUM);

    int trial = 0;

    while (1) {
        struct sockaddr_in clnt_addr;
        socklen_t clnt_addr_size = sizeof(clnt_addr);

        int clnt_sock =
            accept(
                serv_sock,
                (struct sockaddr*)&clnt_addr,
                &clnt_addr_size);

        if (clnt_sock == -1) {
            SST_print_error("accept() failed.");
            continue;
        }

        trial++;

        printf("\n");
        printf("========================================\n");
        printf("[RESOURCE] TRIAL %d\n", trial);
        printf("========================================\n");

        session_key_list_t* s_key_list =
            init_empty_session_key_list();

        if (s_key_list == NULL) {
            close(clnt_sock);
            continue;
        }

        SST_session_ctx_t* session_ctx =
            server_secure_comm_setup(
                ctx,
                clnt_sock,
                s_key_list);

        if (session_ctx == NULL) {
            SST_print_error(
                "Failed server_secure_comm_setup().");

            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        if (ctx->verification_policy_json == NULL) {
            SST_print_error(
                "No verification policy received from Auth.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        VerificationPolicy policy;

        if (parse_verification_policy(
                ctx->verification_policy_json,
                &policy) != 0) {

            SST_print_error(
                "Failed to parse verification policy.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        printf(
            "[RESOURCE] Verification policy received from Auth\n");

        ActionRequest request;

        if (read_exact_message(
                session_ctx,
                &request,
                sizeof(request),
                "ActionRequest") != 0) {

            SST_print_error(
                "Failed to receive ActionRequest.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        if (request.msg_type != MSG_ACTION_REQUEST ||
            request.action != ACTION_MOVE) {

            SST_print_error("Invalid action request.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        /*
         * Ask Robot to produce its location claim.
         */
        uint8_t location_request = MSG_LOCATION_REQUEST;

        if (send_secure_message(
                (char*)&location_request,
                sizeof(location_request),
                session_ctx) < 0) {

            SST_print_error(
                "Failed to send location request.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        LocationResponse claim;

        if (read_exact_message(
                session_ctx,
                &claim,
                sizeof(claim),
                "LocationResponse") != 0) {

            SST_print_error(
                "Failed to receive Robot location claim.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        printf(
            "[RESOURCE] Robot claims position: "
            "(%.3f, %.3f)\n",
            claim.x,
            claim.y);

        /*
         * At this point Prover has CLOSED /dev/ttyACM2.
         *
         * Resource can now safely acquire the same UWB
         * device and obtain a fresh measurement set.
         */
        int uwb_fd = uwb_open();

        if (uwb_fd < 0) {
            SST_print_error(
                "Resource failed to open UWB device.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        AnchorMeasurement measurements[UWB_ANCHOR_COUNT];

        printf(
            "[RESOURCE] Independently verifying location...\n");

        if (!uwb_read_measurements(
                uwb_fd,
                measurements)) {

            uwb_close(uwb_fd);

            SST_print_error(
                "Resource failed to collect UWB measurements.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        /*
         * Release serial immediately after acquiring
         * Resource's independent measurement.
         */
        uwb_close(uwb_fd);

        if (!apply_policy_anchor_coordinates(
                measurements,
                &policy)) {

            SST_print_error(
                "Anchor IDs do not match Auth policy.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        Position verified_position;

        if (!multilaterate(
                measurements,
                UWB_ANCHOR_COUNT,
                &verified_position)) {

            SST_print_error(
                "Resource multilateration failed.");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            close(clnt_sock);

            continue;
        }

        printf(
            "[RESOURCE] Verified position: "
            "(%.3f, %.3f)\n",
            verified_position.x,
            verified_position.y);

        /*
         * Compare Robot claim against Resource's
         * independently measured position.
         */
        double difference =
            position_difference(
                claim.x,
                claim.y,
                verified_position.x,
                verified_position.y);

        printf(
            "[RESOURCE] Claim difference: %.3f m\n",
            difference);

        printf(
            "[RESOURCE] Allowed difference: %.3f m\n",
            policy.max_error_m);

        bool claim_matches =
            difference <= policy.max_error_m;

        /*
         * Authorization uses Resource's verified position,
         * not the Robot's claimed position.
         */
        bool verified_in_zone =
            verify_position_against_policy(
                verified_position.x,
                verified_position.y,
                &policy);

        bool allowed =
            claim_matches && verified_in_zone;

        if (!claim_matches) {
            printf(
                "[RESOURCE] Robot location claim rejected\n");
        }

        if (!verified_in_zone) {
            printf(
                "[RESOURCE] Verified position outside authorized zone\n");
        }

        ActionResponse response = {
            .msg_type = MSG_ACTION_RESPONSE,
            .allowed = allowed ? 1 : 0
        };

        if (send_secure_message(
                (char*)&response,
                sizeof(response),
                session_ctx) < 0) {

            SST_print_error(
                "Failed to send ActionResponse.");
        } else {
            printf(
                "[RESOURCE] ACTION %s\n",
                allowed ? "ALLOWED" : "DENIED");
        }

        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        close(clnt_sock);

        printf(
            "[RESOURCE] Trial %d complete\n",
            trial);
    }

    close(serv_sock);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}