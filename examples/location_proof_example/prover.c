#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "multilateration.h"
#include "protocol.h"
#include "uwb_reader.h"

#define NUM_TRIALS 100
#define RESULTS_FILE "protocol_latency.csv"

#define ANCHOR_WIDTH_M 1.0668
#define ANCHOR_HEIGHT_M 0.5842

static double elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

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

    /*
     * Open the UWB serial connection once for the complete experiment.
     */
    int uwb_fd = uwb_open();

    if (uwb_fd < 0) {
        SST_print_error_exit("Failed to open UWB device.");
    }

    FILE* results = fopen(RESULTS_FILE, "w");

    if (results == NULL) {
        uwb_close(uwb_fd);
        SST_print_error_exit("Failed to open latency results file.");
    }

    fprintf(results,
            "trial,"
            "auth_ms,"
            "connection_ms,"
            "uwb_ms,"
            "total_ms,"
            "x,"
            "y,"
            "result\n");

    printf("\n");
    printf("========================================\n");
    printf(" END-TO-END AUTHORIZATION LATENCY TEST\n");
    printf("========================================\n");
    printf("Trials: %d\n", NUM_TRIALS);
    printf("Results: %s\n", RESULTS_FILE);
    printf("========================================\n\n");

    int successful_trials = 0;

    double total_sum = 0.0;
    double auth_sum = 0.0;
    double connection_sum = 0.0;
    double uwb_sum = 0.0;

    for (int trial = 1; trial <= NUM_TRIALS; trial++) {
        printf("[%3d/%d] ", trial, NUM_TRIALS);
        fflush(stdout);

        struct timespec total_start;
        struct timespec total_end;

        struct timespec auth_start;
        struct timespec auth_end;

        struct timespec connection_start;
        struct timespec connection_end;

        struct timespec uwb_start;
        struct timespec uwb_end;

        clock_gettime(CLOCK_MONOTONIC, &total_start);

        /*
         * Create a fresh SST context so each trial represents
         * an independent authorization attempt.
         */
        SST_ctx_t* ctx = init_SST(config_path);

        if (ctx == NULL) {
            printf("FAILED: init_SST\n");
            continue;
        }

        /*
         * Obtain authorization/session credentials from Auth.
         */
        clock_gettime(CLOCK_MONOTONIC, &auth_start);

        session_key_list_t* s_key_list =
            get_session_key(ctx, NULL);

        clock_gettime(CLOCK_MONOTONIC, &auth_end);

        if (s_key_list == NULL) {
            printf("FAILED: session key\n");
            free_SST_ctx_t(ctx);
            continue;
        }

        double auth_ms =
            elapsed_ms(auth_start, auth_end);

        /*
         * Establish a fresh secure SST connection with Resource.
         */
        clock_gettime(CLOCK_MONOTONIC, &connection_start);

        SST_session_ctx_t* session_ctx =
            secure_connect_to_server(
                &s_key_list->s_key[0],
                ctx
            );

        clock_gettime(CLOCK_MONOTONIC, &connection_end);

        if (session_ctx == NULL) {
            printf("FAILED: SST connection\n");

            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        double connection_ms =
            elapsed_ms(connection_start, connection_end);

        /*
         * Request MOVE authorization.
         */
        ActionRequest request = {
            .msg_type = MSG_ACTION_REQUEST,
            .action = ACTION_MOVE
        };

        if (send_secure_message(
                (char*)&request,
                sizeof(request),
                session_ctx) < 0) {
            printf("FAILED: MOVE request\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        /*
         * Wait for Resource's location challenge.
         */
        uint8_t message_type;

        if (read_exact_message(
                session_ctx,
                &message_type,
                sizeof(message_type),
                "LocationRequest") != 0) {
            printf("FAILED: location request\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        if (message_type != MSG_LOCATION_REQUEST) {
            printf("FAILED: unexpected message\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        /*
         * Measure live UWB ranging + multilateration latency.
         */
        AnchorMeasurement measurements[UWB_ANCHOR_COUNT];

        clock_gettime(CLOCK_MONOTONIC, &uwb_start);

        if (!uwb_read_measurements(
                uwb_fd,
                measurements)) {
            printf("FAILED: UWB\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        set_anchor_coordinates(measurements);

        Position position;

        if (!multilaterate(
                measurements,
                UWB_ANCHOR_COUNT,
                &position)) {
            printf("FAILED: multilateration\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &uwb_end);

        double uwb_ms =
            elapsed_ms(uwb_start, uwb_end);

        /*
         * Send the live estimated position.
         */
        LocationResponse location_response = {
            .msg_type = MSG_LOCATION_RESPONSE,
            .x = position.x,
            .y = position.y
        };

        if (send_secure_message(
                (char*)&location_response,
                sizeof(location_response),
                session_ctx) < 0) {
            printf("FAILED: location response\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        /*
         * Receive final authorization decision.
         */
        ActionResponse response;

        if (read_exact_message(
                session_ctx,
                &response,
                sizeof(response),
                "ActionResponse") != 0) {
            printf("FAILED: action response\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        if (response.msg_type != MSG_ACTION_RESPONSE) {
            printf("FAILED: unexpected response\n");

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);

            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &total_end);

        double total_ms =
            elapsed_ms(total_start, total_end);

        const char* result =
            response.allowed ? "ALLOW" : "DENY";

        fprintf(results,
                "%d,"
                "%.3f,"
                "%.3f,"
                "%.3f,"
                "%.3f,"
                "%.6f,"
                "%.6f,"
                "%s\n",
                trial,
                auth_ms,
                connection_ms,
                uwb_ms,
                total_ms,
                position.x,
                position.y,
                result);

        fflush(results);

        successful_trials++;

        auth_sum += auth_ms;
        connection_sum += connection_ms;
        uwb_sum += uwb_ms;
        total_sum += total_ms;

        printf(
            "%s | "
            "Auth %.1f ms | "
            "SST %.1f ms | "
            "UWB %.1f ms | "
            "Total %.1f ms | "
            "(%.3f, %.3f)\n",
            result,
            auth_ms,
            connection_ms,
            uwb_ms,
            total_ms,
            position.x,
            position.y);

        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);

        /*
         * Small pause between independent trials.
         */
        usleep(100000);
    }

    printf("\n");
    printf("========================================\n");
    printf("TEST COMPLETE\n");
    printf("========================================\n");
    printf("Successful trials: %d/%d\n",
           successful_trials, NUM_TRIALS);

    if (successful_trials > 0) {
        printf("Mean Auth latency: %.2f ms\n",
               auth_sum / successful_trials);

        printf("Mean SST connection latency: %.2f ms\n",
               connection_sum / successful_trials);

        printf("Mean UWB latency: %.2f ms\n",
               uwb_sum / successful_trials);

        printf("Mean end-to-end latency: %.2f ms\n",
               total_sum / successful_trials);
    }

    printf("Results written to: %s\n", RESULTS_FILE);
    printf("========================================\n");

    fclose(results);
    uwb_close(uwb_fd);

    return EXIT_SUCCESS;
}