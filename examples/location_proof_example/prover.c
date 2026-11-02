#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "multilateration.h"
#include "protocol.h"
#include "uwb_reader.h"

#define NUM_TRIALS 100
#define RESULTS_FILE "sequential_verification_latency.csv"

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

    FILE* results = fopen(RESULTS_FILE, "w");

    if (results == NULL) {
        SST_print_error_exit("Failed to open results file.");
    }

    fprintf(results,
            "trial,auth_ms,connection_ms,prover_uwb_ms,"
            "total_ms,claimed_x,claimed_y,result\n");

    printf("\n");
    printf("========================================\n");
    printf(" SEQUENTIAL LOCATION VERIFICATION TEST\n");
    printf("========================================\n");
    printf("Trials: %d\n", NUM_TRIALS);
    printf("========================================\n\n");

    int successful_trials = 0;
    double total_sum = 0.0;

    for (int trial = 1; trial <= NUM_TRIALS; trial++) {
        struct timespec total_start, total_end;
        struct timespec auth_start, auth_end;
        struct timespec connection_start, connection_end;
        struct timespec uwb_start, uwb_end;

        clock_gettime(CLOCK_MONOTONIC, &total_start);

        SST_ctx_t* ctx = init_SST(config_path);

        if (ctx == NULL) {
            printf("[%3d/%d] FAILED: init_SST\n",
                   trial, NUM_TRIALS);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &auth_start);

        session_key_list_t* s_key_list =
            get_session_key(ctx, NULL);

        clock_gettime(CLOCK_MONOTONIC, &auth_end);

        if (s_key_list == NULL) {
            printf("[%3d/%d] FAILED: session key\n",
                   trial, NUM_TRIALS);
            free_SST_ctx_t(ctx);
            continue;
        }

        double auth_ms = elapsed_ms(auth_start, auth_end);

        clock_gettime(CLOCK_MONOTONIC, &connection_start);

        SST_session_ctx_t* session_ctx =
            secure_connect_to_server(
                &s_key_list->s_key[0],
                ctx);

        clock_gettime(CLOCK_MONOTONIC, &connection_end);

        if (session_ctx == NULL) {
            printf("[%3d/%d] FAILED: connection\n",
                   trial, NUM_TRIALS);

            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        double connection_ms =
            elapsed_ms(connection_start, connection_end);

        ActionRequest request = {
            .msg_type = MSG_ACTION_REQUEST,
            .action = ACTION_MOVE
        };

        if (send_secure_message(
                (char*)&request,
                sizeof(request),
                session_ctx) < 0) {

            printf("[%3d/%d] FAILED: MOVE\n",
                   trial, NUM_TRIALS);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        /*
         * Resource asks Robot to prove its location.
         */
        uint8_t message_type;

        if (read_exact_message(
                session_ctx,
                &message_type,
                sizeof(message_type),
                "LocationRequest") != 0 ||
            message_type != MSG_LOCATION_REQUEST) {

            printf("[%3d/%d] FAILED: location request\n",
                   trial, NUM_TRIALS);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        /*
         * PROVER MEASUREMENT
         *
         * Prover temporarily owns the UWB serial port.
         */
        int uwb_fd = uwb_open();

        if (uwb_fd < 0) {
            printf("[%3d/%d] FAILED: UWB open\n",
                   trial, NUM_TRIALS);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        AnchorMeasurement measurements[UWB_ANCHOR_COUNT];

        clock_gettime(CLOCK_MONOTONIC, &uwb_start);

        if (!uwb_read_measurements(uwb_fd, measurements)) {
            uwb_close(uwb_fd);

            printf("[%3d/%d] FAILED: UWB read\n",
                   trial, NUM_TRIALS);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        set_anchor_coordinates(measurements);

        Position claimed_position;

        if (!multilaterate(
                measurements,
                UWB_ANCHOR_COUNT,
                &claimed_position)) {

            uwb_close(uwb_fd);

            printf("[%3d/%d] FAILED: multilateration\n",
                   trial, NUM_TRIALS);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &uwb_end);

        /*
         * CRITICAL:
         * Release the serial device BEFORE Resource verifies.
         */
        uwb_close(uwb_fd);

        double prover_uwb_ms =
            elapsed_ms(uwb_start, uwb_end);

        LocationResponse location_response = {
            .msg_type = MSG_LOCATION_RESPONSE,
            .x = claimed_position.x,
            .y = claimed_position.y
        };

        /*
         * Once this is sent, Resource performs its own
         * fresh UWB measurement.
         */
        if (send_secure_message(
                (char*)&location_response,
                sizeof(location_response),
                session_ctx) < 0) {

            printf("[%3d/%d] FAILED: location response\n",
                   trial, NUM_TRIALS);

            free_session_ctx(session_ctx);
            free_session_key_list_t(s_key_list);
            free_SST_ctx_t(ctx);
            continue;
        }

        ActionResponse response;

        if (read_exact_message(
                session_ctx,
                &response,
                sizeof(response),
                "ActionResponse") != 0 ||
            response.msg_type != MSG_ACTION_RESPONSE) {

            printf("[%3d/%d] FAILED: action response\n",
                   trial, NUM_TRIALS);

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
                "%d,%.3f,%.3f,%.3f,%.3f,"
                "%.6f,%.6f,%s\n",
                trial,
                auth_ms,
                connection_ms,
                prover_uwb_ms,
                total_ms,
                claimed_position.x,
                claimed_position.y,
                result);

        fflush(results);

        successful_trials++;
        total_sum += total_ms;

        printf(
            "[%3d/%d] %s | "
            "Claim (%.3f, %.3f) | "
            "Total %.1f ms\n",
            trial,
            NUM_TRIALS,
            result,
            claimed_position.x,
            claimed_position.y,
            total_ms);

        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);

        usleep(100000);
    }

    printf("\n");
    printf("========================================\n");
    printf("TEST COMPLETE\n");
    printf("========================================\n");
    printf("Successful trials: %d/%d\n",
           successful_trials, NUM_TRIALS);

    if (successful_trials > 0) {
        printf("Mean end-to-end latency: %.2f ms\n",
               total_sum / successful_trials);
    }

    printf("Results: %s\n", RESULTS_FILE);
    printf("========================================\n");

    fclose(results);

    return EXIT_SUCCESS;
}