
/**
 * @file encrypt_buf_with_session_key_without_malloc_execution_time_test.c
 * @author Dongha Kim
 * @brief Measure execution time of encrypt function.
 * This program measures the execution time of the
 * `encrypt_buf_with_session_key_without_malloc` and
 * `decrypt_buf_with_session_key_without_malloc` functions in a nested loop.
 * These functions encrypt and decrypt data using a session key without dynamic
 * memory allocation.
 *
 * The outer loop simulates processing multiple files by repeating the inner
 * loop for each file iteration, measuring total and average times per file. The
 * inner loop handles encryption and decryption of data blocks, measuring the
 * time taken for each block and accumulating it. The results provide average
 * encryption and decryption times per block and per file for performance
 * evaluation.
 */
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../c_api.h"
#define FILE_ITERATION 100
#define BLOCK_ITERATION 16384
#define BLOCK_SIZE 4096

long get_time_diff_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000000000L +
           (end.tv_nsec - start.tv_nsec);
}

int main(int argc, char *argv[]) {
    // Just to pass compiler warnings.
    (void)argc;
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }

    unsigned char plaintext_buf[BLOCK_SIZE];

    // Insert random bytes inside buffer.
    RAND_bytes(plaintext_buf, BLOCK_SIZE);

    unsigned char encrypted_data[BLOCK_SIZE + 16];
    unsigned char decrypted_data[BLOCK_SIZE];
    unsigned int processed_size;

    struct timespec start_outer, end_outer, start_inner, end_inner;
    long total_inner_time_ns = 0, total_outer_time_ns = 0;

    // Start measuring time for the outer loop
    clock_gettime(CLOCK_MONOTONIC, &start_outer);
    for (int j = 0; j < FILE_ITERATION; j++) {
        total_inner_time_ns = 0;

        for (int i = 0; i < BLOCK_ITERATION; i++) {
            // Start measuring time for the inner loop
            clock_gettime(CLOCK_MONOTONIC, &start_inner);

            if (encrypt_buf_with_session_key_without_malloc(
                    &s_key_list->s_key[0], plaintext_buf, BLOCK_SIZE,
                    encrypted_data, &processed_size) < 0) {
                SST_print_error_exit(
                    "Failed encrypt_buf_with_session_key_without_malloc().");
            }
            if (decrypt_buf_with_session_key_without_malloc(
                    &s_key_list->s_key[0], encrypted_data, processed_size,
                    decrypted_data, &processed_size) < 0) {
                SST_print_error_exit(
                    "Failed decrypt_buf_with_session_key_without_malloc().");
            }
            // End measuring time for the inner loop
            clock_gettime(CLOCK_MONOTONIC, &end_inner);

            // Calculate the time for this iteration of the inner loop
            long inner_time_ns = get_time_diff_ns(start_inner, end_inner);
            total_inner_time_ns += inner_time_ns;
        }

        // Calculate and print the average time for the inner loop
        printf("Average inner loop time for iteration %d: %ld ns\n", j,
               total_inner_time_ns / BLOCK_ITERATION);
    }

    // End measuring time for the outer loop
    clock_gettime(CLOCK_MONOTONIC, &end_outer);

    // Calculate the total and average time for the outer loop
    total_outer_time_ns = get_time_diff_ns(start_outer, end_outer);
    printf("Average outer loop time: %ld ns\n",
           total_outer_time_ns / FILE_ITERATION);

    return 0;
}
