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
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);

    unsigned char iv_high[8], iv_low[8];
    memset(iv_high, 0, 8);
    memset(iv_low, 0, 8);

    uint64_t initial_iv_high = 0, initial_iv_low = 0;
    memcpy(&initial_iv_high, iv_high, sizeof(iv_high));
    memcpy(&initial_iv_low, iv_low, sizeof(iv_low));

    unsigned char plaintext_buf[BLOCK_SIZE];

    // Insert random bytes inside buffer.
    RAND_bytes(plaintext_buf, BLOCK_SIZE);

    unsigned char encrypted_data[BLOCK_SIZE];
    unsigned char decrypted_data[BLOCK_SIZE];
    unsigned int processed_size;

    struct timespec start_outer, end_outer, start_inner, end_inner;
    long total_inner_time_ns = 0, total_outer_time_ns = 0;

    // Start measuring time for the outer loop
    clock_gettime(CLOCK_MONOTONIC, &start_outer);
    for (int j = 0; j < FILE_ITERATION; j++) {
        unsigned int file_offset = 0;
        total_inner_time_ns = 0;

        for (int i = 0; i < BLOCK_ITERATION; i++) {
            // Start measuring time for the inner loop
            clock_gettime(CLOCK_MONOTONIC, &start_inner);

            // Encrypt the data
            if (CTR_encrypt_buf_with_session_key(
                    &s_key_list->s_key[0], initial_iv_high, initial_iv_low,
                    file_offset, plaintext_buf, BLOCK_SIZE, encrypted_data,
                    sizeof(encrypted_data), &processed_size) != 0) {
                fprintf(stderr, "Encryption failed\n");
                return 1;
            }

            // End measuring time for the inner loop
            clock_gettime(CLOCK_MONOTONIC, &end_inner);

            // Calculate the time for this iteration of the inner loop
            long inner_time_ns = get_time_diff_ns(start_inner, end_inner);
            total_inner_time_ns += inner_time_ns;

            file_offset += BLOCK_SIZE;
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
