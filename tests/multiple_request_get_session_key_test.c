/**
 * @file multiple_request_get_session_key_test.c
 * @brief Test get_session_key() when called multiple times sequentially.
 * This checks list appending and capacity limits.
 *
 * NOTE: This test assumes that entityInfo.number_key=3 is configured
 * in the client configuration file (e.g., ../test_configs/client.config).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/c_api.h"

#define EXPECTED_KEYS_1ST 3
#define EXPECTED_KEYS_2ND 6
#define EXPECTED_KEYS_3RD 9
#define EXPECTED_KEYS_4TH 9

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }
    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    // 1st request: Initialize session key list.
    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed 1st get_session_key().");
    } else {
        printf("1st request succeeded. num_key: %d\n", s_key_list->num_key);
        assert(s_key_list->num_key == EXPECTED_KEYS_1ST);
    }

    // 2nd request: Append to session key list.
    s_key_list = get_session_key(ctx, s_key_list);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed 2nd get_session_key().");
    } else {
        printf("2nd request completed. num_key: %d\n", s_key_list->num_key);
        assert(s_key_list->num_key == EXPECTED_KEYS_2ND);
    }

    // 3rd request: Append to session key list again.
    s_key_list = get_session_key(ctx, s_key_list);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed 3rd get_session_key().");
    } else {
        printf("3rd request completed. num_key: %d\n", s_key_list->num_key);
        assert(s_key_list->num_key == EXPECTED_KEYS_3RD);
    }

    // 4th request: This should reach the limit and fail to add.
    s_key_list = get_session_key(ctx, s_key_list);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed 4th get_session_key().");
    } else {
        printf("4th request completed. num_key: %d\n", s_key_list->num_key);
        assert(s_key_list->num_key == EXPECTED_KEYS_4TH);
    }

    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
    return 0;
}
