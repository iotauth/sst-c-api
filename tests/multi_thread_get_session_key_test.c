/**
 * @file multi_thread_get_session_key_test.c
 * @author your name (you@domain.com)
 * @brief Test get_session_key() in multiple threads.
 * This tests if get_session_key() can be called in multiple threads without
 * mutex locks. However, this test nondeterministically fails.
 * @copyright Copyright (c) 2025
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../c_api.h"

void *send_request(void *SST_ctx) {
    SST_ctx_t *ctx = (SST_ctx_t *)SST_ctx;
    for (int i = 0; i < 1; i++) {
        // If there is no mutex_lock, this test fails.
        // pthread_mutex_lock(&ctx->mutex);
        session_key_list_t *s_key_list = NULL;
        s_key_list = get_session_key(ctx, s_key_list);
        if (s_key_list == NULL) {
            SST_print_error_exit("Failed get_session_key().");
        }
        // pthread_mutex_unlock(&ctx->mutex);
        free_session_key_list_t(s_key_list);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    // Request one session key to just ensure getting the distribution key.
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    sleep(2);
    int num_threads = 5;
    pthread_t thread[num_threads];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, &send_request, (void *)ctx);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(thread[i], NULL);
    }
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
    return 0;
}
