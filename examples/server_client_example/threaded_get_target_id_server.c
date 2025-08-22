/**
 * @file threaded_get_target_id_server.c
 * @author Dongha Kim
 * @brief A multi-threaded server program that retrieves session keys by their
 * IDs. Create multiple threads, read the meta data that contains the session
 * key ID, and request the session key by their IDs. This program uses the
 * SST_ctx_t's mutex, to ensure thread-safe.
 * @copyright Copyright (c) 2025
 *
 */
#include <pthread.h>
#include <stdio.h>

#include "../../c_api.h"

// Define a struct to hold the thread arguments
typedef struct {
    SST_ctx_t *ctx;
    char *file_path;
} thread_args_t;

void *call_get_session_key_by_ID(void *args) {
    thread_args_t *data = (thread_args_t *)args;
    SST_ctx_t *ctx = data->ctx;
    char *file_path = data->file_path;

    session_key_list_t *s_key_list = init_empty_session_key_list();

    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open file %s\n", file_path);
        return NULL;
    }
    fread(target_session_key_id, SESSION_KEY_ID_SIZE, 1, fp);
    fclose(fp);
    printf("Session Key ID from file %s: %u\n", file_path,
           convert_skid_buf_to_int(target_session_key_id, SESSION_KEY_ID_SIZE));

    pthread_mutex_lock(&ctx->mutex);
    session_key_t *session_key =
        get_session_key_by_ID(target_session_key_id, ctx, s_key_list);
    if (session_key == NULL) {
        SST_print_error_exit("Failed get_session_key_by_ID().");
    }
    pthread_mutex_unlock(&ctx->mutex);

    if (session_key) {
        printf(
            "Retrieved Session Key ID: %u\n",
            convert_skid_buf_to_int(session_key->key_id, SESSION_KEY_ID_SIZE));
    } else {
        fprintf(stderr, "Error: Failed to retrieve session key for %s\n",
                file_path);
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Too many arguments. Usage: %s <config_path>",
                             argv[0]);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    pthread_mutex_init(&ctx->mutex, NULL);

    pthread_t threads[3];
    thread_args_t args[3] = {
        {ctx, "s_key_id0.dat"}, {ctx, "s_key_id1.dat"}, {ctx, "s_key_id2.dat"}};

    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, call_get_session_key_by_ID,
                       (void *)&args[i]);
    }

    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&ctx->mutex);
    return 0;
}
