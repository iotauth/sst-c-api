#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/c_api.h"

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        SST_print_error_exit("Usage: %s <config_file_path> [message]", argv[0]);
    }

    const char* config_path = argv[1];
    const char* message =
        argc == 3 ? argv[2] : "Hello from heterogeneous C client";

    printf("[SST] Loading C client config: %s\n", config_path);
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    printf("[SST] Requesting a session key from Auth.\n");
    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL || s_key_list->num_key <= 0) {
        free_SST_ctx_t(ctx);
        SST_print_error_exit("Failed get_session_key().");
    }

    printf("[SST] Connecting securely to the Node.js server.\n");
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == NULL) {
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);
        SST_print_error_exit("Failed secure_connect_to_server().");
    }

    pthread_t receive_thread;
    if (pthread_create(&receive_thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx) != 0) {
        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);
        SST_print_error_exit("Failed pthread_create().");
    }

    printf("[SST] Sending secure message: %s\n", message);
    int bytes_written =
        send_secure_message((char*)message, strlen(message), session_ctx);
    if (bytes_written < 0) {
        pthread_cancel(receive_thread);
        pthread_join(receive_thread, NULL);
        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);
        SST_print_error_exit("Failed send_secure_message().");
    }

    sleep(2);
    pthread_cancel(receive_thread);
    pthread_join(receive_thread, NULL);

    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
    printf("[SST] Heterogeneous C client finished.\n");
    return 0;
}
