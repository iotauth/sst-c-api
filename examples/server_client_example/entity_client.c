#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../c_api.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }
    sleep(1);
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread_read_one_each,
                   (void *)session_ctx);
    int msg = send_secure_message("Hello server", strlen("Hello server"),
                                  session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    sleep(1);
    msg = send_secure_message("Hello server - second message",
                              strlen("Hello server - second message"),
                              session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    sleep(1);
    pthread_cancel(thread);
    pthread_join(thread, NULL);  // Needs to wait until the thread is joined.
    free(session_ctx);

    s_key_list = get_session_key(ctx, s_key_list);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    s_key_list = get_session_key(ctx, s_key_list);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    s_key_list = get_session_key(ctx, s_key_list);  // Intended to fail.
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }

    sleep(3);
    pthread_t thread2;
    session_ctx = secure_connect_to_server(&s_key_list->s_key[1], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }
    pthread_create(&thread2, NULL, &receive_thread_read_one_each,
                   (void *)session_ctx);
    msg = send_secure_message("Hello server 2", strlen("Hello server 2"),
                              session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    sleep(1);
    msg = send_secure_message("Hello server 2 - second message",
                              strlen("Hello server 2 - second message"),
                              session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    sleep(3);
    pthread_cancel(thread2);
    pthread_join(thread2, NULL);  // Needs to wait until the thread is joined.
    free(session_ctx);

    free_session_key_list_t(s_key_list);

    free_SST_ctx_t(ctx);

    sleep(3);
}
