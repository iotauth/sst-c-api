#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../c_api.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        printf("Failed to get session key. Returning NULL.\n");
        exit(1);
    }
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    sleep(1);
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread_read_one_each,
                   (void *)session_ctx);
    send_secure_message("Hello server", strlen("Hello server"), session_ctx);
    sleep(1);
    send_secure_message("Hello server - second message",
                        strlen("Hello server - second message"), session_ctx);
    sleep(1);
    pthread_cancel(thread);
    pthread_join(thread, NULL); // Needs to wait until the thread is joined.
    free(session_ctx);

    s_key_list = get_session_key(ctx, s_key_list);
    s_key_list = get_session_key(ctx, s_key_list);
    s_key_list = get_session_key(ctx, s_key_list);  // Intended to fail.

    sleep(3);
    pthread_t thread2;
    session_ctx = secure_connect_to_server(&s_key_list->s_key[1], ctx);
    pthread_create(&thread2, NULL, &receive_thread_read_one_each,
                   (void *)session_ctx);
    send_secure_message("Hello server 2", strlen("Hello server 2"),
                        session_ctx);
    sleep(1);
    send_secure_message("Hello server 2 - second message",
                        strlen("Hello server 2 - second message"), session_ctx);
    sleep(3);
    pthread_cancel(thread2);
    pthread_join(thread2, NULL); // Needs to wait until the thread is joined.
    free(session_ctx);

    free_session_key_list_t(s_key_list);

    free_SST_ctx_t(ctx);

    sleep(3);
}
