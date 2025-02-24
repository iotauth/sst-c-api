#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../c_api.h"

void *SST_read_thread(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char data_buf[512];
    unsigned int data_buf_length = 0;
    while (1) {
        data_buf_length = SST_read(session_ctx, data_buf, 512);
        if(data_buf_length < 0) {
            printf("Read failed.\n");
            break;
        }
        else if(data_buf_length == 0) {
            printf("Disconnected.\n");
            break;
        }
        printf("Received from client: %s\n", data_buf);
        printf("--------------------\n");
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fputs("Enter config path", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        printf("Failed to get session key. Returning NULL.\n");
        exit(1);
    }
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    pthread_t thread;
    pthread_create(&thread, NULL, &SST_read_thread,
                   (void *)session_ctx);
    SST_write(session_ctx, "Hello server", strlen("Hello server"));
    SST_write(session_ctx, "Hello server - second message",
              strlen("Hello server - second message"));
    pthread_join(thread, NULL);
    free_SST_session_ctx_t(session_ctx);

    s_key_list = get_session_key(ctx, s_key_list);
    s_key_list = get_session_key(ctx, s_key_list);
    s_key_list = get_session_key(ctx, s_key_list);  // Intended to fail.

    sleep(1);

    pthread_t thread2;
    session_ctx = secure_connect_to_server(&s_key_list->s_key[1], ctx);
    pthread_create(&thread2, NULL, &SST_read_thread,
                   (void *)session_ctx);
    SST_write(session_ctx, "Hello server 2", strlen("Hello server 2"));
    SST_write(session_ctx, "Hello server 2 - second message",
              strlen("Hello server 2 - second message"));
    pthread_join(thread2, NULL);
    free_SST_session_ctx_t(session_ctx);

    free_session_key_list_t(s_key_list);

    free_SST_ctx_t(ctx);
}
