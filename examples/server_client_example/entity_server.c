#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../c_api.h"

void exit_with_error(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void *SST_read_thread(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char data_buf[512];
    unsigned int data_buf_length = 0;
    while (1) {
        data_buf_length = SST_read(session_ctx, data_buf, 512);
        if (data_buf_length < 0) {
            printf("Read failed.\n");
            break;
        } else if (data_buf_length == 0) {
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
        exit_with_error("Enter config path");
    }

    int serv_sock, clnt_sock, clnt_sock2;
    const char *PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        exit_with_error("socket() error");
    }
    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        printf("socket option set error\n");
        return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(PORT_NUM));

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        exit_with_error("bind() error");
        return -1;
    }

    if (listen(serv_sock, 5) == -1) {
        exit_with_error("listen() error");
        return -1;
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        exit_with_error("accept() error");
        return -1;
    }

    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    session_key_list_t *s_key_list = init_empty_session_key_list();
    SST_session_ctx_t *session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        printf("There is no session key.\n");
    } else {
        pthread_t thread;
        pthread_create(&thread, NULL, &SST_read_thread, (void *)session_ctx);

        SST_write(session_ctx, "Hello client", strlen("Hello client"));
        SST_write(session_ctx, "Hello client - second message",
                  strlen("Hello client - second message"));
        shutdown(clnt_sock, SHUT_RD);
        pthread_join(thread, NULL);
        close(clnt_sock);
        printf("Finished first communication\n");
    }
    // Second connection. session_key_list caches the session key.
    clnt_sock2 =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock2 == -1) {
        exit_with_error("accept() error");
    }

    sleep(1);

    SST_session_ctx_t *session_ctx2 =
        server_secure_comm_setup(ctx, clnt_sock2, s_key_list);
    if (session_ctx == NULL) {
        printf("There is no session key.\n");
    } else {
        pthread_t thread2;
        pthread_create(&thread2, NULL, &SST_read_thread, (void *)session_ctx2);

        SST_write(session_ctx2, "Hello client 2", strlen("Hello client 2"));
        SST_write(session_ctx2, "Hello client 2 - second message",
                  strlen("Hello client 2 - second message"));
        shutdown(clnt_sock2, SHUT_RD);
        pthread_join(thread2, NULL);
        close(clnt_sock2);
    }
    close(serv_sock);
    free_SST_ctx_t(ctx);
}
