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
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void *)session_ctx);
        sleep(1);

        send_secure_message("Hello client", strlen("Hello client"),
                            session_ctx);
        sleep(1);
        send_secure_message("Hello client - second message",
                            strlen("Hello client - second message"),
                            session_ctx);
        sleep(2);
        pthread_cancel(thread);
        pthread_join(thread, NULL); // Needs to wait until the thread is joined.
        printf("Finished first communication\n");
    }
    // Second connection. session_key_list caches the session key.
    clnt_sock2 =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock2 == -1) {
        exit_with_error("accept() error");
    }
    SST_session_ctx_t *session_ctx2 =
        server_secure_comm_setup(ctx, clnt_sock2, s_key_list);

    pthread_t thread2;
    pthread_create(&thread2, NULL, &receive_thread_read_one_each,
                   (void *)session_ctx2);
    sleep(1);

    send_secure_message("Hello client 2", strlen("Hello client 2"),
                        session_ctx2);
    sleep(1);
    send_secure_message("Hello client 2 - second message",
                        strlen("Hello client 2 - second message"),
                        session_ctx2);
    sleep(1);

    sleep(3);
    pthread_cancel(thread2);
    pthread_join(thread2, NULL); // Needs to wait until the thread is joined.
    close(clnt_sock);
    close(clnt_sock2);
    close(serv_sock);
    free_SST_ctx_t(ctx);
}
