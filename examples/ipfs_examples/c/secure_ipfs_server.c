#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../../src/c_api.h"

#define PORT_NUM "21100"

static void* receive_thread(void* arg) {
    SST_session_ctx_t* session_ctx = (SST_session_ctx_t*)arg;
    unsigned char buffer[MAX_SECURE_COMM_MSG_LENGTH];
    int recv_len;

    while ((recv_len = read_secure_message(buffer, session_ctx)) > 0) {
        printf("Received %d bytes from client\n", recv_len);
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    int serv_sock, clnt_sock;
    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        SST_print_error_exit("socket() error");
    }

    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        printf("socket option set error\n");
        close(serv_sock);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(PORT_NUM));

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        SST_print_error_exit("bind() error");
    }

    if (listen(serv_sock, 5) == -1) {
        SST_print_error_exit("listen() error");
    }

    printf("Secure IPFS Server listening on port %s...\n", PORT_NUM);

    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock =
        accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        SST_print_error_exit("accept() error");
    }

    printf("Client connected\n");

    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed server_secure_comm_setup().");
    }

    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread, (void*)session_ctx);

    sleep(2);
    pthread_cancel(thread);
    pthread_join(thread, NULL);

    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    close(clnt_sock);
    close(serv_sock);
    free_SST_ctx_t(ctx);

    printf("Server finished\n");
    return 0;
}
