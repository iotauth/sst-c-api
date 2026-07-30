#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/c_api.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    int serv_sock, clnt_sock;
    const char* PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        SST_print_error_exit("socket() error in %s", __FILE__);
    }
    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        SST_print_error("socket option set error");
        return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(PORT_NUM));

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        SST_print_error_exit("bind() error in %s", __FILE__);
        return -1;
    }

    if (listen(serv_sock, 5) == -1) {
        SST_print_error_exit("listen() error in %s", __FILE__);
        return -1;
    }

    SST_print_log("Box server listening on port %s...", PORT_NUM);

    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock =
        accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        SST_print_error_exit("accept() error in %s", __FILE__);
        return -1;
    }

    char* config_path = argv[1];
    // Initialize SST context for Box
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed server_secure_comm_setup().");
    } else {
        pthread_t thread;
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx);
        sleep(1);

        int msg = send_secure_message("Box: Hello Robot!",
                                      strlen("Box: Hello Robot!"), session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(2);

        pthread_cancel(thread);
        pthread_join(thread, NULL);
        free_session_ctx(session_ctx);
        SST_print_log("Box: Finished secure communication with Robot.");
    }

    free_session_key_list_t(s_key_list);
    close(clnt_sock);
    close(serv_sock);
    free_SST_ctx_t(ctx);

    return 0;
}
