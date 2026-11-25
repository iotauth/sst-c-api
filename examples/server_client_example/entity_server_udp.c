#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/c_api.h"

static int exchange_messages(SST_session_ctx_t* session_ctx) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, receive_thread_read_one_each,
                       session_ctx) != 0) {
        SST_print_error("Failed to start receive thread.");
        return -1;
    }
    char replies[][sizeof("Hello client - second message")] = {
        "Hello client", "Hello client - second message"};
    int result = 0;
    for (size_t i = 0; i < sizeof(replies) / sizeof(replies[0]); ++i) {
        sleep(1);
        if (send_secure_message(replies[i], strlen(replies[i]), session_ctx) <
            0) {
            SST_print_error("Failed send_secure_message().");
            result = -1;
            break;
        }
    }
    if (result == 0) sleep(2);
    pthread_cancel(thread);
    pthread_join(thread, NULL);
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    SST_ctx_t* ctx = init_SST(argv[1]);
    if (ctx == NULL) {
        SST_print_error("init_SST() failed.");
        return EXIT_FAILURE;
    }
    int result = EXIT_FAILURE;
    int listenfd = -1;
    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx = NULL;
    if (s_key_list == NULL) goto cleanup;

    if (strcmp(ctx->config.network_protocol, "UDP") != 0 ||
        ctx->config.entity_server_port_num < 1 ||
        ctx->config.entity_server_port_num > 65535) {
        SST_print_error("A UDP config with a valid server port is required.");
        goto cleanup;
    }
    listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd < 0) {
        SST_print_error("socket() failed.");
        goto cleanup;
    }
    struct sockaddr_in servaddr = {0};
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(ctx->config.entity_server_port_num);
    servaddr.sin_family = AF_INET;
    if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        SST_print_error("bind() failed.");
        goto cleanup;
    }
    session_ctx = server_secure_comm_setup(ctx, listenfd, s_key_list);
    if (session_ctx == NULL) {
        SST_print_error("Failed server_secure_comm_setup().");
        goto cleanup;
    }
    if (exchange_messages(session_ctx) < 0) goto cleanup;
    puts("Finished first communication");
    result = EXIT_SUCCESS;

cleanup:
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    if (listenfd >= 0) close(listenfd);
    free_SST_ctx_t(ctx);
    return result;
}
