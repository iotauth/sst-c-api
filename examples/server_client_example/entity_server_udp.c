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

    int serv_sock, clnt_sock, clnt_sock2;
    const char* PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    
    int listenfd;
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));

    // Create a UDP Socket
    listenfd = socket(AF_INET, SOCK_DGRAM, 0);        
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(atoi(PORT_NUM));
    servaddr.sin_family = AF_INET; 
 
    // bind server address to socket descriptor
    bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, listenfd, s_key_list);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed server_secure_comm_setup().");
    } else {
        pthread_t thread;
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx);
        sleep(1);

        //receive the datagram
        int msg = send_secure_message("Hello client", strlen("Hello client"),
                                      session_ctx);

        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(1);
        // send the response
        msg = send_secure_message("Hello client - second message",
                                  strlen("Hello client - second message"),
                                  session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(2);
        pthread_cancel(thread);
        pthread_join(thread,
                     NULL);  // Needs to wait until the thread is joined.
        free_session_ctx(session_ctx);
        printf("Finished first communication\n");
    }
    
    free_session_key_list_t(s_key_list);
    close(clnt_sock);
    close(serv_sock);
    free_SST_ctx_t(ctx);
}
