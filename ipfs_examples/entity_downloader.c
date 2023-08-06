#include "../ipfs.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        error_handling("Enter config path");
    }

    int serv_sock, clnt_sock, clnt_sock2;
    const int PORT_NUM = 21100;
    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        error_handling("socket() error");
    }
    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        printf("socket option set error\n");
        return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT_NUM);

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        error_handling("bind() error");
        return -1;
    }

    if (listen(serv_sock, 5) == -1) {
        error_handling("listen() error");
        return -1;
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        error_handling("accept() error");
        return -1;
    }

    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    INIT_SESSION_KEY_LIST(s_key_list);
    ctx->purpose_index = 0;
    SST_session_ctx_t *session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, &s_key_list);
    sleep(5);
    
    char file_name[BUFF_SIZE];
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    download_from_file_system_manager(&received_skey_id[0], ctx, &file_name[0]);
    session_key_t *session_key =
        check_sessionkey_request_to_auth(&received_skey_id[0], ctx, &s_key_list);
    sleep(5);
    file_download_decrypt(*session_key, &file_name[0]);

    sleep(3);
    char file_name1[BUFF_SIZE];
    unsigned char received_skey_id1[SESSION_KEY_ID_SIZE];
    download_from_file_system_manager(&received_skey_id1[0], ctx, &file_name1[0]);
    session_key_t *session_key1 =
        check_sessionkey_request_to_auth(&received_skey_id1[0], ctx, &s_key_list);
    sleep(5);
    file_download_decrypt(*session_key1, &file_name1[0]);

    close(clnt_sock2);
    close(serv_sock);
    free_SST_ctx_t(ctx);
}
