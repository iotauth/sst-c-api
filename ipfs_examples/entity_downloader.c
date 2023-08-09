#include "../ipfs.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        error_handling("Enter config path");
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    // Initialize the session key list.
    INIT_SESSION_KEY_LIST(s_key_list);
    ctx->purpose_index = 0;
    sleep(5);
    
    char file_name[BUFF_SIZE];
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    download_from_file_system_manager(&received_skey_id[0], ctx, &file_name[0]);
    session_key_t *session_key =
        check_sessionkey_from_key_list(&received_skey_id[0], ctx, &s_key_list);
    sleep(5);
    file_download_decrypt(*session_key, &file_name[0]);

    sleep(3);
    char file_name1[BUFF_SIZE];
    unsigned char received_skey_id1[SESSION_KEY_ID_SIZE];
    download_from_file_system_manager(&received_skey_id1[0], ctx, &file_name1[0]);
    session_key_t *session_key1 =
        check_sessionkey_from_key_list(&received_skey_id1[0], ctx, &s_key_list);
    sleep(5);
    file_download_decrypt(*session_key1, &file_name1[0]);

    free_SST_ctx_t(ctx);
}
