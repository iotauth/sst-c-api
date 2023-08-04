#include "../ipfs.h"

int main(int argc, char* argv[]) {
    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);
    ctx->purpose_index = 1;
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list_0->s_key[0], ctx);
    sleep(1);
    char* my_file_path = argv[2];
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len = file_encrypt_upload(&s_key_list_0->s_key[0], ctx, my_file_path, &hash_value[0]);
    // print_buf(s_key_list_0->s_key[0])
    sleep(1);
    upload_to_file_system_manager(&s_key_list_0->s_key[0], ctx, &hash_value[0], hash_value_len);
    sleep(5);

    unsigned char hash_value1[BUFF_SIZE];
    int hash_value_len1 = file_encrypt_upload(&s_key_list_0->s_key[1], ctx, my_file_path, &hash_value1[0]);
    // print_buf(s_key_list_0->s_key[0])
    sleep(1);
    upload_to_file_system_manager(&s_key_list_0->s_key[1], ctx, &hash_value1[0], hash_value_len1);

    free(session_ctx);

    free_SST_ctx_t(ctx);

    sleep(3);
}