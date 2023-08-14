#include "../ipfs.h"

int main(int argc, char* argv[]) {
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);

    // request the adding reader request to Auth without distribution key
    ctx->purpose_index = 2;
    send_add_reader_req_via_TCP(ctx, add_reader_path);

    ctx->purpose_index = 1;
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    sleep(1);
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len = file_encrypt_upload(&s_key_list_0->s_key[0], ctx, my_file_path, &hash_value[0]);
    sleep(1);
    upload_to_file_system_manager(&s_key_list_0->s_key[0], ctx, &hash_value[0], hash_value_len);
    sleep(5);

    unsigned char hash_value1[BUFF_SIZE];
    int hash_value_len1 = file_encrypt_upload(&s_key_list_0->s_key[1], ctx, my_file_path, &hash_value1[0]);
    sleep(1);
    upload_to_file_system_manager(&s_key_list_0->s_key[1], ctx, &hash_value1[0], hash_value_len1);

    ctx->purpose_index = 2;
    send_add_reader_req_via_TCP(ctx, add_reader_path);

    free_SST_ctx_t(ctx);
}