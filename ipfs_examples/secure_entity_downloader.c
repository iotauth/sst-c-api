#include "../ipfs.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        error_exit("Enter config path");
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    INIT_SESSION_KEY_LIST(s_key_list);
    ctx->purpose_index = 0;
    session_key_list_t *s_key_list_0 = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list_0->s_key[0], ctx);
    sleep(3);
    char concat_buffer[MAX_PAYLOAD_LENGTH];
    int concat_buffer_size = make_download_req_buffer(ctx, &concat_buffer);
    send_secure_message(concat_buffer, concat_buffer_size, session_ctx);
    // ctx->purpose_index = 1;
    char file_name[BUFF_SIZE];
    memcpy(file_name, "0", BUFF_SIZE);
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    unsigned char data_buf[MAX_PAYLOAD_LENGTH];
    unsigned int data_buf_length = 0;
    unsigned char message_type;
    unsigned char session_key_id[8];
    int command_size;
    read_header_return_data_buf_pointer(session_ctx->sock, &message_type,
                                        data_buf, &data_buf_length);
    unsigned char *decrypted;
    if (message_type == SECURE_COMM_MSG) {
        decrypted =
            decrypt_received_message(data_buf, data_buf_length, session_ctx);
        sleep(1);
        if (decrypted[SEQ_NUM_SIZE] != DOWNLOAD_RESP) {
            error_exit("Not download response!!\n");
        }
        printf("Session key id size: %x\n", decrypted[SEQ_NUM_SIZE + 1]);
        printf("Command size: %d\n",
               decrypted[SEQ_NUM_SIZE + SESSION_KEY_ID_SIZE + 2]);
    }

    download_file(&decrypted[SEQ_NUM_SIZE], &received_skey_id[0],
                  &file_name[0]);
    print_buf(received_skey_id, 8);
    session_key_t *session_key =
        get_session_key_by_ID(&received_skey_id[0], ctx, &s_key_list);
    if (session_key == NULL) {
        error_return_null("There is no session key.\n");
    } else {
        sleep(5);
        file_decrypt_save(*session_key, &file_name[0]);
    }
    free_SST_ctx_t(ctx);
}