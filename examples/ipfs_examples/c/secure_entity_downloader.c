#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../ipfs.h"

#define MAX_PAYLOAD_LENGTH 1024
#define SEQ_NUM_SIZE 8

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fputs("Enter config path", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    session_key_list_t *s_key_list = init_empty_session_key_list();
    ctx->config->purpose_index = 0;
    session_key_list_t *s_key_list_0 = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list_0->s_key[0], ctx);
    sleep(3);
    char concat_buffer[MAX_PAYLOAD_LENGTH];
    int concat_buffer_size = make_download_req_buffer(ctx, concat_buffer);
    send_secure_message(concat_buffer, concat_buffer_size, session_ctx);
    char file_name[BUFF_SIZE];
    memcpy(file_name, "0", BUFF_SIZE);
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    unsigned char decrypted[MAX_SECURE_COMM_MSG_LENGTH];
    unsigned int data_buf_length = 0;
    unsigned char message_type;
    unsigned char session_key_id[8];
    int command_size;
    data_buf_length = read_secure_message(decrypted, session_ctx);
    if (decrypted[SEQ_NUM_SIZE] != DOWNLOAD_RESP) {
        fputs("Not download response!!", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    printf("Session key id size: %x\n", decrypted[SEQ_NUM_SIZE + 1]);
    printf("Command size: %d\n",
           decrypted[SEQ_NUM_SIZE + SESSION_KEY_ID_SIZE + 2]);

    download_file(&decrypted[SEQ_NUM_SIZE], &received_skey_id[0],
                  &file_name[0]);
    session_key_t *session_key =
        get_session_key_by_ID(&received_skey_id[0], ctx, s_key_list);
    if (session_key == NULL) {
        printf("There is no session key.\n");
        exit(1);
    } else {
        sleep(5);
        file_decrypt_save(*session_key, &file_name[0]);
    }
    free_SST_ctx_t(ctx);
}
