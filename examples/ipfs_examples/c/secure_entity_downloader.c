#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../ipfs.h"

#define MAX_PAYLOAD_LENGTH 1024
#define SEQ_NUM_SIZE 8

int main(int argc, char *argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    session_key_list_t *s_key_list = init_empty_session_key_list();
    ctx->config->purpose_index = 0;
    session_key_list_t *s_key_list_0 = get_session_key(ctx, NULL);
    if (s_key_list_0 == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list_0->s_key[0], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }
    sleep(3);
    char concat_buffer[MAX_PAYLOAD_LENGTH];
    int concat_buffer_size = make_download_req_buffer(ctx, concat_buffer);
    int msg =
        send_secure_message(concat_buffer, concat_buffer_size, session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    char file_name[BUFF_SIZE];
    strncpy(file_name, "0", BUFF_SIZE);
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    unsigned char decrypted[MAX_SECURE_COMM_MSG_LENGTH];
    if (read_secure_message(decrypted, session_ctx) < 0) {
        SST_print_error_exit("Failed read_secure_message()");
    }
    if (decrypted[0] != DOWNLOAD_RESP) {
        SST_print_error_exit("Not download response!!");
    }
    printf("Session key id size: %x\n", decrypted[1]);
    printf("Command size: %d\n", decrypted[SESSION_KEY_ID_SIZE + 2]);

    download_file(&decrypted[0], &received_skey_id[0], &file_name[0]);
    session_key_t *session_key =
        get_session_key_by_ID(&received_skey_id[0], ctx, s_key_list);
    if (session_key == NULL) {
        SST_print_error_exit("Failed to get_session_key_by_ID().");
    } else {
        sleep(5);
        if (file_decrypt_save(*session_key, &file_name[0]) < 0) {
            SST_print_error_exit("Failed file_decrypt_save()");
        }
    }
    free_SST_ctx_t(ctx);
}
