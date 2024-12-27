#include "block_common.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    // Open file_metadata structs.
    char *encrypted_metadata_filename = "encrypted_file_metadata.dat";
    char *plaintext_metadata_filename = "plaintext_file_metadata.dat";
    FILE *encrypted_metadata_fp;
    FILE *plaintext_metadata_fp;
    encrypted_metadata_fp = fopen(encrypted_metadata_filename, "rb");
    plaintext_metadata_fp = fopen(plaintext_metadata_filename, "rb");

    file_metadata_t encrypted_file_metadata[TOTAL_FILE_NUM];
    file_metadata_t plaintext_file_metadata[TOTAL_FILE_NUM];
    for (int var = 0; var < TOTAL_FILE_NUM; ++var) {
        fread(&encrypted_file_metadata[var], sizeof(file_metadata_t), 1,
              encrypted_metadata_fp);
        fread(&plaintext_file_metadata[var], sizeof(file_metadata_t), 1,
              plaintext_metadata_fp);
    }

    session_key_list_t *s_key_list = init_empty_session_key_list();
    //  ----Decrypt and compare with plaintext----

    // Read files.
    for (int i = 0; i < TOTAL_FILE_NUM; i++) {
        // Request session key by session key ID. It will be added to the
        // s_key_list.
        get_session_key_by_ID(encrypted_file_metadata[i].key_id, ctx,
                              s_key_list);
        // printf("Testing if resending exception is working..\n");
        // session_key_list_t *temp_s_key_list = init_empty_session_key_list();
        // session_key_t* session_key =
        // get_session_key_by_ID(encrypted_file_metadata[i].key_id, ctx,
        //                       temp_s_key_list);
        // if (session_key == NULL) {
        //     printf("Yeah it worked\n");
        // }
        char encrypted_filename[15];
        sprintf(encrypted_filename, "encrypted%d.txt", i);
        char plaintext_filename[15];
        sprintf(plaintext_filename, "plaintext%d.txt", i);

        FILE *encrypted_fp;
        FILE *plaintext_fp;
        encrypted_fp = fopen(encrypted_filename, "rb");
        plaintext_fp = fopen(plaintext_filename, "rb");

        // Compare each block.
        for (int j = 0; j < TOTAL_BLOCK_NUM; j++) {
            // Move file pointer to the block's first index
            fseek(encrypted_fp,
                  encrypted_file_metadata[i].block_metadata[j].first_index,
                  SEEK_SET);
            unsigned char read_encrypted_buf
                [encrypted_file_metadata[i].block_metadata[j].length];
            // Read the file pointer and save it to the buffer
            fread(read_encrypted_buf,
                  encrypted_file_metadata[i].block_metadata[j].length, 1,
                  encrypted_fp);

            // Same for plaintext file for comparison.
            fseek(plaintext_fp,
                  plaintext_file_metadata[i].block_metadata[j].first_index,
                  SEEK_SET);
            unsigned char read_plaintext_buf
                [plaintext_file_metadata[i].block_metadata[j].length];
            fread(read_plaintext_buf,
                  plaintext_file_metadata[i].block_metadata[j].length, 1,
                  plaintext_fp);

            unsigned int decrypted_length;
            unsigned char *decrypted;
            // if (decrypt_buf_with_session_key(
            //         &s_key_list->s_key[i], read_encrypted_buf,
            //         encrypted_file_metadata[i].block_metadata[j].length,
            //         &decrypted, &decrypted_length)) {
            //     printf("Decryption failed!\n");
            //     break;
            // }
            // No HMAC mode.
            if (decrypt_buf_with_session_key_no_hmac(
                    &s_key_list->s_key[i], read_encrypted_buf,
                    encrypted_file_metadata[i].block_metadata[j].length,
                    &decrypted, &decrypted_length)) {
                printf("Decryption failed!\n");
                break;
            }

            // Compare original buffer and reopened buffer.
            if (!memcmp(read_plaintext_buf, decrypted, decrypted_length)) {
                printf(
                    "Checked file encrypted%d.txt's block: %d. Decrypted "
                    "blocks and original plaintext blocks are same!\n",
                    i, j);
            } else {
                printf(
                    "Checked file encrypted%d.txt's block: %d. Decrypted "
                    "blocks and original plaintext blocks are different!\n",
                    i, j);
            }
        }
        fclose(encrypted_fp);
        fclose(plaintext_fp);
    }
    fclose(encrypted_metadata_fp);
    fclose(plaintext_metadata_fp);
    // Free memory.
    free_SST_ctx_t(ctx);
}
