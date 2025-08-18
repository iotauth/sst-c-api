#include "block_common.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    // This will bring 3 keys. It is changable in the config file's
    // entityInfo.number_key=3
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }

    // Initialization of RAND, should only be called once.
    srand((unsigned int)time(NULL));

    file_metadata_t encrypted_file_metadata[TOTAL_FILE_NUM];
    file_metadata_t plaintext_file_metadata[TOTAL_FILE_NUM];

    char *encrypted_metadata_filename = "encrypted_file_metadata.dat";
    char *plaintext_metadata_filename = "plaintext_file_metadata.dat";
    FILE *encrypted_metadata_fp;
    FILE *plaintext_metadata_fp;
    encrypted_metadata_fp = fopen(encrypted_metadata_filename, "wb");
    plaintext_metadata_fp = fopen(plaintext_metadata_filename, "wb");

    // Create three files.
    for (int i = 0; i < TOTAL_FILE_NUM; i++) {
        // Reset temporary buf. It will be used for the leftover buffers, when
        // the total block size exceeds the available block size. It will be
        // saved in the next block. However, if the file is full, the leftover
        // buffer will not be moved to the next file.
        int temp_buf_length = 0;
        unsigned char temp_buf[MAX_KEY_VALUE_SIZE];

        memcpy(encrypted_file_metadata[i].key_id, s_key_list->s_key[i].key_id,
               SESSION_KEY_ID_SIZE);
        char encrypted_filename[BLOCK_FILE_NAME_MAX_LENGTH + 1];
        snprintf(encrypted_filename, sizeof(encrypted_filename),
                 "encrypted%d.txt", i);
        char plaintext_filename[BLOCK_FILE_NAME_MAX_LENGTH + 1];
        snprintf(plaintext_filename, sizeof(plaintext_filename),
                 "plaintext%d.txt", i);

        FILE *encrypted_fp;
        FILE *plaintext_fp;
        encrypted_fp = fopen(encrypted_filename, "wb");
        plaintext_fp = fopen(plaintext_filename, "wb");
        // Create blocks.
        for (int j = 0; j < TOTAL_BLOCK_NUM; j++) {
            encrypted_file_metadata[i].block_metadata[j].first_index =
                ftell(encrypted_fp);
            plaintext_file_metadata[i].block_metadata[j].first_index =
                ftell(plaintext_fp);

            // The buffer that will contain multiple key_values and compose a
            // single block.
            unsigned char plaintext_block_buf[MAX_PLAINTEXT_BLOCK_SIZE];
            unsigned int total_block_size = 0;

            if (temp_buf_length != 0) {
                memcpy(plaintext_block_buf, temp_buf, temp_buf_length);
                total_block_size += temp_buf_length;
            }

            // Create random key value buffers.
            while (total_block_size < MAX_PLAINTEXT_BLOCK_SIZE) {
                // Create a random integer that is >= 56 and <= 144.
                int plaintext_buf_length =
                    secure_rand(MIN_KEY_VALUE_SIZE, MAX_KEY_VALUE_SIZE);

                // This buffer contains a single key_value.
                unsigned char
                    plaintext_buf[plaintext_buf_length];  // Variable Length
                                                          // Arrays work from
                                                          // C99

                // If the block size exceeds MAX_PLAINTEXT_BLOCK_SIZE after
                // adding the next block, it should be saved to the next block.
                // The leftover space should be filled with zero padding.
                if (total_block_size + plaintext_buf_length >
                    MAX_PLAINTEXT_BLOCK_SIZE) {
                    // Add zero padding to the end of the plaintext_block_buf.
                    bzero(plaintext_block_buf + total_block_size,
                          MAX_PLAINTEXT_BLOCK_SIZE - total_block_size);
                    SST_print_log(
                        "Add zero paddings for the leftover %d bytes.",
                        MAX_PLAINTEXT_BLOCK_SIZE - total_block_size);
                    // Now the total_block_size becomes the
                    // MAX_PLAINTEXT_BLOCK_SIZE.
                    total_block_size +=
                        MAX_PLAINTEXT_BLOCK_SIZE - total_block_size;

                    // Save the created random buffer to put it into the next
                    // block.
                    temp_buf_length = plaintext_buf_length;
                    memcpy(temp_buf, plaintext_buf, temp_buf_length);
                    break;
                } else {
                    memcpy(plaintext_block_buf + total_block_size,
                           plaintext_buf, plaintext_buf_length);
                    total_block_size += plaintext_buf_length;
                }
            }

            // Save the plaintext block for future comparison.
            fwrite(plaintext_block_buf, total_block_size, 1, plaintext_fp);
            plaintext_file_metadata[i].block_metadata[j].length =
                total_block_size;

            unsigned int encrypted_length;
            unsigned char *encrypted = NULL;
            if (encrypt_buf_with_session_key(
                    &s_key_list->s_key[i], plaintext_block_buf,
                    total_block_size, &encrypted, &encrypted_length) < 0) {
                SST_print_error_exit("Encryption failed!");
            }
            // Save the encrypted block.
            fwrite(encrypted, encrypted_length, 1, encrypted_fp);
            encrypted_file_metadata[i].block_metadata[j].length =
                encrypted_length;
            free(encrypted);
            SST_print_log("Wrote encrypted block %d", j);
        }
        fclose(plaintext_fp);
        fclose(encrypted_fp);
        SST_print_log("Finished writing encrypted blocks to encrypted%d.txt",
                      i);
    }

    // Save the file_metadata.
    for (int var = 0; var < TOTAL_FILE_NUM; ++var) {
        fwrite(&encrypted_file_metadata[var], sizeof(file_metadata_t), 1,
               encrypted_metadata_fp);
        fwrite(&plaintext_file_metadata[var], sizeof(file_metadata_t), 1,
               plaintext_metadata_fp);
    }

    fclose(encrypted_metadata_fp);
    fclose(plaintext_metadata_fp);
    if (save_session_key_list(s_key_list, "s_key_list.bin") < 0) {
        SST_print_error_exit("Failed save_session_key_list().");
    }
    // Free memory.
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}
