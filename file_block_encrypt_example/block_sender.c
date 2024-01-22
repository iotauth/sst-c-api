#include <strings.h>  // bzero()

#include "../c_api.h"

#define MAX_SIZE 1000
#define IV_SIZE AES_CBC_128_IV_SIZE

#define MAX_PLAINTEXT_BLOCK_SIZE 32768  // 32kbytes
#define MAX_KEY_VALUE_SIZE 144
#define MIN_KEY_VALUE_SIZE 56

#define TOTAL_BLOCK_NUM 10
#define TOTAL_FILE_NUM 3

typedef struct {
    unsigned long int first_index;
    unsigned int length;
} block_metadata_t;

typedef struct {
    session_key_t *s_key;
    block_metadata_t block_metadata[TOTAL_BLOCK_NUM];
} file_metadata_t;

int main(int argc, char *argv[]) {
    // int block_num;
    // printf("How many random blocks do you want? \n");
    // scanf("%d", &block_num);
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    // This will bring 3 keys. It is changable in the config file's
    // entityInfo.number_key=3
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);

    // Initialization of RAND, should only be called once.
    srand((unsigned int)time(NULL));

    file_metadata_t encrypted_file_metadata[TOTAL_FILE_NUM];
    file_metadata_t plaintext_file_metadata[TOTAL_FILE_NUM];

    char encrypted_metadata_filename = "encrypted_file_metadata";
    char plaintext_metadata_filename = "plaintext_file_metadata";
    FILE *encrypted_metadata_fp;
    FILE *plaintext_metadata_fp;
    encrypted_metadata_fp = fopen(encrypted_metadata_filename, "wb");
    plaintext_metadata_fp = fopen(plaintext_metadata_filename, "wb");

    // Create three files.
    for (int i = 0; i < TOTAL_FILE_NUM; i++) {
        encrypted_file_metadata[i].s_key = &s_key_list->s_key[i];
        char encrypted_filename[15];
        sprintf(encrypted_filename, "encrypted%d.txt", i);
        char plaintext_filename[15];
        sprintf(plaintext_filename, "plaintext%d.txt", i);

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

            // Create random key value buffers.
            while (total_block_size < MAX_PLAINTEXT_BLOCK_SIZE) {
                // Create random int between 56~144
                int plaintext_buf_length =
                    rand() % (MAX_KEY_VALUE_SIZE + 1 - MIN_KEY_VALUE_SIZE) +
                    MIN_KEY_VALUE_SIZE;
                // This buffer contains a single key_value.
                unsigned char
                    plaintext_buf[plaintext_buf_length];  // Variable Length
                                                          // Arrays work from
                                                          // C99

                // Insert random bytes inside buffer.
                RAND_bytes(plaintext_buf, plaintext_buf_length);

                // If the block size exceeds MAX_PLAINTEXT_BLOCK_SIZE after
                // adding the next block, it should be saved to the next block.
                // The leftover space should be filled with zero padding.
                if (total_block_size + plaintext_buf_length >
                    MAX_PLAINTEXT_BLOCK_SIZE) {
                    // Add zero padding to the end of the plaintext_block_buf.
                    bzero(plaintext_block_buf + total_block_size,
                          MAX_PLAINTEXT_BLOCK_SIZE - total_block_size);
                    printf("Add zero paddings for the leftover %d bytes.\n",
                           MAX_PLAINTEXT_BLOCK_SIZE - total_block_size);
                    // Now the total_block_size becomes the
                    // MAX_PLAINTEXT_BLOCK_SIZE.
                    total_block_size +=
                        MAX_PLAINTEXT_BLOCK_SIZE - total_block_size;
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

            // Encrypt plaintext block.
            unsigned int encrypted_length;
            unsigned char *encrypted = symmetric_encrypt_authenticate(
                plaintext_block_buf, total_block_size,
                encrypted_file_metadata[i].s_key->mac_key,
                encrypted_file_metadata[i].s_key->mac_key_size,
                encrypted_file_metadata[i].s_key->cipher_key,
                encrypted_file_metadata[i].s_key->cipher_key_size, IV_SIZE,
                &encrypted_length);

            // Save the encrypted block.
            fwrite(encrypted, encrypted_length, 1, encrypted_fp);
            encrypted_file_metadata[i].block_metadata[j].length =
                encrypted_length;
            printf("Wrote encrypted block %d\n", j);
        }
        fclose(plaintext_fp);
        fclose(encrypted_fp);
        printf("Finished writing encrypted blocks to encrypted%d.txt\n", i);
    }
    fwrite(&encrypted_file_metadata, sizeof(file_metadata_t), 1, encrypted_metadata_fp);
    fwrite(&plaintext_file_metadata, sizeof(file_metadata_t), 1, plaintext_metadata_fp);
    fclose(encrypted_metadata_fp);
    fclose(plaintext_metadata_fp);
    // Free memory.
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);


    ///////////////////// Decrypt and compare with plaintext
    /////////////////////////////////////

    // Read files.
    for (int i = 0; i < TOTAL_FILE_NUM; i++) {
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

            // Decrypt read_encrypted_buf.
            unsigned int decrypted_length;
            unsigned char *decrypted = symmetric_decrypt_authenticate(
                read_encrypted_buf,
                encrypted_file_metadata[i].block_metadata[j].length,
                encrypted_file_metadata[i].s_key->mac_key,
                encrypted_file_metadata[i].s_key->mac_key_size,
                encrypted_file_metadata[i].s_key->cipher_key,
                encrypted_file_metadata[i].s_key->cipher_key_size, IV_SIZE,
                &decrypted_length);

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
}
