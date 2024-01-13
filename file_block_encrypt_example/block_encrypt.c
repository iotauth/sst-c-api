#include "../c_api.h"

#define MAX_SIZE 1000

typedef struct {
    unsigned long int first_index;
    unsigned int length;
} block_metadata_t;

int main(int argc, char *argv[]) {
    unsigned int iv_size = AES_CBC_128_IV_SIZE;

    int block_num;
    printf("How many random blocks do you want? \n");
    scanf("%d", &block_num);
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    // This will bring 3 keys. It is changable in the config file's
    // entityInfo.number_key=3

    // Create Random bytes.
    // Initialization, should only be called once.
    srand((unsigned int)time(NULL));
    char *encrypted_filename = "encrypted.txt";
    char *plaintext_filename =
        "plaintext.txt";  // For comparison if the decryption worked well.
    // Initiate metadata struct.
    block_metadata_t encrypted_block_metadata[block_num];
    block_metadata_t plaintext_block_metadata[block_num];

    for (int i = 0; i < block_num; i++) {
        FILE *encrypted_fp;
        FILE *plaintext_fp;
        if (i == 0) {
            encrypted_fp = fopen(encrypted_filename, "wb");
            plaintext_fp = fopen(plaintext_filename, "wb");
        } else {
            encrypted_fp = fopen(encrypted_filename, "ab");
            plaintext_fp = fopen(plaintext_filename, "ab");
        }
        if (encrypted_fp == NULL || plaintext_fp == NULL) {
            perror("Failed: ");
            return 1;
        }
        // Check the current fp's position.
        encrypted_block_metadata[i].first_index = ftell(encrypted_fp);

        // Create random int between 1~100
        int plaintext_buf_length = rand() % 100 + 1;
        unsigned char
            plaintext_buf[plaintext_buf_length];  // Variable Length Arrays work
                                                  // from C99

        // Insert random bytes inside buffer.
        int x = RAND_bytes(plaintext_buf, plaintext_buf_length);
        if (x == -1) {
            printf("Failed to create Random Nonce");
            exit(1);
        } else {
            printf("Size of the plaintext buffer is : %d\n",
                   plaintext_buf_length);
        }

        // For future comparison.
        plaintext_block_metadata[i].first_index = ftell(plaintext_fp);
        plaintext_block_metadata[i].length = plaintext_buf_length;
        fwrite(plaintext_buf, plaintext_buf_length, 1, plaintext_fp);
        fclose(plaintext_fp);

        unsigned int encrypted_length;
        unsigned char *encrypted = symmetric_encrypt_authenticate(
            plaintext_buf, plaintext_buf_length, s_key_list[0].s_key->mac_key,
            s_key_list[0].s_key->mac_key_size, s_key_list[0].s_key->cipher_key,
            s_key_list[0].s_key->cipher_key_size, iv_size, &encrypted_length);

        // Record the block's length.
        encrypted_block_metadata[i].length = encrypted_length;

        // Write to file.
        fwrite(encrypted, encrypted_length, 1, encrypted_fp);
        printf("Wrote encrypted buffer to file.\n");
        // Close file.
        fclose(encrypted_fp);
    }

    while (1) {
        int input;
        printf("Which block would you like to compare? \n Press -1 to exit.\n");
        scanf("%d", &input);
        if (input < 0) {
            break;
        } else if (input >= block_num) {
            printf("Largest block index is %d, please reenter the index.",
                   block_num - 1);
        } else {
            FILE *encrypted_fp = fopen(encrypted_filename, "rb");
            FILE *plaintext_fp = fopen(plaintext_filename, "rb");
            if (encrypted_fp == NULL || plaintext_fp == NULL) {
                perror("Failed: ");
                return 1;
            }

            // Move file pointer to the block's first index
            fseek(encrypted_fp, encrypted_block_metadata[input].first_index,
                  SEEK_SET);
            unsigned char
                read_encrypted_buf[encrypted_block_metadata[input].length];
            // Read the file pointer and save it to the buffer
            fread(read_encrypted_buf, encrypted_block_metadata[input].length, 1,
                  encrypted_fp);

            // Same for plaintext file for comparison.
            fseek(plaintext_fp, plaintext_block_metadata[input].first_index,
                  SEEK_SET);
            unsigned char
                read_plaintext_buf[encrypted_block_metadata[input].length];
            fread(read_plaintext_buf, plaintext_block_metadata[input].length, 1,
                  plaintext_fp);

            // Decrypt read_encrypted_buf.
            unsigned int decrypted_length;
            unsigned char *decrypted = symmetric_decrypt_authenticate(
                read_encrypted_buf, encrypted_block_metadata[input].length,
                s_key_list[0].s_key->mac_key, s_key_list[0].s_key->mac_key_size,
                s_key_list[0].s_key->cipher_key,
                s_key_list[0].s_key->cipher_key_size, iv_size,
                &decrypted_length);

            // Compare original buffer and reopened buffer.
            if (!memcmp(read_plaintext_buf, decrypted, decrypted_length)) {
                printf("Buffers are same!\n\n");
            } else {
                printf("Buffers are different!\n\n");
            }
            fclose(encrypted_fp);
            fclose(plaintext_fp);
        }
    }
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}
