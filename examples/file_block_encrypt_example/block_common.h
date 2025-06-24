#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // bzero()

#include "../../c_api.h"

#define MAX_SIZE 1000
#define IV_SIZE AES_128_CBC_IV_SIZE

#define MAX_PLAINTEXT_BLOCK_SIZE 32768  // 32kbytes
#define MAX_KEY_VALUE_SIZE 144
#define MIN_KEY_VALUE_SIZE 56

#define TOTAL_BLOCK_NUM 10
#define TOTAL_FILE_NUM 3

#define BLOCK_FILE_NAME_MAX_LENGTH 15

typedef struct {
    unsigned long int first_index;
    unsigned int length;
} block_metadata_t;

typedef struct {
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    block_metadata_t block_metadata[TOTAL_BLOCK_NUM];
} file_metadata_t;
