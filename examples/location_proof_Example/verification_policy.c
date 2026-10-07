#include "verification_policy.h"

#include <stdio.h>
#include <stdlib.h>


char *load_verification_policy(const char *path){
    FILE *file = fopen(path, "rb");

    if(file == NULL){
        return NULL;
    }

    if(fseek(file, 0, SEEK_END) != 0){
        fclose(file);
        return NULL;
    }

    long size = ftell(file);

    if(size < 0){
        fclose(file);
        return NULL;
    }

    rewind(file);

    char *buffer = malloc((size_t)size + 1);

    if(buffer == NULL){
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(buffer, 1, (size_t)size, file);

    fclose(file);

    if(bytes_read != (size_t)size){
        free(buffer);
        return NULL;
    }

    buffer[size] = '\0';

    return buffer;
}

void free_verification_policy(char *policy){
    free(policy);
}