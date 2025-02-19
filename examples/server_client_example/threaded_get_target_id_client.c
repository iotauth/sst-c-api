
/**
 * @file threaded_get_target_id_client.c
 * @author Dongha Kim
 * @brief Get multiple keys and save the session key id as metadata.
 * Gets multiple session keys, and save the IDs to a metadata file respectively.
 * @copyright Copyright (c) 2025
 *
 */
#include <stdio.h>

#include "../../c_api.h"

void write_session_key_to_file(session_key_t *s_key, const char *file_path) {
    FILE *fp = fopen(file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open file %s for writing\n",
                file_path);
        return;
    }
    fwrite(s_key->key_id, SESSION_KEY_ID_SIZE, 1, fp);
    fclose(fp);
}

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);

    const char *file_paths[] = {"s_key_id0.dat", "s_key_id1.dat",
                                "s_key_id2.dat"};

    for (int i = 0; i < 3; i++) {
        write_session_key_to_file(&s_key_list->s_key[i], file_paths[i]);
    }

    return 0;
}