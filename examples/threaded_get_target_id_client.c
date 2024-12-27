#include "../c_api.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    char *file_path0 = "s_key_id0.dat";
    FILE *fp0 = fopen(file_path0, "wb");
    fwrite(s_key_list->s_key[0].key_id, SESSION_KEY_ID_SIZE, 1, fp0);
    fclose(fp0);

    char *file_path1 = "s_key_id1.dat";
    FILE *fp1 = fopen(file_path1, "wb");
    fwrite(s_key_list->s_key[1].key_id, SESSION_KEY_ID_SIZE, 1, fp1);
    fclose(fp1);

    char *file_path2 = "s_key_id2.dat";
    FILE *fp2 = fopen(file_path2, "wb");
    fwrite(s_key_list->s_key[2].key_id, SESSION_KEY_ID_SIZE, 1, fp2);
    fclose(fp2);
}
