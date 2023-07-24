#include "../c_api.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    ctx->purpose_index = 1;
    session_key_list_t *s_key_list_0 = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list_0->s_key[0], ctx);
    sleep(1);
    file_encrypt_upload(session_ctx);
    sleep(1);
    upload_to_datamanagement(session_ctx, ctx);

    free(session_ctx);

    free_SST_ctx_t(ctx);

    sleep(3);
}
