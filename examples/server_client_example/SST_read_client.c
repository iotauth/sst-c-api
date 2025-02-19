#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../c_api.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fputs("Enter config path", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        printf("Failed to get session key. Returning NULL.\n");
        exit(1);
    }
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    SST_write(session_ctx, "Hello server", strlen("Hello server"));
    sleep(1);
    SST_write(session_ctx, "Hello server - second message",
              strlen("Hello server - second message"));
    free_SST_session_ctx_t(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}
