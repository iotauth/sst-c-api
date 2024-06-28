#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../c_api.h"

void *send_request(void *SST_ctx) {
    SST_ctx_t *ctx = (SST_ctx_t *)SST_ctx;
    session_key_list_t *s_key_list;
    for(int i = 0; i < MAX_SESSION_KEY; i ++) {
        pthread_mutex_lock(&ctx->mutex);
        s_key_list = get_session_key(ctx, s_key_list);
        pthread_mutex_unlock(&ctx->mutex);
    }
    free_session_key_list_t(s_key_list);
}

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    // Request one session key to just ensure got distribution key.
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    sleep(2);
    int num_threads = 100;
    pthread_t thread[num_threads];
    for (int i = 0; i < 100; i++) {
        pthread_create(&thread[i], NULL, &send_request, (void *)ctx);
    }
    for (int i = 0; i< 100; i++) {
        pthread_join(thread[i], NULL);
    }
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}
