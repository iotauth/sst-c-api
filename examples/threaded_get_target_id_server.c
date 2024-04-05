#include "../c_api.h"
#include <stdio.h>

void *call_get_session_key_by_ID0(void* SST_ctx){
    SST_ctx_t *ctx = (SST_ctx_t *)SST_ctx;
    session_key_list_t *s_key_list = init_empty_session_key_list();

    char *file_path0 = "s_key_id0.dat";
    FILE *fp0 = fopen(file_path0, "rb");
    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    fread(target_session_key_id, SESSION_KEY_ID_SIZE, 1, fp0);
    printf("Session Key ID: %s\n", target_session_key_id);
    // pthread_mutex_lock(&ctx->mutex);
    pthread_mutex_lock(&ctx->mutex);
    session_key_t *session_key = get_session_key_by_ID(target_session_key_id, ctx, s_key_list);
    pthread_mutex_unlock(&ctx->mutex);
    printf("Session Key ID: %s\n", session_key->key_id);
}

void *call_get_session_key_by_ID1(void* SST_ctx){
    SST_ctx_t *ctx = (SST_ctx_t *)SST_ctx;
    session_key_list_t *s_key_list = init_empty_session_key_list();

    char *file_path0 = "s_key_id1.dat";
    FILE *fp0 = fopen(file_path0, "rb");
    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    fread(target_session_key_id, SESSION_KEY_ID_SIZE, 1, fp0);
    printf("Session Key ID: %s\n", target_session_key_id);
    // pthread_mutex_lock(&ctx->mutex);
    pthread_mutex_lock(&ctx->mutex);
    session_key_t *session_key = get_session_key_by_ID(target_session_key_id, ctx, s_key_list);
    pthread_mutex_unlock(&ctx->mutex);
    printf("Session Key ID: %s\n", session_key->key_id);
}

void *call_get_session_key_by_ID2(void* SST_ctx){
    SST_ctx_t *ctx = (SST_ctx_t *)SST_ctx;
    session_key_list_t *s_key_list = init_empty_session_key_list();

    char *file_path0 = "s_key_id2.dat";
    FILE *fp0 = fopen(file_path0, "rb");
    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    fread(target_session_key_id, SESSION_KEY_ID_SIZE, 1, fp0);
    printf("Session Key ID: %s\n", target_session_key_id);
    // pthread_mutex_lock(&ctx->mutex);
    pthread_mutex_lock(&ctx->mutex);
    session_key_t *session_key = get_session_key_by_ID(target_session_key_id, ctx, s_key_list);
    pthread_mutex_unlock(&ctx->mutex);
    printf("Session Key ID: %s\n", session_key->key_id);
}

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    pthread_mutex_init(&ctx->mutex, NULL);
    pthread_t thread0, thread1, thread2;
    pthread_create(&thread0, NULL, &call_get_session_key_by_ID0,
                   (void *)ctx);
    pthread_create(&thread1, NULL, &call_get_session_key_by_ID1,
                   (void *)ctx);
    pthread_create(&thread2, NULL, &call_get_session_key_by_ID2,
                   (void *)ctx);
    pthread_join(thread0, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    // session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    // char *file_path0 = "s_key_id0.dat";
    // FILE *fp0 = fopen(file_path0, "wb");
    // fwrite(s_key_list->s_key->key_id, SESSION_KEY_ID_SIZE, 1, fp0);
    // fclose(fp0);

    // char *file_path1 = "s_key_id1.dat";
    // FILE *fp1 = fopen(file_path1, "wb");
    // fwrite(s_key_list->s_key->key_id, SESSION_KEY_ID_SIZE, 1, fp1);
    // fclose(fp1);

    // char *file_path2 = "s_key_id2.dat";
    // FILE *fp2 = fopen(file_path2, "wb");
    // fwrite(s_key_list->s_key->key_id, SESSION_KEY_ID_SIZE, 1, fp2);
    // fclose(fp2);
}
