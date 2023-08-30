#include "../ipfs.h"

int main(int argc, char* argv[]) {
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);
    
    FILE* add_reader_file = fopen(add_reader_path,"r");
    char addReader[64];
    if (add_reader_file == NULL) {
        error_exit("Cannot open file.\n");
        exit(1);
    }
    while(fgets(addReader, sizeof(addReader), add_reader_file) != NULL) {
        send_add_reader_req_via_TCP(ctx, addReader);
    }
    fclose(add_reader_file);
    
    // Set purpose to make session key request for file sharing.
    ctx->purpose_index = 1;
    estimate_time_t total_time[5];
    struct timeval start, end;
    float time_interval;
    gettimeofday(&start, NULL);
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    gettimeofday(&end, NULL);
    float usec = (end.tv_usec - start.tv_usec);
    total_time[0].keygenerate_time = (end.tv_sec - start.tv_sec) + usec / 1000000;
    sleep(1);

    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len;
    for(int i = 0; i < ctx->config->numkey; i++) {
        if (i != 0) {
            total_time[i].keygenerate_time = 0;
        }
        hash_value_len = file_encrypt_upload(&s_key_list_0->s_key[i], ctx, my_file_path, &hash_value[0], &total_time[i]);
        sleep(1);
        struct timeval start1, end1;
        float time_interval1;
        gettimeofday(&start1, NULL);
        upload_to_file_system_manager(&s_key_list_0->s_key[i], ctx, &hash_value[0], hash_value_len);
        gettimeofday(&end1, NULL);
        float usec1 = (end1.tv_usec - start1.tv_usec);
        total_time[i].filemanager_time = (end1.tv_sec - start1.tv_sec) + usec1 / 1000000;
        printf("download from filesystem manager %lf\n", total_time[i].filemanager_time);
        printf("download the file from IPFS %lf\n", total_time[i].up_download_time);
        printf("key generate %lf\n", total_time[i].keygenerate_time);
        printf("decrypt the file %lf\n", total_time[i].enc_dec_time);
        sleep(5);

    }

    // unsigned char hash_value1[BUFF_SIZE];
    // int hash_value_len1 = file_encrypt_upload(&s_key_list_0->s_key[1], ctx, my_file_path, &hash_value1[0]);
    // sleep(1);
    // upload_to_file_system_manager(&s_key_list_0->s_key[1], ctx, &hash_value1[0], hash_value_len1);

    free_SST_ctx_t(ctx);
}