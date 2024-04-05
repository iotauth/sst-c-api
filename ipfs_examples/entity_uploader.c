#include "../ipfs.h"

int main(int argc, char* argv[]) {
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);
    
    FILE* add_reader_file = fopen(add_reader_path,"r");
    char addReader[64];
    if (add_reader_file == NULL) {
        fputs("Cannot open file.", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    while(fgets(addReader, sizeof(addReader), add_reader_file) != NULL) {
        send_add_reader_req_via_TCP(ctx, addReader);
    }
    fclose(add_reader_file);
    // Set purpose to make session key request for file sharing.
    ctx->config->purpose_index = 1;
    estimate_time_t estimate_time[5];
    struct timeval keygen_start, keygen_end;
    float time_interval;
    gettimeofday(&keygen_start, NULL);
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    gettimeofday(&keygen_end, NULL);
    float keygen_time = keygen_end.tv_sec - keygen_start.tv_sec;
    float keygen_utime = keygen_end.tv_usec - keygen_start.tv_usec;
    estimate_time[0].keygenerate_time = keygen_time + keygen_utime / 1000000;
    sleep(1);
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len;

    char* filename="Upload_result.csv";
    FILE* file;
    file = fopen(filename, "r");
    if(file){
        fclose(file);
    } else {
        file = fopen(filename, "w");
        fprintf(file, "upload_time,keygenerate_time,enc_time,filemanager_time\n");   // columns
        fclose(file);
    }
    
    file = fopen(filename, "a");
    for(int i = 0; i < ctx->config->numkey; i++) {
        if (i != 0) {
            estimate_time[i].keygenerate_time = 0;
        }
        hash_value_len = file_encrypt_upload(&s_key_list_0->s_key[i], ctx, my_file_path, &hash_value[0], &estimate_time[i]);
        sleep(1);
        struct timeval filemanager_start, filemanager_end;
        gettimeofday(&filemanager_start, NULL);
        upload_to_file_system_manager(&s_key_list_0->s_key[i], ctx, &hash_value[0], hash_value_len);
        gettimeofday(&filemanager_end, NULL);
        float filemanager_time = filemanager_end.tv_sec - filemanager_start.tv_sec;
        float filemanager_utime = filemanager_end.tv_usec - filemanager_start.tv_usec;
        estimate_time[i].filemanager_time = filemanager_time + filemanager_utime / 1000000;

        printf("Time for sending the data to filesystem manager %lf\n", estimate_time[i].filemanager_time);
        printf("Time for uploading the file to IPFS %lf\n", estimate_time[i].up_download_time);
        printf("Time for key generation %lf\n", estimate_time[i].keygenerate_time);
        printf("Time for encrypting the file %lf\n", estimate_time[i].enc_dec_time);
        fprintf(file, "%.6f,%.6f,%.6f,%.6f\n", estimate_time[i].up_download_time, estimate_time[i].keygenerate_time, estimate_time[i].enc_dec_time, estimate_time[i].filemanager_time);
        sleep(5);

    }
    fclose(file);

    free_SST_ctx_t(ctx);
}