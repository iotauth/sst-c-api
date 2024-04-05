#include "../ipfs.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fputs("Enter config path", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    session_key_list_t *s_key_list = init_empty_session_key_list();
    ctx->config->purpose_index = 0;
    
    char file_name[BUFF_SIZE];
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    estimate_time_t estimate_time[5];

    char* filename="Download_result.csv";
    FILE* file;
    file = fopen(filename, "r");
    if(file){
        fclose(file);
    } else {
        file = fopen(filename, "w");
        fprintf(file, "download_time,keygenerate_time,dec_time,filemanager_time\n");   // columns
        fclose(file);
    }
    // TODO: Check number of files to be provided to me

    file = fopen(filename, "a");
    for(int i = 0; i < 5; i++) {

        receive_data_and_download_file(&received_skey_id[0], ctx, &file_name[0], &estimate_time[i]);
        print_buf(received_skey_id, 8);
        struct timeval keygen_start, keygen_end;
        gettimeofday(&keygen_start, NULL);
        session_key_t *session_key = get_session_key_by_ID(&received_skey_id[0], ctx, s_key_list);
        gettimeofday(&keygen_end, NULL);
        float keygen_time = keygen_end.tv_sec - keygen_start.tv_sec;
        float keygen_utime = keygen_end.tv_usec - keygen_start.tv_usec;
        estimate_time[i].keygenerate_time = keygen_time + keygen_utime / 1000000;
        if (session_key == NULL) {
            error_return_null("There is no session key.\n");
        } else {
            sleep(5);
            struct timeval decrypt_start, decrypt_end;
            gettimeofday(&decrypt_start, NULL);
            file_decrypt_save(*session_key, &file_name[0]);
            gettimeofday(&decrypt_end, NULL);
            float decrypt_time = decrypt_end.tv_sec - decrypt_start.tv_sec;
            float decrypt_utime = decrypt_end.tv_usec - decrypt_start.tv_usec;
            estimate_time[i].enc_dec_time = decrypt_time + decrypt_utime / 1000000;
        }

        printf("Time for receiving the data from filesystem manager %lf\n", estimate_time[i].filemanager_time);
        printf("Time for downloading the file from IPFS %lf\n", estimate_time[i].up_download_time);
        printf("Time for key generation %lf\n", estimate_time[i].keygenerate_time);
        printf("Time for decrypting the file %lf\n", estimate_time[i].enc_dec_time);
        fprintf(file, "%.6f,%.6f,%.6f,%.6f\n", estimate_time[i].up_download_time, estimate_time[i].keygenerate_time, estimate_time[i].enc_dec_time,estimate_time[i].filemanager_time);
        sleep(3);
    }
    fclose(file);
    free_SST_ctx_t(ctx);
}
