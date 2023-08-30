#include "../ipfs.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        error_exit("Enter config path");
    }
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    INIT_SESSION_KEY_LIST(s_key_list);
    ctx->purpose_index = 0;
    
    char file_name[BUFF_SIZE];
    unsigned char received_skey_id[SESSION_KEY_ID_SIZE];
    estimate_time_t total_time[5];
    for(int i = 0; i < 5; i++) {

        download_from_file_system_manager(&received_skey_id[0], ctx, &file_name[0], &total_time[i]);
        print_buf(received_skey_id, 8);
        struct timeval start, end;
        float time_interval;
        gettimeofday(&start, NULL);
        session_key_t *session_key = get_session_key_by_ID(&received_skey_id[0], ctx, &s_key_list);
        gettimeofday(&end, NULL);
        float usec = (end.tv_usec - start.tv_usec);
        total_time[i].keygenerate_time = (end.tv_sec - start.tv_sec) + usec / 1000000;
        if (session_key == NULL) {
            error_return_null("There is no session key.\n");
        } else {
            sleep(5);
            struct timeval start1, end1;
            float time_interval1;
            gettimeofday(&start1, NULL);
            file_download_decrypt(*session_key, &file_name[0]);
            gettimeofday(&end1, NULL);
            float usec1 = (end1.tv_usec - start1.tv_usec);
            total_time[i].enc_dec_time = (end1.tv_sec - start1.tv_sec) + usec1 / 1000000;
        }

        printf("download from filesystem manager %lf\n", total_time[i].filemanager_time);
        printf("download the file from IPFS %lf\n", total_time[i].up_download_time);
        printf("key generate %lf\n", total_time[i].keygenerate_time);
        printf("decrypt the file %lf\n", total_time[i].enc_dec_time);

        sleep(3);

    }
    // char file_name1[BUFF_SIZE];
    // unsigned char received_skey_id1[SESSION_KEY_ID_SIZE];
    // download_from_file_system_manager(&received_skey_id1[0], ctx, &file_name1[0]);
    // session_key_t *session_key1 = get_session_key_by_ID(&received_skey_id1[0], ctx, &s_key_list);
    // sleep(5);
    // file_download_decrypt(*session_key1, &file_name1[0]);

    free_SST_ctx_t(ctx);
}
