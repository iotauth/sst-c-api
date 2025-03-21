#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../../ipfs.h"

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

    const char *filename = "Download_result.csv";
    FILE *file;
    file = fopen(filename, "r");
    if (file) {
        fclose(file);
    } else {
        file = fopen(filename, "w");
        fprintf(
            file,
            "download_time,keygenerate_time,dec_time,filemanager_time\n");  // columns
        fclose(file);
    }

    file = fopen(filename, "a");
    for (int i = 0; i < 5; i++) {
        receive_data_and_download_file(&received_skey_id[0], ctx, &file_name[0],
                                       &estimate_time[i]);
        
        session_key_t *session_key =
            get_session_key_by_ID(&received_skey_id[0], ctx, s_key_list);
        
        if (session_key == NULL) {
            fputs("There is no session key.\n", stderr);
            fputc('\n', stderr);
            exit(1);
        } else {
            sleep(5);
        }
        sleep(3);
    }


    
    fclose(file);
    free_SST_ctx_t(ctx);
}
