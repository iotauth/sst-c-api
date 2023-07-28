
#include "ipfs.h"

void ipfs_add_command_save_result()
{
    char buff[BUFF_SIZE];
    FILE *fp, *fout_0;
    char *file_name = "enc.txt";
    fp = popen("ipfs add enc.txt", "r");
    if (NULL == fp)
    {
            perror("popen() failed");
    }
    while (fgets(buff, BUFF_SIZE, fp))
        printf("%s\n", buff);
    pclose(fp);
    system("rm -rf enc.txt");
    printf("Delete enc.txt\n");
    char * result;
    strtok(buff, " ");
    result = strtok(NULL, " ");

    unsigned char *buffer = NULL;
    buffer = malloc(sizeof(char)* strlen(result));
    memcpy(buffer,result,strlen(result));    
    printf("Hash value: %s\n", buffer);
    fout_0 = fopen("hash_result.txt", "w");
    fwrite(buffer, 1, strlen(result), fout_0);
    fclose(fout_0);
}


void file_encrypt_upload(SST_session_ctx_t *session_ctx)
{
    FILE *fgen,*fin, *fout, *fenc;
    unsigned int cipher_key_size = 16;
    // fgen = popen()
    fin = fopen("../plain_text.txt","r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    if (fin == NULL) {
        // error handling
        exit(1);
    }

    if (fin != NULL) {

        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));

            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; 
            }
        }
    }
    fclose(fin);
    unsigned char iv[AES_CBC_128_IV_SIZE];
    unsigned char prov_info[] = "yeongbin";
    int prov_info_len = sizeof(prov_info);
    unsigned int encrypted_length = (((bufsize) / AES_CBC_128_IV_SIZE) + 1) * AES_CBC_128_IV_SIZE;
    unsigned char *encrypted = (unsigned char *)malloc(encrypted_length);
    generate_nonce(AES_CBC_128_IV_SIZE, iv);
    AES_CBC_128_encrypt(file_buf, bufsize, session_ctx->s_key.cipher_key, cipher_key_size, iv,
                        AES_CBC_128_IV_SIZE, encrypted, &encrypted_length);
    char *file_name = "enc.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s File already exists.\n", file_name);
    }
    else
    {
        fenc = fopen("enc.txt", "w");
    }
    unsigned char * enc_save = (unsigned char *) malloc(encrypted_length+1+AES_CBC_128_IV_SIZE+1+prov_info_len);
    enc_save[0] = prov_info_len;
    memcpy(enc_save+1,prov_info,prov_info_len);
    enc_save[prov_info_len+1] = AES_CBC_128_IV_SIZE;
    memcpy(enc_save+1+prov_info_len+1,iv,AES_CBC_128_IV_SIZE);
    memcpy(enc_save+1+prov_info_len+1+AES_CBC_128_IV_SIZE,encrypted,encrypted_length);
    fwrite(enc_save, 1, encrypted_length+1+AES_CBC_128_IV_SIZE+1+prov_info_len, fenc);
    fclose(fenc);
    sleep(1);
    ipfs_add_command_save_result();
}

void file_download_decrypt(SST_session_ctx_t *session_ctx)
{
    unsigned int cipher_key_size = 16;
    FILE *fp, *fin, *fout;
    fin = fopen("enc_server.txt","r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    if (fin != NULL) {
        
        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));
            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; 
            }
        }
    fclose(fin);
    }    
    unsigned int prov_info_num = file_buf[0];
    unsigned int iv_size = file_buf[1+prov_info_num];
    unsigned char prov_info[prov_info_num];
    memcpy(prov_info,file_buf+1,prov_info_num);
    unsigned char iv[iv_size];
    memcpy(iv,file_buf+1+prov_info_num+1,iv_size);

    unsigned long int enc_length = bufsize - (1+AES_CBC_128_IV_SIZE+1+prov_info_num);

    unsigned int ret_length = (enc_length + iv_size) / iv_size * iv_size;
    unsigned char *ret = (unsigned char *)malloc(ret_length);
    sleep(1);
    AES_CBC_128_decrypt(file_buf+1+AES_CBC_128_IV_SIZE+1+prov_info_num, enc_length, session_ctx->s_key.cipher_key, cipher_key_size, iv,
                        iv_size, ret, &ret_length);

    fout = fopen("rpi_result.txt", "w");
    printf("Complete decryption and save the file as rpi_result.txt \n");
    fwrite(ret, 1,ret_length, fout);
    free(ret);
    fclose(fout);

}

void upload_to_datamanagement(SST_session_ctx_t *session_ctx, SST_ctx_t *ctx)
{
    int sock;
    connect_as_client((const char *)ctx->config->datamanagement_ip_addr,
                      (const char *)ctx->config->datamanagement_port_num, &sock);
    int key_id_size, name_size, purpose_size;
    key_id_size = sizeof(session_ctx->s_key.key_id);
    name_size = sizeof(ctx->config->name);
    purpose_size = strlen(ctx->config->purpose[ctx->purpose_index]);

    int DATA_UPLOAD = 0;
    char buff[BUFF_SIZE];
    FILE *fin;
    char *file_name = "hash_result.txt";
    fin = fopen(file_name,"r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    if (fin != NULL) {
        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));
            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; 
            }
        }
    }
    fclose(fin);
    unsigned char data[MAX_PAYLOAD_LENGTH];
    data[0] = DATA_UPLOAD;
    data[1] = name_size;
    memcpy(data+2,ctx->config->name, name_size);
    data[2+name_size] = key_id_size;
    memcpy(data+3+name_size,session_ctx->s_key.key_id,key_id_size);
    data[3+name_size+key_id_size] = bufsize;
    memcpy(data+4+name_size+key_id_size, file_buf , bufsize);
    write(sock,data,4 + name_size + key_id_size + bufsize);
    printf("Send the data such as sessionkey id, name.\n");

}

void download_from_datamanagement(SST_session_ctx_t *session_ctx, SST_ctx_t *ctx)
{
    int sock;
    connect_as_client((const char *)ctx->config->datamanagement_ip_addr,
                      (const char *)ctx->config->datamanagement_port_num, &sock);
    int DATA_DOWNLOAD = 1;
    int name_size;
    name_size = sizeof(ctx->config->name);
    unsigned char data[MAX_PAYLOAD_LENGTH];
    data[0] = DATA_DOWNLOAD;
    data[1] = name_size;
    memcpy(data+2,ctx->config->name, name_size);

    write(sock, data, 2 + name_size);
    sleep(3);
    unsigned char received_buf[128];
    unsigned int received_buf_length =
        read(sock, received_buf, sizeof(received_buf));
    printf("Receive the information.\n");
    unsigned char *key_id = NULL;
    int key_id_size, command_size;
    key_id_size = received_buf[1];
    command_size = received_buf[2+key_id_size];

    key_id = malloc(sizeof(char) * (key_id_size + 1));
    memcpy(key_id,received_buf+2,key_id_size);
    unsigned char command[100];
    memcpy(command,received_buf+3+key_id_size,command_size);
    printf("Command: %s \n", command);

    unsigned int cipher_key_size = 16;
    FILE *fp, *fin, *fout;
    char *file_name = "enc_server.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s file already exists. \n", file_name);         
        fp = popen("rm enc_server.txt","r");
        pclose(fp);
    }
    fin = popen(command, "r");
    printf("Download the enc_server.txt file\n");
    pclose(fin);
}