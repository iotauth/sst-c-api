#ifndef IPFS_H
#define IPFS_H

#include <stdio.h>

#include "c_api.h"

#define BUFF_SIZE 100
#define UPLOAD_INDEX 0
#define DOWNLOAD_INDEX 1
#define DOWNLOAD_RESP 2
#define MAX_REPLY_NUM 100

typedef struct {
    float up_download_time;
    float keygenerate_time;
    float enc_dec_time;
    float filemanager_time;
} estimate_time_t;

// To get the file content and file size
// @param fin input file.
// @param file_buf buffer to save content for the input file.
// @param bufsize filesize size for the input file.
// @return 0 for success, -1 for fail
int get_file_content(FILE *fin, unsigned char *file_buf, unsigned long bufsize);

// To return the file size.
// @param file_name name of the file.
// @return file size or -1 for failure.
int64_t file_size_return(FILE *fin);

// To check duplication for name of the file.
// @param file_name name of the file.
// @param file_extension name of the file extension.
// @param file_buf buffer including total file name.
void file_duplication_check(const char *file_name, const char *file_extension,
                            char *file_name_buf);

// Do command "ipfs add command" and save the hash value.
// Return length of the hash value received from uploading the file.
// @param file_name file name to upload in IPFS environment.
// @param hash_value result value for command "ipfs add <file_name>".
// @estimate_time value to measure and store the time for each process.
int execute_command_and_save_result(char *file_name, unsigned char *hash_value,
                                    estimate_time_t *estimate_time);

// Encrypt the file with sessionkey and upload the file in IPFS environment.
// Return length of the hash value receieved from
// 'execute_command_and_save_result' function.
// @param session_ctx session key to encrypt the file.
// @param ctx config struct obtained from load_config()
// @param my_file_path path of the file to encrypt.
// @param hash_value value to send to file system manager.
// @estimate_time value to measure and store the time for each process.
// @return 0 for success, -1 for fail
int file_encrypt_upload(session_key_t *session_ctx, SST_ctx_t *ctx,
                        char *my_file_path, unsigned char *hash_value,
                        estimate_time_t *estimate_time);

// Decrypt the file with sessionkey.
// @param session_ctx session key to decrypt the file.
// @param file_name file name to save in my repository.
// @return 0 for success, -1 for fail
int file_decrypt_save(session_key_t session_ctx, char *file_name);

// Request the data to file system manager.
// @param session_ctx session key information to send to file system manager.
// @param ctx config struct obtained from load_config().
// @param hash_value value to send to file system manager.
// @param hash_value_len length of value to send to file system manager.
// @return 0 for success, -1 for fail
int upload_to_file_system_manager(session_key_t *session_ctx, SST_ctx_t *ctx,
                                  unsigned char *hash_value,
                                  int hash_value_len);

// Make request buffer to upload information of the file to file system manager.
// @param session_ctx session key information to send to file system manager.
// @param ctx config struct obtained from load_config().
// @param hash_value value to send to file system manager.
// @param hash_value_len length of value to send to file system manager.
// @param concat_buffer buffer including information for the file.
int make_upload_req_buffer(session_key_t *s_key, SST_ctx_t *ctx,
                           unsigned char *hash_value, int hash_value_len,
                           char *concat_buffer);

// Make request buffer to download information of the file from file system
// manager.
// @param ctx config struct obtained from load_config().
// @param concat_buffer buffer including information for the file.
int make_download_req_buffer(SST_ctx_t *ctx, char *concat_buffer);

// Receive the data from file system manager and download the file in IPFS
// environment.
// @param skey_id_in_str session key information to compare with session key
// received from file system manager.
// @param ctx config struct obtained from load_config()
// @param file_name file name to save the file.
// @param value to measure and store the time for each process.
// @return 0 for success, -1 for fail
int receive_data_and_download_file(unsigned char *skey_id_in_str,
                                   SST_ctx_t *ctx, char *file_name,
                                   estimate_time_t *estimate_time);

// Download the file using command received from file system manager.
// @param received_buf buffer received from file system manager
// @param skey_id_in_str session key information to compare with session key
// received from file system manager.
// @param file_name file name to save the file.
void download_file(unsigned char *received_buf, unsigned char *skey_id_in_str,
                   char *file_name);

// Send the request for adding the reader to Auth.
// @param ctx config struct obtained from load_config()
// @param add_reader_path path to the file including a list of readers to be
// added
// @return 0 for success, -1 for fail
int send_add_reader_req_via_TCP(SST_ctx_t *ctx, char *add_reader_path);

#endif
