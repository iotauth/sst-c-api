#ifndef IPFS_H
#define IPFS_H

#include "c_api.h"

#define BUFF_SIZE 100
#define UPLOAD_INDEX 0
#define DOWNLOAD_INDEX 1
#define MAX_REPLY_NUM 100

// To get the file content and file size
// @param fin input file.
// @param file_buf buffer to save content for the input file.
// @param bufsize filesize size for the input file.
void get_file_content(FILE* fin, unsigned char* file_buf, unsigned long bufsize);

// To return the file size.
// @param file_name name of the file.
unsigned long file_size_return(FILE* fin);

// To check duplication for name of the file.
// @param file_name name of the file.
// @param file_extension name of the file extension.
// @param file_buf buffer including total file name.
void file_duplication_check(const char* file_name, const char* file_extension, char* file_name_buf);

// Do command "ipfs add command" and save the hash value.
// Return length of the hash value received from uploading the file.
// @param file_name file name to upload in IPFS environment.
// @param hash_value result value for command "ipfs add <file_name>".
int execute_command_and_save_result(char* file_name, unsigned char* hash_value);

// Encrypt the file with sessionkey and upload the file in IPFS environment.
// Return length of the hash value receieved from 'execute_command_and_save_result' function.
// @param session_ctx session key to encrypt the file.
// @param ctx information to be included in encryption.
// @param my_file_path path of the file to encrypt.
// @param hash_value value to send to file system manager.
int file_encrypt_upload(session_key_t* session_ctx, SST_ctx_t* ctx, char* my_file_path, unsigned char* hash_value);

// Download the file in IPFS environment and decrypt the file with sessionkey.
// @param session_ctx session key to decrypt the file.
// @param file_name file name to save in my repository.
void file_download_decrypt(session_key_t session_ctx, char* file_name);

// Request the data to file system manager.
// @param session_ctx session key information to send to file system manager.
// @param ctx owner information to send to file system manager.
// @param hash_value value to send to file system manager.
// @param hash_value_len length of value to send to file system manager.
void upload_to_file_system_manager(session_key_t* session_ctx, SST_ctx_t* ctx, unsigned char* hash_value, int hash_value_len);

// Receive the data from file system manager.
// @param session_ctx session key information to compare with session key received from file system manager.
// @param ctx information to access the file system manager.
// @param file_name file name to save the file.
void download_from_file_system_manager(unsigned char* skey_id, SST_ctx_t* ctx, char* file_name);


session_key_t *check_sessionkey_request_to_auth(unsigned char* expected_key_id, SST_ctx_t *ctx, session_key_list_t *existing_s_key_list);


#endif
