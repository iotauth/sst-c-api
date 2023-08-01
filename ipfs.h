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
void file_duplication_check(char* file_name, char* file_extension, char* file_name_buf);

// Do command "ipfs add command" and save the hash value.
// @param file_name file name to upload in IPFS environment.
// @param hash_value result value for command "ipfs add <file_name>".
void command_excute_and_save_result(char* file_name, unsigned char* hash_value);

// Encrypt the file with sessionkey and upload the file in IPFS environment.
// @param session_ctx session key to encrypt the file.
// @param ctx information to be included in encryption.
// @param my_file_path path of the file to encrypt.
// @param hash_value value to send to filesystem manager.
void file_encrypt_upload(SST_session_ctx_t* session_ctx, SST_ctx_t* ctx, char* my_file_path, unsigned char* hash_value);

// Download the file in IPFS environment and decrypt the file with sessionkey.
// @param session_ctx session key to decrypt the file.
// @param file_name file name to save in my repository.
void file_download_decrypt(SST_session_ctx_t* session_ctx, char* file_name);

// Request the data to filesystem manager.
// @param session_ctx session key information to send to filesystem manager.
// @param ctx owner information to send to filesystem manager.
// @param hash_value value to send to filesystem manager.
void upload_to_filesystem_manager(SST_session_ctx_t* session_ctx, SST_ctx_t* ctx, unsigned char* hash_value);

// Receive the data from filesystem manager.
// @param session_ctx session key information to compare with session key received from filesystem manager.
// @param ctx information to access the filesystem manager.
// @param file_name file name to save the file.
void download_from_filesystem_manager(SST_session_ctx_t* session_ctx, SST_ctx_t* ctx, char* file_name);

#endif
