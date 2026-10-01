/**
 * @file ipfs.hpp
 * @brief IPFS file sharing helpers for the SST C++ API (port of src/ipfs.h).
 *
 * The uploader encrypts a file with a session key, adds it to IPFS and
 * registers the CID with the file system manager. The downloader asks the
 * file system manager for the CID and the session key ID, fetches the file
 * from IPFS and decrypts it. All functions throw sst::SST_Exception on
 * failure.
 *
 * Encrypted file layout (identical to the C API):
 *   [name_len (1)][entity name (name_len)][iv_len (1)][IV (iv_len)][ciphertext]
 */

#ifndef SST_IPFS_HPP
#define SST_IPFS_HPP

#include <string>
#include <vector>

#include "api.hpp"

namespace sst {
namespace ipfs {

constexpr unsigned int BUFF_SIZE = 100;
constexpr unsigned char UPLOAD_INDEX = 0;
constexpr unsigned char DOWNLOAD_INDEX = 1;
constexpr unsigned char DOWNLOAD_RESP = 2;
constexpr int MAX_REPLY_NUM = 100;

/** @brief Timing measurements of one upload or download, in seconds. */
struct estimate_time_t {
    float up_download_time = 0;
    float keygenerate_time = 0;
    float enc_dec_time = 0;
    float filemanager_time = 0;
};

/**
 * @brief Returns `file_name + file_extension`, or with a numeric suffix
 * inserted before the extension when that file already exists.
 * @throws SST_Exception when no free name is found within MAX_REPLY_NUM.
 */
std::string file_duplication_check(const std::string& file_name,
                                   const std::string& file_extension);

/**
 * @brief Runs `ipfs add --quiet <file_name>` and returns the CID.
 * @param estimate_time Receives the upload time.
 */
std::string execute_command_and_save_result(const std::string& file_name,
                                            estimate_time_t& estimate_time);

/**
 * @brief Encrypts the file at `my_file_path` with the session key, saves it
 * as encrypted*.txt and adds it to IPFS.
 * @return The CID of the encrypted file.
 */
std::string file_encrypt_upload(const session_key_t& s_key, const SST_API& api,
                                const std::string& my_file_path,
                                estimate_time_t& estimate_time);

/**
 * @brief Decrypts the downloaded file `file_name` with the session key and
 * saves it as result*.txt.
 * @return The name of the decrypted file.
 */
std::string file_decrypt_save(const session_key_t& s_key,
                              const std::string& file_name);

/**
 * @brief Registers the CID and session key ID with the (plain TCP) file
 * system manager from the config.
 */
void upload_to_file_system_manager(const session_key_t& s_key,
                                   const SST_API& api,
                                   const std::string& hash_value);

/**
 * @brief Builds the upload request (UPLOAD_INDEX + name + key ID + CID) for
 * the secure file system manager.
 */
std::vector<unsigned char> make_upload_req_buffer(
    const session_key_t& s_key, const SST_API& api,
    const std::string& hash_value);

/**
 * @brief Builds the download request (DOWNLOAD_INDEX + name) for the secure
 * file system manager.
 */
std::vector<unsigned char> make_download_req_buffer(const SST_API& api);

/**
 * @brief Asks the (plain TCP) file system manager for the file information
 * and downloads the file from IPFS as download*.txt.
 * @param skey_id_out Receives the session key ID (SESSION_KEY_ID_SIZE bytes)
 *                    of the file.
 * @return The name of the downloaded file.
 */
std::string receive_data_and_download_file(unsigned char* skey_id_out,
                                           const SST_API& api,
                                           estimate_time_t& estimate_time);

/**
 * @brief Parses a DOWNLOAD_RESP payload from the secure file system manager
 * and downloads the file from IPFS as download*.txt.
 * @param received_buf        The decrypted DOWNLOAD_RESP payload.
 * @param received_buf_length Its length.
 * @param skey_id_out         Receives the session key ID of the file.
 * @return The name of the downloaded file.
 */
std::string download_file(const unsigned char* received_buf,
                          unsigned int received_buf_length,
                          unsigned char* skey_id_out);

}  // namespace ipfs
}  // namespace sst

#endif  // SST_IPFS_HPP
