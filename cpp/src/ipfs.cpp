/**
 * @file ipfs.cpp
 * @brief Implementation of the IPFS file sharing helpers (see ipfs.hpp).
 */

#include "ipfs.hpp"

#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

#include "api_internal.hpp"
#include "log/log_manager.hpp"

namespace sst {
namespace ipfs {

namespace {

const char IPFS_ADD_COMMAND[] = "ipfs add --quiet ";
const char TXT_FILE_EXTENSION[] = ".txt";
const char ENCRYPTED_FILE_NAME[] = "encrypted";
const char RESULT_FILE_NAME[] = "result";
const char DOWNLOAD_FILE_NAME[] = "download";

// The entity name is sent as the whole fixed-size config field, NUL padding
// included, exactly like the C API (the file system manager strips it).
constexpr unsigned int NAME_FIELD_SIZE = MAX_ENTITY_NAME_LENGTH + 1;

using Clock = std::chrono::steady_clock;

float seconds_since(Clock::time_point start) {
    return std::chrono::duration<float>(Clock::now() - start).count();
}

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        throw SST_Exception("Cannot read the file: " + path);
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
                                      std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const unsigned char* data,
                size_t length) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        throw SST_Exception("Cannot open file for writing: " + path);
    }
    // reinterpret_cast: ofstream writes char buffers.
    out.write(reinterpret_cast<const char*>(data),
              static_cast<std::streamsize>(length));
    if (!out.good()) {
        throw SST_Exception("Failed to write file: " + path);
    }
}

// Runs a shell command and returns its first output line without the
// trailing newline.
std::string run_command_first_line(const std::string& command) {
    LOG_INF << "Command: " << command;
    FILE* fp = popen(command.c_str(), "r");
    if (fp == nullptr) {
        throw SST_Exception("popen() failed for: " + command);
    }
    char buff[BUFF_SIZE];
    std::string line;
    if (std::fgets(buff, sizeof(buff), fp) != nullptr) {
        line = buff;
    }
    pclose(fp);
    size_t end = line.find_first_of("\r\n");
    if (end != std::string::npos) {
        line.erase(end);
    }
    return line;
}

void append_name_field(std::vector<unsigned char>& buf, const SST_API& api) {
    const char* name = api.get_config().name;
    buf.push_back(static_cast<unsigned char>(NAME_FIELD_SIZE));
    buf.insert(buf.end(), name, name + NAME_FIELD_SIZE);
}

}  // namespace

std::string file_duplication_check(const std::string& file_name,
                                   const std::string& file_extension) {
    for (int suffix_num = 0; suffix_num < MAX_REPLY_NUM; suffix_num++) {
        std::string candidate =
            suffix_num == 0
                ? file_name + file_extension
                : file_name + std::to_string(suffix_num) + file_extension;
        if (::access(candidate.c_str(), F_OK) == 0) {
            LOG_INF << "File already exists: " << candidate << ".";
            continue;
        }
        return candidate;
    }
    throw SST_Exception(
        "Cannot save the file as file name's suffix number exceeds max.");
}

std::string execute_command_and_save_result(const std::string& file_name,
                                            estimate_time_t& estimate_time) {
    auto start = Clock::now();
    std::string cid = run_command_first_line(IPFS_ADD_COMMAND + file_name);
    if (cid.empty()) {
        throw SST_Exception("Failed to read CID from ipfs output.");
    }
    estimate_time.up_download_time = seconds_since(start);
    return cid;
}

std::string file_encrypt_upload(const session_key_t& s_key, const SST_API& api,
                                const std::string& my_file_path,
                                estimate_time_t& estimate_time) {
    auto start = Clock::now();
    std::vector<unsigned char> file_buf = read_file(my_file_path);

    unsigned char iv[AES_128_CBC_IV_SIZE];
    if (Crypto::generate_nonce(AES_128_CBC_IV_SIZE, iv) < 0) {
        throw SST_Exception("Failed generate_nonce().");
    }
    // Room for CBC padding and a GCM tag.
    std::vector<unsigned char> encrypted(
        ((file_buf.size() / AES_128_CBC_IV_SIZE) + 1) * AES_128_CBC_IV_SIZE +
        AES_GCM_TAG_SIZE);
    unsigned int encrypted_length = 0;
    if (Crypto::encrypt_aes(file_buf.data(),
                            static_cast<unsigned int>(file_buf.size()),
                            s_key.cipher_key, iv, s_key.enc_mode,
                            encrypted.data(), &encrypted_length) < 0) {
        throw SST_Exception("Encryption failed!");
    }
    LOG_INF << "File encryption was successful.";

    std::string file_name =
        file_duplication_check(ENCRYPTED_FILE_NAME, TXT_FILE_EXTENSION);
    std::vector<unsigned char> enc_save;
    enc_save.reserve(2 + NAME_FIELD_SIZE + AES_128_CBC_IV_SIZE +
                     encrypted_length);
    append_name_field(enc_save, api);
    enc_save.push_back(static_cast<unsigned char>(AES_128_CBC_IV_SIZE));
    enc_save.insert(enc_save.end(), iv, iv + AES_128_CBC_IV_SIZE);
    enc_save.insert(enc_save.end(), encrypted.begin(),
                    encrypted.begin() + encrypted_length);
    write_file(file_name, enc_save.data(), enc_save.size());
    LOG_INF << "File was saved: " << file_name << ".";
    estimate_time.enc_dec_time = seconds_since(start);

    ::sleep(1);
    return execute_command_and_save_result(file_name, estimate_time);
}

std::string file_decrypt_save(const session_key_t& s_key,
                              const std::string& file_name) {
    std::vector<unsigned char> file_buf = read_file(file_name);
    if (file_buf.size() < 2) {
        throw SST_Exception("Encrypted file too short: " + file_name);
    }
    unsigned int owner_name_len = file_buf[0];
    size_t iv_offset = 1 + owner_name_len + 1;
    if (file_buf.size() < iv_offset + AES_128_CBC_IV_SIZE) {
        throw SST_Exception("Encrypted file too short: " + file_name);
    }
    unsigned char iv[AES_128_CBC_IV_SIZE];
    std::memcpy(iv, file_buf.data() + iv_offset, AES_128_CBC_IV_SIZE);
    size_t enc_offset = iv_offset + AES_128_CBC_IV_SIZE;
    unsigned int enc_length =
        static_cast<unsigned int>(file_buf.size() - enc_offset);

    std::vector<unsigned char> ret(enc_length + AES_128_CBC_IV_SIZE);
    unsigned int ret_length = 0;
    if (Crypto::decrypt_aes(file_buf.data() + enc_offset, enc_length,
                            s_key.cipher_key, iv, s_key.enc_mode, ret.data(),
                            &ret_length) < 0) {
        throw SST_Exception("Error while decrypting " + file_name);
    }
    std::string result_file_name =
        file_duplication_check(RESULT_FILE_NAME, TXT_FILE_EXTENSION);
    write_file(result_file_name, ret.data(), ret_length);
    LOG_INF << "Completed decryption and saved the file: " << result_file_name;
    return result_file_name;
}

std::vector<unsigned char> make_upload_req_buffer(
    const session_key_t& s_key, const SST_API& api,
    const std::string& hash_value) {
    if (hash_value.size() > 255) {
        throw SST_Exception("CID too long.");
    }
    std::vector<unsigned char> buf;
    buf.push_back(UPLOAD_INDEX);
    append_name_field(buf, api);
    buf.push_back(static_cast<unsigned char>(SESSION_KEY_ID_SIZE));
    buf.insert(buf.end(), s_key.key_id, s_key.key_id + SESSION_KEY_ID_SIZE);
    buf.push_back(static_cast<unsigned char>(hash_value.size()));
    buf.insert(buf.end(), hash_value.begin(), hash_value.end());
    return buf;
}

std::vector<unsigned char> make_download_req_buffer(const SST_API& api) {
    std::vector<unsigned char> buf;
    buf.push_back(DOWNLOAD_INDEX);
    append_name_field(buf, api);
    return buf;
}

void upload_to_file_system_manager(const session_key_t& s_key,
                                   const SST_API& api,
                                   const std::string& hash_value) {
    const config_t& config = api.get_config();
    int sock = internal::connect_as_client(config.file_system_manager_ip_addr,
                                           config.file_system_manager_port_num);
    if (sock < 0) {
        throw SST_Exception("Failed to connect to the file system manager.");
    }
    std::vector<unsigned char> data =
        make_upload_req_buffer(s_key, api, hash_value);
    int written = internal::sst_write_to_socket(
        sock, data.data(), static_cast<unsigned int>(data.size()));
    ::close(sock);
    if (written < 0) {
        throw SST_Exception("Failed to send to the file system manager.");
    }
    LOG_INF << "Sent the data such as session key id, hash value for file.";
}

std::string download_file(const unsigned char* received_buf,
                          unsigned int received_buf_length,
                          unsigned char* skey_id_out) {
    // [type][key_id_size][key_id][command_size][command "ipfs cat <cid> > "]
    if (received_buf_length < 3 + SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Download response too short.");
    }
    unsigned int command_size = received_buf[2 + SESSION_KEY_ID_SIZE];
    if (received_buf_length < 3 + SESSION_KEY_ID_SIZE + command_size) {
        throw SST_Exception("Download response truncated.");
    }
    std::memcpy(skey_id_out, received_buf + 2, SESSION_KEY_ID_SIZE);
    // reinterpret_cast: the command is ASCII text.
    std::string base_command(
        reinterpret_cast<const char*>(received_buf + 3 + SESSION_KEY_ID_SIZE),
        command_size);
    std::string file_name =
        file_duplication_check(DOWNLOAD_FILE_NAME, TXT_FILE_EXTENSION);
    run_command_first_line(base_command + file_name);
    LOG_INF << "Downloaded the file: " << file_name;
    return file_name;
}

std::string receive_data_and_download_file(unsigned char* skey_id_out,
                                           const SST_API& api,
                                           estimate_time_t& estimate_time) {
    const config_t& config = api.get_config();
    auto filemanager_start = Clock::now();
    int sock = internal::connect_as_client(config.file_system_manager_ip_addr,
                                           config.file_system_manager_port_num);
    if (sock < 0) {
        throw SST_Exception("Failed to connect to the file system manager.");
    }
    std::vector<unsigned char> data = make_download_req_buffer(api);
    if (internal::sst_write_to_socket(
            sock, data.data(), static_cast<unsigned int>(data.size())) < 0) {
        ::close(sock);
        throw SST_Exception("Failed to send to the file system manager.");
    }
    unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
    int received_buf_length = internal::sst_read_from_socket(
        sock, received_buf, sizeof(received_buf));
    ::close(sock);
    if (received_buf_length <= 0) {
        throw SST_Exception("Failed to read from the file system manager.");
    }
    LOG_INF << "Received the information for file.";
    estimate_time.filemanager_time = seconds_since(filemanager_start);

    auto download_start = Clock::now();
    std::string file_name = download_file(
        received_buf, static_cast<unsigned int>(received_buf_length),
        skey_id_out);
    estimate_time.up_download_time = seconds_since(download_start);
    return file_name;
}

}  // namespace ipfs
}  // namespace sst
