/**
 * @file ipfs.cpp
 * @brief Implementation of the IPFS file sharing helpers (see ipfs.hpp).
 */

#include "ipfs.hpp"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cctype>
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

// Runs `argv` directly (no shell). When `stdout_file` is empty the first
// line of the command's output is returned; otherwise stdout is written to
// that file, which is created or truncated.
// @throws SST_Exception when the command cannot be started or exits with a
// non-zero status.
std::string run_process(const std::vector<std::string>& argv,
                        const std::string& stdout_file) {
    std::string display;
    for (const std::string& arg : argv) {
        display += (display.empty() ? "" : " ") + arg;
    }
    if (!stdout_file.empty()) {
        display += " > " + stdout_file;
    }
    LOG_INF << "Command: " << display;

    int pipefd[2] = {-1, -1};
    if (stdout_file.empty() && ::pipe(pipefd) < 0) {
        throw SST_Exception("pipe() failed: " +
                            std::string(std::strerror(errno)));
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        throw SST_Exception("fork() failed: " +
                            std::string(std::strerror(errno)));
    }
    if (pid == 0) {
        // Child: route stdout, then exec. Only async-signal-safe calls here.
        if (stdout_file.empty()) {
            ::dup2(pipefd[1], STDOUT_FILENO);
            ::close(pipefd[0]);
            ::close(pipefd[1]);
        } else {
            int fd =
                ::open(stdout_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                ::_exit(127);
            }
            ::dup2(fd, STDOUT_FILENO);
            ::close(fd);
        }
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const std::string& arg : argv) {
            args.push_back(const_cast<char*>(arg.c_str()));
        }
        args.push_back(nullptr);
        ::execvp(args[0], args.data());
        ::_exit(127);
    }

    std::string output;
    if (stdout_file.empty()) {
        ::close(pipefd[1]);
        char buff[BUFF_SIZE];
        ssize_t n;
        while ((n = ::read(pipefd[0], buff, sizeof(buff))) > 0) {
            output.append(buff, static_cast<size_t>(n));
        }
        ::close(pipefd[0]);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        throw SST_Exception("waitpid() failed: " +
                            std::string(std::strerror(errno)));
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        throw SST_Exception("Command failed: " + display);
    }
    size_t end = output.find_first_of("\r\n");
    if (end != std::string::npos) {
        output.erase(end);
    }
    return output;
}

// The file system manager describes the download as the text
// "ipfs cat <CID> > ". Only the CID is taken from it, and it must be a
// plain alphanumeric token; the text itself is never handed to a shell.
std::string extract_cid(const std::string& command) {
    const std::string prefix = "ipfs cat ";
    if (command.compare(0, prefix.size(), prefix) != 0) {
        throw SST_Exception(
            "Unexpected download command from the file system manager.");
    }
    size_t start = prefix.size();
    size_t end = start;
    while (end < command.size() &&
           std::isalnum(static_cast<unsigned char>(command[end]))) {
        end++;
    }
    if (end == start) {
        throw SST_Exception("Missing CID in the download command.");
    }
    return command.substr(start, end - start);
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
    std::string cid = run_process({"ipfs", "add", "--quiet", file_name}, "");
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
    if (received_buf[0] != DOWNLOAD_RESP) {
        throw SST_Exception("Not a download response.");
    }
    if (received_buf[1] != SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Unexpected session key ID size in response.");
    }
    unsigned int command_size = received_buf[2 + SESSION_KEY_ID_SIZE];
    if (received_buf_length < 3 + SESSION_KEY_ID_SIZE + command_size) {
        throw SST_Exception("Download response truncated.");
    }
    std::memcpy(skey_id_out, received_buf + 2, SESSION_KEY_ID_SIZE);
    // reinterpret_cast: the command is ASCII text.
    std::string cid = extract_cid(std::string(
        reinterpret_cast<const char*>(received_buf + 3 + SESSION_KEY_ID_SIZE),
        command_size));
    std::string file_name =
        file_duplication_check(DOWNLOAD_FILE_NAME, TXT_FILE_EXTENSION);
    run_process({"ipfs", "cat", cid}, file_name);
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
    // The response is length-prefixed field by field, so read each field
    // exactly rather than trusting a single read() to return it all:
    // [type][key_id_size][key_id][command_size][command].
    std::vector<unsigned char> received_buf(2);
    bool ok = internal::read_exact(sock, received_buf.data(), 2) == 2;
    if (ok) {
        unsigned int key_id_size = received_buf[1];
        received_buf.resize(2 + key_id_size + 1);
        ok = internal::read_exact(sock, received_buf.data() + 2,
                                  key_id_size + 1) ==
             static_cast<int>(key_id_size + 1);
        if (ok) {
            unsigned int command_size = received_buf[2 + key_id_size];
            size_t offset = received_buf.size();
            received_buf.resize(offset + command_size);
            ok = command_size == 0 ||
                 internal::read_exact(sock, received_buf.data() + offset,
                                      command_size) ==
                     static_cast<int>(command_size);
        }
    }
    ::close(sock);
    if (!ok) {
        throw SST_Exception("Failed to read from the file system manager.");
    }
    LOG_INF << "Received the information for file.";
    estimate_time.filemanager_time = seconds_since(filemanager_start);

    auto download_start = Clock::now();
    std::string file_name = download_file(
        received_buf.data(), static_cast<unsigned int>(received_buf.size()),
        skey_id_out);
    estimate_time.up_download_time = seconds_since(download_start);
    return file_name;
}

}  // namespace ipfs
}  // namespace sst
