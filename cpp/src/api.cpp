#include "api.hpp"

#include <unistd.h>

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "net/sockets.hpp"
#include "net/ssl_socket.hpp"
#include "crypto.hpp"
#include "log/log_manager.hpp"
#include "net/sockets.hpp"

// Centralized OpenSSL initialization - fix security issue #1
namespace {
    bool openssl_initialized = false;
    void ensure_openssl_initialized() {
        if (!openssl_initialized) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            openssl_initialized = true;
        }
    }
}

namespace sst {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** @brief Free function for SST_ctx_t (used as unique_ptr deleter). */
void free_SST_ctx_t(SST_ctx_t* ctx) {
    if (!ctx) return;
    // std::mutex is RAII — no manual destroy needed.
    delete ctx;
}

/** @brief Free function for session_key_list_t. */
void free_session_key_list_t(session_key_list_t* list) {
    if (!list) return;
    delete list;
}

/** @brief Free function for SST_session_ctx_t. */
void free_session_ctx(SST_session_ctx_t* session_ctx) {
    if (!session_ctx) return;
    // Fix reliability issue #1: Check if socket is valid before closing
    if (session_ctx->sock > 0) {
        ::close(session_ctx->sock);
    }
    delete session_ctx;
}

// ---------------------------------------------------------------------------
// Config file parser (simple key=value format)
// ---------------------------------------------------------------------------

static void parse_config_file(const std::string& path, config_t& cfg) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw SST_Exception("Failed to open config file: " + path);
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        // Trim whitespace
        auto trim = [](std::string& s) {
            size_t start = s.find_first_not_of(" \t\r\n");
            size_t end = s.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) {
                s.clear();
            } else {
                s = s.substr(start, end - start + 1);
            }
        };

        trim(key);
        trim(value);

        // Map keys to config fields
        if (key == "name") {
            snprintf(cfg.name, sizeof(cfg.name), "%.*s",
                     static_cast<int>(sizeof(cfg.name) - 1),
                     value.c_str());
        } else if (key == "auth_id") {
            cfg.auth_id = std::stoi(value);
        } else if (key == "auth_pubkey_path") {
            snprintf(cfg.auth_pubkey_path, sizeof(cfg.auth_pubkey_path), "%.*s",
                     static_cast<int>(sizeof(cfg.auth_pubkey_path) - 1),
                     value.c_str());
        } else if (key == "entity_privkey_path") {
            snprintf(cfg.entity_privkey_path, sizeof(cfg.entity_privkey_path), "%.*s",
                     static_cast<int>(sizeof(cfg.entity_privkey_path) - 1),
                     value.c_str());
        } else if (key == "auth_ip_addr") {
            snprintf(cfg.auth_ip_addr, sizeof(cfg.auth_ip_addr), "%.*s",
                     static_cast<int>(sizeof(cfg.auth_ip_addr) - 1),
                     value.c_str());
        } else if (key == "auth_port_num") {
            cfg.auth_port_num = std::stoi(value);
        } else if (key == "entity_server_ip_addr") {
            snprintf(cfg.entity_server_ip_addr, sizeof(cfg.entity_server_ip_addr), "%.*s",
                     static_cast<int>(sizeof(cfg.entity_server_ip_addr) - 1),
                     value.c_str());
        } else if (key == "entity_server_port_num") {
            cfg.entity_server_port_num = std::stoi(value);
        } else if (key == "session_key_enc_mode") {
            cfg.session_key_enc_mode =
                static_cast<AES_encryption_mode_t>(std::stoi(value));
        } else if (key == "dist_key_enc_mode") {
            cfg.dist_key_enc_mode =
                static_cast<AES_encryption_mode_t>(std::stoi(value));
        } else if (key == "hmac_mode") {
            cfg.hmac_mode = static_cast<hmac_mode_t>(std::stoi(value));
        } else if (key == "perm_dist_key_mode") {
            cfg.perm_dist_key_mode =
                static_cast<perm_dist_key_mode_t>(std::stoi(value));
        } else if (key == "numkey") {
            cfg.numkey = std::stoi(value);
        } else if (key == "purpose_index") {
            cfg.purpose_index = static_cast<unsigned short>(std::stoi(value));
        } else if (key.substr(0, 7) == "purpose") {
            // purpose[0] or purpose[1]
            size_t bracket_start = key.find('[');
            size_t bracket_end = key.find(']');
            if (bracket_start != std::string::npos &&
                bracket_end != std::string::npos) {
                int idx = std::stoi(key.substr(
                    bracket_start + 1, bracket_end - bracket_start - 1));
                if (idx >= 0 && idx < 2) {
snprintf(cfg.purpose[idx], sizeof(cfg.purpose[idx]), "%.*s",
                             static_cast<int>(sizeof(cfg.purpose[idx]) - 1),
                             value.c_str());
                }
            }
        }
    }

    file.close();
}

// ---------------------------------------------------------------------------
// SST_API Implementation
// ---------------------------------------------------------------------------

SST_API::SST_API(const std::string& config_path)
    : ctx_(new SST_ctx_t(), &free_SST_ctx_t), session_key_list_(nullptr)
{
    // Ensure OpenSSL is initialized before any crypto operations
    ensure_openssl_initialized();
    LOG_INF << "Initializing SST_API with config: " << config_path;

    // Parse configuration file
    parse_config_file(config_path, ctx_->config);

    LOG_INF << "Entity name: " << ctx_->config.name;
LOG_INF << "Auth server: " << ctx_->config.auth_ip_addr
        << ":" << ctx_->config.auth_port_num;

    // Load Auth's public key
    EVP_PKEY* auth_pub_key =
        Crypto::load_auth_public_key(ctx_->config.auth_pubkey_path);
    if (!auth_pub_key) {
        throw SST_Exception("Failed to load Auth public key from: " +
std::string(ctx_->config.auth_pubkey_path));
    }

    // Transfer ownership to unique_ptr with custom deleter
    ctx_->pub_key.reset(auth_pub_key);

    LOG_INF << "Auth public key loaded successfully";

    // Load entity's private key
    EVP_PKEY* entity_priv_key =
        Crypto::load_entity_private_key(ctx_->config.entity_privkey_path);
    if (!entity_priv_key) {
        throw SST_Exception("Failed to load entity private key from: " +
std::string(ctx_->config.entity_privkey_path));
    }

    ctx_->priv_key.reset(entity_priv_key);

    LOG_INF << "Entity private key loaded successfully";

    // Initialize session key list (circular buffer)
    session_key_list_ = new session_key_list_t();
    session_key_list_->num_key = 0;
    session_key_list_->rear_idx = 0;
    session_key_list_->s_key.reset(new session_key_t[MAX_SESSION_KEY]);

    LOG_INF << "SST_API initialization complete";
}

SST_API::~SST_API() {
    LOG_INF << "Cleaning up SST_API";

    // Free session key list (unique_ptr handles the array)
    if (session_key_list_) {
        free_session_key_list_t(session_key_list_);
        session_key_list_ = nullptr;
    }

    // ctx_ is automatically freed by unique_ptr with custom deleter
}

void SST_API::auth_hello() {
    LOG_INF << "Performing AUTH_HELLO handshake";

    // Lock guards session_key_list_ — perform_auth_handshake writes it,
    // and get_session_key_by_id (called from within perform_auth_handshake)
    // reads it. We hold the lock across the entire call chain; the recursive
    // path inside perform_auth_handshake uses std::scoped_lock which is safe
    // with std::mutex when we only enter from public API methods.
    std::scoped_lock lock(key_list_mutex_);
    perform_auth_handshake("");  // Empty purpose for initial hello
}

std::vector<SessionKey> SST_API::get_session_keys(const std::string& purpose) {
    LOG_INF << "Requesting session keys for purpose: " << purpose;

    // Lock guards the full operation: perform_auth_handshake writes
    // session_key_list_, and the iteration below reads it. Holding the lock
    // across both ensures we never iterate over a list being mutated.
    std::scoped_lock lock(key_list_mutex_);
    perform_auth_handshake(purpose);

    // Convert internal session_key_list_t to high-level SessionKey vector
    std::vector<SessionKey> result;
    if (!session_key_list_) return result;

    for (int i = 0; i < session_key_list_->num_key; ++i) {
        int idx = (session_key_list_->rear_idx - 1 - i + MAX_SESSION_KEY) %
                  MAX_SESSION_KEY;

        SessionKey sk;
        sk.id.assign(
            session_key_list_->s_key[idx].key_id,
            session_key_list_->s_key[idx].key_id + SESSION_KEY_ID_SIZE);
        sk.abs_validity = session_key_list_->s_key[idx].abs_validity;
        sk.rel_validity = session_key_list_->s_key[idx].rel_validity;

        result.push_back(sk);
    }

    LOG_INF << "Retrieved " << result.size() << " session key(s)";
    return result;
}

std::optional<SessionKey> SST_API::get_session_key_by_id(
    const std::vector<uint8_t>& session_key_id) const {
    // Lock guards read of session_key_list_ while perform_auth_handshake
    // (called by get_session_keys/auth_hello) may concurrently mutate it.
    std::scoped_lock lock(key_list_mutex_);

    if (!session_key_list_ || session_key_id.empty() ||
        session_key_id.size() > SESSION_KEY_ID_SIZE) {
        return std::nullopt;
    }

    // Search through the circular buffer
    for (int i = 0; i < session_key_list_->num_key; ++i) {
        int idx = (session_key_list_->rear_idx - 1 - i + MAX_SESSION_KEY) %
                  MAX_SESSION_KEY;

        if (std::memcmp(session_key_id.data(),
                        session_key_list_->s_key[idx].key_id,
                        session_key_id.size()) == 0) {
            SessionKey sk;
            sk.id.assign(
                session_key_list_->s_key[idx].key_id,
                session_key_list_->s_key[idx].key_id + SESSION_KEY_ID_SIZE);
            sk.abs_validity = session_key_list_->s_key[idx].abs_validity;
            sk.rel_validity = session_key_list_->s_key[idx].rel_validity;

            return sk;
        }
    }

    return std::nullopt;
}

void SST_API::perform_auth_handshake(const std::string& purpose) {
    // Connect to Auth server
    ClientSocket auth_socket(static_cast<SST_SOCK_DOMAIN>(AF_INET),
                             ctx_->config.auth_ip_addr,
                             ctx_->config.auth_port_num);

    try {
        // The Auth server wire protocol (IoTSP):
        //   Message: [1 byte: msgType][variable-length: payloadLen][payload]
        //
        // Step 1: Receive AUTH_HELLO from Auth server.
        //   msgType = 0x00, payload = auth_id[6 bytes] + auth_nonce[8 bytes] = 14 bytes.
        unsigned char auth_hello_buf[MAX_SECURE_COMM_MSG_LENGTH];
        int bytes_recv = recv_from_auth(auth_socket.get_fd(), auth_hello_buf,
                                        sizeof(auth_hello_buf));
        if (bytes_recv <= 0) {
            throw SST_Exception("Failed to receive AUTH_HELLO from Auth server");
        }

        // Parse AUTH_HELLO payload: auth_id (6 bytes) + auth_nonce (RSA_KEY_SIZE bytes)
        const unsigned int AUTH_ID_SIZE = 6;
        unsigned char auth_id[AUTH_ID_SIZE] = {};
        if (bytes_recv < static_cast<int>(AUTH_ID_SIZE + RSA_KEY_SIZE)) {
            throw SST_Exception("AUTH_HELLO response too short: " +
                                std::to_string(bytes_recv));
        }
        std::memcpy(auth_id, auth_hello_buf, AUTH_ID_SIZE);
        unsigned char auth_nonce[RSA_KEY_SIZE];
        std::memcpy(auth_nonce, auth_hello_buf + AUTH_ID_SIZE, RSA_KEY_SIZE);

        LOG_INF << "AUTH_HELLO received. Auth ID: ";
        for (int i = 0; i < AUTH_ID_SIZE; ++i) {
            LOG_DBG << std::hex << static_cast<int>(auth_id[i]);
        }
        LOG_DBG << std::dec << " Nonce: ";
        for (int i = 0; i < RSA_KEY_SIZE; ++i) {
            LOG_DBG << std::hex << static_cast<int>(auth_nonce[i]);
        }
        LOG_DBG << std::dec;

        // Step 2: Build and send SESSION_KEY_REQ_IN_PUB_ENC (IoTSP message).
        //
        // Wire format:
        //   [msgType=0x14][payloadLen varint][payload]
        //
        // payload = entity_nonce[8] + auth_nonce[8] + numKeys[4 BE] +
        //           entityName (varlen string) + purpose (varlen string)
        //
        // The payload is then:
        //   - Encrypted with Auth's public key (RSA_PKCS1_OAEP_PADDING)
        //   - Signed with entity's private key (SHA-256 + RSA)
        //   - Auth appends the RSA signature (RSA_KEY_SIZE bytes) to the ciphertext.

        // --- 2a. Build the plaintext payload ---
        size_t entity_nonce_size = 8;
        size_t num_keys = static_cast<size_t>(ctx_->config.numkey);
        size_t name_len = strlen(ctx_->config.name);
        size_t purpose_len = purpose.size();

        // Variable-length integer encoding: each byte has high bit set except the last.
        auto encode_varint = [](size_t val, unsigned char* out) -> size_t {
            size_t n = 0;
            if (val < 128) {
                out[n++] = static_cast<unsigned char>(val);
            } else {
                // Encode with high bit set for continuation bytes
                unsigned char tmp[5];
                size_t count = 0;
                while (val >= 128) {
                    tmp[count++] = static_cast<unsigned char>(128 | (val & 0x7F));
                    val >>= 7;
                }
                tmp[count++] = static_cast<unsigned char>(val);
                // Write in reverse (little-endian varint)
                for (size_t i = 0; i < count; ++i) {
                    out[n++] = tmp[count - 1 - i];
                }
            }
            return n;
        };

        // Calculate payload size
        size_t name_varlen_size = 1; // short name fits in 1 varint byte
        size_t purpose_varlen_size = 1;
        unsigned char plaintext_payload[MAX_SECURE_COMM_MSG_LENGTH];
        size_t offset = 0;

        // Entity nonce (8 bytes, random)
        int ret = Crypto::generate_nonce(entity_nonce_size, plaintext_payload);
        if (ret != 0) {
            throw SST_Exception("Failed to generate entity nonce");
        }
        offset += entity_nonce_size;

        // Auth nonce (8 bytes, received from AUTH_HELLO)
        std::memcpy(plaintext_payload + offset, auth_nonce, RSA_KEY_SIZE);
        offset += RSA_KEY_SIZE;

        // numKeys as 4-byte big-endian
        plaintext_payload[offset++] = static_cast<unsigned char>((ctx_->config.numkey >> 24) & 0xFF);
        plaintext_payload[offset++] = static_cast<unsigned char>((ctx_->config.numkey >> 16) & 0xFF);
        plaintext_payload[offset++] = static_cast<unsigned char>((ctx_->config.numkey >> 8) & 0xFF);
        plaintext_payload[offset++] = static_cast<unsigned char>(ctx_->config.numkey & 0xFF);

        // Entity name: [varint length][entity name bytes]
        size_t name_prefix_len = encode_varint(name_len, plaintext_payload + offset);
        offset += name_prefix_len;
        std::memcpy(plaintext_payload + offset, ctx_->config.name, name_len);
        offset += name_len;

        // Purpose: [varint length][purpose JSON bytes]
        size_t purpose_prefix_len = encode_varint(purpose_len, plaintext_payload + offset);
        offset += purpose_prefix_len;
        std::memcpy(plaintext_payload + offset, purpose.c_str(), purpose_len);
        offset += purpose_len;

        size_t plaintext_len = offset;
        LOG_INF << "Plaintext payload size: " << plaintext_len << " bytes";

        // --- 2b. Encrypt payload with Auth's public key (RSA-OAEP) ---
        unsigned char encrypted[MAX_SECURE_COMM_MSG_LENGTH + RSA_KEY_SIZE];
        size_t encrypted_len = sizeof(encrypted);
        ret = Crypto::public_encrypt(
            plaintext_payload, plaintext_len,
            RSA_PKCS1_OAEP_PADDING,
            ctx_->pub_key.get(),
            encrypted, &encrypted_len);
        if (ret != 0) {
            throw SST_Exception("Failed to encrypt session key request with OAEP");
        }
        LOG_INF << "Encrypted payload size: " << encrypted_len << " bytes";

        // --- 2c. Sign the encrypted payload with entity's private key (SHA-256 + RSA) ---
        unsigned char signature[RSA_KEY_SIZE];
        size_t sig_len = RSA_KEY_SIZE;
        ret = Crypto::sha256_sign(encrypted, static_cast<unsigned int>(encrypted_len),
                                  ctx_->priv_key.get(), signature, &sig_len);
        if (ret != 0) {
            throw SST_Exception("Failed to sign session key request");
        }

        // --- 2d. Build the IoTSP message: [msgType][payloadLen varint][ciphertext + signature] ---
        // Auth server expects: ciphertext + signature appended (see EntityConnectionHandler)
        size_t total_payload_size = encrypted_len + RSA_KEY_SIZE;

        unsigned char iotsp_msg[MAX_SECURE_COMM_MSG_LENGTH + RSA_KEY_SIZE * 2];
        size_t iotsp_offset = 0;

        // msgType = 0x14 (SESSION_KEY_REQ_IN_PUB_ENC)
        iotsp_msg[iotsp_offset++] = 0x14;

        // payloadLen as variable-length integer
        size_t len_varint_size = encode_varint(total_payload_size, iotsp_msg + iotsp_offset);
        iotsp_offset += len_varint_size;

        // Copy encrypted payload
        std::memcpy(iotsp_msg + iotsp_offset, encrypted, encrypted_len);
        iotsp_offset += encrypted_len;

        // Append signature
        std::memcpy(iotsp_msg + iotsp_offset, signature, RSA_KEY_SIZE);
        iotsp_offset += RSA_KEY_SIZE;

        LOG_INF << "Total IoTSP message size: " << iotsp_offset << " bytes";

        // --- 2e. Send the IoTSP message ---
        int bytes_sent = send_to_auth(auth_socket.get_fd(), iotsp_msg, iotsp_offset);
        if (bytes_sent <= 0) {
            throw SST_Exception("Failed to send SESSION_KEY_REQ_IN_PUB_ENC to Auth server");
        }
        LOG_INF << "Sent " << bytes_sent << " bytes to Auth server";

        // Step 3: Receive SESSION_KEY_RESP_WITH_DIST_KEY or AUTH_ALERT
        unsigned char resp_buf[MAX_SECURE_COMM_MSG_LENGTH];
        bytes_recv = recv_from_auth(auth_socket.get_fd(), resp_buf, sizeof(resp_buf));

        if (bytes_recv <= 0) {
            throw SST_Exception("Failed to receive session key response from Auth server");
        }
        LOG_INF << "Received " << bytes_recv << " bytes from Auth server";

        // --- 3a. Check for AUTH_ALERT (msgType = 0x64 = 100) ---
        if (bytes_recv >= 2 && resp_buf[0] == 0x64) {
            unsigned char alert_code = resp_buf[1];
            throw SST_Exception("AUTH_ALERT received from Auth server: code=" +
                                std::to_string(alert_code));
        }

        // --- 3b. Parse IoTSP response: [msgType][payloadLen varint][payload] ---
        if (bytes_recv < 2) {
            throw SST_Exception("Session key response too short");
        }
        unsigned char resp_msg_type = resp_buf[0];
        // Parse variable-length integer for payload length
        size_t resp_payload_len = 0;
        size_t resp_len_varint_size = 0;
        unsigned char tmp_val[5];
        size_t tmp_count = 0;
        for (size_t i = 1; i < static_cast<size_t>(bytes_recv) && i < 6; ++i) {
            tmp_val[tmp_count++] = resp_buf[i];
            resp_payload_len |= static_cast<size_t>(resp_buf[i] & 0x7F) << (7 * (i - 1));
            if ((resp_buf[i] & 0x80) == 0) {
                resp_len_varint_size = i - 1 + 1; // +1 for the last byte
                break;
            }
        }

        if (resp_payload_len == 0 ||
            static_cast<size_t>(bytes_recv) < 1 + resp_len_varint_size + resp_payload_len) {
            throw SST_Exception("Invalid session key response format");
        }

        const unsigned char* resp_payload = resp_buf + 1 + resp_len_varint_size;

        // --- 3c. Decrypt the response using entity's private key (RSA-OAEP) ---
        unsigned char decrypted[MAX_SECURE_COMM_MSG_LENGTH];
        size_t dec_len = sizeof(decrypted);
        ret = Crypto::private_decrypt(
            resp_payload, static_cast<size_t>(resp_payload_len),
            RSA_PKCS1_OAEP_PADDING,
            ctx_->priv_key.get(),
            decrypted, &dec_len);
        if (ret != 0) {
            throw SST_Exception("Failed to decrypt session key response with OAEP");
        }
        LOG_INF << "Decrypted response size: " << dec_len << " bytes";

        // --- 3d. Parse the decrypted response ---
        // Format: distribution_key + num_keys(4 BE) + session_keys[]
        if (dec_len < sizeof(distribution_key_t) + 4) {
            throw SST_Exception("Decrypted response too short for distribution key");
        }

        std::memcpy(&ctx_->dist_key, decrypted, sizeof(distribution_key_t));
        size_t resp_offset = sizeof(distribution_key_t);

        int num_keys_resp = 0;
        std::memcpy(&num_keys_resp, decrypted + resp_offset, sizeof(int));
        resp_offset += sizeof(int);
        LOG_INF << "Auth returned " << num_keys_resp << " session key(s)";

        // Clear existing session keys
        session_key_list_->num_key = 0;
        session_key_list_->rear_idx = 0;

        for (int i = 0; i < num_keys_resp && i < static_cast<int>(MAX_SESSION_KEY); ++i) {
            if (offset + sizeof(session_key_t) > dec_len) {
                throw SST_Exception("Response too short for session key");
            }
            std::memcpy(&session_key_list_->s_key[i], decrypted + offset,
                       sizeof(session_key_t));
            offset += sizeof(session_key_t);
            session_key_list_->num_key = i + 1;
            session_key_list_->rear_idx = (i + 1) % MAX_SESSION_KEY;

            LOG_DBG << "Session key " << i << " ID: ";
            for (int j = 0; j < static_cast<int>(SESSION_KEY_ID_SIZE); ++j) {
                LOG_DBG << std::hex << static_cast<int>(session_key_list_->s_key[i].key_id[j]);
            }
            LOG_DBG << std::dec;
        }

        LOG_INF << "Session keys received and parsed successfully";
    } catch (...) {
        // RAII guard will automatically close the socket
        throw;
    }
}

int SST_API::send_to_auth(int sock, const unsigned char* data, size_t len) {
    if (sock < 0) {
        throw SST_Exception("Invalid socket FD");
    }

    ssize_t total = 0;
    while (total < static_cast<ssize_t>(len)) {
        ssize_t n = ::send(sock, data + total, len - total, MSG_NOSIGNAL);
        if (n <= 0) {
            LOG_ERR << "Failed to send to Auth server";
            throw SST_Exception("Failed to send to Auth server");
        }
        total += n;
    }

    return static_cast<int>(total);
}

// Read the IoTSP message header: [1 byte: msgType][variable-length: payloadLen]
// Returns the payload length, or -1 on error.
static int read_iotsp_header(int sock) {
    unsigned char header_buf[5]; // 1 byte msgType + up to 4 bytes varint
    ssize_t total = 0;

    // Read msgType byte
    ssize_t n = ::recv(sock, header_buf, 1, 0);
    if (n <= 0) {
        LOG_ERR << "Failed to receive msgType from Auth server";
        return -1;
    }
    total += n;

    // Read variable-length payloadLen (until byte with high bit clear)
    while (total < 5) {
        n = ::recv(sock, header_buf + total, 1, 0);
        if (n <= 0) {
            LOG_ERR << "Failed to receive payloadLen from Auth server";
            return -1;
        }
        total += n;
        if (!(header_buf[total - 1] & 0x80)) {
            break; // last byte
        }
    }

    // Decode payloadLen from varint (little-endian, 7 bits per byte)
    int payload_len = 0;
    int shift = 0;
    for (int i = 1; i < total; ++i) {
        payload_len |= (header_buf[i] & 0x7F) << shift;
        shift += 7;
    }

    return payload_len;
}

int SST_API::recv_from_auth(int sock, unsigned char* buf, size_t len) {
    if (sock < 0) {
        throw SST_Exception("Invalid socket FD");
    }

    // Parse IoTSP header first to get actual payload length
    int payload_len = read_iotsp_header(sock);
    if (payload_len < 0) {
        throw SST_Exception("Failed to receive IoTSP header from Auth server");
    }

    // Sanity check: header (1 + varint) + payload should fit in buf
    size_t total_msg_size = static_cast<size_t>(payload_len) + 1; // +1 for msgType
    if (total_msg_size > len) {
        LOG_ERR << "IoTSP message too large: " << total_msg_size << " > " << len;
        throw SST_Exception("IoTSP message too large");
    }

    // Read msgType byte
    ssize_t n = ::recv(sock, buf, 1, 0);
    if (n <= 0) {
        LOG_ERR << "Failed to receive msgType from Auth server";
        throw SST_Exception("Failed to receive from Auth server");
    }

    // Read payload bytes
    ssize_t total = 1;
    while (total < total_msg_size) {
        n = ::recv(sock, buf + total, total_msg_size - total, 0);
        if (n <= 0) {
            LOG_ERR << "Failed to receive payload from Auth server (got "
                    << total << " of " << total_msg_size << " bytes)";
            throw SST_Exception("Failed to receive from Auth server");
        }
        total += n;
    }

    return static_cast<int>(total);
}

// ---------------------------------------------------------------------------
// SST_Session Implementation
// ---------------------------------------------------------------------------

SST_Session::SST_Session(SST_session_ctx_t* session_ctx, SSL_Socket socket)
    : session_ctx_(session_ctx), socket_(std::move(socket)) {
    LOG_INF << "SST_Session created with FD: " << session_ctx_->sock;
}

SST_Session::~SST_Session() {
    free_session_ctx(session_ctx_);
    session_ctx_ = nullptr;
}

std::unique_ptr<SST_Session> SST_Session::connect_to_server(
    SST_API& api, const std::vector<uint8_t>& session_key_id) {
    LOG_INF << "Connecting to server with session key ID";

    // Get the session key from API context
    auto key_opt = api.get_session_key_by_id(session_key_id);
    if (!key_opt) {
        throw SST_Exception("Session key not found for provided ID");
    }
    const SessionKey& key = *key_opt;

    LOG_INF << "Found session key, establishing secure connection";

    // Create a session_key_t from the high-level SessionKey
    session_key_t s_key{};
    std::copy(key.id.begin(), key.id.end(), s_key.key_id);
    s_key.abs_validity = key.abs_validity;
    s_key.rel_validity = key.rel_validity;

    // Connect to the entity server using SSL
    SSL_Socket ssl_socket;

    int ret = ssl_socket.InitClientContext(
        nullptr,  // cert_file (optional for client)
        nullptr,  // key_file (optional for client)
        nullptr   // ca_file (optional for client)
    );

    if (ret != 0) {
        throw SST_Exception("Failed to initialize SSL context");
    }

    ret = ssl_socket.Connect(static_cast<SST_SOCK_DOMAIN>(AF_INET),
                             api.get_ctx().config.entity_server_ip_addr,
                             api.get_ctx().config.entity_server_port_num);

    if (ret != 0) {
        throw SST_Exception("Failed to connect to entity server via TLS");
    }

    LOG_INF << "TLS connection established";

    // Create session context — SSL_Socket is moved into SST_Session to own
    // the socket for the session's lifetime.
    SST_session_ctx_t* session_ctx = new SST_session_ctx_t();
    session_ctx->sock = ssl_socket.get_fd();
    std::memcpy(&session_ctx->s_key, &s_key, sizeof(session_key_t));
    session_ctx->sent_seq_num = 0;
    session_ctx->received_seq_num = 0;

    LOG_INF << "Secure session established";

    // Move SSL_Socket into the session — transfers ownership, the SSL_Socket
    // destructor will not close the socket because ssl_ is nullified by move.
    return std::unique_ptr<SST_Session>(
        new SST_Session(session_ctx, std::move(ssl_socket)));
}

int SST_Session::send_message(const std::vector<uint8_t>& data) {
    if (!session_ctx_ || !session_ctx_->sock) {
        throw SST_Exception("No active session for sending");
    }

    LOG_INF << "Sending secure message, payload size: " << data.size();

    // Stack-allocated buffers — no heap allocation (per crypto design
    // principle).
    std::array<unsigned char, MAX_SECURE_COMM_MSG_LENGTH> enc_buf{};
    std::array<unsigned char, MAX_SECURE_COMM_MSG_LENGTH + 3> frame{};

    // Encrypt and authenticate the payload
    unsigned int enc_len = Crypto::get_expected_encrypted_total_length(
        data.size(), AES_IV_SIZE, MAC_KEY_SIZE, session_ctx_->s_key.enc_mode,
        session_ctx_->s_key.hmac_mode);

    int ret = Crypto::symmetric_encrypt_authenticate(
        data.data(), static_cast<unsigned int>(data.size()),
        session_ctx_->s_key.mac_key, session_ctx_->s_key.mac_key_size,
        session_ctx_->s_key.cipher_key, session_ctx_->s_key.cipher_key_size,
        AES_IV_SIZE, session_ctx_->s_key.enc_mode,
        session_ctx_->s_key.hmac_mode, enc_buf.data(), &enc_len);

    if (ret != 0) {
        throw SST_Exception("Failed to encrypt message");
    }

    // Build the full frame: [type=0x01][2-byte length][IV + encrypted_payload +
    // HMAC]
    frame[0] = 0x01;  // DATA message type
    uint16_t msg_len = static_cast<uint16_t>(enc_len + AES_IV_SIZE);
    frame[1] = static_cast<unsigned char>((msg_len >> 8) & 0xFF);
    frame[2] = static_cast<unsigned char>(msg_len & 0xFF);
    std::memcpy(frame.data() + 3, enc_buf.data(), enc_len);

    // Send the frame using the SSL/TLS socket (uses SSL_write internally)
    int bytes_sent =
        socket_.Write(reinterpret_cast<char*>(frame.data()), 3 + enc_len);

    if (bytes_sent <= 0) {
        throw SST_Exception("Failed to send secure message");
    }

    session_ctx_->sent_seq_num++;

    LOG_INF << "Secure message sent successfully (" << bytes_sent << " bytes)";
    return bytes_sent;
}

std::vector<uint8_t> SST_Session::read_message() {
    if (!session_ctx_ || !session_ctx_->sock) {
        throw SST_Exception("No active session for reading");
    }

    LOG_INF << "Reading secure message";

    // Stack-allocated buffers — no heap allocation (per crypto design
    // principle). Frame: [type=0x01][2-byte length][IV + encrypted_payload +
    // HMAC] Max frame size = 3 (header) + MAX_SECURE_COMM_MSG_LENGTH (encrypted
    // body)
    std::array<unsigned char, MAX_SECURE_COMM_MSG_LENGTH + 3> frame{};

    // Read the frame header: type (1 byte) + length (2 bytes)
    int bytes_recv = socket_.Read(reinterpret_cast<char*>(frame.data()), 3);

    if (bytes_recv <= 0) {
        throw SST_Exception("Failed to read message header");
    }

    // Parse length (big-endian)
    uint16_t msg_len = (static_cast<uint16_t>(frame[1]) << 8) | frame[2];

    // Bounds check: validate msg_len before reading
    if (msg_len == 0) {
        throw SST_Exception("Received message with zero length");
    }
    if (msg_len > MAX_SECURE_COMM_MSG_LENGTH) {
        throw SST_Exception("Received message too large: " +
                           std::to_string(msg_len) + " bytes (max: " +
                           std::to_string(MAX_SECURE_COMM_MSG_LENGTH) + ")");
    }

    LOG_INF << "Received message with length: " << msg_len;

    // Read the rest of the frame: IV + encrypted data
    bytes_recv = socket_.Read(reinterpret_cast<char*>(frame.data() + 3),
                              static_cast<int>(msg_len));

    if (bytes_recv <= 0) {
        throw SST_Exception("Failed to read message body");
    }

    // Extract IV and encrypted data
    unsigned int enc_len = static_cast<unsigned int>(msg_len - AES_IV_SIZE);

    // Compute expected decrypted length
    unsigned int dec_len = Crypto::get_expected_decrypted_maximum_length(
        enc_len, AES_IV_SIZE, MAC_KEY_SIZE, session_ctx_->s_key.enc_mode,
        session_ctx_->s_key.hmac_mode);

    // Decrypt and verify the message
    std::array<unsigned char, MAX_PAYLOAD_LENGTH + AES_IV_SIZE + MAC_KEY_SIZE>
        decrypted{};

    int ret = Crypto::symmetric_decrypt_authenticate(
        frame.data() + 3 + AES_IV_SIZE, enc_len, session_ctx_->s_key.mac_key,
        session_ctx_->s_key.mac_key_size, session_ctx_->s_key.cipher_key,
        session_ctx_->s_key.cipher_key_size, AES_IV_SIZE,
        session_ctx_->s_key.enc_mode, session_ctx_->s_key.hmac_mode,
        decrypted.data(), &dec_len);

    if (ret != 0) {
        throw SST_Exception("Failed to decrypt/verify message");
    }

    session_ctx_->received_seq_num++;

    LOG_INF << "Secure message received and decrypted successfully";

    return std::vector<uint8_t>(decrypted.begin(), decrypted.begin() + dec_len);
}

}  // namespace sst