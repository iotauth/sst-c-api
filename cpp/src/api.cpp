/**
 * @file api.cpp
 * @brief SST entity initialization and Auth request orchestration.
 */

#include "api.hpp"

#include <openssl/crypto.h>
#include <openssl/rsa.h>

#include <cstring>
#include <fstream>
#include <utility>

#include "api_internal.hpp"
#include "log/log_manager.hpp"
#include "message/add_reader_req_message.hpp"
#include "message/add_reader_resp_message.hpp"
#include "message/auth_alert_message.hpp"
#include "message/auth_hello_message.hpp"
#include "message/iotsp_message.hpp"
#include "message/session_key_req_message.hpp"
#include "message/session_key_resp_message.hpp"

namespace sst {

using internal::Bytes;
using internal::connect_as_client;
using internal::FdGuard;
using internal::load_config;
using internal::read_unsigned_long_int_BE;
using internal::to_hex;
using internal::write_bytes_to_socket;
using message::IoTSPMessage;
using message::MessageType;

namespace {

constexpr unsigned int NONCE_SIZE = 8;
// Payload limit for Auth responses, excluding msgType and payloadLen.
// Keep 4096 rather than the C API's 1024: ten keys plus an RSA-encrypted
// distribution key/signature, cryptoSpec, IV, padding and MAC can exceed 1 KiB.
constexpr unsigned int MAX_AUTH_COMM_LENGTH = 4096;

// abs_validity (6) + cipher_key_size (1) + cipher_key + mac_key_size (1) +
// mac_key.
void parse_distribution_key(distribution_key_t& parsed,
                            const unsigned char* buf, size_t buf_length) {
    size_t cur_index = 0;
    if (buf_length < DIST_KEY_EXPIRATION_TIME_SIZE + 1) {
        throw SST_Exception("Distribution key buffer too short.",
                            SST_ErrorCode::Protocol);
    }
    parsed.abs_validity =
        read_unsigned_long_int_BE(buf, DIST_KEY_EXPIRATION_TIME_SIZE);
    cur_index += DIST_KEY_EXPIRATION_TIME_SIZE;

    unsigned int cipher_key_size = buf[cur_index];
    cur_index += 1;
    if (cipher_key_size > MAX_CIPHER_KEY_SIZE ||
        cur_index + cipher_key_size + 1 > buf_length) {
        throw SST_Exception("Invalid distribution cipher key size.",
                            SST_ErrorCode::Protocol);
    }
    parsed.cipher_key_size = cipher_key_size;
    std::memcpy(parsed.cipher_key, buf + cur_index, cipher_key_size);
    cur_index += cipher_key_size;

    unsigned int mac_key_size = buf[cur_index];
    cur_index += 1;
    if (mac_key_size > MAC_KEY_SIZE || cur_index + mac_key_size > buf_length) {
        throw SST_Exception("Invalid distribution MAC key size.",
                            SST_ErrorCode::Protocol);
    }
    parsed.mac_key_size = mac_key_size;
    std::memcpy(parsed.mac_key, buf + cur_index, mac_key_size);
}

int connect_to_auth(const config_t& config) {
    int sock = connect_as_client(config.auth_ip_addr, config.auth_port_num);
    if (sock < 0) {
        throw SST_Exception(std::string("Failed to connect to Auth at ") +
                                config.auth_ip_addr + ":" +
                                std::to_string(config.auth_port_num),
                            SST_ErrorCode::Network);
    }
    return sock;
}

// Reads the next message from Auth. An AUTH_ALERT is turned into an
// SST_Exception here, so every request flow handles alerts the same way.
IoTSPMessage receive_from_auth(int sock) {
    IoTSPMessage msg = IoTSPMessage::receive(sock, MAX_AUTH_COMM_LENGTH);
    if (msg.get_type() == MessageType::AUTH_ALERT) {
        throw SST_Exception(message::AuthAlertMessage(msg).describe(),
                            SST_ErrorCode::AuthRejected);
    }
    return msg;
}

// Reads AUTH_HELLO and checks that it comes from the configured Auth.
message::AuthHelloMessage receive_auth_hello(int sock, int expected_auth_id) {
    message::AuthHelloMessage hello(receive_from_auth(sock));
    if (hello.get_auth_id() != static_cast<uint32_t>(expected_auth_id)) {
        throw SST_Exception("Auth ID NOT matched. Received " +
                                std::to_string(hello.get_auth_id()) +
                                ", expected " +
                                std::to_string(expected_auth_id),
                            SST_ErrorCode::Protocol);
    }
    return hello;
}

void send_to_auth(int sock, const Bytes& wire) {
    if (write_bytes_to_socket(sock, wire) < 0) {
        throw SST_Exception("Failed to send request to Auth.",
                            SST_ErrorCode::Network);
    }
}

const char* configured_purpose(const config_t& config, int purpose_index) {
    if (purpose_index < 0 || purpose_index > 1) {
        throw SST_Exception("Purpose index out of range.",
                            SST_ErrorCode::InvalidArgument);
    }
    return config.purpose[purpose_index];
}

}  // namespace

SST_API::SST_API(const std::string& config_path)
    : pub_key_(nullptr, &EVP_PKEY_free), priv_key_(nullptr, &EVP_PKEY_free) {
    // Suppress OpenSSL's atexit cleanup, as the C API does, so that messages
    // can still be sent from other atexit handlers.
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, nullptr);

    load_config(config_, config_path);

    if (config_.perm_dist_key_mode == NO_PERMANENT_DIST_KEY) {
        pub_key_.reset(Crypto::load_auth_public_key(config_.auth_pubkey_path));
        if (!pub_key_) {
            throw SST_Exception(
                std::string("Failed load_auth_public_key(). Given path: ") +
                    config_.auth_pubkey_path + ", config_path: " + config_path,
                SST_ErrorCode::KeyLoad);
        }
        priv_key_.reset(
            Crypto::load_entity_private_key(config_.entity_privkey_path));
        if (!priv_key_) {
            throw SST_Exception(
                std::string("Failed load_entity_private_key(). Given path: ") +
                    config_.entity_privkey_path +
                    ", config_path: " + config_path,
                SST_ErrorCode::KeyLoad);
        }
        // abs_validity 0 makes the distribution key invalid until Auth sends
        // one.
        dist_key_ = distribution_key_t{};
    } else {
        dist_key_ = distribution_key_t{};
        dist_key_.abs_validity = UINT64_MAX;
        dist_key_.enc_mode = config_.dist_key_enc_mode;
        load_permanent_distribution_key();
    }
    if (config_.numkey > static_cast<int>(MAX_SESSION_KEY)) {
        LOG_WRN << "Too much requests of session keys. The max number of "
                   "requestable session keys are "
                << MAX_SESSION_KEY;
    }
}

void SST_API::load_permanent_distribution_key() {
    if (std::strlen(config_.dist_cipher_key_path) == 0 ||
        std::strlen(config_.dist_mac_key_path) == 0) {
        throw SST_Exception(
            "PermanentDistKeyMode is on, so both distKey.cipherkey.path and "
            "distkey.mackey.path must be set.",
            SST_ErrorCode::Configuration);
    }
    {
        std::ifstream fp(config_.dist_cipher_key_path, std::ios::binary);
        if (!fp.is_open()) {
            throw SST_Exception(
                std::string("Failed to open dist_cipher_key_path: ") +
                    config_.dist_cipher_key_path,
                SST_ErrorCode::KeyLoad);
        }
        fp.read(reinterpret_cast<char*>(dist_key_.cipher_key), CIPHER_KEY_SIZE);
        if (static_cast<unsigned int>(fp.gcount()) != CIPHER_KEY_SIZE) {
            throw SST_Exception(
                std::string("Failed to read CIPHER_KEY_SIZE bytes from "
                            "dist_cipher_key_path: ") +
                    config_.dist_cipher_key_path,
                SST_ErrorCode::KeyLoad);
        }
        dist_key_.cipher_key_size = CIPHER_KEY_SIZE;
    }
    {
        std::ifstream fp(config_.dist_mac_key_path, std::ios::binary);
        if (!fp.is_open()) {
            throw SST_Exception(
                std::string("Failed to open dist_mac_key_path: ") +
                    config_.dist_mac_key_path,
                SST_ErrorCode::KeyLoad);
        }
        fp.read(reinterpret_cast<char*>(dist_key_.mac_key), MAC_KEY_SIZE);
        if (static_cast<unsigned int>(fp.gcount()) != MAC_KEY_SIZE) {
            throw SST_Exception(
                std::string("Failed to read MAC_KEY_SIZE bytes from "
                            "dist_mac_key_path: ") +
                    config_.dist_mac_key_path,
                SST_ErrorCode::KeyLoad);
        }
        dist_key_.mac_key_size = MAC_KEY_SIZE;
    }
}

SessionKeyList SST_API::get_session_key_with_index(int purpose_index) {
    std::scoped_lock lock(mutex_);
    return request_session_keys_locked(
        configured_purpose(config_, purpose_index));
}

void SST_API::get_session_key_with_index(int purpose_index,
                                         SessionKeyList& existing_s_key_list) {
    std::scoped_lock lock(mutex_);
    const char* purpose = configured_purpose(config_, purpose_index);
    if (!existing_s_key_list.addable(config_.numkey)) {
        LOG_WRN << "The session key list is not addable.";
        return;
    }
    existing_s_key_list.append(request_session_keys_locked(purpose));
}

SessionKeyList SST_API::get_session_key() {
    return get_session_key_with_index(config_.purpose_index);
}

void SST_API::get_session_key(SessionKeyList& existing_s_key_list) {
    get_session_key_with_index(config_.purpose_index, existing_s_key_list);
}

session_key_t* SST_API::get_session_key_by_ID(
    const unsigned char* target_session_key_id,
    SessionKeyList& existing_s_key_list) {
    std::scoped_lock lock(mutex_);
    uint64_t target_id =
        convert_skid_buf_to_int(target_session_key_id, SESSION_KEY_ID_SIZE);
    int session_key_idx = existing_s_key_list.find(target_id);
    if (session_key_idx >= 0) {
        return &existing_s_key_list.at_slot(session_key_idx);
    }

    // Purpose is local to this request, including when Auth rejects it.
    SessionKeyList keys = request_session_keys_locked(
        "{\"keyId\":" + std::to_string(target_id) + "}", target_session_key_id);
    int index = existing_s_key_list.add(keys.at(0));
    return &existing_s_key_list.at_slot(index);
}

void SST_API::save_distribution_key(const Bytes& encrypted_dist_key) {
    // Enc_entityPubKey(dist key) (key_size) + Sign_authPrivKey(...)
    // (key_size).
    size_t key_size = encrypted_dist_key.size() / 2;
    const unsigned char* data_buf = encrypted_dist_key.data();
    if (Crypto::sha256_verify(data_buf, static_cast<unsigned int>(key_size),
                              data_buf + key_size, key_size,
                              pub_key_.get()) < 0) {
        throw SST_Exception("Failed sha256_verify() of distribution key.",
                            SST_ErrorCode::Crypto);
    }
    LOG_DBG << "Auth signature verified.";

    Bytes decrypted(key_size);
    size_t decrypted_length = decrypted.size();
    if (Crypto::private_decrypt(data_buf, key_size, RSA_PKCS1_OAEP_PADDING,
                                priv_key_.get(), decrypted.data(),
                                &decrypted_length) < 0) {
        throw SST_Exception("Failed private_decrypt() of distribution key.",
                            SST_ErrorCode::Crypto);
    }
    parse_distribution_key(dist_key_, decrypted.data(), decrypted_length);
    dist_key_.enc_mode = config_.dist_key_enc_mode;
}

size_t SST_API::entity_rsa_key_size() const {
    return priv_key_ ? static_cast<size_t>(EVP_PKEY_size(priv_key_.get())) : 0;
}

void SST_API::decrypt_auth_response(message::EntityRespMessage& resp,
                                    const unsigned char* entity_nonce) {
    if (resp.has_distribution_key()) {
        save_distribution_key(resp.get_encrypted_distribution_key());
    }
    resp.decrypt_and_parse(dist_key_, config_.session_key_enc_mode);
    LOG_DBG << "Reply nonce in response: "
            << to_hex(resp.get_entity_nonce().data(), NONCE_SIZE);
    if (std::memcmp(resp.get_entity_nonce().data(), entity_nonce, NONCE_SIZE) !=
        0) {
        throw SST_Exception(
            "Entity nonce in Auth response does not match the request.",
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Entity nonce in Auth response verified.";
}

template <class Request, class Response, class... Args>
Response SST_API::request_auth_locked(Args&&... args) {
    if (std::strcmp(config_.network_protocol, "TCP") != 0) {
        throw SST_Exception(std::string("Unsupported network protocol: ") +
                                config_.network_protocol,
                            SST_ErrorCode::Configuration);
    }
    FdGuard guard(connect_to_auth(config_));
    message::AuthHelloMessage hello =
        receive_auth_hello(guard.get(), config_.auth_id);
    unsigned char entity_nonce[NONCE_SIZE];
    if (Crypto::generate_nonce(NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.",
                            SST_ErrorCode::Crypto);
    }
    Request req(entity_nonce, hello.get_auth_nonce().data(),
                std::forward<Args>(args)...);
    send_to_auth(guard.get(), req.serialize_and_encrypt(
                                  dist_key_, pub_key_.get(), priv_key_.get()));
    Response resp(receive_from_auth(guard.get()), entity_rsa_key_size());
    decrypt_auth_response(resp, entity_nonce);
    return resp;
}

SessionKeyList SST_API::request_session_keys_locked(
    const std::string& purpose, const unsigned char* expected_key_id) {
    auto resp = request_auth_locked<message::SessionKeyReqMessage,
                                    message::SessionKeyRespMessage>(
        config_.numkey, config_.name, purpose);
    SessionKeyList keys = resp.get_session_keys();
    if (expected_key_id) {
        if (keys.empty()) {
            throw SST_Exception("Auth returned no session key.",
                                SST_ErrorCode::Protocol);
        }
        if (std::memcmp(keys.at(0).key_id, expected_key_id,
                        SESSION_KEY_ID_SIZE) != 0) {
            throw SST_Exception("Session key id is NOT as expected.",
                                SST_ErrorCode::Protocol);
        }
    }
    // Key modes come from the config, not the serialized SessionKey fields.
    for (int i = 0; i < keys.size(); i++) {
        session_key_t& key = keys.at(static_cast<size_t>(i));
        key.enc_mode = config_.session_key_enc_mode;
        key.hmac_mode = config_.hmac_mode;
        key.perm_dist_key_mode = config_.perm_dist_key_mode;
    }
    return keys;
}

void SST_API::send_add_reader_req_via_TCP(const std::string& add_reader) {
    std::scoped_lock lock(mutex_);
    request_auth_locked<message::AddReaderReqMessage,
                        message::AddReaderRespMessage>(config_.name,
                                                       add_reader);
    LOG_INF << "Add a file reader to the database.";
}

}  // namespace sst
