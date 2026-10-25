/**
 * @file handshake.cpp
 * @brief Entity-to-entity session key handshakes using the SST C wire format.
 */

#include <cstring>
#include <utility>

#include "api.hpp"
#include "api_internal.hpp"
#include "log/log_manager.hpp"
#include "message/iotsp_message.hpp"

namespace sst {

using internal::Bytes;
using internal::connect_as_client;
using internal::FdGuard;
using internal::symmetric_decrypt_authenticate;
using internal::symmetric_encrypt_authenticate;
using internal::to_hex;
using internal::write_bytes_to_socket;
using message::IoTSPMessage;
using message::MessageType;

namespace {

constexpr unsigned int HS_NONCE_SIZE = 8;
constexpr unsigned int HS_NONCE_FIELDS_SIZE = 1 + HS_NONCE_SIZE * 2;
constexpr unsigned char HS_NONCE_PRESENT = 0x01;
constexpr unsigned char HS_REPLY_NONCE_PRESENT = 0x02;
constexpr unsigned int MAX_HS_BUF_LENGTH = 256;

// Each peer sends a fresh nonce and proves key possession by echoing the other.
struct HS_nonce_t {
    unsigned char nonce[HS_NONCE_SIZE];
    unsigned char reply_nonce[HS_NONCE_SIZE];
};

// Decrypted handshake body: handshake_flags (1) + nonce (8) + replyNonce (8).
// These flags are the protocol's inner "indicator" bitmask. The outer frame
// starts with msgType, added separately by IoTSPMessage::serialize().
int serialize_handshake_body(const unsigned char* nonce,
                             const unsigned char* reply_nonce,
                             unsigned char* ret) {
    if (nonce == nullptr && reply_nonce == nullptr) {
        LOG_ERR << "Handshake should include at least one nonce.";
        return -1;
    }
    unsigned char handshake_flags = 0;
    if (nonce != nullptr) {
        handshake_flags |= HS_NONCE_PRESENT;
        std::memcpy(ret + 1, nonce, HS_NONCE_SIZE);
    }
    if (reply_nonce != nullptr) {
        handshake_flags |= HS_REPLY_NONCE_PRESENT;
        std::memcpy(ret + 1 + HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    ret[0] = handshake_flags;
    return 0;
}

void parse_handshake_body(const unsigned char* buf, HS_nonce_t& ret) {
    std::memset(&ret, 0, sizeof(ret));
    if ((buf[0] & HS_NONCE_PRESENT) != 0) {
        std::memcpy(ret.nonce, buf + 1, HS_NONCE_SIZE);
    }
    if ((buf[0] & HS_REPLY_NONCE_PRESENT) != 0) {
        std::memcpy(ret.reply_nonce, buf + 1 + HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
}

// Session key handshake messages are always encrypted with CBC-sized IV and
// HMAC (hmac_mode 0 == USE_HMAC in the C API).
int handshake_encrypt(const unsigned char* buf, unsigned int buf_length,
                      const session_key_t& s_key, Bytes& ret) {
    return symmetric_encrypt_authenticate(
        buf, buf_length, s_key.mac_key, MAC_KEY_SIZE, s_key.cipher_key,
        CIPHER_KEY_SIZE, s_key.enc_mode, USE_HMAC, ret);
}

int handshake_decrypt(const unsigned char* buf, unsigned int buf_length,
                      const session_key_t& s_key, Bytes& ret) {
    return symmetric_decrypt_authenticate(
        buf, buf_length, s_key.mac_key, MAC_KEY_SIZE, s_key.cipher_key,
        CIPHER_KEY_SIZE, s_key.enc_mode, USE_HMAC, ret);
}

// SKEY_HANDSHAKE_1 payload: sessionKeyId (8) + Enc(handshake_flags + nonce).
// Preserve the C API's compact 9-byte body; no replyNonce slot is sent here.
Bytes make_handshake_1_payload(const session_key_t& s_key,
                               unsigned char* entity_nonce) {
    if (Crypto::generate_nonce(HS_NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.",
                            SST_ErrorCode::Crypto);
    }
    unsigned char handshake_body[1 + HS_NONCE_SIZE];
    handshake_body[0] = HS_NONCE_PRESENT;
    std::memcpy(handshake_body + 1, entity_nonce, HS_NONCE_SIZE);

    Bytes encrypted;
    if (handshake_encrypt(handshake_body, 1 + HS_NONCE_SIZE, s_key, encrypted) <
        0) {
        throw SST_Exception("Failed to encrypt handshake 1.",
                            SST_ErrorCode::Crypto);
    }
    Bytes ret;
    ret.reserve(SESSION_KEY_ID_SIZE + encrypted.size());
    ret.insert(ret.end(), s_key.key_id, s_key.key_id + SESSION_KEY_ID_SIZE);
    ret.insert(ret.end(), encrypted.begin(), encrypted.end());
    return ret;
}

// Client: verifies SKEY_HANDSHAKE_2 and builds SKEY_HANDSHAKE_3.
Bytes check_handshake_2_send_handshake_3(const unsigned char* data_buf,
                                         unsigned int data_buf_length,
                                         const unsigned char* entity_nonce,
                                         const session_key_t& s_key) {
    LOG_DBG << "Received session key handshake2!";
    Bytes decrypted;
    if (handshake_decrypt(data_buf, data_buf_length, s_key, decrypted) < 0 ||
        decrypted.size() < HS_NONCE_FIELDS_SIZE) {
        throw SST_Exception("Error during decryption in checking handshake2.",
                            SST_ErrorCode::Crypto);
    }
    HS_nonce_t hs;
    parse_handshake_body(decrypted.data(), hs);

    if (std::memcmp(hs.reply_nonce, entity_nonce, HS_NONCE_SIZE) != 0) {
        throw SST_Exception(
            "Comm init failed: server NOT verified, nonce NOT matched, "
            "disconnecting...",
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Server authenticated/authorized by solving nonce!";

    unsigned char buf[HS_NONCE_FIELDS_SIZE];
    std::memset(buf, 0, HS_NONCE_FIELDS_SIZE);
    if (serialize_handshake_body(entity_nonce, hs.nonce, buf) < 0) {
        throw SST_Exception("Failed serialize_handshake_body().",
                            SST_ErrorCode::Protocol);
    }
    Bytes ret;
    if (handshake_encrypt(buf, HS_NONCE_FIELDS_SIZE, s_key, ret) < 0) {
        throw SST_Exception("Error during encryption while send_handshake_3.",
                            SST_ErrorCode::Crypto);
    }
    return ret;
}

// Server: verifies SKEY_HANDSHAKE_1 and builds SKEY_HANDSHAKE_2.
Bytes check_handshake1_send_handshake2(const unsigned char* received_buf,
                                       unsigned int received_buf_length,
                                       unsigned char* server_nonce,
                                       const session_key_t& s_key) {
    if (received_buf_length <= SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.", SST_ErrorCode::Protocol);
    }
    Bytes decrypted;
    if (handshake_decrypt(received_buf + SESSION_KEY_ID_SIZE,
                          received_buf_length - SESSION_KEY_ID_SIZE, s_key,
                          decrypted) < 0 ||
        decrypted.size() < 1 + HS_NONCE_SIZE) {
        throw SST_Exception("Error during decrypting handshake1.",
                            SST_ErrorCode::Crypto);
    }
    HS_nonce_t hs;
    parse_handshake_body(decrypted.data(), hs);
    LOG_DBG << "Client's nonce: " << to_hex(hs.nonce, HS_NONCE_SIZE);

    if (Crypto::generate_nonce(HS_NONCE_SIZE, server_nonce) < 0) {
        throw SST_Exception("Failed to generate server nonce.",
                            SST_ErrorCode::Crypto);
    }
    LOG_DBG << "Server's nonce: " << to_hex(server_nonce, HS_NONCE_SIZE);

    unsigned char buf[HS_NONCE_FIELDS_SIZE];
    std::memset(buf, 0, HS_NONCE_FIELDS_SIZE);
    if (serialize_handshake_body(server_nonce, hs.nonce, buf) < 0) {
        throw SST_Exception("Failed serialize_handshake_body().",
                            SST_ErrorCode::Protocol);
    }
    Bytes ret;
    if (handshake_encrypt(buf, HS_NONCE_FIELDS_SIZE, s_key, ret) < 0) {
        throw SST_Exception("Error during encryption while sending handshake2.",
                            SST_ErrorCode::Crypto);
    }
    return ret;
}

}  // namespace

std::unique_ptr<SST_Session> SST_API::secure_connect_to_server(
    session_key_t& s_key) {
    int sock = connect_as_client(config_.entity_server_ip_addr,
                                 config_.entity_server_port_num);
    if (sock < 0) {
        throw SST_Exception(
            std::string("Failed to connect to entity server at ") +
                config_.entity_server_ip_addr + ":" +
                std::to_string(config_.entity_server_port_num),
            SST_ErrorCode::Network);
    }
    return secure_connect_to_server_with_socket(s_key, sock);
}

std::unique_ptr<SST_Session> SST_API::secure_connect_to_server_with_socket(
    session_key_t& s_key, int sock) {
    FdGuard guard(sock);

    // Send handshake 1.
    unsigned char entity_nonce[HS_NONCE_SIZE];
    Bytes parsed = make_handshake_1_payload(s_key, entity_nonce);
    Bytes sender_HS_1 =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_1, std::move(parsed))
            .serialize();
    if (write_bytes_to_socket(sock, sender_HS_1) < 0) {
        throw SST_Exception("Failed to send handshake 1.",
                            SST_ErrorCode::Network);
    }

    // Receive handshake 2.
    MessageType message_type;
    Bytes received;
    int data_buf_length =
        IoTSPMessage::read(sock, MAX_HS_BUF_LENGTH, message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception(
            "Socket read error in secure_connect_to_server_with_socket().",
            SST_ErrorCode::Network);
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake2 in "
            "secure_connect_to_server_with_socket().",
            SST_ErrorCode::PeerClosed);
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_2) {
        throw SST_Exception(
            "Comm init failed: expected SKEY_HANDSHAKE_2, got " +
                message::to_string(message_type),
            SST_ErrorCode::Protocol);
    }

    // Send handshake 3.
    Bytes hs3 = check_handshake_2_send_handshake_3(
        received.data(), static_cast<unsigned int>(received.size()),
        entity_nonce, s_key);
    Bytes sender_HS_3 =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_3, std::move(hs3)).serialize();
    if (write_bytes_to_socket(sock, sender_HS_3) < 0) {
        throw SST_Exception("Failed to send handshake 3.",
                            SST_ErrorCode::Network);
    }
    update_validity(s_key);
    LOG_DBG << "Switching to IN_COMM.";
    return std::make_unique<SST_Session>(guard.release(), s_key);
}

std::unique_ptr<SST_Session> SST_API::server_secure_comm_setup(
    int clnt_sock, SessionKeyList& existing_s_key_list) {
    FdGuard guard(clnt_sock);

    // Receive handshake 1.
    MessageType message_type;
    Bytes received;
    int data_buf_length = IoTSPMessage::read(clnt_sock, MAX_HS_BUF_LENGTH,
                                             message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().",
                            SST_ErrorCode::Network);
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake1 in "
            "server_secure_comm_setup().",
            SST_ErrorCode::PeerClosed);
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_1) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_1, got " +
                message::to_string(message_type),
            SST_ErrorCode::Protocol);
    }
    if (received.size() < SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.", SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Received session key handshake1.";

    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    std::memcpy(target_session_key_id, received.data(), SESSION_KEY_ID_SIZE);
    session_key_t* s_key =
        get_session_key_by_ID(target_session_key_id, existing_s_key_list);

    // Send handshake 2.
    unsigned char server_nonce[HS_NONCE_SIZE];
    Bytes hs2 = check_handshake1_send_handshake2(
        received.data(), static_cast<unsigned int>(received.size()),
        server_nonce, *s_key);
    Bytes sender =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_2, std::move(hs2)).serialize();
    if (write_bytes_to_socket(clnt_sock, sender) < 0) {
        throw SST_Exception("Failed to send handshake 2.",
                            SST_ErrorCode::Network);
    }
    LOG_DBG << "Switching to HANDSHAKE_2_SENT.";

    // Receive handshake 3.
    data_buf_length = IoTSPMessage::read(clnt_sock, MAX_HS_BUF_LENGTH,
                                         message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().",
                            SST_ErrorCode::Network);
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake3 in "
            "server_secure_comm_setup().",
            SST_ErrorCode::PeerClosed);
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_3) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_3, got " +
                message::to_string(message_type),
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Received session key handshake3!";
    Bytes decrypted;
    if (handshake_decrypt(received.data(),
                          static_cast<unsigned int>(received.size()), *s_key,
                          decrypted) < 0 ||
        decrypted.size() < HS_NONCE_FIELDS_SIZE) {
        throw SST_Exception(
            "Error during decryption in HANDSHAKE_2_SENT state.",
            SST_ErrorCode::Crypto);
    }
    HS_nonce_t hs;
    parse_handshake_body(decrypted.data(), hs);
    if (std::memcmp(hs.reply_nonce, server_nonce, HS_NONCE_SIZE) != 0) {
        throw SST_Exception(
            "Comm init failed: client NOT verified, nonce NOT matched, "
            "disconnecting...",
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Client authenticated/authorized by solving nonce!";
    update_validity(*s_key);
    LOG_DBG << "Switching to IN_COMM.";
    return std::make_unique<SST_Session>(guard.release(), *s_key);
}

}  // namespace sst
