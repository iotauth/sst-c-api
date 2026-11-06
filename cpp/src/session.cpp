/**
 * @file session.cpp
 * @brief Secure session lifetime and encrypted message I/O.
 */

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <utility>

#include "api.hpp"
#include "api_internal.hpp"
#include "log/log_manager.hpp"
#include "message/iotsp_message.hpp"

namespace sst {

using internal::Bytes;
using internal::read_unsigned_int_BE;
using internal::symmetric_decrypt_authenticate;
using internal::write_bytes_to_socket;
using internal::write_in_n_bytes;
using message::IoTSPMessage;
using message::MessageType;

SST_Session::SST_Session(int sock, const session_key_t& s_key)
    : sock_(sock), s_key_(s_key) {}

SST_Session::~SST_Session() {
    if (sock_ >= 0) {
        ::close(sock_);
    }
}

// Retain the public member type, including callers taking its address.
void SST_Session::shutdown() {  // NOSONAR: S5817, public API compatibility.
    if (sock_ >= 0) {
        ::shutdown(sock_, SHUT_RDWR);
    }
}

int SST_Session::send_secure_message(const std::string& msg) {
    return send_secure_message_result(msg).legacy_value();
}

int SST_Session::send_secure_message(const unsigned char* msg,
                                     unsigned int length) {
    return send_secure_message_result(msg, length).legacy_value();
}

int SST_Session::read_secure_message(unsigned char* plaintext,
                                     unsigned int capacity) {
    return read_secure_message_result(plaintext, capacity).legacy_value();
}

// The std::string overload is part of the public API; retain its exact
// signature.
SST_IOResult SST_Session::send_secure_message_result(
    const std::string& msg) {  // NOSONAR: S6009, public API compatibility.
    if (msg.size() > MAX_PAYLOAD_LENGTH) {
        return SST_IOResult::failure(SST_ErrorCode::InvalidArgument);
    }
    return send_secure_message_result(
        reinterpret_cast<const unsigned char*>(msg.data()),
        static_cast<unsigned int>(msg.size()));
}

SST_IOResult SST_Session::send_secure_message_result(const unsigned char* msg,
                                                     unsigned int msg_length) {
    std::scoped_lock lock(send_mutex_);
    if (msg_length > MAX_PAYLOAD_LENGTH || (!msg && msg_length != 0)) {
        LOG_ERR << "Invalid message buffer or length: " << msg_length;
        return SST_IOResult::failure(SST_ErrorCode::InvalidArgument);
    }
    if (!is_session_key_valid(s_key_)) {
        LOG_ERR << "Session key expired!";
        return SST_IOResult::failure(SST_ErrorCode::KeyExpired);
    }
    // Encrypt the sequence number with the payload so authentication also
    // protects message ordering. Each direction has its own counter.
    Bytes buf(SEQ_NUM_SIZE + msg_length, 0);
    write_in_n_bytes(sent_seq_num_, SEQ_NUM_SIZE, buf.data());
    if (msg_length != 0)
        std::memcpy(buf.data() + SEQ_NUM_SIZE, msg, msg_length);

    unsigned int expected_length = Crypto::get_expected_encrypted_total_length(
        static_cast<unsigned int>(buf.size()), AES_128_IV_SIZE,
        MAC_KEY_SHA256_SIZE, s_key_.enc_mode, s_key_.hmac_mode);
    Bytes encrypted(expected_length, 0);
    unsigned int encrypted_length = 0;
    if (SST_API::encrypt_buf_with_session_key(
            s_key_, buf.data(), static_cast<unsigned int>(buf.size()),
            encrypted.data(), &encrypted_length) < 0) {
        LOG_ERR << "Failed to encrypt_buf_with_session_key().";
        return SST_IOResult::failure(SST_ErrorCode::Crypto);
    }
    sent_seq_num_++;
    encrypted.resize(encrypted_length);
    Bytes sender =
        IoTSPMessage(MessageType::SECURE_COMM_MSG, std::move(encrypted))
            .serialize();
    int bytes_written = write_bytes_to_socket(sock_, sender);
    if (bytes_written < 0) {
        LOG_ERR << "Failed sst_write_to_socket().";
        return SST_IOResult::failure(SST_ErrorCode::Network);
    }
    return SST_IOResult::success(static_cast<unsigned int>(bytes_written));
}

SST_IOResult SST_Session::read_secure_message_result(
    unsigned char* plaintext, unsigned int plaintext_capacity) {
    std::scoped_lock lock(recv_mutex_);
    if (!plaintext && plaintext_capacity != 0) {
        return SST_IOResult::failure(SST_ErrorCode::InvalidArgument);
    }
    MessageType message_type;
    Bytes received;
    if (const SST_IOResult frame = IoTSPMessage::read_result(
            sock_, MAX_SECURE_COMM_MSG_LENGTH, message_type, received);
        !frame.ok())
        return frame;
    if (message_type != MessageType::SECURE_COMM_MSG) {
        LOG_ERR << "Wrong message type " << message::to_string(message_type)
                << ", expected SECURE_COMM_MSG.";
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    Bytes decrypted;
    if (symmetric_decrypt_authenticate(
            received.data(), static_cast<unsigned int>(received.size()),
            {s_key_.mac_key, MAC_KEY_SIZE, s_key_.cipher_key, CIPHER_KEY_SIZE,
             s_key_.enc_mode, s_key_.hmac_mode},
            decrypted) < 0) {
        LOG_ERR << "Failed to decrypt received message.";
        return SST_IOResult::failure(SST_ErrorCode::Crypto);
    }
    if (decrypted.size() < SEQ_NUM_SIZE) {
        LOG_ERR << "Decrypted message shorter than the sequence number.";
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    unsigned int received_seq_num =
        read_unsigned_int_BE(decrypted.data(), SEQ_NUM_SIZE);
    if (received_seq_num != received_seq_num_) {
        LOG_ERR << "Wrong sequence number expected. Got " << received_seq_num
                << ", expected " << received_seq_num_;
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    if (!is_session_key_valid(s_key_)) {
        LOG_ERR << "Session key expired!";
        return SST_IOResult::failure(SST_ErrorCode::KeyExpired);
    }
    received_seq_num_++;
    LOG_DBG << "Received seq_num: " << received_seq_num << ".";

    unsigned int plaintext_length =
        static_cast<unsigned int>(decrypted.size()) - SEQ_NUM_SIZE;
    if (plaintext_length > plaintext_capacity) {
        LOG_ERR << "Plaintext buffer too small: need " << plaintext_length
                << ", have " << plaintext_capacity;
        return SST_IOResult::failure(SST_ErrorCode::BufferTooSmall);
    }
    if (plaintext_length != 0) {
        std::memcpy(plaintext, decrypted.data() + SEQ_NUM_SIZE,
                    plaintext_length);
    }
    return SST_IOResult::success(plaintext_length);
}

void SST_Session::receive_loop() {
    std::array<unsigned char, MAX_SECURE_COMM_MSG_LENGTH> data_buf{};
    while (true) {
        int data_buf_length =
            read_secure_message(data_buf.data(), data_buf.size());
        if (data_buf_length < 0) {
            LOG_ERR << "Failed to read_secure_message().";
            return;
        }
        if (data_buf_length == 0) {
            return;
        }
        LOG_INF << "Received: "
                << std::string(data_buf.begin(),
                               data_buf.begin() + data_buf_length);
    }
}

}  // namespace sst
