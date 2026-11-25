#include "message/entity_req_message.hpp"

#include <openssl/rsa.h>

#include <cstring>
#include <limits>
#include <utility>

#include "log/log_manager.hpp"

namespace sst {
namespace message {

namespace {

template <size_t Size>
std::array<unsigned char, Size> copy_nonce(const unsigned char* nonce) {
    if (nonce == nullptr) {
        throw SST_Exception("Request nonce must not be null.",
                            SST_ErrorCode::InvalidArgument);
    }
    std::array<unsigned char, Size> result{};
    std::memcpy(result.data(), nonce, Size);
    return result;
}

// Enc_authPubKey(buf) (RSA-OAEP) followed by the entity's SHA-256 RSA
// signature over the ciphertext.
Bytes encrypt_and_sign(const Bytes& buf, EVP_PKEY* pub_key,
                       EVP_PKEY* priv_key) {
    Bytes encrypted(static_cast<size_t>(EVP_PKEY_size(pub_key)));
    size_t encrypted_length = encrypted.size();
    if (Crypto::public_encrypt(buf.data(), buf.size(), RSA_PKCS1_OAEP_PADDING,
                               pub_key, encrypted.data(),
                               &encrypted_length) < 0) {
        throw SST_Exception("Failed public_encrypt().", SST_ErrorCode::Crypto);
    }
    encrypted.resize(encrypted_length);

    Bytes signature(static_cast<size_t>(EVP_PKEY_size(priv_key)));
    size_t sig_length = signature.size();
    if (Crypto::sha256_sign(encrypted.data(),
                            static_cast<unsigned int>(encrypted.size()),
                            priv_key, signature.data(), &sig_length) < 0) {
        throw SST_Exception("Failed sha256_sign().", SST_ErrorCode::Crypto);
    }
    signature.resize(sig_length);

    encrypted.insert(encrypted.end(), signature.begin(), signature.end());
    return encrypted;
}

// senderLen (1) + sender + Enc_distKey(buf).
Bytes encrypt_with_distribution_key(const Bytes& buf,
                                    const distribution_key_t& dist_key,
                                    const std::string& name) {
    Bytes encrypted;
    if (internal::symmetric_encrypt_authenticate(
            buf.data(), static_cast<unsigned int>(buf.size()),
            {dist_key.mac_key, dist_key.mac_key_size, dist_key.cipher_key,
             dist_key.cipher_key_size, dist_key.enc_mode, USE_HMAC},
            encrypted) < 0) {
        throw SST_Exception(
            "Error during encryption with the distribution key.",
            SST_ErrorCode::Crypto);
    }
    Bytes ret;
    ret.reserve(1 + name.size() + encrypted.size());
    ret.push_back(static_cast<unsigned char>(name.size()));
    ret.insert(ret.end(), name.begin(), name.end());
    ret.insert(ret.end(), encrypted.begin(), encrypted.end());
    return ret;
}

}  // namespace

EntityReqMessage::EntityReqMessage(MessageType pub_enc_type,
                                   MessageType dist_key_type,
                                   const EntityNonce& entity_nonce,
                                   const AuthNonce& auth_nonce,
                                   std::string entity_name, std::string purpose)
    : IoTSPMessage(pub_enc_type),
      pub_enc_type_(pub_enc_type),
      dist_key_type_(dist_key_type),
      entity_nonce_(entity_nonce),
      auth_nonce_(auth_nonce),
      entity_name_(std::move(entity_name)),
      purpose_(std::move(purpose)) {
    // The distribution-key envelope uses a single byte for the sender length.
    // Check at construction so switching encryption modes cannot truncate it.
    if (entity_name_.size() > std::numeric_limits<uint8_t>::max()) {
        throw SST_Exception("Entity name exceeds the 255-byte wire limit.",
                            SST_ErrorCode::InvalidArgument);
    }
}

EntityReqMessage::EntityReqMessage(MessageType pub_enc_type,
                                   MessageType dist_key_type,
                                   const unsigned char* entity_nonce,
                                   const unsigned char* auth_nonce,
                                   std::string entity_name, std::string purpose)
    : EntityReqMessage(pub_enc_type, dist_key_type,
                       copy_nonce<ENTITY_NONCE_SIZE>(entity_nonce),
                       copy_nonce<AUTH_NONCE_SIZE>(auth_nonce),
                       std::move(entity_name), std::move(purpose)) {}

Bytes EntityReqMessage::serialize_and_encrypt(
    const distribution_key_t& dist_key, EVP_PKEY* auth_pub_key,
    EVP_PKEY* entity_priv_key) {
    Bytes plain = serialize_payload();
    if (internal::is_distribution_key_valid(dist_key)) {
        type_ = dist_key_type_;
        payload_ = encrypt_with_distribution_key(plain, dist_key, entity_name_);
    } else {
        LOG_DBG << "Current distribution key expired, requesting new "
                   "distribution key as well...";
        if (auth_pub_key == nullptr || entity_priv_key == nullptr) {
            throw SST_Exception(
                "Distribution key expired but no public/private key loaded.",
                SST_ErrorCode::KeyLoad);
        }
        type_ = pub_enc_type_;
        payload_ = encrypt_and_sign(plain, auth_pub_key, entity_priv_key);
    }
    return serialize();
}

void EntityReqMessage::append_nonces(Bytes& buf) const {
    buf.insert(buf.end(), entity_nonce_.begin(), entity_nonce_.end());
    buf.insert(buf.end(), auth_nonce_.begin(), auth_nonce_.end());
}

void EntityReqMessage::append_buffered_string(Bytes& buf,
                                              const std::string& str) {
    unsigned char len_buf[internal::MAX_PAYLOAD_BUF_SIZE];
    unsigned int len_size;
    internal::num_to_var_length_int(static_cast<unsigned int>(str.size()),
                                    len_buf, &len_size);
    buf.insert(buf.end(), len_buf, len_buf + len_size);
    buf.insert(buf.end(), str.begin(), str.end());
}

}  // namespace message
}  // namespace sst
