#include "message/entity_req_message.hpp"

#include <openssl/rsa.h>

#include <cstring>
#include <utility>

#include "log/log_manager.hpp"

namespace sst {
namespace message {

namespace {

// Enc_authPubKey(buf) (RSA-OAEP) followed by the entity's SHA-256 RSA
// signature over the ciphertext.
Bytes encrypt_and_sign(const Bytes& buf, EVP_PKEY* pub_key,
                       EVP_PKEY* priv_key) {
    Bytes encrypted(static_cast<size_t>(EVP_PKEY_size(pub_key)));
    size_t encrypted_length = encrypted.size();
    if (Crypto::public_encrypt(buf.data(), buf.size(), RSA_PKCS1_OAEP_PADDING,
                               pub_key, encrypted.data(),
                               &encrypted_length) < 0) {
        throw SST_Exception("Failed public_encrypt().");
    }
    encrypted.resize(encrypted_length);

    Bytes signature(static_cast<size_t>(EVP_PKEY_size(priv_key)));
    size_t sig_length = signature.size();
    if (Crypto::sha256_sign(encrypted.data(),
                            static_cast<unsigned int>(encrypted.size()),
                            priv_key, signature.data(), &sig_length) < 0) {
        throw SST_Exception("Failed sha256_sign().");
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
            buf.data(), static_cast<unsigned int>(buf.size()), dist_key.mac_key,
            dist_key.mac_key_size, dist_key.cipher_key,
            dist_key.cipher_key_size, dist_key.enc_mode, USE_HMAC,
            encrypted) < 0) {
        throw SST_Exception(
            "Error during encryption with the distribution key.");
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
                                   const unsigned char* entity_nonce,
                                   const unsigned char* auth_nonce,
                                   std::string entity_name, std::string purpose)
    : IoTSPMessage(pub_enc_type),
      pub_enc_type_(pub_enc_type),
      dist_key_type_(dist_key_type),
      entity_name_(std::move(entity_name)),
      purpose_(std::move(purpose)) {
    std::memcpy(entity_nonce_.data(), entity_nonce, ENTITY_NONCE_SIZE);
    std::memcpy(auth_nonce_.data(), auth_nonce, AUTH_NONCE_SIZE);
}

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
                "Distribution key expired but no public/private key loaded.");
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
