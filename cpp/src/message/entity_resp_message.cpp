#include "message/entity_resp_message.hpp"

#include <cstring>

namespace sst {
namespace message {

EntityRespMessage::EntityRespMessage(const IoTSPMessage& message,
                                     MessageType dist_key_type,
                                     MessageType type, size_t rsa_key_size)
    : IoTSPMessage(message) {
    if (type_ == dist_key_type) {
        if (rsa_key_size == 0) {
            throw SST_Exception("Received message type " + to_string(type_) +
                                " with a distribution key, but no private "
                                "key is loaded.");
        }
        size_t dist_key_size = rsa_key_size * 2;
        if (payload_.size() <= dist_key_size) {
            throw SST_Exception("Message type " + to_string(type_) +
                                " too short.");
        }
        encrypted_distribution_key_.assign(
            payload_.begin(),
            payload_.begin() + static_cast<std::ptrdiff_t>(dist_key_size));
        encrypted_payload_.assign(
            payload_.begin() + static_cast<std::ptrdiff_t>(dist_key_size),
            payload_.end());
    } else if (type_ == type) {
        encrypted_payload_ = payload_;
    } else {
        throw SST_Exception("Unexpected message type " + to_string(type_) +
                            " from Auth.");
    }
}

void EntityRespMessage::decrypt_and_parse(const distribution_key_t& dist_key,
                                          AES_encryption_mode_t enc_mode) {
    Bytes plaintext;
    if (internal::symmetric_decrypt_authenticate(
            encrypted_payload_.data(),
            static_cast<unsigned int>(encrypted_payload_.size()),
            dist_key.mac_key, dist_key.mac_key_size, dist_key.cipher_key,
            dist_key.cipher_key_size, enc_mode, USE_HMAC, plaintext) < 0) {
        throw SST_Exception("Failed to decrypt message type " +
                            to_string(type_) + " with the distribution key.");
    }
    if (plaintext.size() < ENTITY_NONCE_SIZE) {
        throw SST_Exception("Message type " + to_string(type_) +
                            " has no entity nonce.");
    }
    std::memcpy(entity_nonce_.data(), plaintext.data(), ENTITY_NONCE_SIZE);
    parse_fields(plaintext, ENTITY_NONCE_SIZE);
}

}  // namespace message
}  // namespace sst
