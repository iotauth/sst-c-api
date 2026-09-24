/**
 * @file entity_resp_message.hpp
 * @brief Common base of the responses Auth sends to an entity.
 *
 * The Auth server has no such base class: its SessionKeyRespMessage and
 * AddReaderRespMessage each prepend the encrypted distribution key and
 * encrypt the payload with it. On the entity side that handling is the same
 * for both responses, so it lives here once.
 * <pre>
 * With a distribution key (dist_key_type):
 *      encryptedDistKey: /Buffer/, (Enc_entityPubKey(distKey) +
 *                                   Sign_authPrivKey(...), 2 x RSA key size)
 *      Enc_distKey(payload)
 * Without (type):
 *      Enc_distKey(payload)
 * payload always starts with entityNonce (ENTITY_NONCE_SIZE).
 * </pre>
 * Decryption takes two steps, mirroring Auth where the caller handles the
 * public key cryptography: the caller verifies and decrypts
 * get_encrypted_distribution_key() (if any), then calls decrypt_and_parse()
 * with the resulting distribution key.
 */

#ifndef SST_MESSAGE_ENTITY_RESP_MESSAGE_HPP
#define SST_MESSAGE_ENTITY_RESP_MESSAGE_HPP

#include <array>
#include <cstddef>

#include "message/iotsp_message.hpp"

namespace sst {
namespace message {

class EntityRespMessage : public IoTSPMessage {
   public:
    /** @brief True when the response carries a new distribution key. */
    bool has_distribution_key() const {
        return !encrypted_distribution_key_.empty();
    }

    /**
     * @brief The distribution key encrypted with the entity's public key,
     * followed by Auth's signature. Empty when has_distribution_key() is
     * false.
     */
    const Bytes& get_encrypted_distribution_key() const {
        return encrypted_distribution_key_;
    }

    /**
     * @brief Decrypts the payload with the distribution key and parses it.
     * @throws SST_Exception when decryption or parsing fails.
     */
    void decrypt_and_parse(const distribution_key_t& dist_key,
                           AES_encryption_mode_t enc_mode);

    const std::array<unsigned char, ENTITY_NONCE_SIZE>& get_entity_nonce()
        const {
        return entity_nonce_;
    }

   protected:
    /**
     * @brief Splits a received response.
     * @param rsa_key_size Size of the entity's RSA key (0 if none is
     *                     loaded), which sizes the encrypted distribution key.
     * @throws SST_Exception on a wrong type or a truncated message.
     */
    EntityRespMessage(const IoTSPMessage& message, MessageType dist_key_type,
                      MessageType type, size_t rsa_key_size);

    /**
     * @brief Parses the decrypted payload after the entity nonce.
     * @param offset Index of the first byte after the entity nonce.
     */
    virtual void parse_fields(const Bytes& plaintext, size_t offset) = 0;

   private:
    Bytes encrypted_distribution_key_;
    Bytes encrypted_payload_;
    std::array<unsigned char, ENTITY_NONCE_SIZE> entity_nonce_{};
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_ENTITY_RESP_MESSAGE_HPP
