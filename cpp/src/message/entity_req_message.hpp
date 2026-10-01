/**
 * @file entity_req_message.hpp
 * @brief Common base of the requests an entity sends to Auth.
 *
 * The Auth server has no such base class: its SessionKeyReqMessage and
 * AddReaderReqMessage each hold the same nonce, name and purpose fields, and
 * the encryption lives in its connection handler. On the entity side both
 * requests are encrypted the same way, so that code lives here once.
 *
 * Encryption (chosen by serialize_and_encrypt()):
 * <pre>
 * With a valid distribution key (dist_key_type):
 *      senderLen: /UInt8/, sender: /string/,
 *      Enc_distKey(payload)
 * Otherwise (pub_enc_type), and Auth answers with a new distribution key:
 *      Enc_authPubKey(payload), Sign_entityPrivKey(Enc_authPubKey(payload))
 * </pre>
 */

#ifndef SST_MESSAGE_ENTITY_REQ_MESSAGE_HPP
#define SST_MESSAGE_ENTITY_REQ_MESSAGE_HPP

#include <openssl/evp.h>

#include <array>
#include <string>

#include "message/iotsp_message.hpp"

namespace sst {
namespace message {

class EntityReqMessage : public IoTSPMessage {
   public:
    /**
     * @brief Encrypts the payload and returns the wire bytes. Sets the
     * message type to the distribution key or public key variant.
     * @throws SST_Exception when encryption fails, or when the distribution
     *         key is expired and no public/private key is loaded.
     */
    Bytes serialize_and_encrypt(const distribution_key_t& dist_key,
                                EVP_PKEY* auth_pub_key,
                                EVP_PKEY* entity_priv_key);

    const std::array<unsigned char, ENTITY_NONCE_SIZE>& get_entity_nonce()
        const {
        return entity_nonce_;
    }
    const std::array<unsigned char, AUTH_NONCE_SIZE>& get_auth_nonce() const {
        return auth_nonce_;
    }
    const std::string& get_entity_name() const { return entity_name_; }
    const std::string& get_purpose() const { return purpose_; }

   protected:
    EntityReqMessage(MessageType pub_enc_type, MessageType dist_key_type,
                     const unsigned char* entity_nonce,
                     const unsigned char* auth_nonce, std::string entity_name,
                     std::string purpose);

    /** @brief The plaintext payload, before encryption. */
    virtual Bytes serialize_payload() const = 0;

    /** @brief Appends entityNonce and authNonce. */
    void append_nonces(Bytes& buf) const;

    /** @brief Appends a string as [variable-length size][bytes]. */
    static void append_buffered_string(Bytes& buf, const std::string& str);

   private:
    MessageType pub_enc_type_;
    MessageType dist_key_type_;
    std::array<unsigned char, ENTITY_NONCE_SIZE> entity_nonce_{};
    std::array<unsigned char, AUTH_NONCE_SIZE> auth_nonce_{};
    std::string entity_name_;
    std::string purpose_;
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_ENTITY_REQ_MESSAGE_HPP
