/**
 * @file session_key_resp_message.hpp
 * @brief Session key response from Auth to an entity.
 *
 * C++ counterpart of org.iot.auth.message.SessionKeyRespMessage. Auth
 * serializes and encrypts it; the entity decrypts and parses it.
 * <pre>
 * SessionKeyResp Format (after decryption, see EntityRespMessage)
 * {
 *      entityNonce:    /Buffer/, (ENTITY_NONCE_SIZE)
 *      cryptoSpec:     /JSON/, (e.g., {cipher: 'AES-128-CBC', mac: 'SHA256'})
 *      sessionKeyList: /UInt32BE for length and List of SessionKey's/
 * }
 * SessionKey Format
 * {
 *      id: /UInt64BE/, absValidity: /UInt48BE/, relValidity: /UInt48BE/,
 *      cipherKey: /Buffer/ (keyLen UInt8), macKey: /Buffer/ (keyLen UInt8)
 * } </pre>
 * Received as SESSION_KEY_RESP, or SESSION_KEY_RESP_WITH_DIST_KEY.
 */

#ifndef SST_MESSAGE_SESSION_KEY_RESP_MESSAGE_HPP
#define SST_MESSAGE_SESSION_KEY_RESP_MESSAGE_HPP

#include <string>

#include "message/entity_resp_message.hpp"

namespace sst {
namespace message {

class SessionKeyRespMessage : public EntityRespMessage {
   public:
    static constexpr unsigned int SESSION_KEY_COUNT_SIZE = 4;

    /** @copydoc EntityRespMessage::EntityRespMessage */
    SessionKeyRespMessage(const IoTSPMessage& message, size_t rsa_key_size);

    /** @brief Valid after decrypt_and_parse(). */
    const std::string& get_crypto_spec() const { return crypto_spec_; }

    /**
     * @brief Valid after decrypt_and_parse(). The keys' enc_mode, hmac_mode
     * and perm_dist_key_mode are not on the wire; the caller sets them.
     */
    const SessionKeyList& get_session_keys() const { return session_keys_; }

   protected:
    void parse_fields(const Bytes& plaintext, size_t offset) override;

   private:
    std::string crypto_spec_;
    SessionKeyList session_keys_;
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_SESSION_KEY_RESP_MESSAGE_HPP
