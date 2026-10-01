/**
 * @file session_key_req_message.hpp
 * @brief Session key request from an entity to Auth.
 *
 * C++ counterpart of org.iot.auth.message.SessionKeyReqMessage. The entity
 * serializes and encrypts it; Auth decrypts and parses it.
 * <pre>
 * SessionKeyReq Format
 * {
 *      entityNonce: /Buffer/, (ENTITY_NONCE_SIZE)
 *      authNonce:   /Buffer/, (AUTH_NONCE_SIZE)
 *      numKeys: /UInt32BE/,
 *      sender: /string/, (senderLen UInt8)
 *      purpose: JSON
 * } </pre>
 * Sent as SESSION_KEY_REQ, or SESSION_KEY_REQ_IN_PUB_ENC when the
 * distribution key is expired (see EntityReqMessage).
 */

#ifndef SST_MESSAGE_SESSION_KEY_REQ_MESSAGE_HPP
#define SST_MESSAGE_SESSION_KEY_REQ_MESSAGE_HPP

#include <string>

#include "message/entity_req_message.hpp"

namespace sst {
namespace message {

class SessionKeyReqMessage : public EntityReqMessage {
   public:
    static constexpr unsigned int NUM_KEYS_SIZE = 4;

    SessionKeyReqMessage(const unsigned char* entity_nonce,
                         const unsigned char* auth_nonce, int num_keys,
                         std::string entity_name, std::string purpose);

    int get_num_keys() const { return num_keys_; }

   protected:
    Bytes serialize_payload() const override;

   private:
    int num_keys_;
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_SESSION_KEY_REQ_MESSAGE_HPP
