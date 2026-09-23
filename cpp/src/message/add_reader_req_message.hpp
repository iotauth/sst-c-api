/**
 * @file add_reader_req_message.hpp
 * @brief Request from an entity to Auth to add a reader of its files.
 *
 * C++ counterpart of org.iot.auth.message.AddReaderReqMessage. The entity
 * serializes and encrypts it; Auth decrypts and parses it.
 * <pre>
 * AddReaderReq Format
 * {
 *      entityNonce: /Buffer/, (ENTITY_NONCE_SIZE)
 *      authNonce:   /Buffer/, (AUTH_NONCE_SIZE)
 *      sender: /string/, (senderLen UInt8)
 *      purpose: JSON, e.g. {"AddReader":"net1.Bob"}
 * } </pre>
 * Sent as ADD_READER_REQ, or ADD_READER_REQ_IN_PUB_ENC when the distribution
 * key is expired (see EntityReqMessage).
 */

#ifndef SST_MESSAGE_ADD_READER_REQ_MESSAGE_HPP
#define SST_MESSAGE_ADD_READER_REQ_MESSAGE_HPP

#include <string>

#include "message/entity_req_message.hpp"

namespace sst {
namespace message {

class AddReaderReqMessage : public EntityReqMessage {
   public:
    AddReaderReqMessage(const unsigned char* entity_nonce,
                        const unsigned char* auth_nonce,
                        std::string entity_name, std::string purpose);

   protected:
    Bytes serialize_payload() const override;
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_ADD_READER_REQ_MESSAGE_HPP
