/**
 * @file add_reader_resp_message.hpp
 * @brief Response from Auth to an add reader request.
 *
 * C++ counterpart of org.iot.auth.message.AddReaderRespMessage. Auth
 * serializes and encrypts it; the entity decrypts and parses it.
 * <pre>
 * AddReaderResp Format (after decryption, see EntityRespMessage)
 * {
 *      entityNonce: /Buffer/, (ENTITY_NONCE_SIZE)
 * } </pre>
 * Received as ADD_READER_RESP, or ADD_READER_RESP_WITH_DIST_KEY.
 */

#ifndef SST_MESSAGE_ADD_READER_RESP_MESSAGE_HPP
#define SST_MESSAGE_ADD_READER_RESP_MESSAGE_HPP

#include "message/entity_resp_message.hpp"

namespace sst {
namespace message {

class AddReaderRespMessage : public EntityRespMessage {
   public:
    /** @copydoc EntityRespMessage::EntityRespMessage */
    AddReaderRespMessage(const IoTSPMessage& message, size_t rsa_key_size);

   protected:
    /** @brief The payload holds only the entity nonce. */
    void parse_fields(const Bytes& plaintext, size_t offset) override;
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_ADD_READER_RESP_MESSAGE_HPP
