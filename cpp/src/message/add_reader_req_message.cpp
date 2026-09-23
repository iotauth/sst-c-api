#include "message/add_reader_req_message.hpp"

#include <utility>

namespace sst {
namespace message {

AddReaderReqMessage::AddReaderReqMessage(const unsigned char* entity_nonce,
                                         const unsigned char* auth_nonce,
                                         std::string entity_name,
                                         std::string purpose)
    : EntityReqMessage(MessageType::ADD_READER_REQ_IN_PUB_ENC,
                       MessageType::ADD_READER_REQ, entity_nonce, auth_nonce,
                       std::move(entity_name), std::move(purpose)) {}

Bytes AddReaderReqMessage::serialize_payload() const {
    Bytes buf;
    append_nonces(buf);
    append_buffered_string(buf, get_entity_name());
    append_buffered_string(buf, get_purpose());
    return buf;
}

}  // namespace message
}  // namespace sst
