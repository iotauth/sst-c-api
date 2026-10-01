#include "message/session_key_req_message.hpp"

#include <utility>

namespace sst {
namespace message {

SessionKeyReqMessage::SessionKeyReqMessage(const unsigned char* entity_nonce,
                                           const unsigned char* auth_nonce,
                                           int num_keys,
                                           std::string entity_name,
                                           std::string purpose)
    : EntityReqMessage(MessageType::SESSION_KEY_REQ_IN_PUB_ENC,
                       MessageType::SESSION_KEY_REQ, entity_nonce, auth_nonce,
                       std::move(entity_name), std::move(purpose)),
      num_keys_(num_keys) {}

Bytes SessionKeyReqMessage::serialize_payload() const {
    Bytes buf;
    append_nonces(buf);
    unsigned char num_keys_buf[NUM_KEYS_SIZE];
    internal::write_in_n_bytes(static_cast<uint64_t>(num_keys_), NUM_KEYS_SIZE,
                               num_keys_buf);
    buf.insert(buf.end(), num_keys_buf, num_keys_buf + NUM_KEYS_SIZE);
    append_buffered_string(buf, get_entity_name());
    append_buffered_string(buf, get_purpose());
    return buf;
}

}  // namespace message
}  // namespace sst
