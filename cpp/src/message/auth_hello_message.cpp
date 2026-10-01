#include "message/auth_hello_message.hpp"

#include <cstring>

namespace sst {
namespace message {

AuthHelloMessage::AuthHelloMessage(const IoTSPMessage& message)
    : IoTSPMessage(message) {
    if (type_ != MessageType::AUTH_HELLO) {
        throw SST_Exception("Expected AUTH_HELLO from Auth, got message type " +
                            to_string(type_) + ".");
    }
    if (payload_.size() < AUTH_ID_SIZE + AUTH_NONCE_SIZE) {
        throw SST_Exception("AUTH_HELLO too short.");
    }
    auth_id_ = internal::read_unsigned_int_BE(payload_.data(), AUTH_ID_SIZE);
    std::memcpy(auth_nonce_.data(), payload_.data() + AUTH_ID_SIZE,
                AUTH_NONCE_SIZE);
}

}  // namespace message
}  // namespace sst
