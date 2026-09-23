#include "message/auth_alert_message.hpp"

namespace sst {
namespace message {

AuthAlertMessage::AuthAlertMessage(const IoTSPMessage& message)
    : IoTSPMessage(message) {
    if (type_ != MessageType::AUTH_ALERT) {
        throw SST_Exception("Expected AUTH_ALERT, got message type " +
                            to_string(type_) + ".");
    }
    if (payload_.size() < AUTH_ALERT_CODE_SIZE) {
        throw SST_Exception("AUTH_ALERT without an alert code.");
    }
    auth_alert_code_ = static_cast<AuthAlertCode>(payload_[0]);
}

std::string AuthAlertMessage::describe() const {
    return std::string("AUTH_ALERT received from Auth: ") +
           to_string(auth_alert_code_) + " (code " +
           std::to_string(static_cast<int>(auth_alert_code_)) + ")";
}

}  // namespace message
}  // namespace sst
