/**
 * @file auth_alert_message.hpp
 * @brief AUTH_ALERT sent by Auth when there is a problem with a request.
 *
 * C++ counterpart of org.iot.auth.message.AuthAlertMessage. Auth serializes
 * it; the entity parses it.
 * <pre>
 * AuthAlert Format
 * {
 *      AuthAlertCode: /AUTH_ALERT_CODE_SIZE/
 * } </pre>
 */

#ifndef SST_MESSAGE_AUTH_ALERT_MESSAGE_HPP
#define SST_MESSAGE_AUTH_ALERT_MESSAGE_HPP

#include <string>

#include "message/auth_alert_code.hpp"
#include "message/iotsp_message.hpp"

namespace sst {
namespace message {

class AuthAlertMessage : public IoTSPMessage {
   public:
    static constexpr unsigned int AUTH_ALERT_CODE_SIZE = 1;

    /**
     * @brief Parses a received message.
     * @throws SST_Exception if it is not a well-formed AUTH_ALERT.
     */
    explicit AuthAlertMessage(const IoTSPMessage& message);

    AuthAlertCode get_auth_alert_code() const { return auth_alert_code_; }

    /** @brief E.g. "AUTH_ALERT received from Auth: ... (code 1)". */
    std::string describe() const;

   private:
    AuthAlertCode auth_alert_code_ = AuthAlertCode::UNKNOWN_INTERNAL_ERROR;
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_AUTH_ALERT_MESSAGE_HPP
