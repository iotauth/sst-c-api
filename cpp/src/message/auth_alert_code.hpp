/**
 * @file auth_alert_code.hpp
 * @brief Codes carried by AUTH_ALERT.
 *
 * C++ counterpart of org.iot.auth.message.AuthAlertCode.
 */

#ifndef SST_MESSAGE_AUTH_ALERT_CODE_HPP
#define SST_MESSAGE_AUTH_ALERT_CODE_HPP

namespace sst {
namespace message {

enum class AuthAlertCode : unsigned char {
    INVALID_DISTRIBUTION_KEY = 0,
    INVALID_SESSION_KEY_REQ = 1,
    UNKNOWN_INTERNAL_ERROR = 2,
};

/** @brief Human-readable description of an alert code. */
inline const char* to_string(AuthAlertCode code) {
    switch (code) {
        case AuthAlertCode::INVALID_DISTRIBUTION_KEY:
            return "Invalid Distribution Key.";
        case AuthAlertCode::INVALID_SESSION_KEY_REQ:
            return "Invalid Session Key Request.";
        case AuthAlertCode::UNKNOWN_INTERNAL_ERROR:
            return "Unknown Internal Error.";
    }
    return "Unknown Code.";
}

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_AUTH_ALERT_CODE_HPP
