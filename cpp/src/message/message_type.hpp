/**
 * @file message_type.hpp
 * @brief Message types exchanged between entities and Auth.
 *
 * C++ counterpart of org.iot.auth.message.MessageType in the Auth server.
 */

#ifndef SST_MESSAGE_MESSAGE_TYPE_HPP
#define SST_MESSAGE_MESSAGE_TYPE_HPP

#include <string>

namespace sst {
namespace message {

/** @brief Message type byte of an IoTSP message. */
enum class MessageType : unsigned char {
    AUTH_HELLO = 0,
    ENTITY_HELLO = 1,
    AUTH_SESSION_KEY_REQ = 10,
    AUTH_SESSION_KEY_RESP = 11,
    SESSION_KEY_REQ_IN_PUB_ENC = 20,
    /** Includes distribution key as well as session keys. */
    SESSION_KEY_RESP_WITH_DIST_KEY = 21,
    SESSION_KEY_REQ = 22,
    /** Distribution message including session keys. */
    SESSION_KEY_RESP = 23,
    SESSION_KEY_RESP_FOR_DELEGATION = 24,
    SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY = 25,
    /** Handshake for initializing secure communication. */
    SKEY_HANDSHAKE_1 = 30,
    SKEY_HANDSHAKE_2 = 31,
    SKEY_HANDSHAKE_3 = 32,
    SECURE_COMM_MSG = 33,
    FIN_SECURE_COMM = 34,
    SECURE_PUB = 40,
    /** For migrating registered entities. */
    MIGRATION_REQ_WITH_SIGN = 50,
    MIGRATION_RESP_WITH_SIGN = 51,
    MIGRATION_REQ_WITH_MAC = 52,
    MIGRATION_RESP_WITH_MAC = 53,
    /** File sharing reader info. */
    ADD_READER_REQ_IN_PUB_ENC = 60,
    ADD_READER_RESP_WITH_DIST_KEY = 61,
    ADD_READER_REQ = 62,
    ADD_READER_RESP = 63,
    /** For delegated access. */
    DELEGATED_ACCESS_REQ_IN_PUB_ENC = 70,
    DELEGATED_ACCESS_RESP_WITH_DIST_KEY = 71,
    DELEGATED_ACCESS_REQ = 72,
    DELEGATED_ACCESS_RESP = 73,
    /** For privilege to grant delegation authority access. */
    PRIVILEGED_REQ_IN_PUB_ENC = 80,
    PRIVILEGED_RESP_WITH_DIST_KEY = 81,
    PRIVILEGED_REQ = 82,
    PRIVILEGED_RESP = 83,
    AUTH_ALERT = 100,
};

/** @brief The wire value of a message type, for logs and error messages. */
inline std::string to_string(MessageType type) {
    return std::to_string(static_cast<int>(type));
}

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_MESSAGE_TYPE_HPP
