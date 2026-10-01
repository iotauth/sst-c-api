/**
 * @file auth_hello_message.hpp
 * @brief AUTH_HELLO sent by Auth when an entity connects.
 *
 * C++ counterpart of org.iot.auth.message.AuthHelloMessage. Auth serializes
 * it; the entity parses it.
 * <pre>
 * AuthHello Format
 * {
 *      authId: /UInt32BE/,    // identifier of auth (when auths are replicated)
 *      nonce: /Buffer/        (AUTH_NONCE_SIZE)
 * } </pre>
 */

#ifndef SST_MESSAGE_AUTH_HELLO_MESSAGE_HPP
#define SST_MESSAGE_AUTH_HELLO_MESSAGE_HPP

#include <array>
#include <cstdint>

#include "message/iotsp_message.hpp"

namespace sst {
namespace message {

class AuthHelloMessage : public IoTSPMessage {
   public:
    static constexpr unsigned int AUTH_ID_SIZE = 4;

    /**
     * @brief Parses a received message.
     * @throws SST_Exception if it is not a well-formed AUTH_HELLO.
     */
    explicit AuthHelloMessage(const IoTSPMessage& message);

    uint32_t get_auth_id() const { return auth_id_; }
    const std::array<unsigned char, AUTH_NONCE_SIZE>& get_auth_nonce() const {
        return auth_nonce_;
    }

   private:
    uint32_t auth_id_ = 0;
    std::array<unsigned char, AUTH_NONCE_SIZE> auth_nonce_{};
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_AUTH_HELLO_MESSAGE_HPP
