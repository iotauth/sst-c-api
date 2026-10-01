/**
 * @file iotsp_message.hpp
 * @brief Base class for IoTSP (IoT Secure Protocol) messages.
 *
 * C++ counterpart of org.iot.auth.message.IoTSPMessage in the Auth server.
 * <pre>
 * IoTSP Message Format
 * {
 *      msgType: /UInt8/,
 *      payloadLen: /variable-length integer encoding/
 *      payload: /Buffer/
 * } </pre>
 */

#ifndef SST_MESSAGE_IOTSP_MESSAGE_HPP
#define SST_MESSAGE_IOTSP_MESSAGE_HPP

#include "api_internal.hpp"
#include "message/message_type.hpp"

namespace sst {
namespace message {

using internal::Bytes;

class IoTSPMessage {
   public:
    static constexpr unsigned int MSG_TYPE_SIZE = 1;
    static constexpr unsigned int AUTH_NONCE_SIZE = 8;
    static constexpr unsigned int ENTITY_NONCE_SIZE = 8;

    explicit IoTSPMessage(MessageType type, Bytes payload = {});
    virtual ~IoTSPMessage() = default;

    IoTSPMessage(const IoTSPMessage&) = default;
    IoTSPMessage& operator=(const IoTSPMessage&) = default;
    IoTSPMessage(IoTSPMessage&&) = default;
    IoTSPMessage& operator=(IoTSPMessage&&) = default;

    MessageType get_type() const { return type_; }
    const Bytes& get_payload() const { return payload_; }

    /** @brief Returns the wire bytes: [msgType][payloadLen][payload]. */
    Bytes serialize() const;

    /**
     * @brief Reads one message from the socket.
     * @param max_payload_length Largest payload accepted.
     * @return Payload length; 0 when the peer closed the connection (or the
     *         payload is empty); -1 on error.
     */
    static int read(int sock, unsigned int max_payload_length,
                    MessageType& type, Bytes& payload);

    /**
     * @brief Reads one message from the socket.
     * @throws SST_Exception when the peer closed the connection or on error.
     */
    static IoTSPMessage receive(int sock, unsigned int max_payload_length);

   protected:
    MessageType type_;
    Bytes payload_;

   private:
    static int read_impl(int sock, unsigned int max_payload_length,
                         MessageType& type, Bytes& payload, bool& closed);
};

}  // namespace message
}  // namespace sst

#endif  // SST_MESSAGE_IOTSP_MESSAGE_HPP
