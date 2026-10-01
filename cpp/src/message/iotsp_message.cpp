#include "message/iotsp_message.hpp"

#include <utility>

#include "log/log_manager.hpp"

namespace sst {
namespace message {

IoTSPMessage::IoTSPMessage(MessageType type, Bytes payload)
    : type_(type), payload_(std::move(payload)) {}

Bytes IoTSPMessage::serialize() const {
    unsigned char len_buf[internal::MAX_PAYLOAD_BUF_SIZE];
    unsigned int len_size;
    internal::num_to_var_length_int(static_cast<unsigned int>(payload_.size()),
                                    len_buf, &len_size);
    Bytes buf;
    buf.reserve(MSG_TYPE_SIZE + len_size + payload_.size());
    buf.push_back(static_cast<unsigned char>(type_));
    buf.insert(buf.end(), len_buf, len_buf + len_size);
    buf.insert(buf.end(), payload_.begin(), payload_.end());
    return buf;
}

int IoTSPMessage::read_impl(int sock, unsigned int max_payload_length,
                            MessageType& type, Bytes& payload, bool& closed) {
    closed = false;
    unsigned char header[MSG_TYPE_SIZE + internal::MAX_PAYLOAD_BUF_SIZE];
    int ret = internal::read_exact(sock, header, MSG_TYPE_SIZE);
    if (ret < 0) {
        LOG_ERR << "Socket read error while reading the message type.";
        return -1;
    } else if (ret == 0) {
        LOG_INF << "End of file. Disconnected from socket " << sock;
        closed = true;
        return 0;
    }
    type = static_cast<MessageType>(header[0]);

    // Variable length payload size: continue while the high bit is set.
    unsigned int var_length_buf_size = 0;
    while (var_length_buf_size < internal::MAX_PAYLOAD_BUF_SIZE) {
        ret = internal::read_exact(
            sock, header + MSG_TYPE_SIZE + var_length_buf_size, 1);
        if (ret <= 0) {
            LOG_ERR << "Failed to read variable length header.";
            return -1;
        }
        var_length_buf_size++;
        if ((header[MSG_TYPE_SIZE + var_length_buf_size - 1] & 128) == 0) {
            break;
        }
    }
    unsigned int payload_length;
    int var_length_buf_size_checked;
    internal::var_length_int_to_num(header + MSG_TYPE_SIZE, var_length_buf_size,
                                    &payload_length,
                                    &var_length_buf_size_checked);
    if (static_cast<unsigned int>(var_length_buf_size_checked) !=
        var_length_buf_size) {
        LOG_ERR << "Wrong header calculation.";
        return -1;
    }
    if (payload_length > max_payload_length) {
        LOG_ERR << "Larger buffer size required. Payload: " << payload_length
                << ", maximum: " << max_payload_length;
        return -1;
    }
    payload.assign(payload_length, 0);
    if (payload_length > 0 &&
        internal::read_exact(sock, payload.data(), payload_length) <= 0) {
        LOG_ERR << "Failed to read from socket while reading the payload.";
        return -1;
    }
    return static_cast<int>(payload_length);
}

int IoTSPMessage::read(int sock, unsigned int max_payload_length,
                       MessageType& type, Bytes& payload) {
    bool closed;
    return read_impl(sock, max_payload_length, type, payload, closed);
}

IoTSPMessage IoTSPMessage::receive(int sock, unsigned int max_payload_length) {
    MessageType type = MessageType::AUTH_ALERT;
    Bytes payload;
    bool closed;
    if (read_impl(sock, max_payload_length, type, payload, closed) < 0) {
        throw SST_Exception("Failed to read a message from socket " +
                            std::to_string(sock) + ".");
    }
    if (closed) {
        throw SST_Exception("Connection closed by the peer.");
    }
    return IoTSPMessage(type, std::move(payload));
}

}  // namespace message
}  // namespace sst
