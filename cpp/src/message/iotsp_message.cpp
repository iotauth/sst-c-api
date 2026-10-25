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

SST_IOResult IoTSPMessage::read_result(int sock,
                                       unsigned int max_payload_length,
                                       MessageType& type, Bytes& payload) {
    payload.clear();
    unsigned char header[MSG_TYPE_SIZE + internal::MAX_PAYLOAD_BUF_SIZE];
    int ret = internal::read_exact(sock, header, MSG_TYPE_SIZE);
    if (ret == -1) {
        LOG_ERR << "Socket read error while reading the message type.";
        return SST_IOResult::failure(SST_ErrorCode::Network);
    } else if (ret < 0) {
        LOG_ERR << "Truncated message type.";
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    } else if (ret == 0) {
        LOG_INF << "End of file. Disconnected from socket " << sock;
        return SST_IOResult::closed();
    }
    type = static_cast<MessageType>(header[0]);

    // Read the length one byte at a time: TCP can split any field across reads
    // or coalesce adjacent frames. The high bit marks a continuation byte.
    unsigned int var_length_buf_size = 0;
    while (var_length_buf_size < internal::MAX_PAYLOAD_BUF_SIZE) {
        ret = internal::read_exact(
            sock, header + MSG_TYPE_SIZE + var_length_buf_size, 1);
        if (ret <= 0) {
            LOG_ERR << "Failed to read variable length header.";
            return SST_IOResult::failure(ret == -1 ? SST_ErrorCode::Network
                                                   : SST_ErrorCode::Protocol);
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
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    if (payload_length > max_payload_length) {
        LOG_ERR << "Larger buffer size required. Payload: " << payload_length
                << ", maximum: " << max_payload_length;
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    // Bound the peer-supplied length before allocating the payload buffer.
    payload.assign(payload_length, 0);
    if (payload_length > 0) {
        ret = internal::read_exact(sock, payload.data(), payload_length);
        if (ret <= 0) {
            LOG_ERR << "Failed to read from socket while reading the payload.";
            return SST_IOResult::failure(ret == -1 ? SST_ErrorCode::Network
                                                   : SST_ErrorCode::Protocol);
        }
    }
    return SST_IOResult::success(payload_length);
}

int IoTSPMessage::read(int sock, unsigned int max_payload_length,
                       MessageType& type, Bytes& payload) {
    return read_result(sock, max_payload_length, type, payload).legacy_value();
}

IoTSPMessage IoTSPMessage::receive(int sock, unsigned int max_payload_length) {
    MessageType type = MessageType::AUTH_ALERT;
    Bytes payload;
    SST_IOResult result = read_result(sock, max_payload_length, type, payload);
    if (result.status == SST_IOStatus::Error) {
        throw SST_Exception("Failed to read a message from socket " +
                                std::to_string(sock) + ".",
                            result.error);
    }
    if (result.status == SST_IOStatus::PeerClosed) {
        throw SST_Exception("Connection closed by the peer.",
                            SST_ErrorCode::PeerClosed);
    }
    return IoTSPMessage(type, std::move(payload));
}

}  // namespace message
}  // namespace sst
