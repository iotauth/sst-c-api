#include "message/add_reader_resp_message.hpp"

namespace sst {
namespace message {

AddReaderRespMessage::AddReaderRespMessage(const IoTSPMessage& message,
                                           size_t rsa_key_size)
    : EntityRespMessage(message, MessageType::ADD_READER_RESP_WITH_DIST_KEY,
                        MessageType::ADD_READER_RESP, rsa_key_size) {}

void AddReaderRespMessage::parse_fields(const Bytes& /*plaintext*/,
                                        size_t /*offset*/) {}

}  // namespace message
}  // namespace sst
