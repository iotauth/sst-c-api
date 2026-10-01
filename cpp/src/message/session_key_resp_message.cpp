#include "message/session_key_resp_message.hpp"

#include <cstring>

namespace sst {
namespace message {

namespace {

constexpr unsigned int ABS_VALIDITY_SIZE = 6;
constexpr unsigned int REL_VALIDITY_SIZE = 6;

// Parses one SessionKey.
// @return number of bytes consumed.
unsigned int parse_session_key(session_key_t& ret, const unsigned char* buf,
                               unsigned int buf_length) {
    if (buf_length <
        SESSION_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE + 1) {
        throw SST_Exception("Session key buffer too short.");
    }
    std::memcpy(ret.key_id, buf, SESSION_KEY_ID_SIZE);
    unsigned int cur_idx = SESSION_KEY_ID_SIZE;

    ret.abs_validity =
        internal::read_unsigned_long_int_BE(buf + cur_idx, ABS_VALIDITY_SIZE);
    cur_idx += ABS_VALIDITY_SIZE;
    ret.rel_validity =
        internal::read_unsigned_long_int_BE(buf + cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;

    ret.cipher_key_size = buf[cur_idx];
    cur_idx += 1;
    if (ret.cipher_key_size > MAX_CIPHER_KEY_SIZE ||
        cur_idx + ret.cipher_key_size + 1 > buf_length) {
        throw SST_Exception("Invalid session cipher key size.");
    }
    std::memcpy(ret.cipher_key, buf + cur_idx, ret.cipher_key_size);
    cur_idx += ret.cipher_key_size;

    ret.mac_key_size = buf[cur_idx];
    cur_idx += 1;
    if (ret.mac_key_size > MAC_KEY_SIZE ||
        cur_idx + ret.mac_key_size > buf_length) {
        throw SST_Exception("Invalid session MAC key size.");
    }
    std::memcpy(ret.mac_key, buf + cur_idx, ret.mac_key_size);
    cur_idx += ret.mac_key_size;
    return cur_idx;
}

}  // namespace

SessionKeyRespMessage::SessionKeyRespMessage(const IoTSPMessage& message,
                                             size_t rsa_key_size)
    : EntityRespMessage(message, MessageType::SESSION_KEY_RESP_WITH_DIST_KEY,
                        MessageType::SESSION_KEY_RESP, rsa_key_size) {}

void SessionKeyRespMessage::parse_fields(const Bytes& plaintext,
                                         size_t offset) {
    const unsigned char* buf = plaintext.data();
    unsigned int buf_length = static_cast<unsigned int>(plaintext.size());
    unsigned int buf_idx = static_cast<unsigned int>(offset);

    // cryptoSpec: [variable-length size][JSON string].
    unsigned int crypto_spec_len;
    int var_len_int_buf_size;
    internal::var_length_int_to_num(buf + buf_idx, buf_length - buf_idx,
                                    &crypto_spec_len, &var_len_int_buf_size);
    if (var_len_int_buf_size == 0) {
        throw SST_Exception(
            "Buffer size of the variable length integer cannot be 0.");
    }
    unsigned int prefix_len = static_cast<unsigned int>(var_len_int_buf_size);
    // Both subtractions are safe: prefix_len <= buf_length - buf_idx by
    // construction, and the comparison rejects an oversized spec length
    // before it can move buf_idx past the end of the response.
    if (crypto_spec_len > buf_length - buf_idx - prefix_len ||
        buf_length - buf_idx - prefix_len - crypto_spec_len <
            SESSION_KEY_COUNT_SIZE) {
        throw SST_Exception("Session key response truncated.");
    }
    // reinterpret_cast: the crypto spec is ASCII JSON.
    crypto_spec_.assign(
        reinterpret_cast<const char*>(buf + buf_idx + prefix_len),
        crypto_spec_len);
    buf_idx += prefix_len + crypto_spec_len;

    unsigned int session_key_count =
        internal::read_unsigned_int_BE(buf + buf_idx, SESSION_KEY_COUNT_SIZE);
    buf_idx += SESSION_KEY_COUNT_SIZE;
    if (session_key_count > MAX_SESSION_KEY) {
        throw SST_Exception("Too many session keys in response: " +
                            std::to_string(session_key_count));
    }
    session_keys_ = SessionKeyList();
    for (unsigned int i = 0; i < session_key_count; i++) {
        buf_idx += parse_session_key(session_keys_.s_key[i], buf + buf_idx,
                                     buf_length - buf_idx);
    }
    session_keys_.num_key = static_cast<int>(session_key_count);
    session_keys_.rear_idx =
        session_keys_.num_key % static_cast<int>(MAX_SESSION_KEY);
}

}  // namespace message
}  // namespace sst
