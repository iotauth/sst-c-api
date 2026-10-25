/**
 * @file session_key.cpp
 * @brief Key validity, the session key ring and session key buffer encryption.
 */

#include <chrono>
#include <utility>

#include "api.hpp"
#include "api_internal.hpp"
#include "log/log_manager.hpp"

namespace sst {

using internal::check_encrypted_length;
using internal::read_unsigned_long_int_BE;

namespace {

uint64_t current_time_ms() {
    // Auth encodes expiration as Unix-epoch milliseconds. A steady_clock
    // timestamp has a different epoch and cannot be compared with these values.
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// @return true when abs_validity_ms is still in the future.
bool check_validity(uint64_t abs_validity_ms) {
    return current_time_ms() < abs_validity_ms;
}

}  // namespace

namespace internal {

bool is_distribution_key_valid(const distribution_key_t& dist_key) {
    return check_validity(dist_key.abs_validity);
}

}  // namespace internal

uint64_t convert_skid_buf_to_int(const unsigned char* buf, int byte_length) {
    return read_unsigned_long_int_BE(buf, byte_length);
}

void update_validity(session_key_t& session_key) {
    session_key.abs_validity = current_time_ms() + session_key.rel_validity;
}

bool is_session_key_valid(const session_key_t& session_key) {
    return check_validity(session_key.abs_validity);
}

int SessionKeyList::find(uint64_t key_id) const {
    // Walk the ring from the oldest key so that slots left behind by dropped
    // or overwritten keys are never matched.
    const int max = static_cast<int>(MAX_SESSION_KEY);
    for (int i = 0; i < num_key; i++) {
        int idx = (i + rear_idx - num_key) % max;
        if (idx < 0) idx += max;
        if (convert_skid_buf_to_int(s_key[static_cast<size_t>(idx)].key_id,
                                    SESSION_KEY_ID_SIZE) == key_id) {
            return idx;
        }
    }
    return -1;
}

const session_key_t& SessionKeyList::at(size_t index) const {
    if (index >= static_cast<size_t>(num_key)) {
        throw SST_Exception("Session key index out of range.",
                            SST_ErrorCode::InvalidArgument);
    }
    int slot = (rear_idx - num_key + static_cast<int>(MAX_SESSION_KEY) +
                static_cast<int>(index)) %
               static_cast<int>(MAX_SESSION_KEY);
    return s_key[static_cast<size_t>(slot)];
}

session_key_t& SessionKeyList::at(size_t index) {
    return const_cast<session_key_t&>(std::as_const(*this).at(index));
}

const session_key_t& SessionKeyList::at_slot(int slot) const {
    const int max = static_cast<int>(MAX_SESSION_KEY);
    if (slot < 0 || slot >= max ||
        (slot - rear_idx + num_key + max) % max >= num_key) {
        throw SST_Exception("Session key slot is not active.",
                            SST_ErrorCode::InvalidArgument);
    }
    return s_key[static_cast<size_t>(slot)];
}

session_key_t& SessionKeyList::at_slot(int slot) {
    return const_cast<session_key_t&>(std::as_const(*this).at_slot(slot));
}

int SessionKeyList::add(const session_key_t& key) {
    num_key++;
    if (num_key > static_cast<int>(MAX_SESSION_KEY)) {
        LOG_DBG << "Warning: Session_key_list is full. Deleting oldest key, "
                   "and adding new key.";
        num_key = MAX_SESSION_KEY;
    }
    int index = rear_idx;
    s_key[static_cast<size_t>(index)] = key;
    rear_idx = (rear_idx + 1) % static_cast<int>(MAX_SESSION_KEY);
    return index;
}

void SessionKeyList::append(const SessionKeyList& src) {
    if (this == &src) {
        const SessionKeyList snapshot = src;
        append(snapshot);
        return;
    }
    const int max = static_cast<int>(MAX_SESSION_KEY);
    if (num_key + src.num_key > max) {
        int lost = num_key + src.num_key - max;
        LOG_DBG << "Warning: Losing " << lost
                << " keys from original list. Overwriting " << lost
                << " more keys.";
    }
    for (int i = 0; i < src.num_key; i++) {
        int idx = (i + src.rear_idx - src.num_key) % max;
        if (idx < 0) idx += max;
        add(src.s_key[static_cast<size_t>(idx)]);
    }
}

bool SessionKeyList::addable(int requested_num_key) {
    if (requested_num_key < 0 ||
        requested_num_key > static_cast<int>(MAX_SESSION_KEY)) {
        return false;
    }
    const int max = static_cast<int>(MAX_SESSION_KEY);
    int deficit = requested_num_key - (max - num_key);
    if (deficit <= 0) {
        return true;
    }
    if (deficit > num_key) {
        return false;
    }
    // Only the oldest keys can be dropped without disturbing the ring order,
    // so exactly `deficit` of them must all be expired. Nothing is modified
    // unless the request can be satisfied.
    for (int i = 0; i < deficit; i++) {
        int idx = (i + rear_idx - num_key) % max;
        if (idx < 0) idx += max;
        if (is_session_key_valid(s_key[static_cast<size_t>(idx)])) {
            return false;
        }
    }
    num_key -= deficit;
    return true;
}

int SST_API::encrypt_buf_with_session_key(const session_key_t& s_key,
                                          const unsigned char* plaintext,
                                          unsigned int plaintext_length,
                                          unsigned char* encrypted,
                                          unsigned int* encrypted_length) {
    if (!is_session_key_valid(s_key)) {
        LOG_ERR << "Session key is expired.";
        return -1;
    }
    if (Crypto::symmetric_encrypt_authenticate(
            plaintext, plaintext_length, s_key.mac_key, s_key.mac_key_size,
            s_key.cipher_key, s_key.cipher_key_size, AES_128_CBC_IV_SIZE,
            s_key.enc_mode, s_key.hmac_mode, encrypted, encrypted_length) < 0) {
        LOG_ERR << "Failed to symmetric_encrypt_authenticate(). Error during "
                   "encrypting buffer with session key.";
        return -1;
    }
    return 0;
}

int SST_API::decrypt_buf_with_session_key(const session_key_t& s_key,
                                          const unsigned char* encrypted,
                                          unsigned int encrypted_length,
                                          unsigned char* decrypted,
                                          unsigned int* decrypted_length) {
    if (!is_session_key_valid(s_key)) {
        LOG_ERR << "Session key is expired.";
        return -1;
    }
    if (!check_encrypted_length(encrypted_length, s_key.mac_key_size,
                                s_key.enc_mode, s_key.hmac_mode)) {
        return -1;
    }
    if (Crypto::symmetric_decrypt_authenticate(
            encrypted, encrypted_length, s_key.mac_key, s_key.mac_key_size,
            s_key.cipher_key, s_key.cipher_key_size, AES_128_CBC_IV_SIZE,
            s_key.enc_mode, s_key.hmac_mode, decrypted, decrypted_length) < 0) {
        LOG_ERR << "Failed to symmetric_decrypt_authenticate(). Error during "
                   "decrypting buffer with session key.";
        return -1;
    }
    return 0;
}

}  // namespace sst
