/**
 * @file api.hpp
 * @brief High-level C++ API for SST (Secure Swarm Toolkit).
 *
 * This is a C++ port of the SST C API (src/c_api.h). It speaks the same wire
 * protocol as the C API, so a C++ entity can talk to Auth and to C entities
 * without any change on the other side.
 *
 * Main classes:
 *   - SST_API         : entity context (config, keys, distribution key) and
 *                       the Auth handshake orchestration. Equivalent to
 *                       SST_ctx_t plus init_SST(), get_session_key(),
 *                       get_session_key_by_ID(), secure_connect_to_server()
 *                       and server_secure_comm_setup().
 *   - SessionKeyList  : circular list of session keys. Equivalent to
 *                       session_key_list_t.
 *   - SST_Session     : an established secure session over a TCP socket.
 *                       Equivalent to SST_session_ctx_t plus
 *                       send_secure_message() / read_secure_message().
 *
 * Protocol flow:
 *   1. AUTH_HELLO                       Auth -> Entity
 *   2. SESSION_KEY_REQ(_IN_PUB_ENC)     Entity -> Auth
 *   3. SESSION_KEY_RESP(_WITH_DIST_KEY) Auth -> Entity
 *   4. SKEY_HANDSHAKE_1/2/3             Client <-> Server (entity-to-entity)
 *   5. SECURE_COMM_MSG                  Client <-> Server
 *
 * Error handling: operations that set up state (construction, session key
 * requests, handshakes) throw SST_Exception on failure. Data-plane calls
 * (send_secure_message / read_secure_message) return status codes like the C
 * API so that a closed connection can be handled without exceptions.
 */

#ifndef SST_API_HPP
#define SST_API_HPP

#include <arpa/inet.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto.hpp"  // AES_encryption_mode_t, hmac_mode_t, Crypto

namespace sst {

namespace message {
class EntityRespMessage;
}  // namespace message

// ---------------------------------------------------------------------------
// Constants (mirror src/c_api.h)
// ---------------------------------------------------------------------------
constexpr unsigned int DIST_KEY_EXPIRATION_TIME_SIZE = 6;
constexpr unsigned int KEY_EXPIRATION_TIME_SIZE = 6;
constexpr unsigned int SESSION_KEY_ID_SIZE = 8;
constexpr unsigned int MAC_KEY_SIZE = 32;
constexpr unsigned int MAX_CIPHER_KEY_SIZE = 32;
constexpr unsigned int MAX_SESSION_KEY = 10;
constexpr unsigned int MAX_ENTITY_NAME_LENGTH = 32;
constexpr unsigned int MAX_PURPOSE_LENGTH = 64;
constexpr unsigned int NETWORK_PROTOCOL_NAME_LENGTH = 4;
constexpr unsigned int MAX_PATH_LEN = 512;

constexpr unsigned int AES_IV_SIZE = 16;
constexpr unsigned int SEQ_NUM_SIZE = 8;
constexpr unsigned int MAX_PAYLOAD_LENGTH = 1024;

// Largest SECURE_COMM_MSG payload: IV + CBC-padded (seq num + payload) + HMAC,
// plus the message header. Same value as the C API (1091).
constexpr unsigned int MAX_SECURE_COMM_MSG_LENGTH =
    1 + 2 + AES_IV_SIZE +
    (((SEQ_NUM_SIZE + MAX_PAYLOAD_LENGTH) / AES_IV_SIZE) + 1) * AES_IV_SIZE +
    MAC_KEY_SIZE;

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

/** @brief Exception thrown by the SST API on failure. */
class SST_Exception : public std::runtime_error {
   public:
    explicit SST_Exception(const std::string& message)
        : std::runtime_error(message) {}
};

// ---------------------------------------------------------------------------
// Plain data types (binary compatible with the C API structs)
// ---------------------------------------------------------------------------

/** @brief Whether a permanent (pre-shared) distribution key is used. */
enum perm_dist_key_mode_t {
    USE_PERMANENT_DIST_KEY,
    NO_PERMANENT_DIST_KEY,
};

/** @brief Session key with all cryptographic parameters. */
struct session_key_t {
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    uint64_t abs_validity;
    uint64_t rel_validity;
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    AES_encryption_mode_t enc_mode;
    hmac_mode_t hmac_mode;
    perm_dist_key_mode_t perm_dist_key_mode;
};

/** @brief Distribution key shared with Auth. */
struct distribution_key_t {
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    uint64_t abs_validity;
    AES_encryption_mode_t enc_mode;
};

/** @brief Entity configuration loaded from the config file. */
struct config_t {
    char name[MAX_ENTITY_NAME_LENGTH + 1];
    // The config can hold up to two purposes; purpose_index selects one.
    unsigned short purpose_index;
    char purpose[2][MAX_PURPOSE_LENGTH + 1];
    int numkey;
    AES_encryption_mode_t session_key_enc_mode;
    AES_encryption_mode_t dist_key_enc_mode;
    hmac_mode_t hmac_mode;
    perm_dist_key_mode_t perm_dist_key_mode;
    int auth_id;
    char auth_pubkey_path[MAX_PATH_LEN];
    char entity_privkey_path[MAX_PATH_LEN];
    char auth_ip_addr[INET_ADDRSTRLEN];
    int auth_port_num;
    char entity_server_ip_addr[INET_ADDRSTRLEN];
    int entity_server_port_num;
    char network_protocol[NETWORK_PROTOCOL_NAME_LENGTH];
    char file_system_manager_ip_addr[INET_ADDRSTRLEN];
    int file_system_manager_port_num;
    char dist_cipher_key_path[MAX_PATH_LEN];
    char dist_mac_key_path[MAX_PATH_LEN];
};

// ---------------------------------------------------------------------------
// SessionKeyList
// ---------------------------------------------------------------------------

/**
 * @brief Circular list of session keys (equivalent to session_key_list_t).
 *
 * `num_key` is the number of keys in the list and `rear_idx` points to the
 * slot the next key is written to. The storage is a fixed-size array, so the
 * list never allocates.
 */
class SessionKeyList {
   public:
    SessionKeyList() = default;

    int num_key = 0;
    int rear_idx = 0;
    std::array<session_key_t, MAX_SESSION_KEY> s_key{};

    /** @brief Number of keys currently stored. */
    int size() const { return num_key; }

    /** @brief True when the list holds no keys. */
    bool empty() const { return num_key == 0; }

    /**
     * @brief Finds a key by its numeric ID.
     * @return Index of the key, or -1 if not found.
     */
    int find(uint64_t key_id) const;

    /**
     * @brief Appends a key at rear_idx. When the list is full the oldest key
     * is overwritten.
     * @return Index the key was stored at.
     */
    int add(const session_key_t& key);

    /** @brief Appends all keys of `src` (oldest first) to this list. */
    void append(const SessionKeyList& src);

    /**
     * @brief Checks whether `requested_num_key` more keys can be added. When
     * there is not enough room, the request is granted only if the oldest
     * keys that would have to make way have all expired; they are then
     * dropped. Otherwise the list is left untouched.
     * @return true when addable, false otherwise.
     */
    bool addable(int requested_num_key);
};

// ---------------------------------------------------------------------------
// SST_Session
// ---------------------------------------------------------------------------

/**
 * @brief An established secure session (equivalent to SST_session_ctx_t).
 *
 * Owns the TCP socket: it is closed when the session is destroyed. Sending
 * and receiving are each guarded by a mutex, so one thread can send while
 * another one receives.
 */
class SST_Session {
   public:
    /**
     * @brief Wraps an already-handshaked socket. Normally created by
     * SST_API::secure_connect_to_server() or
     * SST_API::server_secure_comm_setup() rather than directly.
     * @param sock  Connected socket; the session takes ownership.
     * @param s_key Session key negotiated for this connection.
     */
    SST_Session(int sock, const session_key_t& s_key);

    /** @brief Closes the socket. */
    ~SST_Session();

    SST_Session(const SST_Session&) = delete;
    SST_Session& operator=(const SST_Session&) = delete;
    SST_Session(SST_Session&&) = delete;
    SST_Session& operator=(SST_Session&&) = delete;

    /**
     * @brief Encrypts `msg` with the session key and sends it as a
     * SECURE_COMM_MSG.
     * @param msg        Plaintext to send.
     * @param msg_length Length of the plaintext (at most MAX_PAYLOAD_LENGTH).
     * @return Number of bytes written to the socket, or -1 on failure.
     */
    int send_secure_message(const unsigned char* msg, unsigned int msg_length);

    /** @brief Convenience overload for string messages. */
    int send_secure_message(const std::string& msg);

    /**
     * @brief Reads one SECURE_COMM_MSG from the socket and decrypts it.
     * @param plaintext          Caller-provided buffer for the plaintext.
     * @param plaintext_capacity Size of `plaintext` in bytes
     *                           (MAX_SECURE_COMM_MSG_LENGTH always suffices).
     * @return Plaintext length, 0 when the peer closed the connection, or -1
     *         on failure.
     */
    int read_secure_message(unsigned char* plaintext,
                            unsigned int plaintext_capacity);

    /**
     * @brief Reads and logs messages until the peer closes the connection or
     * an error occurs (equivalent to receive_thread_read_one_each()).
     */
    void receive_loop();

    /**
     * @brief Shuts down the socket for reading and writing. A thread blocked
     * in read_secure_message() then returns 0, which lets a receiver thread
     * be joined cleanly.
     */
    void shutdown();

    int get_sock() const { return sock_; }
    const session_key_t& get_session_key() const { return s_key_; }
    unsigned int get_sent_seq_num() const { return sent_seq_num_; }
    unsigned int get_received_seq_num() const { return received_seq_num_; }

   private:
    int sock_;
    session_key_t s_key_;
    unsigned int sent_seq_num_ = 0;
    unsigned int received_seq_num_ = 0;
    std::mutex send_mutex_;
    std::mutex recv_mutex_;
};

// ---------------------------------------------------------------------------
// SST_API
// ---------------------------------------------------------------------------

/**
 * @brief Entity context and Auth handshake orchestration (equivalent to
 * SST_ctx_t and the top-level functions of c_api.h).
 *
 * All methods that talk to Auth are serialized with an internal mutex, so an
 * SST_API instance can be shared between threads (see the
 * threaded_get_target_id_server example).
 */
class SST_API {
   public:
    /**
     * @brief Loads the config file, the entity private key, the Auth public
     * key (or the permanent distribution key). Equivalent to init_SST().
     * @throws SST_Exception if anything fails to load.
     */
    explicit SST_API(const std::string& config_path);

    ~SST_API() = default;

    SST_API(const SST_API&) = delete;
    SST_API& operator=(const SST_API&) = delete;
    SST_API(SST_API&&) = delete;
    SST_API& operator=(SST_API&&) = delete;

    /**
     * @brief Requests `numkey` session keys from Auth for the configured
     * purpose and returns them as a new list.
     * Equivalent to get_session_key(ctx, NULL).
     * @throws SST_Exception on failure (including AUTH_ALERT).
     */
    SessionKeyList get_session_key();

    /**
     * @brief Requests session keys from Auth and appends them to
     * `existing_s_key_list`. Skips the request (with a warning) when the
     * list cannot take `numkey` more keys.
     * Equivalent to get_session_key(ctx, existing_s_key_list).
     * @throws SST_Exception on failure.
     */
    void get_session_key(SessionKeyList& existing_s_key_list);

    /** @brief Like get_session_key() for the purpose at `purpose_index`. */
    SessionKeyList get_session_key_with_index(int purpose_index);

    /** @brief Like get_session_key(list) for the purpose at `purpose_index`. */
    void get_session_key_with_index(int purpose_index,
                                    SessionKeyList& existing_s_key_list);

    /**
     * @brief Returns the session key with the given 8-byte ID. If the key is
     * not in `existing_s_key_list`, it is requested from Auth by ID and added
     * to the list.
     * @return Pointer to the key inside `existing_s_key_list`.
     * @throws SST_Exception on failure.
     */
    session_key_t* get_session_key_by_ID(
        const unsigned char* target_session_key_id,
        SessionKeyList& existing_s_key_list);

    /**
     * @brief Asks Auth to add a reader for this entity's shared files
     * (ADD_READER_REQ). `add_reader` is the request string, e.g.
     * {"AddReader":"net1.Bob"}.
     * @throws SST_Exception on failure.
     */
    void send_add_reader_req_via_TCP(const std::string& add_reader);

    /**
     * @brief Connects to the entity server from the config and runs the
     * session key handshake as the client.
     * The key's validity is refreshed on success (like the C API).
     * @throws SST_Exception on failure.
     */
    std::unique_ptr<SST_Session> secure_connect_to_server(session_key_t& s_key);

    /**
     * @brief Runs the client side of the session key handshake over an
     * already-connected socket. The socket is owned by the returned session,
     * and is closed if the handshake fails.
     * @throws SST_Exception on failure.
     */
    static std::unique_ptr<SST_Session> secure_connect_to_server_with_socket(
        session_key_t& s_key, int sock);

    /**
     * @brief Runs the server side of the session key handshake on an accepted
     * client socket. The session key is looked up in
     * `existing_s_key_list` or fetched from Auth by ID. The socket is owned
     * by the returned session, and is closed if the handshake fails.
     * @throws SST_Exception on failure.
     */
    std::unique_ptr<SST_Session> server_secure_comm_setup(
        int clnt_sock, SessionKeyList& existing_s_key_list);

    /**
     * @brief Encrypts (and HMACs) a buffer with a session key. `encrypted`
     * must hold at least
     * Crypto::get_expected_encrypted_total_length(plaintext_length, ...)
     * bytes.
     * @return 0 on success, -1 if the key is expired or encryption fails.
     */
    static int encrypt_buf_with_session_key(const session_key_t& s_key,
                                            const unsigned char* plaintext,
                                            unsigned int plaintext_length,
                                            unsigned char* encrypted,
                                            unsigned int* encrypted_length);

    /**
     * @brief Verifies and decrypts a buffer with a session key. `decrypted`
     * must hold at least
     * Crypto::get_expected_decrypted_maximum_length(encrypted_length, ...)
     * bytes.
     * @return 0 on success, -1 if the key is expired or decryption fails.
     */
    static int decrypt_buf_with_session_key(const session_key_t& s_key,
                                            const unsigned char* encrypted,
                                            unsigned int encrypted_length,
                                            unsigned char* decrypted,
                                            unsigned int* decrypted_length);

    const config_t& get_config() const { return config_; }
    const distribution_key_t& get_dist_key() const { return dist_key_; }

    /** @brief Mutex serializing all Auth communication of this context. */
    std::mutex& get_mutex() { return mutex_; }

   private:
    // Auth session key request state machine (send_session_key_req_via_TCP).
    SessionKeyList send_session_key_req_via_TCP();
    // Requests a key by ID and checks the returned ID
    // (send_session_key_request_check_protocol).
    SessionKeyList send_session_key_request_check_protocol(
        const unsigned char* target_key_id);
    // Verifies Auth's signature over the encrypted distribution key from a
    // response, decrypts it with the entity's private key and stores it.
    void save_distribution_key(
        const std::vector<unsigned char>& encrypted_dist_key);
    // Stores the response's new distribution key (if any), decrypts the
    // response with the distribution key and checks the entity nonce.
    void decrypt_auth_response(message::EntityRespMessage& resp,
                               const unsigned char* entity_nonce);
    // Size of the entity's RSA key, or 0 when none is loaded.
    size_t entity_rsa_key_size() const;
    // Loads the permanent distribution key files named in the config.
    void load_permanent_distribution_key();
    // Requests keys for the purpose at `purpose_index`; mutex_ must be held.
    SessionKeyList request_session_keys_locked(int purpose_index);

    config_t config_{};
    distribution_key_t dist_key_{};
    std::string purpose_for_requesting_key_;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pub_key_;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> priv_key_;
    std::mutex mutex_;
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * @brief Converts a big-endian session key ID buffer to an integer.
 * Equivalent to convert_skid_buf_to_int().
 */
uint64_t convert_skid_buf_to_int(const unsigned char* buf, int byte_length);

/**
 * @brief Refreshes abs_validity to now + rel_validity. Equivalent to
 * update_validity().
 */
void update_validity(session_key_t& session_key);

/** @brief True when the key's absolute validity has not passed yet. */
bool is_session_key_valid(const session_key_t& session_key);

}  // namespace sst

#endif  // SST_API_HPP
