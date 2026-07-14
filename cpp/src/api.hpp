/**

* @file api.hpp
 * @brief High-level C++ API for SST (Secure Session Transport).
 *
 * Provides two main classes:
 *   - SST_API  : session management, Auth handshake orchestration, key
 * retrieval.
 *   - SST_Session : secure messaging over a connected TLS socket.
 *
 * Protocol flow (client side):
 *   1. AUTH_HELLO       Entity ↔ Auth     Auth → Entity
 *   2. SESSION_KEY_REQ_IN_PUB_ENC  Entity → Auth
 *   3. SESSION_KEY_RESP_WITH_DIST_KEY  Auth → Entity
 *   4. SKEY_HANDSHAKE_1/2/3    Initiator ↔ Responder (entity-to-entity)
 *   5. AUTH_ALERT        Auth → Entity (error notification)
 */

#ifndef SST_API_HPP
#define SST_API_HPP

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <pthread.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>  // recursive_mutex for re-entrant lock in auth handshake
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto.hpp"          // for AES_encryption_mode_t, hmac_mode_t
#include "net/ssl_socket.hpp"  // for SSL_Socket

namespace sst {

// ---------------------------------------------------------------------------
// Constants (mirrors the C API)
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

#define ROUND_UP_TO_Y(X, Y) ((((X) / (Y)) + 1) * (Y))
constexpr unsigned int MAX_SECURE_COMM_MSG_LENGTH =
    1 + 2 + AES_IV_SIZE +
    ROUND_UP_TO_Y(SEQ_NUM_SIZE + MAX_PAYLOAD_LENGTH, AES_IV_SIZE) +
    MAC_KEY_SIZE;

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

/**
 * @brief Exception class for SST API errors.
 */
class SST_Exception : public std::runtime_error {
 public:
  explicit SST_Exception(const std::string& message)
      : std::runtime_error(message) {}
};

// ---------------------------------------------------------------------------
// C-level types (opaque to the high-level API but needed internally)
// ---------------------------------------------------------------------------

/** @brief Permanent distribution key mode. */
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

/** @brief Distribution key with cryptographic parameters. */
struct distribution_key_t {
  unsigned char mac_key[MAC_KEY_SIZE];
  unsigned int mac_key_size;
  unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
  unsigned int cipher_key_size;
  uint64_t abs_validity;
  AES_encryption_mode_t enc_mode;
};

/** @brief Entity configuration parameters. */
struct config_t {
  char name[MAX_ENTITY_NAME_LENGTH + 1];
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
};

/** @brief List of session keys (circular buffer). */
struct session_key_list_t {
  int num_key;
  int rear_idx;
  std::unique_ptr<session_key_t[]> s_key;
};

/** @brief Full SST context: config, keys, distribution key. */
struct SST_ctx_t {
  distribution_key_t dist_key;
  config_t config;
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pub_key;
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> priv_key;
  pthread_mutex_t mutex;

  SST_ctx_t()
      : dist_key{},
        pub_key(nullptr, &EVP_PKEY_free),
        priv_key(nullptr, &EVP_PKEY_free) {
    pthread_mutex_init(&mutex, nullptr);
  }

  ~SST_ctx_t() { pthread_mutex_destroy(&mutex); }

  // Non-copyable
  SST_ctx_t(const SST_ctx_t&) = delete;
  SST_ctx_t& operator=(const SST_ctx_t&) = delete;
};

/** @brief Active secure communication session. */
struct SST_session_ctx_t {
  int sock;
  session_key_t s_key;
  unsigned int sent_seq_num;
  unsigned int received_seq_num;
  bool sock_closed = false;  ///< Tracks whether the socket FD has been closed
                             ///< by free_session_ctx to avoid double-close
                             ///< when socket_ (SSL_Socket) is destroyed.
};

// ---------------------------------------------------------------------------
// Forward declarations for internal free functions (used as unique_ptr
// deleters)
// ---------------------------------------------------------------------------
void free_SST_ctx_t(SST_ctx_t* ctx);
void free_session_key_list_t(session_key_list_t* list);
void free_session_ctx(SST_session_ctx_t* session_ctx);

// ---------------------------------------------------------------------------
// High-level SessionKey wrapper
// ---------------------------------------------------------------------------

/**
 * @brief Represents a session key retrieved from the Auth server.
 */
struct SessionKey {
  std::vector<uint8_t> id;
  uint64_t abs_validity = 0;
  uint64_t rel_validity = 0;
};

// ---------------------------------------------------------------------------
// SST_API — session management & Auth handshake orchestration
// ---------------------------------------------------------------------------

/**
 * @brief High-level API for managing SST context and orchestration.
 *
 * Implements RAII management of the SST_ctx_t and provides high-level
 * endpoints for key retrieval and authentication.
 */
class SST_API {
 public:
  /**
   * @brief Initializes the SST context from a configuration file.
   * Loads entity private key, Auth public key, and distribution key.
   * @param config_path Path to the configuration file.
   * @throws SST_Exception if initialization fails.
   */
  explicit SST_API(const std::string& config_path);

  /**
   * @brief Cleans up the SST context (frees keys, closes mutex).
   */
  ~SST_API();

  // Non-copyable, non-movable (owns unique_ptr resources)
  SST_API(const SST_API&) = delete;
  SST_API& operator=(const SST_API&) = delete;
  SST_API(SST_API&&) = delete;
  SST_API& operator=(SST_API&&) = delete;

  /**
   * @brief Performs the AUTH_HELLO exchange with the Auth server.
   * Establishes a TCP connection, receives AUTH_ID and AUTH_nonce,
   * verifies them against the Auth public key signature.
   * @throws SST_Exception on failure.
   */
  void auth_hello();

  /**
   * @brief Requests session keys from the Auth server using the
   * SESSION_KEY_REQ_IN_PUB_ENC protocol.
   * @param purpose The purpose string for which keys are requested.
   * @return A vector of retrieved SessionKeys.
   * @throws SST_Exception on failure (e.g., AUTH_ALERT received).
   */
  std::vector<SessionKey> get_session_keys(const std::string& purpose);

  /**
   * @brief Retrieves a specific session key by its 8-byte ID from the
   * locally cached list.
   * @param session_key_id The 8-byte identifier of the key.
   * @return The SessionKey if found, or std::nullopt if not found.
   */
  std::optional<SessionKey> get_session_key_by_id(
      const std::vector<uint8_t>& session_key_id) const;

  /**
   * @brief Returns a reference to the underlying SST context.
   */
  SST_ctx_t& get_ctx() { return *ctx_; }

 private:
  /**
   * @brief Connects to the Auth server and performs the full handshake:
   * AUTH_HELLO → SESSION_KEY_REQ_IN_PUB_ENC → SESSION_KEY_RESP_WITH_DIST_KEY.
   * On success, populates session_key_list_ with received keys and
   * dist_key_.
   */
  void perform_auth_handshake(const std::string& purpose);

  /**
   * @brief Sends data to the Auth server over an established socket.
   * @return Number of bytes sent on success.
   * @throws SST_Exception on failure.
   */
  static int send_to_auth(int sock, const unsigned char* data, size_t len);

  /**
   * @brief Receives data from the Auth server over an established socket.
   * @return Number of bytes received on success.
   * @throws SST_Exception on failure.
   */
  static int recv_from_auth(int sock, unsigned char* buf, size_t len);

  std::unique_ptr<SST_ctx_t, decltype(&free_SST_ctx_t)> ctx_;
  session_key_list_t* session_key_list_ = nullptr;

  mutable std::recursive_mutex key_list_mutex_;
};

// ---------------------------------------------------------------------------
// SST_Session — secure messaging over a connected TLS socket
// ---------------------------------------------------------------------------

/**
 * @brief Represents a secure communication session with a specific server.
 *
 * Wraps an active SST_session_ctx_t and provides methods for
 * sending and receiving encrypted messages using the entity's session key.
 */
class SST_Session {
 public:
  /**
   * @brief Connects to the target server using a previously retrieved
   * session key from the API instance. Performs SKEY_HANDSHAKE_1/2/3.
   * @param api Reference to an initialized SST_API with valid keys.
   * @param session_key_id The 8-byte ID of the session key to use.
   * @return A unique pointer to an initialized SST_Session on success.
   * @throws SST_Exception on failure (e.g., session key not found, connection
   * failed).
   */
  static std::unique_ptr<SST_Session> connect_to_server(
      SST_API& api, const std::vector<uint8_t>& session_key_id);

  /**
   * @brief Sends a secure (encrypted + authenticated) message over the
   * session.
   * @param data The raw byte payload to send.
   * @return Number of bytes sent on success, -1 on failure.
   */
  int send_message(const std::vector<uint8_t>& data);

  /**
   * @brief Reads and decrypts a secure message from the session.
   * @return A vector containing the decrypted payload, or empty on error.
   */
  std::vector<uint8_t> read_message();

 private:
  SST_Session(SST_session_ctx_t* session_ctx, SSL_Socket socket);

 public:
  // Public destructor — needed so unique_ptr default deleter can destroy
  // instances created via connect_to_server(). Constructor remains private
  // so the only construction path is the factory method.
  ~SST_Session();

  // Prevent copying
  SST_Session(const SST_Session&) = delete;
  SST_Session& operator=(const SST_Session&) = delete;

  // Allow move (SSL_Socket is move-only)
  SST_Session(SST_Session&&) noexcept = default;
  SST_Session& operator=(SST_Session&&) noexcept = default;

  SST_session_ctx_t* session_ctx_;
  SSL_Socket socket_;  // Owns the TLS socket for the session lifetime
};

}  // namespace sst

#endif  // SST_API_HPP
