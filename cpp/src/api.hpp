/**
 * 
 * Scopes
 * RESTful API for clients
 * 
 * Endpoints: auth_hello
 * Requests session key from auth server, and returns the session key to client.
 * 
 * get_session_key
 * 
 * secure_connect_to_server <-> get_session_key_by_ID
 * 
 * send_secure_message
 * 
 * read_secure_message
 * 
 * 
 * IMPORTANT MESSAGES TYOE:
 * AUTH_HELLO	Entity ↔ Auth	Auth → Entity
 * 
 * SESSION_KEY_REQ_IN_PUB_ENC	Entity ↔ Auth	Entity → Auth
 * 
 * SESSION_KEY_RESP_WITH_DIST_KEY	Entity ↔ Auth	Auth → Entity
 * 
 * 30	SKEY_HANDSHAKE_1	Entity ↔ Entity	Initiator → Responder
 * 31	SKEY_HANDSHAKE_2	Entity ↔ Entity	Responder → Initiator
 * 32	SKEY_HANDSHAKE_3	Entity ↔ Entity	Initiator → Responder
 * 100	AUTH_ALERT	Entity ↔ Auth	Auth → Entity
 */