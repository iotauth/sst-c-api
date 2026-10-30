#include "load_config.h"

#include <errno.h>

#include "c_common.h"
#include "c_crypto.h"

#define MAX_CONFIG_BUF_SIZE 256

const char entity_info_name[] = "entityInfo.name";
const char entity_info_purpose[] = "entityInfo.purpose";
const char entity_info_numkey[] = "entityInfo.number_key";
const char session_key_encryption_mode[] = "sessionKey.encryptionMode";
const char hmac_mode[] = "HmacMode";
const char permanent_dist_key_mode[] = "PermanentDistKeyMode";
const char auth_id[] = "authInfo.id";
const char authinfo_pubkey_path[] = "authInfo.pubkey.path";
const char entity_info_privkey_path[] = "entityInfo.privkey.path";
const char authInfo_ip_address[] = "auth.ip.address";
const char authInfo_port[] = "auth.port.number";
const char entity_serverInfo_ip_address[] = "entity.server.ip.address";
const char entity_serverInfo_port_number[] = "entity.server.port.number";
const char file_system_manager_ip_address[] = "fileSystemManager.ip.address";
const char file_system_manager_port_number[] = "fileSystemManager.port.number";
const char network_protocol[] = "network.protocol";
const char dist_cipher_key_path_label[] = "distKey.cipherkey.path";
const char dist_mac_key_path_label[] = "distkey.mackey.path";
const char dist_encryption_mode_label[] = "distKey.encryptionMode";

config_type_t get_key_value(char* ptr) {
    if (strcmp(ptr, entity_info_name) == 0) {
        return ENTITY_INFO_NAME;
    } else if (strcmp(ptr, entity_info_purpose) == 0) {
        return ENTITY_INFO_PURPOSE;
    } else if (strcmp(ptr, entity_info_numkey) == 0) {
        return ENTITY_INFO_NUMKEY;
    } else if (strcmp(ptr, session_key_encryption_mode) == 0) {
        return SESSION_KEY_ENCRYPTION_MODE;
    } else if (strcmp(ptr, hmac_mode) == 0) {
        return HMAC_MODE;
    } else if (strcmp(ptr, permanent_dist_key_mode) == 0) {
        return PERMANENT_DIST_KEY_MODE;
    } else if (strcmp(ptr, auth_id) == 0) {
        return AUTH_ID;
    } else if (strcmp(ptr, authinfo_pubkey_path) == 0) {
        return AUTH_INFO_PUBKEY_PATH;
    } else if (strcmp(ptr, entity_info_privkey_path) == 0) {
        return ENTITY_INFO_PRIVKEY_PATH;
    } else if (strcmp(ptr, authInfo_ip_address) == 0) {
        return AUTH_INFO_IP_ADDRESS;
    } else if (strcmp(ptr, authInfo_port) == 0) {
        return AUTH_INFO_PORT;
    } else if (strcmp(ptr, entity_serverInfo_ip_address) == 0) {
        return ENTITY_SERVER_INFO_IP_ADDRESS;
    } else if (strcmp(ptr, entity_serverInfo_port_number) == 0) {
        return ENTITY_SERVER_INFO_PORT_NUMBER;
    } else if (strcmp(ptr, network_protocol) == 0) {
        return NETWORK_PROTOCOL;
    } else if (strcmp(ptr, file_system_manager_ip_address) == 0) {
        return FILE_SYSTEM_MANAGER_INFO_IP_ADDRESS;
    } else if (strcmp(ptr, file_system_manager_port_number) == 0) {
        return FILE_SYSTEM_MANAGER_INFO_PORT_NUMBER;
    } else if (strcmp(ptr, dist_cipher_key_path_label) == 0) {
        return DIST_CIPHER_KEY_PATH;
    } else if (strcmp(ptr, dist_mac_key_path_label) == 0) {
        return DIST_MAC_KEY_PATH;
    } else if (strcmp(ptr, dist_encryption_mode_label) == 0) {
        return DIST_ENCRYPTION_MODE;
    } else {
        return UNKNOWN_CONFIG;
    }
}

int safe_config_value_copy(char* dest, const char* src, size_t dest_size) {
    if ((strlen(src) + 1) > dest_size) {
        SST_print_error("Problem found while copying config value: %s.", src);
        return -1;
    } else {
        dest[dest_size - 1] = 0;
        strncpy(dest, src, dest_size);
        if (dest[dest_size - 1] != 0) {
            SST_print_error(
                "Problem found while copying config value, dest string is not "
                "null terminated: %s.",
                src);
            return -1;
        }
        return 1;
    }
}

static int parse_encryption_mode(const char* value,
                                 AES_encryption_mode_t* mode) {
    if (strcmp(value, "AES_128_CBC") == 0)
        *mode = AES_128_CBC;
    else if (strcmp(value, "AES_128_CTR") == 0)
        *mode = AES_128_CTR;
    else if (strcmp(value, "AES_128_GCM") == 0)
        *mode = AES_128_GCM;
    else
        return -1;
    return 0;
}

static int parse_enabled(const char* value) {
    if (strcmp(value, "on") == 0 || strcmp(value, "1") == 0) return 1;
    if (strcmp(value, "off") == 0 || strcmp(value, "0") == 0) return 0;
    SST_print_error("Expected on, off, 1, or 0.");
    return -1;
}

static int parse_port(const char* value, int* port) {
    *port = atoi(value);
    if (*port < 0 || *port > 65535) {
        SST_print_error("Invalid port number.");
        return -1;
    }
    return 0;
}

static int add_config_purpose(config_t* c, const char* value,
                              unsigned short* count) {
    if (*count >= 2) {
        SST_print_debug("Error for wrong number of purpose.");
        return 0;
    }
    if (safe_config_value_copy(c->purpose[*count], value,
                               sizeof(c->purpose[*count])) < 0)
        return -1;
    c->purpose_index = (*count)++;
    return 0;
}

static int parse_config_value(config_t* c, config_type_t type,
                              const char* value,
                              unsigned short* purpose_count) {
    int enabled;
    switch (type) {
        case ENTITY_INFO_NAME:
            return safe_config_value_copy(c->name, value, sizeof(c->name));
        case ENTITY_INFO_PURPOSE:
            return add_config_purpose(c, value, purpose_count);
        case ENTITY_INFO_NUMKEY:
            c->numkey = atoi(value);
            return 0;
        case SESSION_KEY_ENCRYPTION_MODE:
            // Preserve the default for unrecognized session modes, as before.
            (void)parse_encryption_mode(value, &c->session_key_enc_mode);
            return 0;
        case HMAC_MODE:
            enabled = parse_enabled(value);
            if (enabled < 0) return -1;
            c->hmac_mode = enabled ? USE_HMAC : NO_HMAC;
            return 0;
        case PERMANENT_DIST_KEY_MODE:
            enabled = parse_enabled(value);
            if (enabled < 0) return -1;
            c->perm_dist_key_mode =
                enabled ? USE_PERMANENT_DIST_KEY : NO_PERMANENT_DIST_KEY;
            return 0;
        case AUTH_ID:
            c->auth_id = atoi(value);
            return 0;
        case AUTH_INFO_PUBKEY_PATH:
            return safe_config_value_copy(c->auth_pubkey_path, value,
                                          sizeof(c->auth_pubkey_path));
        case ENTITY_INFO_PRIVKEY_PATH:
            return safe_config_value_copy(c->entity_privkey_path, value,
                                          sizeof(c->entity_privkey_path));
        case AUTH_INFO_IP_ADDRESS:
            return safe_config_value_copy(c->auth_ip_addr, value,
                                          sizeof(c->auth_ip_addr));
        case AUTH_INFO_PORT:
            return parse_port(value, &c->auth_port_num);
        case ENTITY_SERVER_INFO_IP_ADDRESS:
            return safe_config_value_copy(c->entity_server_ip_addr, value,
                                          sizeof(c->entity_server_ip_addr));
        case ENTITY_SERVER_INFO_PORT_NUMBER:
            return parse_port(value, &c->entity_server_port_num);
        case NETWORK_PROTOCOL:
            return safe_config_value_copy(c->network_protocol, value,
                                          sizeof(c->network_protocol));
        case FILE_SYSTEM_MANAGER_INFO_IP_ADDRESS:
            return safe_config_value_copy(
                c->file_system_manager_ip_addr, value,
                sizeof(c->file_system_manager_ip_addr));
        case FILE_SYSTEM_MANAGER_INFO_PORT_NUMBER:
            return parse_port(value, &c->file_system_manager_port_num);
        case DIST_CIPHER_KEY_PATH:
            return safe_config_value_copy(c->dist_cipher_key_path, value,
                                          sizeof(c->dist_cipher_key_path));
        case DIST_MAC_KEY_PATH:
            return safe_config_value_copy(c->dist_mac_key_path, value,
                                          sizeof(c->dist_mac_key_path));
        case DIST_ENCRYPTION_MODE:
            return parse_encryption_mode(value, &c->dist_key_enc_mode);
        case UNKNOWN_CONFIG:
            return -1;
    }
    return -1;
}

// The caller owns the stream; parsing errors never bypass its fclose().
static int parse_config_stream(config_t* c, FILE* stream) {
    char buffer[MAX_CONFIG_BUF_SIZE];
    unsigned short purpose_count = 0;
    while (fgets(buffer, sizeof(buffer), stream) != NULL) {
        char* key = strtok(buffer, "=");
        if (key == NULL) continue;
        config_type_t type = get_key_value(key);
        if (type == UNKNOWN_CONFIG) {
            SST_print_error("Unknown config type %s.", key);
            return -1;
        }
        char* value = strtok(NULL, " \n");
        if (value == NULL) {
            SST_print_error("Config value does not exist.");
            return -1;
        }
        if (parse_config_value(c, type, value, &purpose_count) < 0) return -1;
    }
    return ferror(stream) ? -1 : 0;
}

int load_config(config_t* c, const char* path) {
    FILE* stream = fopen(path, "r");
    if (stream == NULL) {
        SST_print_error("Cannot open SST config %s: %s.", path,
                        strerror(errno));
        return -1;
    }
    c->purpose_index = 0;
    c->hmac_mode = USE_HMAC;
    c->perm_dist_key_mode = NO_PERMANENT_DIST_KEY;
    c->dist_cipher_key_path[0] = '\0';
    c->dist_mac_key_path[0] = '\0';
    c->session_key_enc_mode = AES_128_CBC;
    c->dist_key_enc_mode = AES_128_CBC;
    int result = parse_config_stream(c, stream);
    fclose(stream);
    if (result < 0) return -1;
    if (c->perm_dist_key_mode == NO_PERMANENT_DIST_KEY &&
        (c->dist_cipher_key_path[0] != '\0' ||
         c->dist_mac_key_path[0] != '\0')) {
        SST_print_error(
            "PermanentDistKeyMode is off, but dist_key paths are provided.");
        return -1;
    }
    return 0;
}
