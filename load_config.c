#include "load_config.h"

#include <errno.h>

#include "c_common.h"
#include "c_crypto.h"

#define MAX_CONFIG_BUF_SIZE 256

const char entity_info_name[] = "entityInfo.name";
const char entity_info_purpose[] = "entityInfo.purpose";
const char entity_info_numkey[] = "entityInfo.number_key";
const char encryption_mode[] = "encryptionMode";
const char hmac_mode[] = "HmacMode";
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

config_type_t get_key_value(char *ptr) {
    if (strcmp(ptr, entity_info_name) == 0) {
        return ENTITY_INFO_NAME;
    } else if (strcmp(ptr, entity_info_purpose) == 0) {
        return ENTITY_INFO_PURPOSE;
    } else if (strcmp(ptr, entity_info_numkey) == 0) {
        return ENTITY_INFO_NUMKEY;
    } else if (strcmp(ptr, encryption_mode) == 0) {
        return ENCRYPTION_MODE;
    } else if (strcmp(ptr, hmac_mode) == 0) {
        return HMAC_MODE;
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
    } else {
        return UNKNOWN_CONFIG;
    }
}

int safe_config_value_copy(char *dest, const char *src, size_t dest_size) {
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

config_t *load_config(const char *path) {
    config_t *c = malloc(sizeof(config_t));
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        // Print an error message based on the error code
        if (errno == ENOENT) {
            SST_print_error("SST Config file not found on path %s.", path);
        } else if (errno == EACCES) {
            SST_print_error("SST Config file permission denied on path %s.",
                            path);
        } else {
            SST_print_error("SST Config file open failed on path %s.", path);
        }
        // Print the specific error message
        SST_print_error("fopen() failed.");
        free(c);
        return NULL;
    }
    char buffer[MAX_CONFIG_BUF_SIZE] = {
        0,
    };
    char *pline;
    static const char delimiters[] = " \n";
    unsigned short purpose_count = 0;  // Option for ipfs.
    c->purpose_index = 0;              // Option for ipfs.
    c->hmac_mode = USE_HMAC;           // Default with HMAC.
    c->encryption_mode = AES_128_CBC;  // Default encryption mode.
    SST_print_debug("-----SST configuration of %s.-----", path);
    while (!feof(fp)) {
        pline = fgets(buffer, MAX_CONFIG_BUF_SIZE, fp);
        char *ptr = strtok(pline, "=");
        while (ptr != NULL) {
            config_type_t config = get_key_value(ptr);
            if (config == UNKNOWN_CONFIG) {
                SST_print_error("Unknown config type %s.", ptr);
                free_config_t(c);
                return NULL;
            }
            ptr = strtok(NULL, delimiters);
            if (ptr == NULL) {
                SST_print_error("Config value does not exist.");
                free_config_t(c);
                return NULL;
            }
            switch (config) {
                case UNKNOWN_CONFIG:
                    SST_print_error(
                        "This line must not be reached. UNKNOWN_CONFIG");
                    free_config_t(c);
                    return NULL;
                    break;
                case ENTITY_INFO_NAME:
                    SST_print_debug("Name: %s", ptr);
                    if (safe_config_value_copy(c->name, ptr, sizeof(c->name)) <
                        0) {
                        SST_print_error(
                            "Failed safe_config_value_copy() ENTITY_INFO_NAME");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case ENTITY_INFO_PURPOSE:
                    if (purpose_count <= 1) {
                        SST_print_debug("Purpose #%d: %s", purpose_count + 1,
                                        ptr);
                        if (safe_config_value_copy(
                                c->purpose[purpose_count], ptr,
                                sizeof(c->purpose[purpose_count])) < -1) {
                            SST_print_error(
                                "Failed safe_config_value_copy() "
                                "ENTITY_INFO_PURPOSE");
                            free_config_t(c);
                            return NULL;
                        }
                        purpose_count += 1;
                    } else {
                        SST_print_debug("Error for wrong number of purpose.");
                    }
                    c->purpose_index = purpose_count - 1;
                    break;
                case ENTITY_INFO_NUMKEY:
                    SST_print_debug("Numkey: %s", ptr);
                    c->numkey = atoi((const char *)ptr);
                    break;
                case ENCRYPTION_MODE:
                    SST_print_debug("Encryption mode: %s", ptr);
                    if (strcmp(ptr, "AES_128_CBC") == 0) {
                        c->encryption_mode = AES_128_CBC;
                    } else if (strcmp(ptr, "AES_128_CTR") == 0) {
                        c->encryption_mode = AES_128_CTR;
                    } else if (strcmp(ptr, "AES_128_GCM") == 0) {
                        c->encryption_mode = AES_128_GCM;
                    }
                    break;
                case HMAC_MODE:
                    if (strcmp(ptr, "off") == 0 || strcmp(ptr, "0") == 0) {
                        c->hmac_mode = NO_HMAC;
                    } else if (strcmp(ptr, "on") == 0 ||
                               strcmp(ptr, "1") == 0) {
                        c->hmac_mode = USE_HMAC;
                    } else {
                        SST_print_error(
                            "Wrong input for hmac_mode.\n Please type "
                            "\"off\" or \"0\" to not use HMAC mode.\n Please "
                            "type "
                            "\"on\" or \"1\" to use HMAC mode.");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case AUTH_ID:
                    SST_print_debug("Auth ID: %s", ptr);
                    c->auth_id = atoi((const char *)ptr);
                    break;
                case AUTH_INFO_PUBKEY_PATH:
                    SST_print_debug("Pubkey path of Auth: %s", ptr);
                    c->auth_pubkey_path = malloc(strlen(ptr) + 1);
                    strcpy(c->auth_pubkey_path, ptr);
                    break;
                case ENTITY_INFO_PRIVKEY_PATH:
                    SST_print_debug("Privkey path of Entity: %s", ptr);
                    c->entity_privkey_path = malloc(strlen(ptr) + 1);
                    strcpy(c->entity_privkey_path, ptr);
                    break;
                case AUTH_INFO_IP_ADDRESS:
                    SST_print_debug("IP address of Auth: %s", ptr);
                    if (safe_config_value_copy(c->auth_ip_addr, ptr,
                                               sizeof(c->auth_ip_addr)) < 0) {
                        SST_print_error(
                            "Failed safe_config_value_copy() "
                            "AUTH_INFO_IP_ADDRESS");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case AUTH_INFO_PORT:
                    c->auth_port_num = atoi(ptr);
                    if (c->auth_port_num < 0 || c->auth_port_num > 65535) {
                        SST_print_error("Error: Invalid Auth port number.");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case ENTITY_SERVER_INFO_IP_ADDRESS:
                    SST_print_debug("IP address of entity server: %s", ptr);
                    if (safe_config_value_copy(
                            c->entity_server_ip_addr, ptr,
                            sizeof(c->entity_server_ip_addr)) < 0) {
                        SST_print_error(
                            "Failed safe_config_value_copy() "
                            "ENTITY_SERVER_INFO_IP_ADDRESS");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case ENTITY_SERVER_INFO_PORT_NUMBER:
                    SST_print_debug("Port number of entity server: %s", ptr);
                    c->entity_server_port_num = atoi(ptr);
                    if (c->entity_server_port_num < 0 ||
                        c->entity_server_port_num > 65535) {
                        SST_print_error("Error: Invalid server port number.");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case NETWORK_PROTOCOL:
                    SST_print_debug("Network Protocol: %s", ptr);
                    if (safe_config_value_copy(c->network_protocol, ptr,
                                               sizeof(c->network_protocol)) <
                        0) {
                        SST_print_error(
                            "Failed safe_config_value_copy() NETWORK_PROTOCOL");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case FILE_SYSTEM_MANAGER_INFO_IP_ADDRESS:
                    SST_print_debug("IP address of file system manager: %s",
                                    ptr);
                    if (safe_config_value_copy(
                            c->file_system_manager_ip_addr, ptr,
                            sizeof(c->file_system_manager_ip_addr)) < 0) {
                        SST_print_error(
                            "Failed safe_config_value_copy() "
                            "FILE_SYSTEM_MANAGER_INFO_IP_ADDRESS");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
                case FILE_SYSTEM_MANAGER_INFO_PORT_NUMBER:
                    c->file_system_manager_port_num = atoi(ptr);
                    if (c->file_system_manager_port_num < 0 ||
                        c->file_system_manager_port_num > 65535) {
                        SST_print_error(
                            "Error: Invalid file system manager port "
                            "number.");
                        free_config_t(c);
                        return NULL;
                    }
                    break;
            }
            break;
        }
    }
    fclose(fp);
    return c;
}

void free_config_t(config_t *config) {
    free(config->auth_pubkey_path);
    free(config->entity_privkey_path);
    free(config);
}
