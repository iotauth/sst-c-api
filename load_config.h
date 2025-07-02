#ifndef LOAD_CONFIG_H
#define LOAD_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_api.h"

typedef enum {
    ENTITY_INFO_NAME = 1,
    ENTITY_INFO_PURPOSE,
    ENTITY_INFO_NUMKEY,
    ENCRYPTION_MODE,
    HMAC_MODE,
    AUTH_ID,
    AUTH_INFO_PUBKEY_PATH,
    ENTITY_INFO_PRIVKEY_PATH,
    AUTH_INFO_IP_ADDRESS,
    AUTH_INFO_PORT,
    ENTITY_SERVER_INFO_IP_ADDRESS,
    ENTITY_SERVER_INFO_PORT_NUMBER,
    FILE_SYSTEM_MANAGER_INFO_IP_ADDRESS,
    FILE_SYSTEM_MANAGER_INFO_PORT_NUMBER,
    NETWORK_PROTOCOL,
    UNKNOWN_CONFIG
} config_type_t;

// Get a value by comparing a string of conditional statement with a variable.
// @param ptr input variable to compare with string
// @return value
config_type_t get_key_value(char *ptr);

// Load config file from path and save the information in config struct.
// @param path config file path
// @return config struct to use when connecting to Auth
config_t *load_config(const char *path);

// Free memory used in config_t.
// @param config struct config_t to be freed.
void free_config_t(config_t *config);

#endif  // LOAD_CONFIG_H
