/**
 * @file config.cpp
 * @brief SST configuration parsing, defaults and validation.
 */

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>

#include "api_internal.hpp"
#include "log/log_manager.hpp"

namespace sst {

namespace internal {
namespace {

void copy_config_value(char* dest, size_t dest_size, const std::string& value,
                       const std::string& key) {
    if (value.size() + 1 > dest_size) {
        throw SST_Exception("Config value too long for " + key + ": " + value,
                            SST_ErrorCode::Configuration);
    }
    std::memcpy(dest, value.c_str(), value.size() + 1);
}

AES_encryption_mode_t parse_enc_mode(const std::string& v,
                                     const std::string& key) {
    if (v == "AES_128_CBC") return AES_128_CBC;
    if (v == "AES_128_CTR") return AES_128_CTR;
    if (v == "AES_128_GCM") return AES_128_GCM;
    // Numeric form used by the earlier C++ config style.
    if (v == "0") return AES_128_CBC;
    if (v == "1") return AES_128_CTR;
    if (v == "2") return AES_128_GCM;
    throw SST_Exception("Wrong input for " + key +
                            ". Please type \"AES_128_CBC\", \"AES_128_CTR\" or "
                            "\"AES_128_GCM\".",
                        SST_ErrorCode::Configuration);
}

bool parse_on_off(const std::string& v, const std::string& key) {
    if (v == "on" || v == "1") return true;
    if (v == "off" || v == "0") return false;
    throw SST_Exception("Wrong input for " + key +
                            ". Please type \"on\"/\"1\" or \"off\"/\"0\".",
                        SST_ErrorCode::Configuration);
}

int parse_int(const std::string& v, const std::string& key) {
    try {
        size_t consumed = 0;
        int parsed = std::stoi(v, &consumed);
        if (consumed != v.size())
            throw std::invalid_argument("trailing characters");
        return parsed;
    } catch (const std::exception&) {
        throw SST_Exception("Invalid integer for " + key + ": " + v,
                            SST_ErrorCode::Configuration);
    }
}

int parse_port(const std::string& v, const std::string& key) {
    int port = parse_int(v, key);
    if (port < 0 || port > 65535) {
        throw SST_Exception("Invalid port number for " + key + ": " + v,
                            SST_ErrorCode::Configuration);
    }
    return port;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

template <auto Field, auto Parse>
void set_config_value(config_t& config, const std::string& value,
                      const std::string& key) {
    config.*Field = Parse(value, key);
}

template <auto Field>
void set_config_string(config_t& config, const std::string& value,
                       const std::string& key) {
    auto& destination = config.*Field;
    copy_config_value(destination, sizeof(destination), value, key);
}

template <int Index>
void set_config_purpose(config_t& config, const std::string& value,
                        const std::string& key) {
    copy_config_value(config.purpose[Index], sizeof(config.purpose[Index]),
                      value, key);
}

unsigned short parse_purpose_index(const std::string& value,
                                   const std::string& key) {
    int index = parse_int(value, key);
    if (index < 0 || index > 1) {
        throw SST_Exception("purpose_index must be 0 or 1, got " + value,
                            SST_ErrorCode::Configuration);
    }
    return static_cast<unsigned short>(index);
}

hmac_mode_t parse_hmac_mode(const std::string& value, const std::string& key) {
    return parse_on_off(value, key) ? USE_HMAC : NO_HMAC;
}

perm_dist_key_mode_t parse_perm_dist_key_mode(const std::string& value,
                                              const std::string& key) {
    return parse_on_off(value, key) ? USE_PERMANENT_DIST_KEY
                                    : NO_PERMANENT_DIST_KEY;
}

struct ConfigField {
    const char* name;
    const char* alias;
    void (*set)(config_t&, const std::string&, const std::string&);
};

// Each alias uses the same destination and validator as its canonical name.
const ConfigField config_fields[] = {
    {"entityInfo.name", "name", set_config_string<&config_t::name>},
    {"purpose[0]", nullptr, set_config_purpose<0>},
    {"purpose[1]", nullptr, set_config_purpose<1>},
    {"purpose_index", nullptr,
     set_config_value<&config_t::purpose_index, parse_purpose_index>},
    {"entityInfo.number_key", "numkey",
     set_config_value<&config_t::numkey, parse_int>},
    {"sessionKey.encryptionMode", "session_key_enc_mode",
     set_config_value<&config_t::session_key_enc_mode, parse_enc_mode>},
    {"distKey.encryptionMode", "dist_key_enc_mode",
     set_config_value<&config_t::dist_key_enc_mode, parse_enc_mode>},
    {"HmacMode", "hmac_mode",
     set_config_value<&config_t::hmac_mode, parse_hmac_mode>},
    {"PermanentDistKeyMode", "perm_dist_key_mode",
     set_config_value<&config_t::perm_dist_key_mode, parse_perm_dist_key_mode>},
    {"authInfo.id", "auth_id", set_config_value<&config_t::auth_id, parse_int>},
    {"authInfo.pubkey.path", "auth_pubkey_path",
     set_config_string<&config_t::auth_pubkey_path>},
    {"entityInfo.privkey.path", "entity_privkey_path",
     set_config_string<&config_t::entity_privkey_path>},
    {"auth.ip.address", "auth_ip_addr",
     set_config_string<&config_t::auth_ip_addr>},
    {"auth.port.number", "auth_port_num",
     set_config_value<&config_t::auth_port_num, parse_port>},
    {"entity.server.ip.address", "entity_server_ip_addr",
     set_config_string<&config_t::entity_server_ip_addr>},
    {"entity.server.port.number", "entity_server_port_num",
     set_config_value<&config_t::entity_server_port_num, parse_port>},
    {"network.protocol", nullptr,
     set_config_string<&config_t::network_protocol>},
    {"fileSystemManager.ip.address", nullptr,
     set_config_string<&config_t::file_system_manager_ip_addr>},
    {"fileSystemManager.port.number", nullptr,
     set_config_value<&config_t::file_system_manager_port_num, parse_port>},
    {"distKey.cipherkey.path", nullptr,
     set_config_string<&config_t::dist_cipher_key_path>},
    {"distkey.mackey.path", nullptr,
     set_config_string<&config_t::dist_mac_key_path>},
};

}  // namespace

// Parses the SST config file. Accepts the C API key names
// (entityInfo.name=...) and, for compatibility, the earlier C++ key names
// (name = ...).
void load_config(config_t& c, const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (errno == ENOENT) {
            throw SST_Exception("SST Config file not found on path " + path,
                                SST_ErrorCode::Configuration);
        } else if (errno == EACCES) {
            throw SST_Exception(
                "SST Config file permission denied on path " + path,
                SST_ErrorCode::Configuration);
        }
        throw SST_Exception("SST Config file open failed on path " + path,
                            SST_ErrorCode::Configuration);
    }
    c = config_t{};
    unsigned short purpose_count = 0;
    c.purpose_index = 0;
    c.hmac_mode = USE_HMAC;
    c.perm_dist_key_mode = NO_PERMANENT_DIST_KEY;
    c.session_key_enc_mode = AES_128_CBC;
    c.dist_key_enc_mode = AES_128_CBC;
    copy_config_value(c.network_protocol, sizeof(c.network_protocol), "TCP",
                      "network.protocol");

    LOG_DBG << "-----SST configuration of " << path << ".-----";
    std::string line;
    while (std::getline(file, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        size_t eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) {
            throw SST_Exception("Config line without '=': " + trimmed,
                                SST_ErrorCode::Configuration);
        }
        std::string key = trim(trimmed.substr(0, eq_pos));
        std::string value = trim(trimmed.substr(eq_pos + 1));
        if (value.empty()) {
            throw SST_Exception("Config value does not exist for " + key,
                                SST_ErrorCode::Configuration);
        }

        // Repeated purpose entries are ordered; all other fields are
        // table-driven.
        if (key == "entityInfo.purpose") {
            if (purpose_count >= 2) {
                throw SST_Exception(
                    "At most two entityInfo.purpose entries are supported.",
                    SST_ErrorCode::Configuration);
            }
            copy_config_value(c.purpose[purpose_count],
                              sizeof(c.purpose[purpose_count]), value, key);
            c.purpose_index = purpose_count++;
            continue;
        }
        const auto* field = std::find_if(
            std::begin(config_fields), std::end(config_fields),
            [&key](const ConfigField& entry) {
                return key == entry.name || (entry.alias && key == entry.alias);
            });
        if (field == std::end(config_fields)) {
            throw SST_Exception("Unknown config type " + key + ".",
                                SST_ErrorCode::Configuration);
        }
        field->set(c, value, key);
    }

    if (c.perm_dist_key_mode == NO_PERMANENT_DIST_KEY) {
        if (std::strlen(c.dist_cipher_key_path) > 0 ||
            std::strlen(c.dist_mac_key_path) > 0) {
            throw SST_Exception(
                "PermanentDistKeyMode is turned off, but dist_key path(s) are "
                "provided.",
                SST_ErrorCode::Configuration);
        }
    }
}

}  // namespace internal

}  // namespace sst
