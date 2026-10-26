/**
 * @file config.cpp
 * @brief SST configuration parsing, defaults and validation.
 */

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string_view>

#include "api_internal.hpp"
#include "log/log_manager.hpp"

namespace sst::internal {
namespace {

void copy_config_value(char* dest, size_t dest_size, const std::string& value,
                       const std::string& key) {
    if (value.size() + 1 > dest_size) {
        throw SST_Exception("Config value too long for " + key + ": " + value,
                            SST_ErrorCode::Configuration);
    }
    std::memcpy(dest, value.c_str(), value.size() + 1);
}

AES_encryption_mode_t parse_enc_mode(std::string_view v,
                                     const std::string& key) {
    if (v == "AES_128_CBC") return AES_128_CBC;
    if (v == "AES_128_CTR") return AES_128_CTR;
    if (v == "AES_128_GCM") return AES_128_GCM;
    // Numeric form used by the earlier C++ config style.
    if (v == "0") return AES_128_CBC;
    if (v == "1") return AES_128_CTR;
    if (v == "2") return AES_128_GCM;
    throw SST_Exception(
        "Wrong input for " + key +
            R"(. Please type "AES_128_CBC", "AES_128_CTR" or "AES_128_GCM".)",
        SST_ErrorCode::Configuration);
}

bool parse_on_off(std::string_view v, const std::string& key) {
    if (v == "on" || v == "1") return true;
    if (v == "off" || v == "0") return false;
    throw SST_Exception(
        "Wrong input for " + key + R"(. Please type "on"/"1" or "off"/"0".)",
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

std::string trim(std::string_view s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
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
const std::array<ConfigField, 21> config_fields{
    {{"entityInfo.name", "name",
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.name, sizeof(c.name), value, key);
      }},
     {"purpose[0]", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.purpose[0], sizeof(c.purpose[0]), value, key);
      }},
     {"purpose[1]", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.purpose[1], sizeof(c.purpose[1]), value, key);
      }},
     {"purpose_index", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          c.purpose_index = parse_purpose_index(value, key);
      }},
     {"entityInfo.number_key", "numkey",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.numkey = parse_int(value, key);
      }},
     {"sessionKey.encryptionMode", "session_key_enc_mode",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.session_key_enc_mode = parse_enc_mode(value, key);
      }},
     {"distKey.encryptionMode", "dist_key_enc_mode",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.dist_key_enc_mode = parse_enc_mode(value, key);
      }},
     {"HmacMode", "hmac_mode",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.hmac_mode = parse_hmac_mode(value, key);
      }},
     {"PermanentDistKeyMode", "perm_dist_key_mode",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.perm_dist_key_mode = parse_perm_dist_key_mode(value, key);
      }},
     {"authInfo.id", "auth_id",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.auth_id = parse_int(value, key);
      }},
     {"authInfo.pubkey.path", "auth_pubkey_path",
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.auth_pubkey_path, sizeof(c.auth_pubkey_path),
                            value, key);
      }},
     {"entityInfo.privkey.path", "entity_privkey_path",
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.entity_privkey_path,
                            sizeof(c.entity_privkey_path), value, key);
      }},
     {"auth.ip.address", "auth_ip_addr",
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.auth_ip_addr, sizeof(c.auth_ip_addr), value, key);
      }},
     {"auth.port.number", "auth_port_num",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.auth_port_num = parse_port(value, key);
      }},
     {"entity.server.ip.address", "entity_server_ip_addr",
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.entity_server_ip_addr,
                            sizeof(c.entity_server_ip_addr), value, key);
      }},
     {"entity.server.port.number", "entity_server_port_num",
      [](config_t& c, const std::string& value, const std::string& key) {
          c.entity_server_port_num = parse_port(value, key);
      }},
     {"network.protocol", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.network_protocol, sizeof(c.network_protocol),
                            value, key);
      }},
     {"fileSystemManager.ip.address", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.file_system_manager_ip_addr,
                            sizeof(c.file_system_manager_ip_addr), value, key);
      }},
     {"fileSystemManager.port.number", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          c.file_system_manager_port_num = parse_port(value, key);
      }},
     {"distKey.cipherkey.path", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.dist_cipher_key_path,
                            sizeof(c.dist_cipher_key_path), value, key);
      }},
     {"distkey.mackey.path", nullptr,
      [](config_t& c, const std::string& value, const std::string& key) {
          copy_config_value(c.dist_mac_key_path, sizeof(c.dist_mac_key_path),
                            value, key);
      }}}};

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
        const auto field = std::find_if(
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

    if (c.perm_dist_key_mode == NO_PERMANENT_DIST_KEY &&
        (c.dist_cipher_key_path[0] != '\0' || c.dist_mac_key_path[0] != '\0')) {
        throw SST_Exception(
            "PermanentDistKeyMode is turned off, but dist_key path(s) are "
            "provided.",
            SST_ErrorCode::Configuration);
    }
}

}  // namespace sst::internal
