#include "crypto/key_manager.h"
#include "crypto/chacha20.h"
#include <openssl/rand.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace crypto {

Key generate_key() {
    Key key{};
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for key generation");
    return key;
}

Key key_from_env() {
    const char* env = std::getenv("KEYENV");
    if (!env)
        throw std::runtime_error("KEYENV environment variable is not set");
    return key_from_hex(env);
}

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

Key key_from_hex(std::string_view hex) {
    // Strip trailing whitespace/newline
    while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r' ||
                            hex.back() == ' ' || hex.back() == '\t')) {
        hex.remove_suffix(1);
    }

    if (hex.size() != CHACHA20_KEY_SIZE * 2)
        throw std::runtime_error("key hex string must be exactly " +
                                 std::to_string(CHACHA20_KEY_SIZE * 2) + " characters");

    Key key{};
    for (size_t i = 0; i < CHACHA20_KEY_SIZE; ++i) {
        if (!is_hex_char(hex[i * 2]) || !is_hex_char(hex[i * 2 + 1]))
            throw std::runtime_error("key hex string contains invalid characters");

        auto hex_byte = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            return static_cast<uint8_t>(c - 'A' + 10);
        };
        key[i] = (hex_byte(hex[i * 2]) << 4) | hex_byte(hex[i * 2 + 1]);
    }
    return key;
}

std::string key_to_hex(const Key& key) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : key)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

static bool try_read_hex_key(const std::string& content, Key& out) {
    std::string_view sv(content);
    // Strip trailing whitespace
    while (!sv.empty() && (sv.back() == '\n' || sv.back() == '\r' ||
                           sv.back() == ' ' || sv.back() == '\t')) {
        sv.remove_suffix(1);
    }
    if (sv.size() == CHACHA20_KEY_SIZE * 2) {
        try {
            out = key_from_hex(sv);
            return true;
        } catch (...) {
            return false;
        }
    }
    return false;
}

static bool try_read_raw_key(const std::string& content, Key& out) {
    if (content.size() == CHACHA20_KEY_SIZE) {
        std::memcpy(out.data(), content.data(), CHACHA20_KEY_SIZE);
        return true;
    }
    return false;
}

Key key_from_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("cannot open key file: " + path);

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    Key key{};
    if (try_read_raw_key(content, key))
        return key;
    if (try_read_hex_key(content, key))
        return key;

    throw std::runtime_error("invalid key file format: must be " +
                             std::to_string(CHACHA20_KEY_SIZE) + " raw bytes or " +
                             std::to_string(CHACHA20_KEY_SIZE * 2) + " hex characters");
}

} // namespace crypto
