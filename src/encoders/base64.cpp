#include "encoders/base64.h"
#include <cstdint>

namespace encoders {

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(std::string_view data) {
    if (data.empty()) return {};

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < data.size()) {
        uint32_t octets = 0;
        size_t remain = data.size() - i;

        octets |= (static_cast<uint8_t>(data[i]) << 16);
        if (remain > 1) octets |= (static_cast<uint8_t>(data[i + 1]) << 8);
        if (remain > 2) octets |= static_cast<uint8_t>(data[i + 2]);

        result += alphabet[(octets >> 18) & 0x3F];
        result += alphabet[(octets >> 12) & 0x3F];

        if (remain > 1) {
            result += alphabet[(octets >> 6) & 0x3F];
        } else {
            result += '=';
        }

        if (remain > 2) {
            result += alphabet[octets & 0x3F];
        } else {
            result += '=';
        }

        i += 3;
    }

    return result;
}

static uint8_t base64_val(char c) {
    if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<uint8_t>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0xFF;
}

std::string base64_decode(std::string_view data) {
    if (data.empty()) return {};

    size_t padding = 0;
    if (data.size() >= 1 && data[data.size() - 1] == '=') ++padding;
    if (data.size() >= 2 && data[data.size() - 2] == '=') ++padding;

    size_t decoded_len = (data.size() / 4) * 3;
    if (decoded_len > padding) decoded_len -= padding;

    std::string result;
    result.reserve(decoded_len);

    for (size_t i = 0; i + 3 < data.size(); i += 4) {
        uint8_t v[4];
        int n = 0;
        for (int j = 0; j < 4; ++j) {
            if (data[i + j] == '=') break;
            v[j] = base64_val(data[i + j]);
            ++n;
        }

        if (n >= 2) result += static_cast<char>((v[0] << 2) | (v[1] >> 4));
        if (n >= 3) result += static_cast<char>((v[1] << 4) | (v[2] >> 2));
        if (n >= 4) result += static_cast<char>((v[2] << 6) | v[3]);
    }

    return result;
}

} // namespace encoders
