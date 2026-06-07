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

} // namespace encoders
