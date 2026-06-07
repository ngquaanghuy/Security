#include "encoders/base85.h"
#include <cstdint>

namespace encoders {

std::string base85_encode(std::string_view data) {
    if (data.empty()) return {};

    std::string result;
    result.reserve(data.size() * 5 / 4 + 5);

    size_t i = 0;
    while (i < data.size()) {
        size_t remain = data.size() - i;

        uint32_t value = 0;
        for (size_t j = 0; j < 4; ++j) {
            value <<= 8;
            if (j < remain) {
                value |= static_cast<uint8_t>(data[i + j]);
            }
        }

        if (value == 0 && remain >= 4) {
            result += 'z';
            i += 4;
            continue;
        }

        char encoded[5];
        for (int j = 4; j >= 0; --j) {
            encoded[j] = static_cast<char>((value % 85) + 33);
            value /= 85;
        }

        int chars_to_output = (remain >= 4) ? 5 : (static_cast<int>(remain) + 1);
        result.append(encoded, chars_to_output);

        i += (remain >= 4) ? 4 : remain;
    }

    return result;
}

std::string base85_decode(std::string_view data) {
    if (data.empty()) return {};

    std::string result;
    result.reserve(data.size());

    size_t i = 0;
    while (i < data.size()) {
        if (data[i] <= ' ') { ++i; continue; }

        if (data[i] == 'z') {
            result.append(4, '\0');
            ++i;
            continue;
        }

        uint32_t value = 0;
        size_t count = 0;
        while (count < 5 && i < data.size()) {
            char c = data[i];
            if (c <= ' ') { ++i; continue; }
            if (c == 'z') break;
            if (c < 33 || c > 117) { ++i; continue; }
            value = value * 85 + (static_cast<uint8_t>(c) - 33);
            ++count;
            ++i;
        }

        if (count < 2) continue;

        size_t output_bytes = count - 1;

        // Pad partial group with 'u' (value 84) to get full 32-bit value
        while (count < 5) {
            value = value * 85 + 84;
            ++count;
        }

        uint8_t bytes[4];
        bytes[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        bytes[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        bytes[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        bytes[3] = static_cast<uint8_t>(value & 0xFF);

        result.append(reinterpret_cast<const char*>(bytes), output_bytes);
    }

    return result;
}

} // namespace encoders
