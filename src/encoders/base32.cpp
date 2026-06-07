#include "encoders/base32.h"
#include <cstdint>
#include <algorithm>

namespace encoders {

static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string base32_encode(std::string_view data) {
    if (data.empty()) return {};

    size_t groups = (data.size() + 4) / 5;
    std::string result;
    result.reserve(groups * 8);

    size_t i = 0;
    while (i < data.size()) {
        uint8_t bytes[5] = {0};
        size_t n = std::min(data.size() - i, size_t(5));
        std::copy_n(data.data() + i, n, bytes);

        uint64_t bits = 0;
        for (size_t j = 0; j < 5; ++j) {
            bits = (bits << 8) | bytes[j];
        }

        int total_bits = static_cast<int>(n) * 8;
        int output_chars = (total_bits + 4) / 5;
        int padding = 8 - output_chars;

        static const int shifts[8] = {35, 30, 25, 20, 15, 10, 5, 0};

        for (int j = 0; j < output_chars; ++j) {
            result += alphabet[(bits >> shifts[j]) & 0x1F];
        }
        result.append(padding, '=');

        i += 5;
    }

    return result;
}

} // namespace encoders
