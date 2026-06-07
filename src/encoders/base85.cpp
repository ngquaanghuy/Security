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

} // namespace encoders
