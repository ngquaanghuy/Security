#include "encoders/base36.h"
#include <cstdint>
#include <vector>

namespace encoders {

static const char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

std::string base36_encode(std::string_view data) {
    if (data.empty()) return {};

    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == '\0') {
        ++leading_zeros;
    }

    if (leading_zeros == data.size()) {
        return std::string(data.size(), '0');
    }

    std::vector<uint8_t> quotient;
    for (size_t i = leading_zeros; i < data.size(); ++i) {
        int carry = static_cast<uint8_t>(data[i]);
        for (auto& q : quotient) {
            carry += q * 256;
            q = carry % 36;
            carry /= 36;
        }
        while (carry > 0) {
            quotient.push_back(carry % 36);
            carry /= 36;
        }
    }

    std::string result(leading_zeros, '0');
    for (auto it = quotient.rbegin(); it != quotient.rend(); ++it) {
        result += digits[*it];
    }

    return result;
}

std::string base36_decode(std::string_view data) {
    if (data.empty()) return {};

    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == '0') {
        ++leading_zeros;
    }

    if (leading_zeros == data.size()) {
        return std::string(leading_zeros, '\0');
    }

    std::vector<uint8_t> digits;
    for (size_t i = leading_zeros; i < data.size(); ++i) {
        char c = data[i];
        uint8_t d;
        if (c >= '0' && c <= '9') d = static_cast<uint8_t>(c - '0');
        else if (c >= 'A' && c <= 'Z') d = static_cast<uint8_t>(c - 'A' + 10);
        else if (c >= 'a' && c <= 'z') d = static_cast<uint8_t>(c - 'a' + 10);
        else continue;

        int carry = d;
        for (auto& b : digits) {
            carry += b * 36;
            b = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            digits.push_back(static_cast<uint8_t>(carry & 0xFF));
            carry >>= 8;
        }
    }

    std::string result(leading_zeros, '\0');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        result += static_cast<char>(*it);
    }

    return result;
}

} // namespace encoders
