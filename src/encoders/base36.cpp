#include "encoders/base36.h"
#include <cstdint>
#include <vector>

namespace encoders {

static const char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static constexpr size_t CHUNK_BYTES = 5;
static constexpr size_t CHUNK_DIGITS = 8;

static int needed_digits_for_bytes(size_t n) {
    if (n == 1) return 2;
    if (n == 2) return 4;
    if (n == 3) return 5;
    if (n == 4) return 7;
    if (n == 5) return 8;
    return 0;
}

static int bytes_from_digits(size_t n) {
    if (n == 2) return 1;
    if (n == 4) return 2;
    if (n == 5) return 3;
    if (n == 7) return 4;
    if (n == 8) return 5;
    return 0;
}

static void encode_chunk(uint64_t value, int nd, char out[CHUNK_DIGITS]) {
    char tmp[CHUNK_DIGITS];
    for (int j = nd - 1; j >= 0; --j) {
        tmp[j] = digits[value % 36];
        value /= 36;
    }
    for (int j = 0; j < nd; ++j)
        out[j] = tmp[j];
    for (size_t j = static_cast<size_t>(nd); j < CHUNK_DIGITS; ++j)
        out[j] = '=';
}

static uint64_t decode_chunk(std::string_view s, size_t valid) {
    uint64_t value = 0;
    for (size_t j = 0; j < valid && j < s.size(); ++j) {
        char c = s[j];
        uint8_t d;
        if (c >= '0' && c <= '9') d = static_cast<uint8_t>(c - '0');
        else if (c >= 'A' && c <= 'Z') d = static_cast<uint8_t>(c - 'A' + 10);
        else if (c >= 'a' && c <= 'z') d = static_cast<uint8_t>(c - 'a' + 10);
        else continue;
        value = value * 36 + d;
    }
    return value;
}

std::string base36_encode(std::string_view data) {
    if (data.empty()) return {};

    std::string result;
    size_t full = data.size() / CHUNK_BYTES;
    size_t rem = data.size() % CHUNK_BYTES;
    result.reserve((full + (rem ? 1 : 0)) * CHUNK_DIGITS);

    size_t pos = 0;
    for (size_t c = 0; c < full; ++c) {
        uint64_t value = 0;
        for (int j = 0; j < CHUNK_BYTES; ++j)
            value = (value << 8) | static_cast<uint8_t>(data[pos++]);
        char chunk[CHUNK_DIGITS];
        encode_chunk(value, CHUNK_DIGITS, chunk);
        result.append(chunk, CHUNK_DIGITS);
    }

    if (rem > 0) {
        uint64_t value = 0;
        for (size_t j = 0; j < rem; ++j)
            value = (value << 8) | static_cast<uint8_t>(data[pos++]);
        char chunk[CHUNK_DIGITS];
        encode_chunk(value, needed_digits_for_bytes(rem), chunk);
        result.append(chunk, CHUNK_DIGITS);
    }

    return result;
}

std::string base36_decode(std::string_view data) {
    if (data.empty()) return {};

    std::string result;
    result.reserve((data.size() / CHUNK_DIGITS) * CHUNK_BYTES + CHUNK_BYTES);

    size_t pos = 0;
    while (pos < data.size()) {
        size_t valid = 0;
        while (valid < CHUNK_DIGITS && pos + valid < data.size() &&
               data[pos + valid] != '=') {
            ++valid;
        }

        if (valid == 0) { ++pos; continue; }

        int out_bytes = bytes_from_digits(valid);
        if (out_bytes == 0) { ++pos; continue; }

        uint64_t value = decode_chunk(data.substr(pos, valid), valid);

        uint8_t bytes[CHUNK_BYTES];
        for (int j = 0; j < out_bytes; ++j)
            bytes[j] = static_cast<uint8_t>((value >> (8 * (out_bytes - 1 - j))) & 0xFF);

        result.append(reinterpret_cast<const char*>(bytes),
                      static_cast<size_t>(out_bytes));
        pos += CHUNK_DIGITS;
    }

    return result;
}

} // namespace encoders
