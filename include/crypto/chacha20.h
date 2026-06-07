#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace crypto {

static constexpr size_t CHACHA20_KEY_SIZE = 32;
static constexpr size_t CHACHA20_NONCE_SIZE = 8;
static constexpr size_t CHACHA20_COUNTER_SIZE = 8;
static constexpr size_t CHACHA20_IV_SIZE = 16;

using Key = std::array<uint8_t, CHACHA20_KEY_SIZE>;
using Nonce = std::array<uint8_t, CHACHA20_NONCE_SIZE>;

std::string chacha20_encrypt(std::string_view plaintext, const Key& key);

std::string chacha20_decrypt(std::string_view data, const Key& key);

std::string chacha20_encrypt(std::string_view plaintext, const Key& key,
                             const Nonce& nonce, uint64_t counter);

std::string chacha20_decrypt(std::string_view ciphertext, const Key& key,
                             const Nonce& nonce, uint64_t counter);

} // namespace crypto
