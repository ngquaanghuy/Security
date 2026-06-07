#pragma once

#include "crypto/chacha20.h"
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace crypto {

static constexpr size_t POLY1305_KEY_SIZE = 32;
static constexpr size_t POLY1305_TAG_SIZE = 16;
static constexpr size_t POLY1305_BLOCK_SIZE = 16;
static constexpr size_t CHACHA20_POLY1305_NONCE_SIZE = 12;

using Poly1305Key = std::array<uint8_t, POLY1305_KEY_SIZE>;
using Poly1305Tag = std::array<uint8_t, POLY1305_TAG_SIZE>;
using ChaCha20Poly1305Nonce = std::array<uint8_t, CHACHA20_POLY1305_NONCE_SIZE>;

Poly1305Tag poly1305_mac(std::string_view message, const Poly1305Key& key);

bool poly1305_verify(const Poly1305Tag& tag, std::string_view message,
                     const Poly1305Key& key);

std::string chacha20_poly1305_encrypt(std::string_view plaintext,
                                       const Key& key,
                                       std::string_view aad = {});

std::string chacha20_poly1305_encrypt(std::string_view plaintext,
                                       const Key& key,
                                       const ChaCha20Poly1305Nonce& nonce,
                                       std::string_view aad = {});

std::string chacha20_poly1305_decrypt(std::string_view data,
                                       const Key& key,
                                       std::string_view aad = {});

std::string chacha20_poly1305_decrypt(std::string_view data,
                                       const Key& key,
                                       const ChaCha20Poly1305Nonce& nonce,
                                       std::string_view aad = {});

} // namespace crypto
