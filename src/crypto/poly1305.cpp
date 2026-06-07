#include "crypto/poly1305.h"
#include "crypto/chacha20.h"
#include "crypto/ossl_raii.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace crypto {

// 26-bit limb decomposition helpers
static constexpr uint64_t MASK26 = 0x3ffffff;

static void le_bytes_to_limbs(uint64_t h[5], const uint8_t bytes[16]) {
    h[0] = (uint64_t)bytes[0]
         | ((uint64_t)bytes[1] << 8)
         | ((uint64_t)bytes[2] << 16)
         | ((uint64_t)(bytes[3] & 0x03) << 24);
    h[1] = ((uint64_t)bytes[3] >> 2)
         | ((uint64_t)bytes[4] << 6)
         | ((uint64_t)bytes[5] << 14)
         | ((uint64_t)(bytes[6] & 0x0f) << 22);
    h[2] = ((uint64_t)bytes[6] >> 4)
         | ((uint64_t)bytes[7] << 4)
         | ((uint64_t)bytes[8] << 12)
         | ((uint64_t)(bytes[9] & 0x3f) << 20);
    h[3] = ((uint64_t)bytes[9] >> 6)
         | ((uint64_t)bytes[10] << 2)
         | ((uint64_t)bytes[11] << 10)
         | ((uint64_t)bytes[12] << 18);
    h[4] = (uint64_t)bytes[13]
         | ((uint64_t)bytes[14] << 8)
         | ((uint64_t)bytes[15] << 16);
}

static void carry_propagate(uint64_t h[5]) {
    uint64_t c;
    c = h[0] >> 26; h[0] &= MASK26; h[1] += c;
    c = h[1] >> 26; h[1] &= MASK26; h[2] += c;
    c = h[2] >> 26; h[2] &= MASK26; h[3] += c;
    c = h[3] >> 26; h[3] &= MASK26; h[4] += c;

    c = h[4] >> 26; h[4] &= MASK26; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= MASK26; h[1] += c;
    c = h[1] >> 26; h[1] &= MASK26; h[2] += c;
    c = h[2] >> 26; h[2] &= MASK26; h[3] += c;
    c = h[3] >> 26; h[3] &= MASK26; h[4] += c;
    h[4] &= MASK26;
}

static void poly1305_process_block(uint64_t h[5], const uint64_t r[5],
                                   const uint8_t block[16], size_t block_len) {
    uint64_t b[5];
    le_bytes_to_limbs(b, block);
    h[0] += b[0];
    h[1] += b[1];
    h[2] += b[2];
    h[3] += b[3];
    h[4] += b[4];

    // Add the high bit: 1 << (8 * block_len)
    // Map to limb position based on bit index
    size_t bit_pos = 8 * block_len;
    if (bit_pos < 26) {
        h[0] += (uint64_t)1 << bit_pos;
    } else if (bit_pos < 52) {
        h[1] += (uint64_t)1 << (bit_pos - 26);
    } else if (bit_pos < 78) {
        h[2] += (uint64_t)1 << (bit_pos - 52);
    } else if (bit_pos < 104) {
        h[3] += (uint64_t)1 << (bit_pos - 78);
    } else {
        h[4] += (uint64_t)1 << (bit_pos - 104);
    }

    __int128 d[10] = {0};
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 5; ++j) {
            d[i + j] += (__int128)h[i] * r[j];
        }
    }

    d[0] += 5 * (uint64_t)d[5];
    d[1] += 5 * (uint64_t)d[6];
    d[2] += 5 * (uint64_t)d[7];
    d[3] += 5 * (uint64_t)d[8];
    d[4] += 5 * (uint64_t)d[9];

    h[0] = (uint64_t)d[0] & MASK26;
    uint64_t c = (uint64_t)(d[0] >> 26); d[1] += c;
    h[1] = (uint64_t)d[1] & MASK26;
    c = (uint64_t)(d[1] >> 26); d[2] += c;
    h[2] = (uint64_t)d[2] & MASK26;
    c = (uint64_t)(d[2] >> 26); d[3] += c;
    h[3] = (uint64_t)d[3] & MASK26;
    c = (uint64_t)(d[3] >> 26); d[4] += c;
    h[4] = (uint64_t)d[4] & MASK26;
    c = (uint64_t)(d[4] >> 26);

    h[0] += c * 5;
    carry_propagate(h);
}

static void clamp_r(uint8_t r[16]) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

static void limbs_to_tag(uint8_t tag[16], const uint64_t h[5]) {
    uint64_t t0 = h[0] | (h[1] << 26) | ((h[2] & 0xfff) << 52);
    uint64_t t1 = (h[2] >> 12) | (h[3] << 14) | ((h[4] & 0xffffff) << 40);

    tag[0]  = (uint8_t)t0;
    tag[1]  = (uint8_t)(t0 >> 8);
    tag[2]  = (uint8_t)(t0 >> 16);
    tag[3]  = (uint8_t)(t0 >> 24);
    tag[4]  = (uint8_t)(t0 >> 32);
    tag[5]  = (uint8_t)(t0 >> 40);
    tag[6]  = (uint8_t)(t0 >> 48);
    tag[7]  = (uint8_t)(t0 >> 56);

    tag[8]  = (uint8_t)t1;
    tag[9]  = (uint8_t)(t1 >> 8);
    tag[10] = (uint8_t)(t1 >> 16);
    tag[11] = (uint8_t)(t1 >> 24);
    tag[12] = (uint8_t)(t1 >> 32);
    tag[13] = (uint8_t)(t1 >> 40);
    tag[14] = (uint8_t)(t1 >> 48);
    tag[15] = (uint8_t)(t1 >> 56);
}

static bool constant_time_compare(const uint8_t* a, const uint8_t* b,
                                  size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

Poly1305Tag poly1305_mac(std::string_view message, const Poly1305Key& key) {
    uint64_t h[5] = {0};
    uint8_t r_bytes[16];
    std::memcpy(r_bytes, key.data(), 16);
    clamp_r(r_bytes);

    uint64_t r[5];
    le_bytes_to_limbs(r, r_bytes);

    size_t remaining = message.size();
    size_t offset = 0;

    while (remaining > 0) {
        uint8_t block[16] = {0};
        size_t chunk = remaining < 16 ? remaining : 16;
        std::memcpy(block, message.data() + offset, chunk);
        poly1305_process_block(h, r, block, chunk);
        offset += chunk;
        remaining -= chunk;
    }

    // Finalize: add s (second half of key)
    carry_propagate(h);

    uint8_t tag[16] = {0};
    limbs_to_tag(tag, h);

    // Add s
    uint64_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        uint32_t sum = (uint32_t)tag[i] + key.data()[16 + i] + carry;
        tag[i] = (uint8_t)(sum & 0xff);
        carry = sum >> 8;
    }

    Poly1305Tag result{};
    std::memcpy(result.data(), tag, POLY1305_TAG_SIZE);
    return result;
}

bool poly1305_verify(const Poly1305Tag& tag, std::string_view message,
                     const Poly1305Key& key) {
    Poly1305Tag computed = poly1305_mac(message, key);
    return constant_time_compare(tag.data(), computed.data(), POLY1305_TAG_SIZE);
}

// ChaCha20-Poly1305 AEAD using OpenSSL EVP_chacha20_poly1305()
// Output format: nonce(12 bytes) || ciphertext || tag(16 bytes)

static void aead_encrypt_impl(std::string& result,
                               const Key& key,
                               const ChaCha20Poly1305Nonce& nonce,
                               std::string_view plaintext,
                               std::string_view aad) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw std::runtime_error("failed to allocate EVP_CIPHER_CTX");

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_AEAD_SET_IVLEN failed");

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (key+iv) failed");

    if (!aad.empty()) {
        int outlen = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                              reinterpret_cast<const uint8_t*>(aad.data()),
                              static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("EVP_EncryptUpdate (aad) failed");
    }

    std::string ciphertext(plaintext.size() + POLY1305_TAG_SIZE, '\0');
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx.get(),
                          reinterpret_cast<uint8_t*>(ciphertext.data()),
                          &outlen,
                          reinterpret_cast<const uint8_t*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    int finallen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(),
                            reinterpret_cast<uint8_t*>(ciphertext.data() + outlen),
                            &finallen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    size_t ct_len = static_cast<size_t>(outlen + finallen);

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                            POLY1305_TAG_SIZE,
                            reinterpret_cast<uint8_t*>(ciphertext.data() + ct_len)) != 1)
        throw std::runtime_error("EVP_CTRL_AEAD_GET_TAG failed");

    ct_len += POLY1305_TAG_SIZE;
    ciphertext.resize(ct_len);

    result.reserve(nonce.size() + ct_len);
    result.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    result.append(ciphertext);
}

std::string chacha20_poly1305_encrypt(std::string_view plaintext,
                                       const Key& key,
                                       std::string_view aad) {
    if (plaintext.empty()) return {};

    ChaCha20Poly1305Nonce nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for nonce generation");

    std::string result;
    aead_encrypt_impl(result, key, nonce, plaintext, aad);
    return result;
}

std::string chacha20_poly1305_encrypt(std::string_view plaintext,
                                       const Key& key,
                                       const ChaCha20Poly1305Nonce& nonce,
                                       std::string_view aad) {
    std::string result;
    aead_encrypt_impl(result, key, nonce, plaintext, aad);
    return result;
}

static void aead_decrypt_impl(std::string& plaintext,
                               const Key& key,
                               const ChaCha20Poly1305Nonce& nonce,
                               std::string_view ciphertext,
                               std::string_view tag,
                               std::string_view aad) {
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw std::runtime_error("failed to allocate EVP_CIPHER_CTX");

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_AEAD_SET_IVLEN failed");

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex (key+iv) failed");

    if (!aad.empty()) {
        int outlen = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                              reinterpret_cast<const uint8_t*>(aad.data()),
                              static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("EVP_DecryptUpdate (aad) failed");
    }

    plaintext.resize(ciphertext.size());
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx.get(),
                          reinterpret_cast<uint8_t*>(plaintext.data()),
                          &outlen,
                          reinterpret_cast<const uint8_t*>(ciphertext.data()),
                          static_cast<int>(ciphertext.size())) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                            POLY1305_TAG_SIZE,
                            const_cast<uint8_t*>(
                                reinterpret_cast<const uint8_t*>(tag.data()))) != 1)
        throw std::runtime_error("EVP_CTRL_AEAD_SET_TAG failed");

    int finallen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(),
                            reinterpret_cast<uint8_t*>(plaintext.data() + outlen),
                            &finallen) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed: authentication failed");

    plaintext.resize(static_cast<size_t>(outlen + finallen));
}

std::string chacha20_poly1305_decrypt(std::string_view data,
                                       const Key& key,
                                       std::string_view aad) {
    if (data.size() < CHACHA20_POLY1305_NONCE_SIZE + POLY1305_TAG_SIZE)
        throw std::runtime_error("encrypted data too short: missing nonce or tag");

    ChaCha20Poly1305Nonce nonce{};
    std::memcpy(nonce.data(), data.data(), CHACHA20_POLY1305_NONCE_SIZE);

    size_t ct_len = data.size() - CHACHA20_POLY1305_NONCE_SIZE - POLY1305_TAG_SIZE;
    std::string_view ciphertext(data.data() + CHACHA20_POLY1305_NONCE_SIZE, ct_len);
    std::string_view tag(data.data() + data.size() - POLY1305_TAG_SIZE, POLY1305_TAG_SIZE);

    std::string plaintext;
    aead_decrypt_impl(plaintext, key, nonce, ciphertext, tag, aad);
    return plaintext;
}

std::string chacha20_poly1305_decrypt(std::string_view data,
                                       const Key& key,
                                       const ChaCha20Poly1305Nonce& nonce,
                                       std::string_view aad) {
    if (data.size() < POLY1305_TAG_SIZE)
        throw std::runtime_error("encrypted data too short: missing tag");

    size_t ct_len = data.size() - POLY1305_TAG_SIZE;
    std::string_view ciphertext(data.data(), ct_len);
    std::string_view tag(data.data() + ct_len, POLY1305_TAG_SIZE);

    std::string plaintext;
    aead_decrypt_impl(plaintext, key, nonce, ciphertext, tag, aad);
    return plaintext;
}

} // namespace crypto
