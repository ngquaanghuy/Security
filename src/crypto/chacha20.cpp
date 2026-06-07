#include "crypto/chacha20.h"
#include "crypto/ossl_raii.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace crypto {

// Build OpenSSL-compatible 16-byte IV:
//   bytes 0-7: counter (64-bit, little-endian)
//   bytes 8-15: nonce (64-bit, little-endian)
static void build_iv(uint8_t iv[CHACHA20_IV_SIZE], const Nonce& nonce,
                     uint64_t counter) {
    for (int i = 0; i < 8; ++i) {
        iv[i] = static_cast<uint8_t>(counter >> (i * 8));
        iv[8 + i] = nonce[i];
    }
}

static std::string chacha20_impl(std::string_view input, const Key& key,
                                  const Nonce& nonce, uint64_t counter,
                                  int enc) {
    if (input.empty()) return {};

    uint8_t iv[CHACHA20_IV_SIZE];
    build_iv(iv, nonce, counter);

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw std::runtime_error("failed to allocate EVP_CIPHER_CTX");

    const EVP_CIPHER* cipher = EVP_chacha20();

    if (EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key.data(), iv, enc) != 1)
        throw std::runtime_error("EVP_CipherInit_ex failed");

    int outlen = 0;
    std::string result(input.size(), '\0');

    if (EVP_CipherUpdate(ctx.get(),
                         reinterpret_cast<uint8_t*>(result.data()), &outlen,
                         reinterpret_cast<const uint8_t*>(input.data()),
                         static_cast<int>(input.size())) != 1)
        throw std::runtime_error("EVP_CipherUpdate failed");

    int finallen = 0;
    if (EVP_CipherFinal_ex(ctx.get(),
                           reinterpret_cast<uint8_t*>(result.data() + outlen),
                           &finallen) != 1)
        throw std::runtime_error("EVP_CipherFinal_ex failed");

    result.resize(static_cast<size_t>(outlen + finallen));
    return result;
}

std::string chacha20_encrypt(std::string_view plaintext, const Key& key) {
    Nonce nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for nonce generation");

    std::string ciphertext = chacha20_impl(plaintext, key, nonce, 0, 1);

    std::string result;
    result.reserve(CHACHA20_NONCE_SIZE + ciphertext.size());
    result.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    result.append(ciphertext);
    return result;
}

std::string chacha20_decrypt(std::string_view data, const Key& key) {
    if (data.size() < CHACHA20_NONCE_SIZE)
        throw std::runtime_error("encrypted data too short: missing nonce");

    Nonce nonce{};
    std::memcpy(nonce.data(), data.data(), CHACHA20_NONCE_SIZE);
    std::string_view ciphertext = data.substr(CHACHA20_NONCE_SIZE);

    return chacha20_impl(ciphertext, key, nonce, 0, 0);
}

std::string chacha20_encrypt(std::string_view plaintext, const Key& key,
                             const Nonce& nonce, uint64_t counter) {
    return chacha20_impl(plaintext, key, nonce, counter, 1);
}

std::string chacha20_decrypt(std::string_view ciphertext, const Key& key,
                             const Nonce& nonce, uint64_t counter) {
    return chacha20_impl(ciphertext, key, nonce, counter, 0);
}

} // namespace crypto
