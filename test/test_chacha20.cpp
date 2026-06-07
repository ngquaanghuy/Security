#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>
#include "crypto/chacha20.h"
#include "crypto/key_manager.h"

static int failures = 0;
static int tests = 0;

#define TEST(name, expr)                                                \
    do {                                                                \
        ++tests;                                                        \
        if (!(expr)) {                                                  \
            std::fprintf(stderr, "FAIL: %s (%s)\n", name, #expr);      \
            ++failures;                                                 \
        }                                                               \
    } while (0)

#define TEST_THROWS(name, expr)                                         \
    do {                                                                \
        ++tests;                                                        \
        try {                                                           \
            (void)(expr);                                               \
            std::fprintf(stderr, "FAIL: %s (expected exception)\n",     \
                         name);                                         \
            ++failures;                                                 \
        } catch (const std::exception& e) {                             \
        }                                                               \
    } while (0)

static void test_known_vector() {
    crypto::Key key{};
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);

    crypto::Nonce nonce{};
    nonce[0] = 0x01; nonce[1] = 0x02; nonce[2] = 0x03;
    nonce[3] = 0x04; nonce[4] = 0x05; nonce[5] = 0x06;
    nonce[6] = 0x07; nonce[7] = 0x08;

    std::string_view plaintext = "Hello ChaCha20 Test";
    std::string ciphertext = crypto::chacha20_encrypt(plaintext, key, nonce, 0);

    // Verified against: openssl enc -chacha20 -K <key> -iv 00000000000000000102030405060708
    const uint8_t expected[] = {
        0xc4, 0x8f, 0x34, 0x53, 0xa8, 0xa8, 0x29, 0x5e,
        0xaa, 0xec, 0x92, 0xc4, 0xa7, 0xdd, 0xf2, 0xb7,
        0xc5, 0xa4, 0x1d
    };
    std::string_view expected_sv(reinterpret_cast<const char*>(expected),
                                  sizeof(expected));

    TEST("known vector size", ciphertext.size() == plaintext.size());
    TEST("known vector match", ciphertext == expected_sv);

    // Decrypt back
    std::string decrypted = crypto::chacha20_decrypt(ciphertext, key, nonce, 0);
    TEST("known vector roundtrip", decrypted == plaintext);
}

static void test_empty() {
    crypto::Key key{};
    crypto::Nonce nonce{};

    std::string enc = crypto::chacha20_encrypt("", key, nonce, 0);
    TEST("empty encrypt returns empty", enc.empty());

    std::string dec = crypto::chacha20_decrypt("", key, nonce, 0);
    TEST("empty decrypt returns empty", dec.empty());
}

static void test_roundtrip() {
    crypto::Key key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i * 7 + 3);

    crypto::Nonce nonce{};
    for (size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<uint8_t>(i * 11 + 5);

    struct {
        std::string_view input;
        const char* label;
    } cases[] = {
        {"a", "single byte"},
        {"hello", "short string"},
        {"The quick brown fox jumps over the lazy dog", "medium string"},
        {"a", "single byte repeat"},
        {"", "empty"},
    };

    for (const auto& c : cases) {
        std::string enc = crypto::chacha20_encrypt(c.input, key, nonce, 0);
        TEST(c.label, enc.size() == c.input.size());

        std::string dec = crypto::chacha20_decrypt(enc, key, nonce, 0);
        TEST(c.label, dec == c.input);
    }
}

static void test_different_nonce() {
    crypto::Key key{};
    crypto::Nonce nonce1{}, nonce2{};
    nonce2[0] = 0x42;

    std::string input = "same plaintext different nonce";
    std::string ct1 = crypto::chacha20_encrypt(input, key, nonce1, 0);
    std::string ct2 = crypto::chacha20_encrypt(input, key, nonce2, 0);

    bool differ = (ct1 != ct2);
    TEST("different nonces produce different ciphertext", differ);
}

static void test_random_nonce_encrypt() {
    crypto::Key key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i);

    std::string input = "Test message for random nonce encryption";
    std::string result1 = crypto::chacha20_encrypt(input, key);
    std::string result2 = crypto::chacha20_encrypt(input, key);

    // First 8 bytes are nonce, should differ
    bool nonces_differ = false;
    if (result1.size() > 8 && result2.size() > 8) {
        nonces_differ = std::memcmp(result1.data(), result2.data(), 8) != 0;
    }
    TEST("random nonces differ", nonces_differ);

    std::string dec1 = crypto::chacha20_decrypt(result1, key);
    std::string dec2 = crypto::chacha20_decrypt(result2, key);
    TEST("decrypt result1", dec1 == input);
    TEST("decrypt result2", dec2 == input);
}

static void test_decrypt_too_short() {
    crypto::Key key{};
    TEST_THROWS("decrypt too short",
                crypto::chacha20_decrypt(std::string_view("short", 5), key));
}

static void test_keygen() {
    crypto::Key k1 = crypto::generate_key();
    crypto::Key k2 = crypto::generate_key();

    bool same = (std::memcmp(k1.data(), k2.data(), k1.size()) == 0);
    TEST("keygen produces unique keys", !same);

    std::string hex = crypto::key_to_hex(k1);
    TEST("key_to_hex length", hex.size() == 64);

    crypto::Key k3 = crypto::key_from_hex(hex);
    TEST("key_from_hex roundtrip",
         std::memcmp(k1.data(), k3.data(), k1.size()) == 0);
}

static void test_key_from_hex() {
    std::string hex = "000102030405060708090a0b0c0d0e0f"
                      "101112131415161718191a1b1c1d1e1f";
    crypto::Key key = crypto::key_from_hex(hex);
    for (int i = 0; i < 32; ++i)
        TEST("key_from_hex byte " + std::to_string(i),
             key[i] == static_cast<uint8_t>(i));

    TEST_THROWS("key_from_hex too short",
                crypto::key_from_hex("aabb"));

    TEST_THROWS("key_from_hex bad char",
                crypto::key_from_hex("zz" + std::string(62, '0')));
}

static void test_key_from_file() {
    crypto::Key k1 = crypto::generate_key();
    std::string hex = crypto::key_to_hex(k1);

    std::string tmp_path = "/tmp/test_key_hex.bin";
    {
        std::FILE* f = std::fopen(tmp_path.c_str(), "wb");
        std::fwrite(hex.data(), 1, hex.size(), f);
        std::fclose(f);
    }
    crypto::Key k2 = crypto::key_from_file(tmp_path);
    TEST("key_from_file hex",
         std::memcmp(k1.data(), k2.data(), k1.size()) == 0);

    std::string tmp_path2 = "/tmp/test_key_raw.bin";
    {
        std::FILE* f = std::fopen(tmp_path2.c_str(), "wb");
        std::fwrite(k1.data(), 1, k1.size(), f);
        std::fclose(f);
    }
    crypto::Key k3 = crypto::key_from_file(tmp_path2);
    TEST("key_from_file raw",
         std::memcmp(k1.data(), k3.data(), k1.size()) == 0);

    TEST_THROWS("key_from_file missing",
                crypto::key_from_file("/tmp/nonexistent_key_file_xyz"));

    {
        std::FILE* f = std::fopen("/tmp/test_key_bad.bin", "wb");
        std::fwrite("bad", 1, 3, f);
        std::fclose(f);
    }
    TEST_THROWS("key_from_file bad content",
                crypto::key_from_file("/tmp/test_key_bad.bin"));
}

int main() {
    test_known_vector();
    test_empty();
    test_roundtrip();
    test_different_nonce();
    test_random_nonce_encrypt();
    test_decrypt_too_short();
    test_keygen();
    test_key_from_hex();
    test_key_from_file();

    std::printf("%d tests, %d failures\n", tests, failures);
    return failures > 0 ? 1 : 0;
}
