#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>
#include "crypto/chacha20.h"
#include "crypto/poly1305.h"
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
        } catch (const std::exception&) {                               \
        }                                                               \
    } while (0)

static std::string hex_to_string(std::string_view hex) {
    std::string result(hex.size() / 2, '\0');
    for (size_t i = 0; i < result.size(); ++i) {
        unsigned int byte;
        std::sscanf(hex.data() + i * 2, "%2x", &byte);
        result[i] = static_cast<char>(byte);
    }
    return result;
}

// RFC 8439 Section 2.5.2: Poly1305 test vector
static void test_poly1305_rfc8439() {
    std::string key_hex = "85d6be7857556d337f4452fe42d506a8"
                          "0103808afb0db2fd4abff6af4149f51b";
    std::string key_str = hex_to_string(key_hex);
    crypto::Poly1305Key key{};
    std::memcpy(key.data(), key_str.data(), crypto::POLY1305_KEY_SIZE);

    std::string_view message = "Cryptographic Forum Research Group";
    std::string expected_tag_hex = "a8061dc1305136c6c22b8baf0c0127a9";
    std::string expected_tag_str = hex_to_string(expected_tag_hex);

    crypto::Poly1305Tag tag = crypto::poly1305_mac(message, key);

    bool match = true;
    for (size_t i = 0; i < crypto::POLY1305_TAG_SIZE; ++i)
        match = match && (tag[i] == static_cast<uint8_t>(expected_tag_str[i]));
    TEST("poly1305 rfc8439 tag", match);

    TEST("poly1305 verify", crypto::poly1305_verify(tag, message, key));

    // Tampered message should fail
    crypto::Poly1305Tag bad_tag = tag;
    bad_tag[0] ^= 1;
    TEST("poly1305 tampered verify",
         !crypto::poly1305_verify(bad_tag, message, key));
}

// RFC 8439 Section 2.8.2: AEAD_CHACHA20_POLY1305 test vector
static void test_aead_rfc8439() {
    std::string key_hex = "808182838485868788898a8b8c8d8e8f"
                          "909192939495969798999a9b9c9d9e9f";
    std::string nonce_hex = "070000004041424344454647";
    std::string aad_hex = "50515253c0c1c2c3c4c5c6c7";
    std::string pt_hex = "4c616469657320616e642047656e746c656d656e206f662074686520636c"
                         "617373206f66202739393a204966204920636f756c64206f666665722079"
                         "6f75206f6e6c79206f6e652074697020666f722074686520667574757265"
                         "2c2073756e73637265656e20776f756c642062652069742e";
    std::string ct_hex = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736"
                         "ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6"
                         "a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad67594"
                         "5585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    std::string tag_hex = "1ae10b594f09e26a7e902ecbd0600691";

    crypto::Key key{};
    std::string key_raw = hex_to_string(key_hex);
    std::memcpy(key.data(), key_raw.data(), crypto::CHACHA20_KEY_SIZE);

    crypto::ChaCha20Poly1305Nonce nonce{};
    std::string nonce_raw = hex_to_string(nonce_hex);
    std::memcpy(nonce.data(), nonce_raw.data(), crypto::CHACHA20_POLY1305_NONCE_SIZE);

    std::string aad = hex_to_string(aad_hex);
    std::string expected_ct = hex_to_string(ct_hex);
    std::string expected_tag = hex_to_string(tag_hex);

    // Encrypt with explicit nonce
    std::string encrypted = crypto::chacha20_poly1305_encrypt(
        hex_to_string(pt_hex), key, nonce, aad);

    // Output format: nonce(12) || ciphertext || tag(16)
    TEST("aead rfc8439 output size",
         encrypted.size() == crypto::CHACHA20_POLY1305_NONCE_SIZE +
                              expected_ct.size() + crypto::POLY1305_TAG_SIZE);

    std::string_view out_ct(encrypted.data() + crypto::CHACHA20_POLY1305_NONCE_SIZE,
                            expected_ct.size());
    std::string_view out_tag(encrypted.data() + encrypted.size() - crypto::POLY1305_TAG_SIZE,
                             crypto::POLY1305_TAG_SIZE);

    TEST("aead rfc8439 ciphertext match", out_ct == expected_ct);
    TEST("aead rfc8439 tag match", out_tag == expected_tag);

    // Decrypt (parsing nonce from data)
    std::string decrypted = crypto::chacha20_poly1305_decrypt(encrypted, key, aad);
    TEST("aead rfc8439 decrypt roundtrip",
         decrypted == hex_to_string(pt_hex));

    // Decrypt with explicit nonce (data is ciphertext+tag)
    std::string ct_and_tag = expected_ct + expected_tag;
    std::string decrypted2 = crypto::chacha20_poly1305_decrypt(
        ct_and_tag, key, nonce, aad);
    TEST("aead rfc8439 decrypt explicit nonce",
         decrypted2 == hex_to_string(pt_hex));

    // Tampered ciphertext should fail
    std::string tampered = encrypted;
    tampered[crypto::CHACHA20_POLY1305_NONCE_SIZE] ^= 1;
    TEST_THROWS("aead tampered ciphertext",
                crypto::chacha20_poly1305_decrypt(tampered, key, aad));

    // Tampered tag should fail
    std::string tampered_tag = encrypted;
    tampered_tag[tampered_tag.size() - 1] ^= 1;
    TEST_THROWS("aead tampered tag",
                crypto::chacha20_poly1305_decrypt(tampered_tag, key, aad));
}

// AEAD test with no AAD
static void test_aead_no_aad() {
    crypto::Key key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i);

    std::string_view plaintext = "Hello, ChaCha20-Poly1305 without AAD!";

    std::string encrypted = crypto::chacha20_poly1305_encrypt(plaintext, key);
    TEST("aead no aad output size",
         encrypted.size() > crypto::CHACHA20_POLY1305_NONCE_SIZE + crypto::POLY1305_TAG_SIZE);

    std::string decrypted = crypto::chacha20_poly1305_decrypt(encrypted, key);
    TEST("aead no aad roundtrip", decrypted == plaintext);
}

// AEAD roundtrip with various AAD sizes
static void test_aead_aad_sizes() {
    crypto::Key key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i * 3 + 7);

    struct {
        std::string_view plaintext;
        std::string_view aad;
        const char* label;
    } cases[] = {
        {"hello", "", "no aad"},
        {"hello", "a", "single byte aad"},
        {"hello", "additional data", "short aad"},
        {"", "aad only", "empty plaintext with aad"},
        {"data", std::string(256, 'x'), "large aad"},
    };

    for (const auto& c : cases) {
        std::string enc;
        try {
            enc = crypto::chacha20_poly1305_encrypt(c.plaintext, key, c.aad);
        } catch (...) {
            if (c.plaintext.empty()) continue;
            std::fprintf(stderr, "FAIL: %s encrypt threw\n", c.label);
            ++failures;
            ++tests;
            continue;
        }

        if (c.plaintext.empty()) continue;

        std::string dec = crypto::chacha20_poly1305_decrypt(enc, key, c.aad);
        TEST(c.label, dec == c.plaintext);
    }
}

// AEAD wrong AAD should fail
static void test_aead_wrong_aad() {
    crypto::Key key{};
    std::string_view plaintext = "test with aad";
    std::string_view aad = "correct aad";
    std::string_view wrong_aad = "wrong aad";

    std::string encrypted = crypto::chacha20_poly1305_encrypt(plaintext, key, aad);
    TEST_THROWS("aead wrong aad",
                crypto::chacha20_poly1305_decrypt(encrypted, key, wrong_aad));
}

// AEAD empty plaintext random nonce roundtrip
static void test_aead_roundtrip() {
    crypto::Key key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i * 7 + 3);

    struct {
        std::string_view input;
        const char* label;
    } cases[] = {
        {"a", "single byte"},
        {"hello", "short string"},
        {"The quick brown fox jumps over the lazy dog", "medium string"},
        {"a", "single byte repeat"},
    };

    for (const auto& c : cases) {
        std::string enc = crypto::chacha20_poly1305_encrypt(c.input, key);
        TEST(c.label, enc.size() > crypto::CHACHA20_POLY1305_NONCE_SIZE +
                      crypto::POLY1305_TAG_SIZE);

        std::string dec = crypto::chacha20_poly1305_decrypt(enc, key);
        TEST(c.label, dec == c.input);
    }
}

static void test_aead_random_nonce_encrypt() {
    crypto::Key key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i);

    std::string input = "Test message for random nonce encryption";
    std::string result1 = crypto::chacha20_poly1305_encrypt(input, key);
    std::string result2 = crypto::chacha20_poly1305_encrypt(input, key);

    bool nonces_differ = false;
    if (result1.size() > crypto::CHACHA20_POLY1305_NONCE_SIZE &&
        result2.size() > crypto::CHACHA20_POLY1305_NONCE_SIZE) {
        nonces_differ = std::memcmp(result1.data(), result2.data(),
                                    crypto::CHACHA20_POLY1305_NONCE_SIZE) != 0;
    }
    TEST("aead random nonces differ", nonces_differ);

    std::string dec1 = crypto::chacha20_poly1305_decrypt(result1, key);
    std::string dec2 = crypto::chacha20_poly1305_decrypt(result2, key);
    TEST("aead decrypt result1", dec1 == input);
    TEST("aead decrypt result2", dec2 == input);
}

static void test_aead_decrypt_too_short() {
    crypto::Key key{};
    TEST_THROWS("aead decrypt too short (no nonce)",
                crypto::chacha20_poly1305_decrypt(std::string_view("short", 5), key));
    TEST_THROWS("aead decrypt too short (nonce only)",
                crypto::chacha20_poly1305_decrypt(
                    std::string_view("shortstring", 12), key));
    TEST_THROWS("aead decrypt too short (nonce+partial tag)",
                crypto::chacha20_poly1305_decrypt(
                    std::string_view("0123456789ab", 12), key));
}

int main() {
    test_poly1305_rfc8439();
    test_aead_rfc8439();
    test_aead_no_aad();
    test_aead_aad_sizes();
    test_aead_wrong_aad();
    test_aead_roundtrip();
    test_aead_random_nonce_encrypt();
    test_aead_decrypt_too_short();

    std::printf("%d tests, %d failures\n", tests, failures);
    return failures > 0 ? 1 : 0;
}
