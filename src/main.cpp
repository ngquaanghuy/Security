#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <fstream>
#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "version.h"
#include "encoders/base64.h"
#include "encoders/base85.h"
#include "encoders/base32.h"
#include "encoders/base36.h"
#include "crypto/chacha20.h"
#include "crypto/key_manager.h"
#include "crypto/poly1305.h"

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#else
#include <windows.h>
#include <io.h>
#endif

static constexpr size_t SALT_SIZE = 32;
static constexpr size_t HMAC_SIZE = 32;
static constexpr size_t HEADER_SIZE = SALT_SIZE + HMAC_SIZE;

enum KeySource { KEY_NONE, KEY_HEX, KEY_GEN, KEY_ENV, KEY_FILE };

static void print_version() {
    std::printf("%s v%s\n", PROJECT_NAME, PROJECT_VERSION);
}

static void print_help() {
    std::printf("Usage: %s <command> [OPTIONS] <input>\n\n", PROJECT_NAME);
    std::printf("Commands:\n");
    std::printf("  encode                    Encode/encrypt a file\n");
    std::printf("  decode                    Decode/decrypt a file\n");
    std::printf("  protect                   Encrypt into self-executing wrapper\n");
    std::printf("\nOptions:\n");
    std::printf("  -v, --version            Show version\n");
    std::printf("  -h, --help               Show this help\n");
    std::printf("  -a, --algorithm <name>   Algorithm (default: base64)\n");
    std::printf("  -o, --output <file>      Output file\n");
    std::printf("  -k, --key <hex>          Key as hex string\n");
    std::printf("\nKey source (mutually exclusive; default: --keygen):\n");
    std::printf("  --keygen [algo]          Generate new random key\n");
    std::printf("  --keyenv                 Read key from KEYENV env var\n");
    std::printf("  --keyfile <path>         Read key from file (raw or hex)\n");
    std::printf("\nSupported algorithms:\n");
    std::printf("  base64, base85, base32, base36, chacha20, chacha20-poly1305\n");
    std::printf("\nExamples:\n");
    std::printf("  %s encode -a chacha20 input.txt -o output.enc\n", PROJECT_NAME);
    std::printf("  %s encode --keyenv -a chacha20 input.txt -o out.enc\n", PROJECT_NAME);
    std::printf("  %s decode -a chacha20 -k <key> output.enc -o output.txt\n", PROJECT_NAME);
    std::printf("  %s decode --keyfile key.bin -a chacha20 output.enc -o out\n", PROJECT_NAME);
    std::printf("  %s decode --keygen -a chacha20 output.enc\n", PROJECT_NAME);
    std::printf("  %s protect -a chacha20-poly1305 script.py -o protected.py\n", PROJECT_NAME);
}

static bool is_valid_algorithm(std::string_view name) {
    return name == "base64" || name == "base85" ||
           name == "base32" || name == "base36" ||
           name == "chacha20" || name == "chacha20-poly1305";
}

static bool is_encoding(std::string_view algo) {
    return algo == "base64" || algo == "base85" ||
           algo == "base32" || algo == "base36";
}

static bool is_encryption(std::string_view algo) {
    return algo == "chacha20" || algo == "chacha20-poly1305";
}

static std::string encode_str(std::string_view algo, std::string_view input) {
    if (algo == "base64") return encoders::base64_encode(input);
    if (algo == "base85") return encoders::base85_encode(input);
    if (algo == "base32") return encoders::base32_encode(input);
    if (algo == "base36") return encoders::base36_encode(input);
    return {};
}

static std::string decode_str(std::string_view algo, std::string_view input) {
    if (algo == "base64") return encoders::base64_decode(input);
    if (algo == "base85") return encoders::base85_decode(input);
    if (algo == "base32") return encoders::base32_decode(input);
    if (algo == "base36") return encoders::base36_decode(input);
    return {};
}

static bool read_file(const std::string& path, std::string& out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    std::streamsize size = file.tellg();
    file.seekg(0);
    out.resize(static_cast<size_t>(size));
    file.read(out.data(), size);
    return file.good();
}

static bool write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(content.data(), static_cast<std::streamsize>(content.size()));
    return file.good();
}

static bool is_hex_string(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

static std::string hmac_sha256(const uint8_t* key, size_t key_len,
                                const uint8_t* data, size_t data_len) {
    unsigned char md[HMAC_SIZE];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), key, static_cast<int>(key_len),
         data, data_len, md, &md_len);
    return std::string(reinterpret_cast<const char*>(md), md_len);
}

static std::string compute_hmac(const crypto::Key& key,
                                 const uint8_t* salt,
                                 std::string_view payload) {
    std::string msg(reinterpret_cast<const char*>(salt), SALT_SIZE);
    msg.append(payload.data(), payload.size());
    return hmac_sha256(key.data(), key.size(),
                        reinterpret_cast<const uint8_t*>(msg.data()),
                        msg.size());
}

struct EncodeResult {
    crypto::Key key;
    std::string output;
};

static EncodeResult do_encoding_encode(std::string_view algo,
                                        std::string_view input) {
    crypto::Key key = crypto::generate_key();
    std::string encoded = encode_str(algo, input);

    std::string encrypted = crypto::chacha20_encrypt(encoded, key);

    std::array<uint8_t, SALT_SIZE> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for salt");

    std::string hmac = compute_hmac(key, salt.data(), encrypted);

    std::string output;
    output.reserve(HEADER_SIZE + encrypted.size());
    output.append(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
    output.append(hmac);
    output.append(encrypted);

    return {key, output};
}

static EncodeResult do_encryption_encode(std::string_view algo,
                                          std::string_view input,
                                          std::string_view aad) {
    crypto::Key key = crypto::generate_key();
    std::string encrypted;

    if (algo == "chacha20-poly1305") {
        encrypted = crypto::chacha20_poly1305_encrypt(input, key, aad);
    } else {
        encrypted = crypto::chacha20_encrypt(input, key);
    }

    std::array<uint8_t, SALT_SIZE> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for salt");

    std::string hmac = compute_hmac(key, salt.data(), encrypted);

    std::string output;
    output.reserve(HEADER_SIZE + encrypted.size());
    output.append(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
    output.append(hmac);
    output.append(encrypted);

    return {key, output};
}

static EncodeResult do_encoding_encode_with_key(std::string_view algo,
                                                 std::string_view input,
                                                 const crypto::Key& key) {
    std::string encoded = encode_str(algo, input);
    std::string encrypted = crypto::chacha20_encrypt(encoded, key);

    std::array<uint8_t, SALT_SIZE> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for salt");

    std::string hmac = compute_hmac(key, salt.data(), encrypted);

    std::string output;
    output.reserve(HEADER_SIZE + encrypted.size());
    output.append(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
    output.append(hmac);
    output.append(encrypted);

    return {key, output};
}

static EncodeResult do_encryption_encode_with_key(std::string_view algo,
                                                   std::string_view input,
                                                   std::string_view aad,
                                                   const crypto::Key& key) {
    std::string encrypted;

    if (algo == "chacha20-poly1305") {
        encrypted = crypto::chacha20_poly1305_encrypt(input, key, aad);
    } else {
        encrypted = crypto::chacha20_encrypt(input, key);
    }

    std::array<uint8_t, SALT_SIZE> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for salt");

    std::string hmac = compute_hmac(key, salt.data(), encrypted);

    std::string output;
    output.reserve(HEADER_SIZE + encrypted.size());
    output.append(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
    output.append(hmac);
    output.append(encrypted);

    return {key, output};
}

static std::string do_encoding_decode(std::string_view algo,
                                       const crypto::Key& key,
                                       std::string_view data) {
    if (data.size() < HEADER_SIZE)
        throw std::runtime_error("input too short");

    auto salt_ptr = reinterpret_cast<const uint8_t*>(data.data());
    std::string_view stored_hmac(data.data() + SALT_SIZE, HMAC_SIZE);
    std::string_view payload = data.substr(HEADER_SIZE);

    std::string computed = compute_hmac(key, salt_ptr, payload);
    if (CRYPTO_memcmp(computed.data(), stored_hmac.data(), HMAC_SIZE) != 0)
        throw std::runtime_error("invalid key or corrupted data");

    std::string encoded = crypto::chacha20_decrypt(payload, key);
    return decode_str(algo, encoded);
}

static std::string do_encryption_decode(std::string_view algo,
                                         const crypto::Key& key,
                                         std::string_view data,
                                         std::string_view aad) {
    if (data.size() < HEADER_SIZE)
        throw std::runtime_error("input too short");

    auto salt_ptr = reinterpret_cast<const uint8_t*>(data.data());
    std::string_view stored_hmac(data.data() + SALT_SIZE, HMAC_SIZE);
    std::string_view payload = data.substr(HEADER_SIZE);

    std::string computed = compute_hmac(key, salt_ptr, payload);
    if (CRYPTO_memcmp(computed.data(), stored_hmac.data(), HMAC_SIZE) != 0)
        throw std::runtime_error("invalid key or corrupted data");

    if (algo == "chacha20-poly1305") {
        return crypto::chacha20_poly1305_decrypt(payload, key, aad);
    }
    return crypto::chacha20_decrypt(payload, key);
}

static std::string bytes_to_hex(const std::string& data) {
    static const char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(data.size() * 2);
    for (unsigned char c : data) {
        hex += digits[c >> 4];
        hex += digits[c & 0xf];
    }
    return hex;
}

static std::string generate_protect_wrapper(std::string_view algo,
                                              const crypto::Key& key,
                                              std::string_view encrypted_output) {
    // Recompute HMAC over salt + algo + payload to bind algorithm to auth
    auto salt_ptr = reinterpret_cast<const uint8_t*>(encrypted_output.data());
    auto payload = encrypted_output.substr(HEADER_SIZE);
    std::string msg;
    msg.reserve(SALT_SIZE + algo.size() + payload.size());
    msg.append(reinterpret_cast<const char*>(salt_ptr), SALT_SIZE);
    msg.append(algo.data(), algo.size());
    msg.append(payload.data(), payload.size());
    std::string hmac_algo = hmac_sha256(key.data(), key.size(),
                                          reinterpret_cast<const uint8_t*>(msg.data()),
                                          msg.size());
    std::string auth_output;
    auth_output.reserve(SALT_SIZE + HMAC_SIZE + payload.size());
    auth_output.append(reinterpret_cast<const char*>(salt_ptr), SALT_SIZE);
    auth_output.append(hmac_algo);
    auth_output.append(payload.data(), payload.size());

    std::string key_hex = crypto::key_to_hex(key);
    std::string data_hex = bytes_to_hex(auth_output);
    std::string sa(algo);

    std::string w;
    w += "#!/usr/bin/env python3\n";
    w += "import os, sys, tempfile, hmac, hashlib, subprocess\n\n";
    w += "ALGO = " + std::string(1, '"') + sa + "\"\n";
    w += "KEY = bytes.fromhex(\"" + key_hex + "\")\n";
    w += "DATA = bytes.fromhex(\"" + data_hex + "\")\n\n";

    w += "SALT = DATA[:32]\n";
    w += "ST = DATA[32:64]\n";
    w += "PL = DATA[64:]\n";
    w += "EX = hmac.new(KEY, SALT + ALGO.encode() + PL, 'sha256').digest()\n";
    w += "if not hmac.compare_digest(EX, ST):\n";
    w += "    print('Error: invalid key or corrupted data', file=sys.stderr)\n";
    w += "    sys.exit(1)\n\n";

    w += "if ALGO == 'chacha20-poly1305':\n";
    w += "    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n";
    w += "    PT = ChaCha20Poly1305(KEY).decrypt(PL[:12], PL[12:], None)\n\n";

    w += "elif ALGO in ('base64', 'base85', 'base32', 'base36'):\n";
    w += "    NONCE = PL[:8]; CT = PL[8:]\n";
    w += "    IV = b'\\x00' * 8 + NONCE\n";
    w += "    P = subprocess.run(['openssl','enc','-chacha20','-d',\n";
    w += "        '-K', KEY.hex(), '-iv', IV.hex()], input=CT,\n";
    w += "        capture_output=True)\n";
    w += "    if P.returncode != 0:\n";
    w += "        print('Error: decryption failed', file=sys.stderr)\n";
    w += "        sys.exit(1)\n";
    w += "    import base64 as B64\n";
    w += "    if ALGO == 'base64': PT = B64.b64decode(P.stdout)\n";
    w += "    elif ALGO == 'base85': PT = B64.a85decode(P.stdout)\n";
    w += "    elif ALGO == 'base32': PT = B64.b32decode(P.stdout)\n";
    w += "    elif ALGO == 'base36':\n";
    w += "        D36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'\n";
    w += "        PT = b''\n";
    w += "        i = 0\n";
    w += "        while i < len(P.stdout):\n";
    w += "            nd = 0; v = 0\n";
    w += "            while i+nd < len(P.stdout) and nd < 8 and chr(P.stdout[i+nd]) != '=':\n";
    w += "                v = v * 36 + D36.index(chr(P.stdout[i+nd]).upper())\n";
    w += "                nd += 1\n";
    w += "            if nd == 0: i += 1; continue\n";
    w += "            ob = {2:1,4:2,5:3,7:4,8:5}.get(nd, 0)\n";
    w += "            if ob == 0: i += 1; continue\n";
    w += "            PT += v.to_bytes(ob, 'big')\n";
    w += "            i += nd\n";
    w += "            while i < len(P.stdout) and chr(P.stdout[i]) == '=':\n";
    w += "                i += 1\n\n";

    w += "else:\n";
    w += "    NONCE = PL[:8]; CT = PL[8:]\n";
    w += "    IV = b'\\x00' * 8 + NONCE\n";
    w += "    P = subprocess.run(['openssl','enc','-chacha20','-d',\n";
    w += "        '-K', KEY.hex(), '-iv', IV.hex()], input=CT,\n";
    w += "        capture_output=True)\n";
    w += "    if P.returncode != 0:\n";
    w += "        print('Error: decryption failed', file=sys.stderr)\n";
    w += "        sys.exit(1)\n";
    w += "    PT = P.stdout\n\n";

    w += "FD, PATH = tempfile.mkstemp()\n";
    w += "try:\n";
    w += "    os.write(FD, PT)\n";
    w += "finally:\n";
    w += "    os.close(FD)\n";
    w += "os.chmod(PATH, 0o755)\n";
    w += "try:\n";
    w += "    os.execv(PATH, [PATH])\n";
    w += "except OSError:\n";
    w += "    os.execv(sys.executable, [sys.executable, PATH])\n";

    return w;
}

static crypto::Key load_key_from_source(KeySource src,
                                         const std::string& hex_str,
                                         const std::string& file_path) {
    switch (src) {
    case KEY_GEN:
        return crypto::generate_key();
    case KEY_ENV:
        return crypto::key_from_env();
    case KEY_FILE:
        return crypto::key_from_file(file_path);
    case KEY_HEX:
        return crypto::key_from_hex(hex_str);
    default:
        throw std::runtime_error("no key source specified");
    }
}

static bool has_key_source(KeySource src) {
    return src == KEY_GEN || src == KEY_ENV || src == KEY_FILE || src == KEY_HEX;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    auto cmd = std::string_view(argv[1]);
    if (cmd == "-v" || cmd == "--version") {
        print_version();
        return 0;
    }
    if (cmd == "-h" || cmd == "--help") {
        print_help();
        return 0;
    }

    bool is_encode = (cmd == "encode");
    bool is_decode = (cmd == "decode");
    bool is_protect = (cmd == "protect");

    if (!is_encode && !is_decode && !is_protect) {
        std::fprintf(stderr, "Error: unknown command '%s'. Use encode, decode, or protect.\n",
                     std::string(cmd).c_str());
        return 1;
    }

    std::string_view algorithm = "base64";
    std::string_view output_path;
    std::string key_hex_str;
    std::string keyfile_path;
    std::string input_path_str;
    std::string aad_path;
    KeySource key_source = KEY_NONE;
    bool has_input = false;

    for (int i = 2; i < argc; ++i) {
        std::string_view arg(argv[i]);

        if (arg == "-a" || arg == "--algorithm") {
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --algorithm requires a value.\n");
                return 1;
            }
            algorithm = argv[i];
            if (!is_valid_algorithm(algorithm)) {
                std::fprintf(stderr, "Error: unsupported algorithm '%s'.\n", argv[i]);
                std::fprintf(stderr, "Supported: base64, base85, base32, base36, chacha20, chacha20-poly1305\n");
                return 1;
            }
            continue;
        }

        if (arg == "-o" || arg == "--output") {
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --output requires a value.\n");
                return 1;
            }
            output_path = argv[i];
            continue;
        }

        if (arg == "-k" || arg == "--key") {
            if (has_key_source(key_source)) {
                std::fprintf(stderr, "Error: --key, --keygen, --keyenv, and --keyfile are mutually exclusive.\n");
                return 1;
            }
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --key requires a value.\n");
                return 1;
            }
            key_source = KEY_HEX;
            key_hex_str = argv[i];
            continue;
        }

        if (arg == "--keygen") {
            if (has_key_source(key_source)) {
                std::fprintf(stderr, "Error: --keygen, --keyenv, --keyfile, and --key are mutually exclusive.\n");
                return 1;
            }
            key_source = KEY_GEN;
            if (i + 1 < argc && is_valid_algorithm(argv[i + 1])) {
                ++i;
            }
            continue;
        }

        if (arg == "--keyenv") {
            if (has_key_source(key_source)) {
                std::fprintf(stderr, "Error: --keyenv, --keygen, --keyfile, and --key are mutually exclusive.\n");
                return 1;
            }
            key_source = KEY_ENV;
            continue;
        }

        if (arg == "--keyfile") {
            if (has_key_source(key_source)) {
                std::fprintf(stderr, "Error: --keyfile, --keygen, --keyenv, and --key are mutually exclusive.\n");
                return 1;
            }
            key_source = KEY_FILE;
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --keyfile requires a file path.\n");
                return 1;
            }
            keyfile_path = argv[i];
            continue;
        }

        if (arg == "--aad") {
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --aad requires a file path.\n");
                return 1;
            }
            aad_path = argv[i];
            continue;
        }

        if (arg == "--") {
            for (++i; i < argc; ++i) {
                if (!has_input) {
                    input_path_str = argv[i];
                    has_input = true;
                }
            }
            break;
        }

        if (arg[0] == '-') {
            std::fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
            std::fprintf(stderr, "Use -h or --help for usage.\n");
            return 1;
        }

        if (!has_input) {
            input_path_str = argv[i];
            has_input = true;
        }
    }

    if (!has_input) {
        std::fprintf(stderr, "Error: no input file specified.\n");
        return 1;
    }

    if (key_source == KEY_NONE)
        key_source = KEY_GEN;

    std::string input;
    if (!read_file(input_path_str, input)) {
        std::fprintf(stderr, "Error: cannot read file '%s'\n",
                     input_path_str.c_str());
        return 1;
    }

    std::string aad;
    if (!aad_path.empty()) {
        if (!read_file(aad_path, aad)) {
            std::fprintf(stderr, "Error: cannot read AAD file '%s'\n",
                         aad_path.c_str());
            return 1;
        }
    }

    if (is_encode) {
        try {
            crypto::Key enc_key = load_key_from_source(key_source,
                                                        key_hex_str,
                                                        keyfile_path);

            EncodeResult result;
            if (is_encoding(algorithm)) {
                result = do_encoding_encode_with_key(algorithm, input, enc_key);
            } else {
                result = do_encryption_encode_with_key(algorithm, input, aad, enc_key);
            }

            if (!output_path.empty()) {
                if (!write_file(std::string(output_path), result.output)) {
                    std::fprintf(stderr, "Error: cannot write to '%s'\n",
                                 std::string(output_path).c_str());
                    return 1;
                }
            } else {
                if (fwrite(result.output.data(), 1, result.output.size(), stdout) != result.output.size()) {
                    std::fprintf(stderr, "Error: cannot write output\n");
                    return 1;
                }
            }

            if (key_source == KEY_GEN) {
                std::printf("\nKey: %s\n", crypto::key_to_hex(enc_key).c_str());
            }
            return 0;
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    if (is_protect) {
        try {
            crypto::Key enc_key = load_key_from_source(key_source,
                                                        key_hex_str,
                                                        keyfile_path);

            bool is_enc = is_encryption(algorithm);
            std::string encrypted;
            if (is_encoding(algorithm)) {
                EncodeResult r = do_encoding_encode_with_key(algorithm, input, enc_key);
                encrypted = r.output;
            } else {
                EncodeResult r = do_encryption_encode_with_key(algorithm, input, aad, enc_key);
                encrypted = r.output;
            }

            std::string wrapper = generate_protect_wrapper(algorithm, enc_key, encrypted);

            if (!output_path.empty()) {
                if (!write_file(std::string(output_path), wrapper)) {
                    std::fprintf(stderr, "Error: cannot write to '%s'\n",
                                 std::string(output_path).c_str());
                    return 1;
                }
#ifndef _WIN32
                chmod(std::string(output_path).c_str(), S_IRWXU);
#endif
            } else {
                if (fwrite(wrapper.data(), 1, wrapper.size(), stdout) != wrapper.size()) {
                    std::fprintf(stderr, "Error: cannot write output\n");
                    return 1;
                }
            }

            if (key_source == KEY_GEN) {
                std::printf("\nKey: %s\n", crypto::key_to_hex(enc_key).c_str());
            }
            return 0;
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    crypto::Key key{};
    try {
        key = load_key_from_source(key_source, key_hex_str, keyfile_path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }

    if (key_source == KEY_GEN) {
        std::printf("Key: %s\n", crypto::key_to_hex(key).c_str());
        std::fflush(stdout);
    }

    if (is_decode) {
        try {
            std::string output;
            if (is_encoding(algorithm)) {
                output = do_encoding_decode(algorithm, key, input);
            } else {
                output = do_encryption_decode(algorithm, key, input, aad);
            }

            std::string out_path;
            if (!output_path.empty()) {
                out_path = output_path;
            } else {
                out_path = input_path_str + "_out";
                size_t dot = out_path.rfind('.');
                if (dot != std::string::npos) {
                    out_path = out_path.substr(0, dot);
                }
                out_path += "_out.py";
            }

            if (!write_file(out_path, output)) {
                std::fprintf(stderr, "Error: cannot write to '%s'\n",
                             out_path.c_str());
                return 1;
            }

            std::printf("Decoded to: %s\n", out_path.c_str());
            return 0;
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    return 0;
}
