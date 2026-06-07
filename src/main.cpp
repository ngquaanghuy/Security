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

static void print_version() {
    std::printf("%s v%s\n", PROJECT_NAME, PROJECT_VERSION);
}

static void print_help() {
    std::printf("Usage: %s <command> [OPTIONS] <input>\n\n", PROJECT_NAME);
    std::printf("Commands:\n");
    std::printf("  encode                    Encode/encrypt a file and generate key\n");
    std::printf("  decode                    Decode/decrypt a file using provided key\n");
    std::printf("  protect                   Decrypt and execute in-memory\n");
    std::printf("\nOptions:\n");
    std::printf("  -v, --version            Show version\n");
    std::printf("  -h, --help               Show this help\n");
    std::printf("  -a, --algorithm <name>   Algorithm (default: base64)\n");
    std::printf("  -o, --output <file>      Output file\n");
    std::printf("  -k, --key <key>          Key (hex) for decode/protect\n");
    std::printf("\nSupported algorithms:\n");
    std::printf("  base64, base85, base32, base36, chacha20, chacha20-poly1305\n");
    std::printf("\nExamples:\n");
    std::printf("  %s encode -a chacha20 input.txt -o output.enc\n", PROJECT_NAME);
    std::printf("  %s decode -a chacha20 -k <key> output.enc -o output.txt\n", PROJECT_NAME);
    std::printf("  %s protect -a chacha20 -k <key> output.enc\n", PROJECT_NAME);
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

static std::string do_encoding_decode(std::string_view algo,
                                       const crypto::Key& key,
                                       std::string_view data) {
    if (data.size() < HEADER_SIZE)
        throw std::runtime_error("input too short");

    auto salt_ptr = reinterpret_cast<const uint8_t*>(data.data());
    std::string_view stored_hmac(data.data() + SALT_SIZE, HMAC_SIZE);
    std::string_view payload = data.substr(HEADER_SIZE);

    std::string computed = compute_hmac(key, salt_ptr, payload);
    if (computed != stored_hmac)
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
    if (computed != stored_hmac)
        throw std::runtime_error("invalid key or corrupted data");

    if (algo == "chacha20-poly1305") {
        return crypto::chacha20_poly1305_decrypt(payload, key, aad);
    }
    return crypto::chacha20_decrypt(payload, key);
}

static int do_protect(const crypto::Key& key, std::string_view algo,
                       std::string_view data, std::string_view aad) {
    std::string decoded;
    if (is_encoding(algo)) {
        decoded = do_encoding_decode(algo, key, data);
    } else {
        decoded = do_encryption_decode(algo, key, data, aad);
    }

#ifdef _WIN32
    char tmp_path[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmp_path) == 0) {
        std::fprintf(stderr, "Error: cannot get temp path\n");
        return 1;
    }
    char fname[MAX_PATH];
    if (GetTempFileNameA(tmp_path, "sec", 0, fname) == 0) {
        std::fprintf(stderr, "Error: cannot create temp file\n");
        return 1;
    }
    std::string path(fname);
#else
    char tmp_template[] = "/tmp/security_XXXXXX";
    int fd = mkstemp(tmp_template);
    if (fd < 0) {
        std::fprintf(stderr, "Error: cannot create temp file\n");
        return 1;
    }
    std::string path(tmp_template);
    if (write(fd, decoded.data(), decoded.size()) < 0) {
        close(fd);
        unlink(path.c_str());
        std::fprintf(stderr, "Error: cannot write temp file\n");
        return 1;
    }
    close(fd);
    chmod(path.c_str(), S_IRWXU);
#endif

    int rc = 0;
#ifdef _WIN32
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::string cmd = "\"" + path + "\"";
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        std::fprintf(stderr, "Error: cannot execute process\n");
        _unlink(path.c_str());
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    rc = static_cast<int>(exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    _unlink(path.c_str());
#else
    pid_t pid = fork();
    if (pid < 0) {
        std::fprintf(stderr, "Error: fork failed\n");
        unlink(path.c_str());
        return 1;
    }
    if (pid == 0) {
        execl(path.c_str(), path.c_str(), nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    unlink(path.c_str());
    rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
#endif

    return rc;
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
    std::string_view key_str;
    std::string input_path_str;
    std::string aad_path;
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
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --key requires a value.\n");
                return 1;
            }
            key_str = argv[i];
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

    if (is_decode && key_str.empty()) {
        std::fprintf(stderr, "Error: decode requires --key.\n");
        return 1;
    }

    if (is_protect && key_str.empty()) {
        std::fprintf(stderr, "Error: protect requires --key.\n");
        return 1;
    }

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
            EncodeResult result;
            if (is_encoding(algorithm)) {
                result = do_encoding_encode(algorithm, input);
            } else {
                result = do_encryption_encode(algorithm, input, aad);
            }

            std::string key_hex = crypto::key_to_hex(result.key);

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

            std::printf("\nKey: %s\n", key_hex.c_str());
            return 0;
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    crypto::Key key{};
    if (!key_str.empty()) {
        if (!is_hex_string(key_str)) {
            std::fprintf(stderr, "Error: key must be a hex string.\n");
            return 1;
        }
        try {
            key = crypto::key_from_hex(key_str);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: invalid key: %s\n", e.what());
            return 1;
        }
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

    if (is_protect) {
        try {
            int rc = do_protect(key, algorithm, input, aad);
            return rc;
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    return 0;
}
