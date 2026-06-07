#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <fstream>
#include <vector>
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
#endif

static void print_version() {
    std::printf("%s v%s\n", PROJECT_NAME, PROJECT_VERSION);
}

static void print_help() {
    std::printf("Usage: %s [OPTIONS] <input>\n\n", PROJECT_NAME);
    std::printf("Options:\n");
    std::printf("  -v, --version            Show version information\n");
    std::printf("  -h, --help               Show this help message\n");
    std::printf("  -a, --algorithm <name>   Algorithm (default: base64)\n");
    std::printf("  -f, --file               Treat input as file path\n");
    std::printf("  -o, --output <file>      Write output to file (implies --file)\n");
    std::printf("  -d, --decrypt            Decrypt instead of encrypt\n");
    std::printf("\nKey management (mutually exclusive):\n");
    std::printf("  --keygen [algo]          Generate a new random key (default)\n");
    std::printf("  --keyenv                 Read key from KEYENV env variable\n");
    std::printf("  --keyfile [path]         Read key from file (raw or hex)\n");
    std::printf("  --aad <file>             Additional Authenticated Data file (chacha20-poly1305 only)\n");
    std::printf("\nSupported algorithms:\n");
    std::printf("  Encoding:   base64, base85, base32, base36\n");
    std::printf("  Encryption: chacha20, chacha20-poly1305\n");
    std::printf("\nExamples:\n");
    std::printf("  %s                                       Generate key\n", PROJECT_NAME);
    std::printf("  %s -a chacha20 -o key.txt               Generate key, save to file\n", PROJECT_NAME);
    std::printf("  %s -a chacha20 --keyenv -f plain -o enc Encrypt file\n", PROJECT_NAME);
    std::printf("  %s --keyfile key.bin -a chacha20 -d -f enc -o out  Decrypt\n", PROJECT_NAME);
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

#ifndef _WIN32
static mode_t get_file_mode(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
        return st.st_mode;
    return 0;
}

static void set_file_mode(const std::string& path, mode_t mode) {
    if (mode)
        chmod(path.c_str(), mode);
}

static const mode_t EXEC_BITS = S_IXUSR | S_IXGRP | S_IXOTH;
#else
static int get_file_mode(const std::string&) { return 0; }
static void set_file_mode(const std::string&, int) {}
static const int EXEC_BITS = 0;
#endif

// Self-executing wrapper for encoding algorithms
static std::string make_exec_wrapper(const std::string& data) {
    std::string b64 = encoders::base64_encode(data);
    std::string w;
    w += "#!/usr/bin/env python3\n";
    w += "import base64, os, subprocess, sys, tempfile\n";
    w += "d = \"\"\""; w += b64; w += "\"\"\"\n";
    w += "f, p = tempfile.mkstemp()\n";
    w += "raw = base64.b64decode(d)\n";
    w += "os.write(f, raw)\n";
    w += "os.close(f)\n";
    w += "os.chmod(p, 0o755)\n";
    w += "try:\n";
    w += "    rc = subprocess.call([p])\n";
    w += "except OSError:\n";
    w += "    rc = subprocess.call([sys.executable, p])\n";
    w += "os.unlink(p)\n";
    w += "sys.exit(rc)\n";
    return w;
}

// Self-executing wrapper for chacha20-poly1305 encryption
static std::string make_chacha20_poly1305_wrapper(const std::string& encrypted,
                                                    std::string_view key_source,
                                                    const std::string& key_data) {
    std::string b64 = encoders::base64_encode(encrypted);
    std::string w;
    w += "#!/usr/bin/env python3\n";
    w += "import base64, os, subprocess, sys, tempfile\n";
    w += "data_b64 = \"\"\""; w += b64; w += "\"\"\"\n";
    w += "raw = base64.b64decode(data_b64)\n";
    w += "nonce_hex = raw[:12].hex()\n";
    w += "ct_and_tag = raw[12:]\n";

    if (key_source == "gen") {
        w += "key_hex = \""; w += key_data; w += "\"\n";
    } else if (key_source == "env") {
        w += "key_hex = os.environ.get(\"KEYENV\", \"\")\n";
        w += "if not key_hex:\n";
        w += "    sys.exit(\"Error: KEYENV environment variable not set\")\n";
    } else if (key_source == "file") {
        w += "try:\n";
        w += "    with open(\""; w += key_data; w += "\") as f:\n";
        w += "        key_hex = f.read().strip()\n";
        w += "except Exception as e:\n";
        w += "    sys.exit(f\"Error: cannot read key file: {e}\")\n";
    }

    w += "proc = subprocess.run(\n";
    w += "    [\"openssl\", \"enc\", \"-chacha20-poly1305\", \"-d\",\n";
    w += "     \"-K\", key_hex, \"-iv\", nonce_hex],\n";
    w += "    input=ct_and_tag, capture_output=True)\n";
    w += "if proc.returncode != 0:\n";
    w += "    sys.exit(\"Error: decryption failed\")\n";
    w += "f, p = tempfile.mkstemp()\n";
    w += "os.write(f, proc.stdout)\n";
    w += "os.close(f)\n";
    w += "os.chmod(p, 0o755)\n";
    w += "try:\n";
    w += "    rc = subprocess.call([p])\n";
    w += "except OSError:\n";
    w += "    rc = subprocess.call([sys.executable, p])\n";
    w += "os.unlink(p)\n";
    w += "sys.exit(rc)\n";

    return w;
}

// Self-executing wrapper for chacha20 encryption
static std::string make_chacha20_wrapper(const std::string& encrypted,
                                          std::string_view key_source,
                                          const std::string& key_data) {
    std::string b64 = encoders::base64_encode(encrypted);
    std::string w;
    w += "#!/usr/bin/env python3\n";
    w += "import base64, os, subprocess, sys, tempfile\n";
    w += "data_b64 = \"\"\""; w += b64; w += "\"\"\"\n";
    w += "raw = base64.b64decode(data_b64)\n";
    w += "nonce_hex = raw[:8].hex()\n";
    w += "ct = raw[8:]\n";

    if (key_source == "gen") {
        w += "key_hex = \""; w += key_data; w += "\"\n";
    } else if (key_source == "env") {
        w += "key_hex = os.environ.get(\"KEYENV\", \"\")\n";
        w += "if not key_hex:\n";
        w += "    sys.exit(\"Error: KEYENV environment variable not set\")\n";
    } else if (key_source == "file") {
        w += "try:\n";
        w += "    with open(\""; w += key_data; w += "\") as f:\n";
        w += "        key_hex = f.read().strip()\n";
        w += "except Exception as e:\n";
        w += "    sys.exit(f\"Error: cannot read key file: {e}\")\n";
    }

    w += "iv_hex = \"0000000000000000\" + nonce_hex\n";
    w += "proc = subprocess.run(\n";
    w += "    [\"openssl\", \"enc\", \"-chacha20\", \"-d\",\n";
    w += "     \"-K\", key_hex, \"-iv\", iv_hex],\n";
    w += "    input=ct, capture_output=True)\n";
    w += "if proc.returncode != 0:\n";
    w += "    sys.exit(\"Error: decryption failed\")\n";
    w += "f, p = tempfile.mkstemp()\n";
    w += "os.write(f, proc.stdout)\n";
    w += "os.close(f)\n";
    w += "os.chmod(p, 0o755)\n";
    w += "try:\n";
    w += "    rc = subprocess.call([p])\n";
    w += "except OSError:\n";
    w += "    rc = subprocess.call([sys.executable, p])\n";
    w += "os.unlink(p)\n";
    w += "sys.exit(rc)\n";

    return w;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        crypto::Key key = crypto::generate_key();
        std::printf("%s\n", crypto::key_to_hex(key).c_str());
        return 0;
    }

    std::string_view algorithm = "base64";
    std::string_view output_path;
    bool file_mode = false;
    bool decrypt = false;
    enum { KEYMODE_NONE, KEYMODE_GEN, KEYMODE_ENV, KEYMODE_FILE } key_mode = KEYMODE_NONE;
    std::string keyfile_path;
    std::string aad_path;
    std::vector<std::string_view> positional;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);

        if (arg == "-v" || arg == "--version") {
            print_version();
            return 0;
        }

        if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        }

        if (arg == "-d" || arg == "--decrypt") {
            decrypt = true;
            continue;
        }

        if (arg == "-a" || arg == "--algorithm") {
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --algorithm requires a value.\n");
                return 1;
            }
            algorithm = argv[i];
            if (!is_valid_algorithm(algorithm)) {
                std::fprintf(stderr, "Error: unsupported algorithm '%s'.\n", argv[i]);
                std::fprintf(stderr, "Supported: base64, base85, base32, base36, chacha20\n");
                return 1;
            }
            continue;
        }

        if (arg == "-f" || arg == "--file") {
            file_mode = true;
            continue;
        }

        if (arg == "-o" || arg == "--output") {
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --output requires a value.\n");
                return 1;
            }
            output_path = argv[i];
            file_mode = true;
            continue;
        }

        if (arg == "--keygen") {
            if (key_mode != KEYMODE_NONE) {
                std::fprintf(stderr, "Error: --keygen, --keyenv, and --keyfile are mutually exclusive.\n");
                return 1;
            }
            key_mode = KEYMODE_GEN;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                ++i;
            }
            continue;
        }

        if (arg == "--keyenv") {
            if (key_mode != KEYMODE_NONE) {
                std::fprintf(stderr, "Error: --keygen, --keyenv, and --keyfile are mutually exclusive.\n");
                return 1;
            }
            key_mode = KEYMODE_ENV;
            continue;
        }

        if (arg == "--keyfile") {
            if (key_mode != KEYMODE_NONE) {
                std::fprintf(stderr, "Error: --keygen, --keyenv, and --keyfile are mutually exclusive.\n");
                return 1;
            }
            key_mode = KEYMODE_FILE;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                keyfile_path = argv[++i];
            }
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
            for (++i; i < argc; ++i)
                positional.push_back(argv[i]);
            break;
        }

        if (arg[0] == '-') {
            std::fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
            std::fprintf(stderr, "Use -h or --help for usage.\n");
            return 1;
        }

        positional.push_back(arg);
    }

    // Default to --keygen if no key mode specified
    if (key_mode == KEYMODE_NONE) {
        key_mode = KEYMODE_GEN;
    }

    // If KEYMODE_GEN with encoding algorithm or no input: just print key
    if (key_mode == KEYMODE_GEN && (!is_encryption(algorithm) ||
        (!file_mode && positional.empty()))) {
        crypto::Key key = crypto::generate_key();
        std::string hex = crypto::key_to_hex(key);
        std::printf("%s\n", hex.c_str());

        if (!output_path.empty()) {
            if (!write_file(std::string(output_path), hex + "\n")) {
                std::fprintf(stderr, "Error: cannot write to '%s'\n",
                             std::string(output_path).c_str());
                return 1;
            }
        }
        return 0;
    }

    // Load encryption key
    crypto::Key enc_key{};
    std::string key_hex_for_wrapper;

    if (is_encryption(algorithm)) {
        try {
            if (key_mode == KEYMODE_GEN) {
                enc_key = crypto::generate_key();
            } else if (key_mode == KEYMODE_ENV) {
                enc_key = crypto::key_from_env();
            } else if (key_mode == KEYMODE_FILE) {
                std::string kp = keyfile_path.empty() ? ".key" : keyfile_path;
                enc_key = crypto::key_from_file(kp);
            }
            key_hex_for_wrapper = crypto::key_to_hex(enc_key);

            if (key_mode == KEYMODE_GEN) {
                std::printf("%s\n", key_hex_for_wrapper.c_str());
            }
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    // Need input
    if (positional.empty() && !file_mode) {
        std::fprintf(stderr, "Error: no input provided.\n");
        return 1;
    }

    std::string input;

    if (!positional.empty()) {
        const std::string input_path(positional[0]);
        if (file_mode) {
            if (!read_file(input_path, input)) {
                std::fprintf(stderr, "Error: cannot read file '%s'\n",
                             input_path.c_str());
                return 1;
            }
        } else {
            input = input_path;
        }
    } else if (file_mode) {
        std::fprintf(stderr, "Error: --file requires an input path.\n");
        return 1;
    }

    // Process
    std::string output;

    if (is_encoding(algorithm)) {
        output = encode_str(algorithm, input);
        if (!output_path.empty()) {
            std::string wrapper = make_exec_wrapper(input);
            if (!write_file(std::string(output_path), wrapper)) {
                std::fprintf(stderr, "Error: cannot write to '%s'\n",
                             std::string(output_path).c_str());
                return 1;
            }
            set_file_mode(std::string(output_path),
                          get_file_mode(std::string(output_path)) | EXEC_BITS);
        } else {
            std::printf("%s\n", output.c_str());
        }
    } else if (is_encryption(algorithm)) {
        try {
            if (algorithm == "chacha20-poly1305") {
                std::string aad;
                if (!aad_path.empty()) {
                    if (!read_file(aad_path, aad)) {
                        std::fprintf(stderr, "Error: cannot read AAD file '%s'\n",
                                     aad_path.c_str());
                        return 1;
                    }
                }
                if (decrypt) {
                    output = crypto::chacha20_poly1305_decrypt(input, enc_key, aad);
                } else {
                    output = crypto::chacha20_poly1305_encrypt(input, enc_key, aad);
                }
            } else {
                if (decrypt) {
                    output = crypto::chacha20_decrypt(input, enc_key);
                } else {
                    output = crypto::chacha20_encrypt(input, enc_key);
                }
            }
        } catch (const std::exception& e) {
            std::fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }

        if (!output_path.empty()) {
            if (algorithm == "chacha20-poly1305") {
                if (!write_file(std::string(output_path), output)) {
                    std::fprintf(stderr, "Error: cannot write to '%s'\n",
                                 std::string(output_path).c_str());
                    return 1;
                }
            } else {
                std::string wrapper;
                if (key_mode == KEYMODE_ENV) {
                    wrapper = make_chacha20_wrapper(output, "env", "");
                } else if (key_mode == KEYMODE_FILE) {
                    std::string kp = keyfile_path.empty() ? ".key" : keyfile_path;
                    wrapper = make_chacha20_wrapper(output, "file", kp);
                } else {
                    wrapper = make_chacha20_wrapper(output, "gen", key_hex_for_wrapper);
                }

                if (!write_file(std::string(output_path), wrapper)) {
                    std::fprintf(stderr, "Error: cannot write to '%s'\n",
                                 std::string(output_path).c_str());
                    return 1;
                }
                set_file_mode(std::string(output_path),
                              get_file_mode(std::string(output_path)) | EXEC_BITS);
            }
        } else {
            std::printf("%s\n", output.c_str());
        }
    }

    return 0;
}
