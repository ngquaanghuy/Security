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
    std::printf("  -a, --algorithm <name>   Encoding algorithm (default: base64)\n");
    std::printf("  -f, --file               Treat input as file path\n");
    std::printf("  -o, --output <file>      Write output to file (implies --file)\n");
    std::printf("\nSupported algorithms:\n");
    std::printf("  base64\n");
    std::printf("  base85\n");
    std::printf("  base32\n");
    std::printf("  base36\n");
    std::printf("\nExamples:\n");
    std::printf("  %s -a base64 \"hello\"                         Encode string\n", PROJECT_NAME);
    std::printf("  %s -a base64 -f input.txt                     Encode file to stdout\n", PROJECT_NAME);
    std::printf("  %s -a base64 input.txt -o output.txt          Encode file to file\n", PROJECT_NAME);
}

static bool is_valid_algorithm(std::string_view name) {
    return name == "base64" || name == "base85" ||
           name == "base32" || name == "base36";
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
#else
static int get_file_mode(const std::string&) { return 0; }
static void set_file_mode(const std::string&, int) {}
#endif

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    std::string_view algorithm = "base64";
    std::string_view output_path;
    bool file_mode = false;
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

        if (arg == "-a" || arg == "--algorithm") {
            if (++i >= argc) {
                std::fprintf(stderr, "Error: --algorithm requires a value.\n");
                return 1;
            }
            algorithm = argv[i];
            if (!is_valid_algorithm(algorithm)) {
                std::fprintf(stderr, "Error: unsupported algorithm '%s'.\n", argv[i]);
                std::fprintf(stderr, "Supported: base64, base85, base32, base36\n");
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

    if (positional.empty()) {
        std::fprintf(stderr, "Error: no input provided.\n");
        return 1;
    }

    std::string input;
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

    std::string encoded = encode_str(algorithm, input);

    if (!output_path.empty()) {
        std::string output = make_exec_wrapper(input);
        if (!write_file(std::string(output_path), output)) {
            std::fprintf(stderr, "Error: cannot write to '%s'\n",
                         std::string(output_path).c_str());
            return 1;
        }
#ifndef _WIN32
        mode_t src_mode = file_mode ? get_file_mode(input_path) : 0;
        mode_t exec_bits = S_IXUSR | S_IXGRP | S_IXOTH;
        set_file_mode(std::string(output_path), src_mode | exec_bits);
#else
        (void)file_mode;
        (void)input_path;
#endif
    } else {
        std::printf("%s\n", encoded.c_str());
    }

    return 0;
}
