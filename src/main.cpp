#include <cstdio>
#include <cstring>
#include "version.h"

static void print_version() {
    std::printf("%s v%s\n", PROJECT_NAME, PROJECT_VERSION);
}

static void print_help() {
    std::printf("Usage: %s [OPTIONS]\n\n", PROJECT_NAME);
    std::printf("Options:\n");
    std::printf("  -v, --version   Show version information\n");
    std::printf("  -h, --help      Show this help message\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
            std::fprintf(stderr, "Use -h or --help for usage.\n");
            return 1;
        }
    }

    return 0;
}
