#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include "encoders/base64.h"
#include "encoders/base85.h"
#include "encoders/base32.h"
#include "encoders/base36.h"

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

static void test_base64() {
    TEST("base64 empty", encoders::base64_encode("") == "");
    TEST("base64 f", encoders::base64_encode("f") == "Zg==");
    TEST("base64 fo", encoders::base64_encode("fo") == "Zm8=");
    TEST("base64 foo", encoders::base64_encode("foo") == "Zm9v");
    TEST("base64 foob", encoders::base64_encode("foob") == "Zm9vYg==");
    TEST("base64 fooba", encoders::base64_encode("fooba") == "Zm9vYmE=");
    TEST("base64 foobar", encoders::base64_encode("foobar") == "Zm9vYmFy");
    TEST("base64 null byte",
         encoders::base64_encode(std::string_view("\0\0\0", 3)) == "AAAA");
}

static void test_base32() {
    TEST("base32 empty", encoders::base32_encode("") == "");
    TEST("base32 f", encoders::base32_encode("f") == "MY======");
    TEST("base32 fo", encoders::base32_encode("fo") == "MZXQ====");
    TEST("base32 foo", encoders::base32_encode("foo") == "MZXW6===");
    TEST("base32 foob", encoders::base32_encode("foob") == "MZXW6YQ=");
    TEST("base32 fooba", encoders::base32_encode("fooba") == "MZXW6YTB");
    TEST("base32 foobar", encoders::base32_encode("foobar") == "MZXW6YTBOI======");
    TEST("base32 null bytes",
         encoders::base32_encode(std::string_view("\0\0\0\0\0", 5)) == "AAAAAAAA");
}

static void test_base36() {
    TEST("base36 empty", encoders::base36_encode("") == "");
    TEST("base36 zero byte",
         encoders::base36_encode(std::string_view("\0", 1)) == "0");
    TEST("base36 two zero bytes",
         encoders::base36_encode(std::string_view("\0\0", 2)) == "00");
    TEST("base36 0xFF",
         encoders::base36_encode(std::string_view("\xFF", 1)) == "73");
    TEST("base36 0x00FF",
         encoders::base36_encode(std::string_view("\x00\xFF", 2)) == "073");
    TEST("base36 hello",
         encoders::base36_encode("hello") == "5PZCSZU7");
    TEST("base36 123",
         encoders::base36_encode("123") == "1X3QR");
}

static void test_base85() {
    TEST("base85 empty", encoders::base85_encode("") == "");
    TEST("base85 Man space",
         encoders::base85_encode("Man ") == "9jqo^");
    TEST("base85 f", encoders::base85_encode("f") == "Ac");
    TEST("base85 fo", encoders::base85_encode("fo") == "Ao@");
    TEST("base85 foo", encoders::base85_encode("foo") == "AoDS");
    TEST("base85 foob", encoders::base85_encode("foob") == "AoDTs");
    TEST("base85 four nulls (z shortcut)",
         encoders::base85_encode(std::string_view("\0\0\0\0", 4)) == "z");
    TEST("base85 eight nulls (zz)",
         encoders::base85_encode(std::string_view("\0\0\0\0\0\0\0\0", 8)) == "zz");
    TEST("base85 six nulls",
         encoders::base85_encode(std::string_view("\0\0\0\0\0\0", 6)) == "z!!!");
}

int main() {
    test_base64();
    test_base32();
    test_base36();
    test_base85();

    std::printf("%d tests, %d failures\n", tests, failures);
    return failures > 0 ? 1 : 0;
}
