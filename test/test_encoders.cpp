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
    TEST("base64 encode empty", encoders::base64_encode("") == "");
    TEST("base64 encode f", encoders::base64_encode("f") == "Zg==");
    TEST("base64 encode fo", encoders::base64_encode("fo") == "Zm8=");
    TEST("base64 encode foo", encoders::base64_encode("foo") == "Zm9v");
    TEST("base64 encode foob", encoders::base64_encode("foob") == "Zm9vYg==");
    TEST("base64 encode fooba", encoders::base64_encode("fooba") == "Zm9vYmE=");
    TEST("base64 encode foobar", encoders::base64_encode("foobar") == "Zm9vYmFy");
    TEST("base64 encode null byte",
         encoders::base64_encode(std::string_view("\0\0\0", 3)) == "AAAA");

    TEST("base64 decode empty", encoders::base64_decode("") == "");
    TEST("base64 decode f", encoders::base64_decode("Zg==") == "f");
    TEST("base64 decode fo", encoders::base64_decode("Zm8=") == "fo");
    TEST("base64 decode foo", encoders::base64_decode("Zm9v") == "foo");
    TEST("base64 decode foob", encoders::base64_decode("Zm9vYg==") == "foob");
    TEST("base64 decode fooba", encoders::base64_decode("Zm9vYmE=") == "fooba");
    TEST("base64 decode foobar", encoders::base64_decode("Zm9vYmFy") == "foobar");
    TEST("base64 decode roundtrip",
         encoders::base64_decode(encoders::base64_encode("Hello World!")) == "Hello World!");
    TEST("base64 decode roundtrip binary",
         encoders::base64_decode(encoders::base64_encode(std::string_view("\x00\x01\x02\xFF\xFE\xFD", 6))) == std::string_view("\x00\x01\x02\xFF\xFE\xFD", 6));
}

static void test_base32() {
    TEST("base32 encode empty", encoders::base32_encode("") == "");
    TEST("base32 encode f", encoders::base32_encode("f") == "MY======");
    TEST("base32 encode fo", encoders::base32_encode("fo") == "MZXQ====");
    TEST("base32 encode foo", encoders::base32_encode("foo") == "MZXW6===");
    TEST("base32 encode foob", encoders::base32_encode("foob") == "MZXW6YQ=");
    TEST("base32 encode fooba", encoders::base32_encode("fooba") == "MZXW6YTB");
    TEST("base32 encode foobar", encoders::base32_encode("foobar") == "MZXW6YTBOI======");
    TEST("base32 encode null bytes",
         encoders::base32_encode(std::string_view("\0\0\0\0\0", 5)) == "AAAAAAAA");

    TEST("base32 decode empty", encoders::base32_decode("") == "");
    TEST("base32 decode f", encoders::base32_decode("MY======") == "f");
    TEST("base32 decode fo", encoders::base32_decode("MZXQ====") == "fo");
    TEST("base32 decode foo", encoders::base32_decode("MZXW6===") == "foo");
    TEST("base32 decode foob", encoders::base32_decode("MZXW6YQ=") == "foob");
    TEST("base32 decode fooba", encoders::base32_decode("MZXW6YTB") == "fooba");
    TEST("base32 decode foobar", encoders::base32_decode("MZXW6YTBOI======") == "foobar");
    TEST("base32 decode roundtrip",
         encoders::base32_decode(encoders::base32_encode("Hello World!")) == "Hello World!");
    TEST("base32 decode roundtrip nulls",
         encoders::base32_decode(encoders::base32_encode(std::string_view("\x00\x01\x02\x03\x04", 5))) == std::string_view("\x00\x01\x02\x03\x04", 5));
}

static void test_base36() {
    TEST("base36 encode empty", encoders::base36_encode("") == "");
    TEST("base36 encode zero byte",
         encoders::base36_encode(std::string_view("\0", 1)) == "0");
    TEST("base36 encode two zeros",
         encoders::base36_encode(std::string_view("\0\0", 2)) == "00");
    TEST("base36 encode 0xFF",
         encoders::base36_encode(std::string_view("\xFF", 1)) == "73");
    TEST("base36 encode 0x00FF",
         encoders::base36_encode(std::string_view("\x00\xFF", 2)) == "073");
    TEST("base36 encode hello",
         encoders::base36_encode("hello") == "5PZCSZU7");
    TEST("base36 encode 123",
         encoders::base36_encode("123") == "1X3QR");

    TEST("base36 decode empty", encoders::base36_decode("") == "");
    TEST("base36 decode 0", encoders::base36_decode("0") == std::string_view("\0", 1));
    TEST("base36 decode 00", encoders::base36_decode("00") == std::string_view("\0\0", 2));
    TEST("base36 decode 73", encoders::base36_decode("73") == std::string_view("\xFF", 1));
    TEST("base36 decode 073", encoders::base36_decode("073") == std::string_view("\x00\xFF", 2));
    TEST("base36 decode 5PZCSZU7", encoders::base36_decode("5PZCSZU7") == "hello");
    TEST("base36 decode 1X3QR", encoders::base36_decode("1X3QR") == "123");
    TEST("base36 decode roundtrip",
         encoders::base36_decode(encoders::base36_encode("Hello World!")) == "Hello World!");
}

static void test_base85() {
    TEST("base85 encode empty", encoders::base85_encode("") == "");
    TEST("base85 encode Man space",
         encoders::base85_encode("Man ") == "9jqo^");
    TEST("base85 encode f", encoders::base85_encode("f") == "Ac");
    TEST("base85 encode fo", encoders::base85_encode("fo") == "Ao@");
    TEST("base85 encode foo", encoders::base85_encode("foo") == "AoDS");
    TEST("base85 encode foob", encoders::base85_encode("foob") == "AoDTs");
    TEST("base85 encode four nulls (z shortcut)",
         encoders::base85_encode(std::string_view("\0\0\0\0", 4)) == "z");
    TEST("base85 encode eight nulls (zz)",
         encoders::base85_encode(std::string_view("\0\0\0\0\0\0\0\0", 8)) == "zz");
    TEST("base85 encode six nulls",
         encoders::base85_encode(std::string_view("\0\0\0\0\0\0", 6)) == "z!!!");

    TEST("base85 decode empty", encoders::base85_decode("") == "");
    TEST("base85 decode Man space",
         encoders::base85_decode("9jqo^") == "Man ");
    TEST("base85 decode f", encoders::base85_decode("Ac") == "f");
    TEST("base85 decode fo", encoders::base85_decode("Ao@") == "fo");
    TEST("base85 decode foo", encoders::base85_decode("AoDS") == "foo");
    TEST("base85 decode foob", encoders::base85_decode("AoDTs") == "foob");
    TEST("base85 decode z", encoders::base85_decode("z") == std::string_view("\0\0\0\0", 4));
    TEST("base85 decode zz", encoders::base85_decode("zz") == std::string_view("\0\0\0\0\0\0\0\0", 8));
    TEST("base85 decode z!!!", encoders::base85_decode("z!!!") == std::string_view("\0\0\0\0\0\0", 6));
    TEST("base85 decode roundtrip",
         encoders::base85_decode(encoders::base85_encode("Hello World!")) == "Hello World!");
    TEST("base85 decode roundtrip binary",
         encoders::base85_decode(encoders::base85_encode(std::string_view("\x00\x01\x02\xFF\xFE\xFD", 6))) == std::string_view("\x00\x01\x02\xFF\xFE\xFD", 6));
}

int main() {
    test_base64();
    test_base32();
    test_base36();
    test_base85();

    std::printf("%d tests, %d failures\n", tests, failures);
    return failures > 0 ? 1 : 0;
}
