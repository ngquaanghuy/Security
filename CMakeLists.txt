cmake_minimum_required(VERSION 3.10)
project(Security LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/encoders/base64.cpp
    src/encoders/base85.cpp
    src/encoders/base32.cpp
    src/encoders/base36.cpp
    src/crypto/chacha20.cpp
    src/crypto/key_manager.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)

enable_testing()

add_executable(test_encoders
    test/test_encoders.cpp
    src/encoders/base64.cpp
    src/encoders/base85.cpp
    src/encoders/base32.cpp
    src/encoders/base36.cpp
)

target_include_directories(test_encoders PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

add_test(NAME Encoders COMMAND test_encoders)

add_executable(test_chacha20
    test/test_chacha20.cpp
    src/crypto/chacha20.cpp
    src/crypto/key_manager.cpp
)

target_include_directories(test_chacha20 PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_chacha20 PRIVATE OpenSSL::Crypto)

add_test(NAME ChaCha20 COMMAND test_chacha20)
