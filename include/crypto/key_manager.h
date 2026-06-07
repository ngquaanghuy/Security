#pragma once

#include "crypto/chacha20.h"
#include <string>
#include <string_view>

namespace crypto {

Key generate_key();

Key key_from_env();

Key key_from_file(const std::string& path);

std::string key_to_hex(const Key& key);

Key key_from_hex(std::string_view hex);

} // namespace crypto
