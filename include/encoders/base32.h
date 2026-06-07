#pragma once

#include <string>
#include <string_view>

namespace encoders {

std::string base32_encode(std::string_view data);

std::string base32_decode(std::string_view data);

} // namespace encoders
