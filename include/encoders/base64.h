#pragma once

#include <string>
#include <string_view>

namespace encoders {

std::string base64_encode(std::string_view data);

std::string base64_decode(std::string_view data);

} // namespace encoders
