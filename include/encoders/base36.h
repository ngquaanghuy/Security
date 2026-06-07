#pragma once

#include <string>
#include <string_view>

namespace encoders {

std::string base36_encode(std::string_view data);

std::string base36_decode(std::string_view data);

} // namespace encoders
