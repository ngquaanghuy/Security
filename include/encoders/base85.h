#pragma once

#include <string>
#include <string_view>

namespace encoders {

std::string base85_encode(std::string_view data);

} // namespace encoders
