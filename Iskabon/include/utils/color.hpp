#pragma once
#include <string_view>

namespace iskabon::utils::color {
std::string green(std::string_view s);
std::string red(std::string_view s);
std::string yellow(std::string_view s);
std::string cyan(std::string_view s);
std::string bold(std::string_view s);
std::string reset();
bool        tty_supported();   // true when stdout is a real terminal
}
