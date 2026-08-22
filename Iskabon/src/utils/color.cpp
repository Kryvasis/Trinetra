#include "utils/color.hpp"
#include <unistd.h>
#include <string>

namespace iskabon::utils::color {

bool tty_supported() { return isatty(STDOUT_FILENO); }

static std::string wrap(std::string_view code, std::string_view s) {
    if (!tty_supported()) return std::string(s);
    return "\033[" + std::string(code) + "m" + std::string(s) + "\033[0m";
}

std::string green (std::string_view s) { return wrap("32", s); }
std::string red   (std::string_view s) { return wrap("31", s); }
std::string yellow(std::string_view s) { return wrap("33", s); }
std::string cyan  (std::string_view s) { return wrap("36", s); }
std::string bold  (std::string_view s) { return wrap("1",  s); }
std::string reset ()                   { return tty_supported() ? "\033[0m" : ""; }

} // namespace
