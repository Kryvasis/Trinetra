#pragma once
#include <string>

namespace iskabon::utils {
/// Pure stdlib SHA-256; no external deps.
std::string sha256(std::string_view input);
}
