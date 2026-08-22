#pragma once
#include <string>
#include <vector>

namespace iskabon::resolver {

/// Expands a hostname, IP, or CIDR into a list of host strings.
/// Throws std::runtime_error on unresolvable input.
std::vector<std::string> expand(const std::string& target);

/// True if s looks like a CIDR block (contains '/').
bool is_cidr(const std::string& s);

/// True if s is a valid IPv4 or IPv6 literal.
bool is_ip_literal(const std::string& s);

}  // namespace iskabon::resolver
