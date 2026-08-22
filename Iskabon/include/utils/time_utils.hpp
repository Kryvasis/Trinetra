#pragma once
#include <cstdint>
#include <string>

namespace iskabon::utils {
std::int64_t epoch_now();           // seconds since Unix epoch
double       monotonic_ms();        // milliseconds, monotonic clock
std::string  iso8601_now();         // "2026-05-23T11:22:00Z"
}
