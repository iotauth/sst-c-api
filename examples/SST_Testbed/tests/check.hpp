#pragma once

#include <cstdlib>
#include <format>
#include <iostream>
#include <source_location>

inline void check(bool condition, std::source_location location =
                                      std::source_location::current()) {
    if (condition) return;
    std::cerr << std::format("{}:{}: check failed in {}\n",
                             location.file_name(), location.line(),
                             location.function_name());
    std::abort();
}
