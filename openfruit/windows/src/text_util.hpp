#pragma once

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace OpenFruit {

// Build metadata (settings, paths, plist keys, tool output) is ASCII-keyed;
// these helpers never depend on the process locale.

inline std::string ToLowerAscii(std::string value) {
    for (char& c : value)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return value;
}

// Strips leading and trailing space, \t, \n, \v, \f and \r.
inline std::string TrimWhitespace(std::string value) {
    constexpr const char* kWhitespace = " \t\n\v\f\r";
    const auto first = value.find_first_not_of(kWhitespace);
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of(kWhitespace) - first + 1);
}

// The file's bytes, or an empty string when it cannot be opened.
inline std::string ReadFileText(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

} // namespace OpenFruit
