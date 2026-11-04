#pragma once

#include <filesystem>
#include <string>
#include <string_view>

// A path from UTF-8 text. std::filesystem::u8path is deprecated in C++20;
// constructing the path from char8_t text is its standard replacement.
inline std::filesystem::path Utf8Path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}
