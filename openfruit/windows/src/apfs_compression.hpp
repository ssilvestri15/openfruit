#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <cstddef>
#include <functional>
namespace OpenFruit {
// Validate every section/token/back-reference before entering the unchanged decoder.
std::optional<std::string> DecodeApfsLzBitmap(std::string_view, std::size_t expected, std::string& error);
std::optional<std::string> DecodeApfsLzBitmapResourceFork(std::string_view, std::size_t expected, std::string& error,
    const std::function<void()>& control = {});
std::optional<std::string> DecodeApfsLzvn(std::string_view, std::size_t expected, std::string& error);
std::optional<std::string> DecodeApfsLzvnResourceFork(std::string_view, std::size_t expected, std::string& error,
    const std::function<void()>& control = {});
}
