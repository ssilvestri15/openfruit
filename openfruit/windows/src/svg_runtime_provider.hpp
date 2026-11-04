#pragma once
#include "json_value.hpp"
#include <filesystem>
#include <string>
namespace OpenFruit {
struct SvgRuntimeProviderResult {
    bool available = false;
    std::filesystem::path executable;
    JsonValue evidence = JsonValue::ObjectValue();
    std::string error;
};
SvgRuntimeProviderResult EnsureNativeSvgProvider(const std::filesystem::path& managed_home);
}
