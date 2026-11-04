#pragma once
#include "json_value.hpp"
#include <string>

namespace OpenFruit {
class Capabilities {
public:
    static JsonValue Query(const std::wstring& repo_root = L"");
};
}
