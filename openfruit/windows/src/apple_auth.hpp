#pragma once

#include "config.hpp"
#include <string>

namespace OpenFruit {

class AppleAuth {
public:
    static bool Login(Secrets& sec, const std::string& apple_id, const std::string& password_or_token, const std::wstring& secrets_path = L"");
};

} // namespace OpenFruit
