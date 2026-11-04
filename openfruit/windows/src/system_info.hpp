#pragma once

#include <string>
#include <filesystem>

namespace OpenFruit {

class SystemInfo {
public:
    static unsigned int GetOptimalThreadCount();
    static std::wstring GetExecutableDirectory();
    static std::wstring DiscoverRepoRoot();
    static std::wstring GetSystem32Directory();
    static std::wstring GetWslExecutable();
    static std::wstring ExpandEnvironmentStringsCustom(const std::wstring& input);
};

} // namespace OpenFruit
