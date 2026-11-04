#pragma once
#include <string>
#include <vector>
namespace OpenFruit {
struct XcodeIosSupport {
    std::wstring xcode_version;
    std::wstring sdk_version;
    std::wstring minimum_deployment;
    std::wstring maximum_deployment;
    std::wstring swift_compiler_version;
};
class XcodeCompatibility {
public:
    static std::vector<XcodeIosSupport> ParseAppleHtml(const std::string& html);
    static std::vector<XcodeIosSupport> FetchAppleTable();
    static bool Supports(const XcodeIosSupport& release, const std::wstring& deployment);
    static bool LessVersion(const std::wstring& left, const std::wstring& right);
};
}
