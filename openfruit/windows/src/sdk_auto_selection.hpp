#pragma once
#include "config.hpp"
#include "xcode_compatibility.hpp"
#include <string>
namespace OpenFruit {
struct SDKAutoResult {
    bool succeeded = false;
    bool acquired = false;
    std::wstring version;
    std::wstring path;
    std::wstring xcode_version;
    std::wstring swift_compiler_version;
    // Required compiler inferred from an installed SDK's original Core Swift
    // interface, rather than from Apple's stable Xcode release table.
    bool compiler_metadata_from_sdk = false;
    std::string message;
};
// Resolve the iPhoneOS Base SDK from target build settings and installed SDK
// metadata. The deployment target is only a compatibility lower bound.
class SDKAutoSelection {
public:
    static SDKAutoResult Resolve(Config& snapshot, const std::wstring& sdk_root,
        const std::wstring& deployment_target, bool allow_acquisition);
    // Pure metadata entry point for deterministic policy tests and callers with
    // an already verified Apple support snapshot.
    static SDKAutoResult ResolveWithSupport(Config& snapshot, const std::wstring& sdk_root,
        const std::wstring& deployment_target, bool allow_acquisition,
        const std::vector<XcodeIosSupport>& support);
};
}
