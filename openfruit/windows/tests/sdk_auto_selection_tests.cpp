#include "sdk_auto_selection.hpp"
#include "operation_events.hpp"
#include <algorithm>
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
int main() {
    if (GetEnvironmentVariableW(L"OPENFRUIT_TEST_LIVE_APPLE_SUPPORT", nullptr, 0)) {
        const auto live = OpenFruit::XcodeCompatibility::FetchAppleTable();
        const auto found = std::find_if(live.begin(), live.end(), [](const auto& release) {
            return release.xcode_version == L"26.6" && release.sdk_version == L"26.5" &&
                release.swift_compiler_version == L"6.3" &&
                OpenFruit::XcodeCompatibility::Supports(release, L"18.6");
        });
        if (found == live.end()) {
            std::cerr << "Live Apple Xcode support table was not parsed.\n";
            return 1;
        }
        return 0;
    }
    const fs::path root = fs::temp_directory_path() / ("OPENFRUIT-sdk-auto-" + OpenFruit::NewOperationId());
    const auto make_sdk = [&](const char* version) {
        const fs::path sdk = root / version / "iPhoneOS.sdk";
        fs::create_directories(sdk / "usr" / "lib");
        fs::create_directories(sdk / "System" / "Library" / "Frameworks");
        std::ofstream(sdk / "SDKSettings.json") << "{\"Version\":\"" << version
            << "\",\"CanonicalName\":\"iphoneos" << version << "\"}";
        return sdk;
    };
    OpenFruit::Config config;
    config.ios_sdk_paths[L"18.5"] = make_sdk("18.5").wstring();
    config.ios_sdk_paths[L"26.5"] = make_sdk("26.5").wstring();
    const std::vector<OpenFruit::XcodeIosSupport> support = {
        {L"16.4", L"18.5", L"15", L"18", L"6.1"},
        {L"26.5", L"26.5", L"15", L"26.5", L"6.3"},
        {L"26.6", L"26.5", L"15", L"26.5", L"6.3"}
    };
    const auto parsed = OpenFruit::XcodeCompatibility::ParseAppleHtml(
        "<table><tr><td>Xcode&nbsp;27.2 beta 2</td><td>macOS</td><td>iOS&nbsp;27.2</td>"
        "<td>iOS&nbsp;15–27</td></tr><tr><td>Xcode&nbsp;26.6</td><td>macOS</td>"
        "<td>iOS&nbsp;26.5<br />tvOS&nbsp;26.5</td><td>iOS&nbsp;15–26.5<br />tvOS&nbsp;15–26.5</td>"
        "<td>iOS&nbsp;15&nbsp;or&nbsp;later</td><td>iOS&nbsp;15&nbsp;or&nbsp;later</td>"
        "<td><strong>Compiler:</strong><br />Swift&nbsp;6.3<br />"
        "<strong>Language&nbsp;mode:</strong><br />Swift&nbsp;6</td>"
        "</tr></table>");
    const bool parsed_ok = parsed.size() == 1 && parsed[0].xcode_version == L"26.6" &&
        parsed[0].sdk_version == L"26.5" && parsed[0].minimum_deployment == L"15" &&
        parsed[0].maximum_deployment == L"26.5" &&
        parsed[0].swift_compiler_version == L"6.3" &&
        OpenFruit::XcodeCompatibility::Supports(parsed[0], L"18.6") &&
        !OpenFruit::XcodeCompatibility::Supports(parsed[0], L"14.9");
    const auto chosen = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos", L"18.6", false, support);
    const bool selected = chosen.succeeded && !chosen.acquired && chosen.version == L"26.5" &&
        chosen.xcode_version == L"26.6" && chosen.swift_compiler_version == L"6.3" &&
        fs::path(chosen.path) == fs::path(config.ios_sdk_paths[L"26.5"]);
    const auto pinned = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iPhoneOS18.5", L"17.0", false, support);
    const bool pinned_ok = pinned.succeeded && pinned.version == L"18.5" &&
        pinned.swift_compiler_version == L"6.1" &&
        fs::path(pinned.path) == fs::path(config.ios_sdk_paths[L"18.5"]);
    const auto unavailable = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos18.6", L"17.0", false, support);
    const auto malformed = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneosbeta", L"17.0", false, support);
    const auto too_old = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos18.5", L"26.0", false, support);
    config.ios_sdk_paths[L"27.0"] = make_sdk("27.0").wstring();
    const auto before_failure = config.sdk_path;
    const auto unknown = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"17.0", false, support);
    const bool honest_unknown = !unknown.succeeded && unknown.swift_compiler_version.empty() &&
        config.sdk_path == before_failure;
    const auto tv = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"appletvos", L"18.6", false, support);
    const auto invalid = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos", L"18.bad", false, support);
    config.ios_sdk_paths[L"26.5"] = make_sdk("17.0").wstring();
    const auto missing = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos", L"18.6", false, support);
    const auto sdk27 = fs::path(config.ios_sdk_paths[L"27.0"]);
    const auto write_metadata = [&](const char* minimum, const char* maximum) {
        std::ofstream(sdk27 / "SDKSettings.json") <<
            "{\"Version\":\"27.0\",\"CanonicalName\":\"iphoneos27.0\",\"SupportedTargets\":{\"iphoneos\":{"
            "\"LLVMTargetTripleVendor\":\"apple\",\"LLVMTargetTripleSys\":\"ios\","
            "\"DeploymentTargetSettingName\":\"IPHONEOS_DEPLOYMENT_TARGET\","
            "\"MinimumDeploymentTarget\":\"" << minimum << "\",\"MaximumDeploymentTarget\":\"" << maximum << "\"}}}";
    };
    const auto module = sdk27 / "usr" / "lib" / "swift" / "Swift.swiftmodule";
    fs::create_directories(module);
    const auto swift_interface = module / "arm64e-apple-ios.swiftinterface";
    std::ofstream(swift_interface) << "// swift-interface-format-version: 1.0\n"
        "// swift-compiler-version: Apple Swift version 6.4 effective-5.10 (swiftlang-6.4.0.31.4 clang-2100.3.31.1)\n";
    write_metadata("15.0", "27.0.99");
    const auto local = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos", L"17.0", false, support);
    const auto no_table = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"17.0", false, {});
    const bool metadata_ok = local.succeeded && local.version == L"27.0" && local.xcode_version.empty() &&
        local.swift_compiler_version == L"6.4" && local.compiler_metadata_from_sdk &&
        no_table.succeeded && no_table.compiler_metadata_from_sdk && no_table.swift_compiler_version == L"6.4";
    const auto below_minimum = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"14.9", false, {});
    const auto above_sdk = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"27.1", false, {});
    const std::vector<OpenFruit::XcodeIosSupport> restrictive_table = {{L"27", L"27.0", L"20", L"27", L"6.4"}};
    const auto known_incompatible = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"17.0", false, restrictive_table);
    write_metadata("15.0", "");
    const auto missing_range = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"17.0", false, {});
    write_metadata("15.0", "27.0.99");
    std::ofstream(swift_interface) << "// swift-compiler-version: Swift version 6.4\n";
    const auto missing_apple_header = OpenFruit::SDKAutoSelection::ResolveWithSupport(config, L"iphoneos27.0", L"17.0", false, {});
    std::error_code ec; fs::remove_all(root, ec); // Unique owned fixture.
    if (!parsed_ok || !selected || !pinned_ok || unavailable.succeeded || malformed.succeeded ||
        too_old.succeeded || !honest_unknown || !metadata_ok || below_minimum.succeeded || above_sdk.succeeded ||
        known_incompatible.succeeded || missing_range.succeeded || missing_apple_header.succeeded ||
        tv.succeeded || invalid.succeeded || missing.succeeded || ec) {
        std::cerr << "SDK platform, deployment compatibility or metadata selection failed.\n";
        return 1;
    }
    return 0;
}
