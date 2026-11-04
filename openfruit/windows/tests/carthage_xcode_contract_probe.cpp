#include "carthage_resolver.hpp"
#include "xcode_project.hpp"

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::wstring ExtendedPath(const fs::path& input) {
    std::wstring value = fs::absolute(input).lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) == 0) return value;
    if (value.rfind(L"\\\\", 0) == 0) {
        return L"\\\\?\\UNC\\" + value.substr(2);
    }
    return L"\\\\?\\" + value;
}

std::optional<std::string> ReadLongPathFile(const fs::path& path) {
    HANDLE file = CreateFileW(
        ExtendedPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return std::nullopt;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        size.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(file);
        return std::nullopt;
    }

    std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD total = 0;
    while (total < result.size()) {
        DWORD read = 0;
        const DWORD remaining = static_cast<DWORD>(
            std::min<std::size_t>(result.size() - total, 1024 * 1024));
        if (!ReadFile(file, result.data() + total, remaining, &read, nullptr)) {
            CloseHandle(file);
            return std::nullopt;
        }
        if (read == 0) break;
        total += read;
    }
    CloseHandle(file);
    result.resize(total);
    return result;
}

std::optional<std::string> PlistString(
    const std::string& dictionary,
    const std::string& key
) {
    const std::string marker = "<key>" + key + "</key>";
    const std::size_t key_pos = dictionary.find(marker);
    if (key_pos == std::string::npos) return std::nullopt;
    const std::size_t begin = dictionary.find("<string>", key_pos + marker.size());
    if (begin == std::string::npos) return std::nullopt;
    const std::size_t value_begin = begin + 8;
    const std::size_t end = dictionary.find("</string>", value_begin);
    if (end == std::string::npos) return std::nullopt;
    return dictionary.substr(value_begin, end - value_begin);
}

bool PlistArrayContains(
    const std::string& dictionary,
    const std::string& key,
    const std::string& value
) {
    const std::string marker = "<key>" + key + "</key>";
    const std::size_t key_pos = dictionary.find(marker);
    if (key_pos == std::string::npos) return false;
    const std::size_t begin = dictionary.find("<array>", key_pos + marker.size());
    const std::size_t end = dictionary.find("</array>", begin);
    if (begin == std::string::npos || end == std::string::npos) return false;
    return dictionary.substr(begin, end - begin).find(
        "<string>" + value + "</string>") != std::string::npos;
}

bool IsIosDeviceArm64Slice(
    const fs::path& xcframework,
    const fs::path& selected_framework
) {
    const auto plist = ReadLongPathFile(xcframework / "Info.plist");
    if (!plist) return false;

    const std::string identifier =
        selected_framework.parent_path().filename().string();
    const std::string identifier_marker =
        "<key>LibraryIdentifier</key>";
    std::size_t position = 0;
    while ((position = plist->find(identifier_marker, position)) !=
           std::string::npos) {
        const std::size_t begin = plist->rfind("<dict>", position);
        const std::size_t end = plist->find("</dict>", position);
        if (begin == std::string::npos || end == std::string::npos) return false;
        const std::string dictionary = plist->substr(begin, end + 7 - begin);
        position = end + 7;

        const auto record_identifier =
            PlistString(dictionary, "LibraryIdentifier");
        if (!record_identifier || *record_identifier != identifier) continue;

        const auto library_path = PlistString(dictionary, "LibraryPath");
        const auto platform = PlistString(dictionary, "SupportedPlatform");
        const auto variant = PlistString(dictionary, "SupportedPlatformVariant");
        return library_path &&
            fs::path(*library_path).filename() == selected_framework.filename() &&
            platform && *platform == "ios" && !variant &&
            PlistArrayContains(dictionary, "SupportedArchitectures", "arm64");
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr << "usage: carthage_xcode_contract_probe "
                     "<xcodeproj-path> [configuration]\n";
        return 2;
    }

    const fs::path project_path =
        fs::absolute(fs::path(argv[1])).lexically_normal();
    const std::string configuration = argc == 3 ? argv[2] : "release";
    const auto project = OpenFruit::XcodeProject::Load(project_path);
    if (!project) {
        std::cerr << "project parse failed\n";
        return 3;
    }
    const auto target = project->MainApplicationTarget();
    if (!target) {
        std::cerr << "main application target discovery failed\n";
        return 4;
    }
    const auto resolved = project->ResolveTarget(*target, configuration);
    if (!resolved) {
        std::cerr << "target resolution failed\n";
        return 5;
    }

    const auto result = OpenFruit::ResolveCarthageBinaryFrameworks(
        project->SourceRoot(), resolved->frameworks);
    if (!result.success) {
        std::cerr << "resolution failed: " << result.error << '\n';
        return 6;
    }
    if (result.frameworks.empty()) {
        std::cerr << "no XCFramework rediscovered\n";
        return 7;
    }
    if (result.device_frameworks.empty()) {
        std::cerr << "no iOS-device framework selected\n";
        return 8;
    }

    for (const auto& framework : result.frameworks) {
        std::cout << "XCFRAMEWORK=" << framework.string() << '\n';
    }
    for (const auto& device : result.device_frameworks) {
        bool matched = false;
        for (const auto& framework : result.frameworks) {
            if (IsIosDeviceArm64Slice(framework, device)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            std::cerr << "selected framework is not an arm64 iOS-device "
                         "slice according to XCFramework Info.plist: "
                      << device.string() << '\n';
            return 9;
        }
        std::cout << "IOS_DEVICE_FRAMEWORK=" << device.string() << '\n';
        std::cout << "SLICE_METADATA=platform:ios,variant:none,arch:arm64\n";
    }

    return 0;
}
