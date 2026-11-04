#include "carthage_resolver.hpp"

#include <windows.h>

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

bool IsRegularFileLongPath(const fs::path& path) {
    std::wstring value = fs::absolute(path).lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) != 0) {
        value = L"\\\\?\\" + value;
    }
    const DWORD attributes = GetFileAttributesW(value.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr << "usage: carthage_binary_probe <fixture-root> "
                     "[declared-xcframework-relative-path]\n";
        return 2;
    }
    const fs::path root = fs::absolute(fs::path(argv[1])).lexically_normal();
    const fs::path upstream_path =
        root / (argc == 3
            ? fs::path(argv[2])
            : fs::path("Carthage/Build/Demo.xcframework"));
    if (fs::exists(upstream_path)) {
        std::cerr << "probe precondition failed: upstream artifact exists\n";
        return 3;
    }

    const auto resolved = OpenFruit::ResolveCarthageBinaryFrameworks(
        root, {upstream_path});
    if (!resolved.success || resolved.frameworks.size() != 1) {
        std::cerr << "resolution failed: " << resolved.error << '\n';
        return 4;
    }
    if (resolved.device_frameworks.size() != 1) {
        std::cerr << "resolution did not select exactly one iOS device slice\n";
        return 8;
    }
    const fs::path framework = fs::absolute(resolved.frameworks.front())
        .lexically_normal();
    if (!fs::is_regular_file(framework / "Info.plist")) {
        std::cerr << "resolved XCFramework has no Info.plist\n";
        return 5;
    }
    if (fs::exists(upstream_path)) {
        std::cerr << "resolver modified the upstream source tree\n";
        return 6;
    }
    const fs::path relative = framework.lexically_relative(root);
    if (!relative.empty() && *relative.begin() != "..") {
        std::cerr << "resolved artifact was placed inside upstream tree\n";
        return 7;
    }
    const fs::path device = fs::absolute(resolved.device_frameworks.front())
        .lexically_normal();
    if (device.extension() != ".framework" ||
        !IsRegularFileLongPath(device / "Modules" / "module.modulemap")) {
        std::cerr << "resolved iOS device slice is not compiler-consumable: "
                  << device.string() << " (extension="
                  << device.extension().string() << ", modulemap="
                  << IsRegularFileLongPath(
                         device / "Modules" / "module.modulemap")
                  << ")\n";
        return 9;
    }
    std::cout << framework.string() << '\n';
    std::cout << device.parent_path().string() << '\n';
    return 0;
}
