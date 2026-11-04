#include "config.hpp"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: config_active_sdk_probe <diagnostic-root>\n";
        return 2;
    }

    const fs::path root = fs::absolute(fs::path(argv[1])).lexically_normal();
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) {
        std::cerr << "unable to create diagnostic root\n";
        return 3;
    }

    const fs::path config_path = root / "config.toml";
    const std::wstring old_sdk = (root / "old" / "iPhoneOS.sdk").wstring();
    const std::wstring new_sdk = (root / "new" / "iPhoneOS.sdk").wstring();

    OpenFruit::Config initial;
    initial.ios_sdk_version = L"26";
    initial.sdk_path = old_sdk;
    initial.ios_sdk_paths[L"26"] = old_sdk;
    if (!initial.Save(config_path.wstring())) {
        std::cerr << "unable to save initial config\n";
        return 4;
    }

    OpenFruit::Config updated = OpenFruit::Config::Load(config_path.wstring());
    updated.SetValue("sdk.ios.path", new_sdk.empty() ? "" : fs::path(new_sdk).string());
    if (!updated.Save(config_path.wstring())) {
        std::cerr << "unable to save updated config\n";
        return 4;
    }

    const OpenFruit::Config reloaded = OpenFruit::Config::Load(config_path.wstring());
    std::cout << "ACTIVE_SDK=" << fs::path(reloaded.sdk_path).string() << "\n";
    std::cout << "VERSIONED_SDK="
              << fs::path(reloaded.ios_sdk_paths.at(L"26")).string() << "\n";

    if (reloaded.sdk_path != new_sdk ||
        reloaded.ios_sdk_paths.at(L"26") != new_sdk) {
        std::cerr << "ACTIVE_SDK_CONFIG_PROPAGATION=fail\n";
        return 5;
    }

    std::cout << "ACTIVE_SDK_CONFIG_PROPAGATION=pass\n";
    return 0;
}
