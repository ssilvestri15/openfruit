#include "sdk_catalog.hpp"
#include "operation_events.hpp"
#include "sdk_manager.hpp"
#include <windows.h>
#include <functional>
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
struct CacheEnvironment {
    std::wstring previous;
    bool had_value = false;
    explicit CacheEnvironment(const fs::path& cache) {
        const auto size = GetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", nullptr, 0);
        if (size) {
            previous.resize(size);
            previous.resize(GetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", previous.data(), size));
            had_value = true;
        }
        SetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", cache.c_str());
    }
    ~CacheEnvironment() { SetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", had_value ? previous.c_str() : nullptr); }
};
int main() {
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-catalog-" + OpenFruit::NewOperationId());
    fs::create_directories(root / "usr" / "lib");
    fs::create_directories(root / "System" / "Library" / "Frameworks");
    bool passed = !OpenFruit::SDKCatalog::HasUsableLayout(root);
    { std::ofstream settings(root / "SDKSettings.plist"); settings << "owned layout fixture"; }
    passed = passed && OpenFruit::SDKCatalog::HasUsableLayout(root);
    // CWD certainly exists, including when TEMP uses a different volume. A
    // relative root must not inspect even that directory's presence.
    const auto relative_root = fs::path(".");
    const auto relative_layout = OpenFruit::SDKCatalog::Inspect(relative_root);
    passed = passed && !relative_layout.directory && !relative_layout.libraries
        && !relative_layout.frameworks && !relative_layout.settings;
    const auto relative_entries = OpenFruit::SDKCatalog::List({{L"relative", relative_root}}, L"relative", {});
    passed = passed && relative_entries.size() == 1 && relative_entries[0].selected
        && !relative_entries[0].layout.directory && !relative_entries[0].layout.libraries
        && !relative_entries[0].layout.frameworks && !relative_entries[0].layout.settings;
    const auto missing = root / "missing";
    {
        CacheEnvironment environment(root / "owned-cache");
        // Seed the old implementation's cache namespace as a negative input.
        // It deliberately has a linker library directory but no provenance.
        const auto legacy = root / "owned-cache" / "sdk" /
            std::to_string(std::hash<std::wstring>{}(fs::absolute(root).lexically_normal().wstring())) /
            "linker-overlay";
        fs::create_directories(legacy / "usr" / "lib");
        { std::ofstream marker(legacy / "usr" / "lib" / "owned-invalid.tbd"); marker << "untrusted"; }
        std::wstring selected = L"prior-value";
        passed = passed && OpenFruit::SDKManager::EnsureLinkerOverlay(L"", root.wstring(), selected)
            && selected == root.wstring()
            && fs::is_regular_file(legacy / "usr" / "lib" / "owned-invalid.tbd");
        const auto unavailable = root / "missing-sdk";
        const auto unavailable_cache = root / "owned-cache" / "sdk" /
            std::to_string(std::hash<std::wstring>{}(fs::absolute(unavailable).lexically_normal().wstring())) /
            "linker-overlay";
        fs::create_directories(unavailable_cache / "usr" / "lib");
        selected = L"prior-value";
        passed = passed && !OpenFruit::SDKManager::EnsureLinkerOverlay(L"", unavailable.wstring(), selected)
            && selected.empty();
    }
    passed = passed && OpenFruit::SDKCatalog::RegistrationTargetMissing(missing)
        && !OpenFruit::SDKCatalog::RegistrationTargetMissing(root)
        && !OpenFruit::SDKCatalog::RegistrationTargetMissing("relative-sdk");
    { std::ofstream file(root / "existing-file"); file << "preserve"; }
    passed = passed && !OpenFruit::SDKCatalog::RegistrationTargetMissing(root / "existing-file")
        && !OpenFruit::SDKCatalog::RegistrationTargetMissing(root / "existing-file" / "child");
    fs::create_directory_symlink(missing, root / "dangling-registration");
    passed = passed && OpenFruit::SDKCatalog::RegistrationTargetMissing(root / "dangling-registration");
    fs::create_directory_symlink(root, root / "live-registration");
    passed = passed && !OpenFruit::SDKCatalog::RegistrationTargetMissing(root / "live-registration");
    const auto entries = OpenFruit::SDKCatalog::List({{L"27", missing}, {L"26", root}}, L"26", missing);
    passed = passed && entries.size() == 2 && entries[0].registration.version == L"26"
        && entries[0].selected && entries[0].layout.Usable() && !entries[1].selected
        && !entries[1].layout.Usable() && !fs::exists(missing);
    const auto fallback = OpenFruit::SDKCatalog::List({}, L"", root);
    passed = passed && fallback.size() == 1 && fallback[0].selected
        && fallback[0].registration.version == L"default" && fallback[0].layout.Usable();
    passed = passed && OpenFruit::SDKCatalog::List({}, L"", {}).empty()
        && !OpenFruit::SDKCatalog::HasUsableLayout({});
    fs::remove(root / "SDKSettings.plist");
    { std::ofstream settings(root / "SDKSettings.json"); settings << "{}"; }
    passed = passed && OpenFruit::SDKCatalog::HasUsableLayout(root);
    fs::remove_all(root / "usr");
    passed = passed && !OpenFruit::SDKCatalog::HasUsableLayout(root);
    fs::remove_all(root); // Unique owned fixture only.
    if (!passed) std::cerr << "SDK layout/catalog contract failed.\n";
    return passed ? 0 : 1;
}
