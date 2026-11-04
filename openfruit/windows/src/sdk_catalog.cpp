#include "sdk_catalog.hpp"
#include <windows.h>
#include <algorithm>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
std::wstring ExtendedWin32Path(const fs::path& input) {
    std::error_code ec;
    fs::path absolute = input.is_absolute() ? input : fs::absolute(input, ec);
    if (ec) absolute = input;
    std::wstring value = absolute.lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) == 0) return value;
    if (value.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}

bool LongPathExists(const fs::path& input) {
    return GetFileAttributesW(ExtendedWin32Path(input).c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool LongPathIsDirectory(const fs::path& input) {
    const DWORD attributes = GetFileAttributesW(ExtendedWin32Path(input).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

}
SDKLayoutInspection SDKCatalog::Inspect(const fs::path& sdk) {
    SDKLayoutInspection result;
    if (sdk.empty() || !sdk.is_absolute()) return result;
    result.directory = LongPathIsDirectory(sdk);
    result.libraries = LongPathIsDirectory(sdk / "usr" / "lib");
    result.frameworks = LongPathIsDirectory(sdk / "System" / "Library" / "Frameworks");
    result.settings = LongPathExists(sdk / "SDKSettings.json") || LongPathExists(sdk / "SDKSettings.plist");
    return result;
}
bool SDKCatalog::HasUsableLayout(const fs::path& sdk) {
    return Inspect(sdk).Usable();
}
bool SDKCatalog::RegistrationTargetMissing(const fs::path& sdk) {
    if (sdk.empty()) return true;
    if (!sdk.is_absolute()) return false;
    std::error_code error;
    const auto status = fs::status(sdk, error); // Follow the registration link.
    if ((error && error != std::errc::no_such_file_or_directory) ||
        status.type() != fs::file_type::not_found) return false;
    // Windows can report a child of a regular file as ENOENT too. Such an
    // invalid path is not evidence of a removed SDK installation.
    for (auto parent = sdk.parent_path(); !parent.empty();) {
        error.clear();
        const auto parent_status = fs::status(parent, error);
        if (error && error != std::errc::no_such_file_or_directory) return false;
        if (parent_status.type() != fs::file_type::not_found)
            return fs::is_directory(parent_status);
        const auto next = parent.parent_path();
        if (next == parent) return false;
        parent = next;
    }
    return false;
}
std::vector<SDKCatalogEntry> SDKCatalog::List(const std::vector<SDKRegistration>& registrations,
    const std::wstring& selected_version, const fs::path& fallback_path) {
    std::vector<SDKCatalogEntry> entries;
    for (const auto& registration : registrations) {
        entries.push_back({registration, registration.version == selected_version, Inspect(registration.path)});
    }
    if (entries.empty() && !fallback_path.empty()) {
        entries.push_back({{L"default", fallback_path}, true, Inspect(fallback_path)});
    }
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        if (left.registration.version != right.registration.version)
            return left.registration.version < right.registration.version;
        return left.registration.path.native() < right.registration.path.native();
    });
    return entries;
}
}
