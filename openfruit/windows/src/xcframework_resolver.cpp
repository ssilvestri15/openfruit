#include "xcframework_resolver.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <unordered_set>
#include <windows.h>

namespace OpenFruit {
namespace fs = std::filesystem;

namespace {

std::string DecodeXml(std::string value) {
    const std::pair<const char*, const char*> entities[] = {
        {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"},
        {"&quot;", "\""}, {"&apos;", "'"},
    };
    for (const auto& [encoded, decoded] : entities) {
        std::size_t position = 0;
        while ((position = value.find(encoded, position)) != std::string::npos) {
            value.replace(position, std::char_traits<char>::length(encoded), decoded);
            position += std::char_traits<char>::length(decoded);
        }
    }
    return value;
}

std::optional<std::string> PlistString(
    const std::string& dictionary,
    const std::string& key
) {
    const std::string marker = "<key>" + key + "</key>";
    const auto key_position = dictionary.find(marker);
    if (key_position == std::string::npos) return std::nullopt;
    const auto start = dictionary.find("<string>", key_position + marker.size());
    if (start == std::string::npos) return std::nullopt;
    const auto end = dictionary.find("</string>", start + 8);
    if (end == std::string::npos) return std::nullopt;
    return DecodeXml(dictionary.substr(start + 8, end - start - 8));
}

std::vector<std::string> PlistStringArray(
    const std::string& dictionary,
    const std::string& key
) {
    std::vector<std::string> result;
    const std::string marker = "<key>" + key + "</key>";
    const auto key_position = dictionary.find(marker);
    if (key_position == std::string::npos) return result;
    const auto array_start = dictionary.find("<array>", key_position + marker.size());
    if (array_start == std::string::npos) return result;
    const auto array_end = dictionary.find("</array>", array_start + 7);
    if (array_end == std::string::npos) return result;

    std::size_t position = array_start + 7;
    while (position < array_end) {
        const auto start = dictionary.find("<string>", position);
        if (start == std::string::npos || start >= array_end) break;
        const auto end = dictionary.find("</string>", start + 8);
        if (end == std::string::npos || end > array_end) break;
        result.push_back(DecodeXml(dictionary.substr(start + 8, end - start - 8)));
        position = end + 9;
    }
    return result;
}

std::vector<std::string> AvailableLibraryDictionaries(const std::string& plist) {
    std::vector<std::string> result;
    const auto key = plist.find("<key>AvailableLibraries</key>");
    if (key == std::string::npos) return result;
    const auto array_start = plist.find("<array>", key);
    if (array_start == std::string::npos) return result;

    std::size_t position = array_start + 7;
    int array_depth = 1;
    while (position < plist.size() && array_depth > 0) {
        const auto next_array = plist.find("<array>", position);
        const auto next_array_end = plist.find("</array>", position);
        const auto next_dict = plist.find("<dict>", position);
        std::size_t next = std::min({next_array, next_array_end, next_dict});
        if (next == std::string::npos) break;

        if (next == next_array) {
            ++array_depth;
            position = next + 7;
            continue;
        }
        if (next == next_array_end) {
            --array_depth;
            position = next + 8;
            continue;
        }
        if (array_depth != 1) {
            position = next + 6;
            continue;
        }

        int dict_depth = 1;
        std::size_t cursor = next + 6;
        while (cursor < plist.size() && dict_depth > 0) {
            const auto child = plist.find("<dict>", cursor);
            const auto end = plist.find("</dict>", cursor);
            if (end == std::string::npos) return {};
            if (child != std::string::npos && child < end) {
                ++dict_depth;
                cursor = child + 6;
            } else {
                --dict_depth;
                cursor = end + 7;
            }
        }
        if (dict_depth != 0) return {};
        result.push_back(plist.substr(next, cursor - next));
        position = cursor;
    }
    return result;
}

struct TargetIdentity {
    std::string architecture;
    std::string platform;
    std::string variant;
};

TargetIdentity ParseTargetTriple(const std::wstring& wide_triple) {
    std::string triple(wide_triple.begin(), wide_triple.end());
    triple = ToLowerAscii(triple);
    TargetIdentity result;
    const auto first_dash = triple.find('-');
    result.architecture = triple.substr(0, first_dash);

    if (triple.find("ios") != std::string::npos) result.platform = "ios";
    else if (triple.find("tvos") != std::string::npos) result.platform = "tvos";
    else if (triple.find("watchos") != std::string::npos) result.platform = "watchos";
    else if (triple.find("xros") != std::string::npos ||
             triple.find("visionos") != std::string::npos) result.platform = "xros";
    else if (triple.find("macos") != std::string::npos) result.platform = "macos";

    if (triple.find("-simulator") != std::string::npos) result.variant = "simulator";
    else if (triple.find("-macabi") != std::string::npos) result.variant = "maccatalyst";
    return result;
}

bool Contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

std::optional<fs::path> FindGitRoot(fs::path path) {
    std::error_code ec;
    if (!fs::is_directory(path, ec)) path = path.parent_path();
    while (!path.empty()) {
        if (fs::exists(path / ".git", ec) && !ec) return path;
        const fs::path parent = path.parent_path();
        if (parent == path) break;
        path = parent;
        ec.clear();
    }
    return std::nullopt;
}

std::optional<std::string> GitIndexContent(
    const fs::path& repository,
    const fs::path& file
) {
    std::error_code ec;
    const fs::path relative = fs::relative(file, repository, ec);
    if (ec || relative.empty()) return std::nullopt;
    const std::string relative_text = relative.generic_string();

    const auto index = Win32Process::Run(
        L"git.exe",
        {L"git.exe", L"-C", repository.wstring(), L"rev-parse",
         Win32Process::ToWide(":" + relative_text)}
    );
    const auto filtered_worktree = Win32Process::Run(
        L"git.exe",
        {L"git.exe", L"-C", repository.wstring(), L"hash-object",
         L"--path=" + Win32Process::ToWide(relative_text), file.wstring()}
    );
    if (!index.success || !filtered_worktree.success ||
        TrimWhitespace(index.std_out) != TrimWhitespace(filtered_worktree.std_out)) {
        return std::nullopt;
    }

    const auto content = Win32Process::Run(
        L"git.exe",
        {L"git.exe", L"-C", repository.wstring(), L"show",
         Win32Process::ToWide(":" + relative_text)}
    );
    if (!content.success) return std::nullopt;
    return content.std_out;
}

bool WriteBinary(const fs::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    return stream.good();
}

std::optional<fs::path> ProjectCanonicalGitInterfaces(
    const fs::path& library,
    std::string& error
) {
    if (ToLowerAscii(library.extension().string()) != ".framework") return library;

    struct CanonicalInterface {
        fs::path source;
        fs::path relative;
        std::string content;
    };
    std::vector<CanonicalInterface> canonical_interfaces;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(
             library, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (!it->is_regular_file(ec) || ec ||
            ToLowerAscii(it->path().extension().string()) != ".swiftinterface") {
            ec.clear();
            continue;
        }

        const std::string physical = ReadFileText(it->path());
        if (physical.find("\r\n") == std::string::npos) continue;
        const auto repository = FindGitRoot(it->path());
        if (!repository) continue;
        const auto canonical = GitIndexContent(*repository, it->path());
        if (!canonical || *canonical == physical ||
            canonical->find("\r\n") != std::string::npos) {
            continue;
        }
        const fs::path relative = fs::relative(it->path(), library, ec);
        if (ec) {
            error = "cannot map tracked Swift interface into framework projection";
            return std::nullopt;
        }
        canonical_interfaces.push_back({it->path(), relative, *canonical});
    }

    if (canonical_interfaces.empty()) return library;

    wchar_t local_app_data[MAX_PATH] = {};
    const DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", local_app_data, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        error = "LOCALAPPDATA is unavailable for XCFramework projection";
        return std::nullopt;
    }

    const std::size_t identity = std::hash<std::wstring>{}(
        fs::absolute(library, ec).lexically_normal().wstring());
    const fs::path projection_root =
        fs::path(local_app_data) / "OPENFRUIT" / "cache" /
        "xcframework-projections" / std::to_string(identity);
    const fs::path projected = projection_root / library.filename();

    fs::remove_all(projection_root, ec);
    ec.clear();
    fs::create_directories(projection_root, ec);
    if (ec) {
        error = "cannot create XCFramework interface projection";
        return std::nullopt;
    }
    fs::copy(
        library,
        projected,
        fs::copy_options::recursive | fs::copy_options::overwrite_existing,
        ec
    );
    if (ec) {
        error = "cannot copy framework into XCFramework interface projection";
        return std::nullopt;
    }

    std::unordered_set<std::wstring> serialized_modules;
    for (const auto& item : canonical_interfaces) {
        const fs::path destination = projected / item.relative;
        if (!WriteBinary(destination, item.content)) {
            error = "cannot write canonical tracked Swift interface projection";
            return std::nullopt;
        }

        std::wstring filename = destination.filename().wstring();
        const std::wstring private_suffix = L".private.swiftinterface";
        const std::wstring package_suffix = L".package.swiftinterface";
        const std::wstring regular_suffix = L".swiftinterface";
        if (filename.ends_with(private_suffix)) {
            filename.resize(filename.size() - private_suffix.size());
        } else if (filename.ends_with(package_suffix)) {
            filename.resize(filename.size() - package_suffix.size());
        } else if (filename.ends_with(regular_suffix)) {
            filename.resize(filename.size() - regular_suffix.size());
        }
        serialized_modules.insert(
            (destination.parent_path() / (filename + L".swiftmodule")).wstring());
    }
    for (const auto& module : serialized_modules) {
        fs::remove(fs::path(module), ec);
        ec.clear();
    }

    std::cout << "OPENFRUIT: Projected " << canonical_interfaces.size()
              << " Git-canonical Swift interface(s) without modifying the "
                 "upstream checkout: "
              << projected.string() << std::endl;
    return projected;
}

} // namespace

XcframeworkSliceResult ResolveXcframeworkSlices(
    const std::vector<fs::path>& artifacts,
    const std::wstring& target_triple
) {
    XcframeworkSliceResult result;
    const TargetIdentity target = ParseTargetTriple(target_triple);
    if (target.architecture.empty() || target.platform.empty()) {
        result.error = "cannot derive XCFramework platform and architecture from target triple";
        return result;
    }

    std::unordered_set<std::wstring> seen;
    for (const auto& artifact : artifacts) {
        if (ToLowerAscii(artifact.extension().string()) != ".xcframework") {
            if (seen.insert(artifact.lexically_normal().wstring()).second) {
                result.libraries.push_back(artifact);
            }
            continue;
        }

        const fs::path plist_path = artifact / "Info.plist";
        const std::string plist = ReadFileText(plist_path);
        if (plist.empty()) {
            result.error = "cannot read XCFramework metadata: " + plist_path.string();
            return result;
        }

        std::optional<fs::path> selected;
        for (const auto& dictionary : AvailableLibraryDictionaries(plist)) {
            const auto identifier = PlistString(dictionary, "LibraryIdentifier");
            const auto library_path = PlistString(dictionary, "LibraryPath");
            const auto platform = PlistString(dictionary, "SupportedPlatform");
            const auto variant = PlistString(dictionary, "SupportedPlatformVariant");
            const auto architectures =
                PlistStringArray(dictionary, "SupportedArchitectures");
            if (!identifier || !library_path || !platform ||
                ToLowerAscii(*platform) != target.platform ||
                ToLowerAscii(variant.value_or("")) != target.variant ||
                !Contains(architectures, target.architecture)) {
                continue;
            }

            const fs::path candidate =
                artifact / fs::path(*identifier) / fs::path(*library_path);
            if (!fs::exists(candidate)) {
                result.error = "selected XCFramework library is missing: " +
                    candidate.string();
                return result;
            }
            if (selected) {
                result.error = "XCFramework metadata has multiple matching libraries: " +
                    artifact.string();
                return result;
            }
            selected = candidate.lexically_normal();
        }

        if (!selected) {
            result.error = "XCFramework has no library matching target " +
                std::string(target_triple.begin(), target_triple.end()) + ": " +
                artifact.string();
            return result;
        }
        const auto projected = ProjectCanonicalGitInterfaces(*selected, result.error);
        if (!projected) return result;
        if (seen.insert(projected->wstring()).second) {
            result.libraries.push_back(*projected);
        }
    }

    result.success = true;
    return result;
}

} // namespace OpenFruit
