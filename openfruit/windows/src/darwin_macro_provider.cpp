#include "darwin_macro_provider.hpp"
#include "tool_paths.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <algorithm>
#include <charconv>
#include <map>
#include <set>
#include <stdexcept>

namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
void Need(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
bool Same(const fs::path& left, const fs::path& right) {
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
}
struct PathLess {
    bool operator()(const fs::path& left, const fs::path& right) const {
        return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    }
};
bool Within(const fs::path& root, const fs::path& file) {
    auto part = file.begin();
    for (const auto& expected : root) {
        if (part == file.end() || !Same(expected, *part)) return false;
        ++part;
    }
    return true;
}
bool Hash(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
const JsonValue& Object(const JsonValue& value, const char* key) {
    const auto* field = value.Get(key); Need(field && field->IsObject(), "Provider object field missing."); return *field;
}
const JsonValue::Array& Array(const JsonValue& value, const char* key) {
    const auto* field = value.Get(key); Need(field && field->IsArray(), "Provider array field missing."); return field->ArrayItems();
}
std::uint64_t Number(const JsonValue& value, const char* key) {
    const auto* field = value.Get(key); Need(field && field->IsNumber(), "Provider integer field missing.");
    const auto text = field->Serialize(); std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    Need(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size(), "Invalid provider unsigned integer."); return result;
}
std::string Digest(const JsonValue& value, const char* key) {
    const auto result = value.GetString(key); Need(Hash(result), "Provider SHA256 binding missing."); return result;
}
void Active(const DarwinClosureOptions& options) {
    const auto context = CurrentOperationContext();
    Need(!options.cancellation.Requested() && (!context || !context->CancellationRequested()), "Darwin provider cancelled.");
    Need(std::chrono::steady_clock::now() < options.deadline && (!context || !context->DeadlineExceeded()), "Darwin provider deadline exceeded.");
}
fs::path Canonical(const fs::path& path) {
    std::error_code error; const auto resolved = fs::canonical(path, error);
    Need(!error && resolved.is_absolute(), "Provider path is unavailable."); return resolved;
}
fs::path Relative(const std::string& text) {
    Need(!text.empty() && text.size() <= 32768 && text.find('\0') == std::string::npos && text.find(':') == std::string::npos,
        "Invalid relative managed provider path.");
    const fs::path path(Win32Process::ToWide(text));
    Need(!path.has_root_path(), "Absolute provider receipt path rejected.");
    for (const auto& component : path) Need(component != L".." && component != L"." && !component.empty(), "Provider path traversal rejected.");
    return path.lexically_normal();
}
std::string Virtual(const std::string& text) {
    const auto result = NormalizeDarwinVirtualPath(text);
    Need(result == text && result != "/", "Provider virtual path is not normalized."); return result;
}
fs::path Bind(const fs::path& root, const std::string& text) {
    const auto lexical = root / Relative(text); const auto resolved = Canonical(lexical);
    Need(Within(root, resolved), "Provider path escapes managed root."); return lexical;
}
struct Held {
    std::shared_ptr<void> handle;
    std::uint64_t bytes = 0;
};
Held Open(const fs::path& path, DarwinMacroProvider& provider, const DarwinClosureOptions& options) {
    Active(options);
    HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Need(raw != INVALID_HANDLE_VALUE, "Stable provider input lease unavailable.");
    Held result{std::shared_ptr<void>(raw, [](void* value) { CloseHandle(value); }), 0};
    BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER length{};
    Need(GetFileInformationByHandle(raw, &info) && !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        && GetFileSizeEx(raw, &length) && length.QuadPart >= 0, "Provider input is not a regular file.");
    result.bytes = static_cast<std::uint64_t>(length.QuadPart);
    provider.retained_inputs.push_back(result.handle); return result;
}
void Verify(const Held& held, const std::string& expected, const DarwinClosureOptions& options) {
    const auto actual = Sha256FileHandleStatCached(held.handle.get(), ToolPaths::FileDigestCache(), options.cancellation, options.deadline);
    Active(options); Need(actual && *actual == expected, "Provider input SHA256 mismatch.");
}
JsonValue ReadJson(const Held& held, std::size_t limit, const DarwinClosureOptions& options) {
    Need(held.bytes <= limit, "Provider JSON byte budget exceeded.");
    LARGE_INTEGER start{}; Need(SetFilePointerEx(held.handle.get(), start, nullptr, FILE_BEGIN), "Provider input seek failed.");
    std::string text(static_cast<std::size_t>(held.bytes), '\0'); DWORD got = 0;
    Need(text.empty() || (ReadFile(held.handle.get(), text.data(), static_cast<DWORD>(text.size()), &got, nullptr)
        && got == text.size()), "Provider input read failed.");
    Active(options); if (text.starts_with("\xef\xbb\xbf")) text.erase(0, 3);
    const auto value = JsonValue::Parse(text); Need(value && value->IsObject(), "Invalid provider JSON object."); return *value;
}
struct Original { fs::path lexical, physical; std::string virtual_path, sha256; };
}

bool ReadDarwinMacroProvider(const fs::path& receipt, const fs::path& managed_root,
    DarwinMacroProvider& output, std::string& error, const fs::path& expected_sdk, const DarwinClosureOptions& options) {
    output = {}; error.clear();
    try {
        Active(options); Need(managed_root.is_absolute() && receipt.is_absolute(), "Absolute managed provider root/receipt required.");
        DarwinMacroProvider provider; provider.managed_root = Canonical(managed_root);
        Need(fs::is_directory(provider.managed_root), "Provider managed root is not a directory.");
        provider.receipt = Canonical(receipt); Need(Within(provider.managed_root, provider.receipt), "Provider receipt escapes managed root.");
        const auto document = ReadJson(Open(provider.receipt, provider, options), 64 * 1024 * 1024, options);
        Need(document.GetString("schema") == "openfruit.darwin-provider.v1" && document.GetString("path_anchor") == "managed-home", "Unsupported Darwin provider receipt schema.");
        const auto& selection = Object(document, "selection");
        provider.sdk = Canonical(Bind(provider.managed_root, selection.GetString("sdk")));
        Need(fs::is_directory(provider.sdk), "Selected provider SDK is not a directory.");
        if (!expected_sdk.empty()) Need(Same(provider.sdk, Canonical(expected_sdk)), "Darwin provider does not match selected SDK.");
        (void)Digest(selection, "archive_sha256");
        Need(!selection.GetString("xcode_build").empty() && !selection.GetString("toolchain_identifier").empty(), "Provider Xcode/toolchain identity missing.");
        const auto settings = Canonical(provider.sdk / "SDKSettings.json");
        Need(Within(provider.managed_root, settings), "Provider SDKSettings escapes managed root.");
        Verify(Open(settings, provider, options), Digest(selection, "sdk_settings_sha256"), options);
        for (const auto& value : Array(document, "original_trees")) {
            Active(options); Need(value.IsString(), "Invalid original provider tree.");
            const auto tree = Bind(provider.managed_root, value.StringValue());
            const auto canonical = Canonical(tree); Need(fs::is_directory(canonical), "Original provider tree unavailable.");
            Need(!fs::is_symlink(tree), "Original provider tree symlink unsupported.");
            for (const auto& previous : provider.original_trees)
                Need(!Within(Canonical(previous), canonical) && !Within(canonical, Canonical(previous)), "Overlapping original provider roots.");
            provider.original_trees.push_back(tree);
            Need(provider.original_trees.size() <= options.max_files, "Provider tree budget exceeded.");
        }
        Need(!provider.original_trees.empty(), "Original provider trees required.");
        const auto& files = Array(document, "original_files");
        Need(!files.empty() && files.size() <= options.max_files, "Provider original file budget exceeded.");
        std::vector<Original> originals; std::map<fs::path, std::size_t, PathLess> admitted;
        std::set<std::string> names;
        for (const auto& value : files) {
            Active(options); Need(value.IsObject(), "Invalid original provider file.");
            Original file; file.lexical = Bind(provider.managed_root, value.GetString("path")); file.physical = Canonical(file.lexical);
            std::size_t memberships = 0;
            for (const auto& tree : provider.original_trees) {
                if (!Within(tree, file.lexical)) continue;
                Need(Within(Canonical(tree), file.physical), "Original provider file escapes its tree.");
                ++memberships; file.virtual_path = Virtual('/' + Win32Process::ToNarrow(file.lexical.lexically_relative(tree).generic_wstring()));
            }
            Need(memberships == 1, "Original provider file must belong to exactly one tree.");
            Need(names.insert(file.virtual_path).second && admitted.emplace(file.lexical, originals.size()).second, "Ambiguous original provider namespace.");
            file.sha256 = Digest(value, "sha256"); const auto held = Open(file.physical, provider, options);
            Need(held.bytes == Number(value, "bytes"), "Original provider file size mismatch."); Verify(held, file.sha256, options);
            originals.push_back(std::move(file));
        }
        std::size_t scanned = 0, scanned_directories = 0;
        for (const auto& tree : provider.original_trees) {
            for (fs::recursive_directory_iterator it(tree), end; it != end; ++it) {
                Active(options); Need(static_cast<std::size_t>(it.depth()) < options.max_depth, "Provider tree depth budget exceeded.");
                const auto target = Canonical(it->path()); Need(Within(Canonical(tree), target), "Original provider tree link escapes root.");
                if (it->is_directory()) {
                    Need(++scanned_directories <= options.max_files, "Provider directory budget exceeded.");
                    const auto virtual_directory = Virtual('/' + Win32Process::ToNarrow(it->path().lexically_relative(tree).generic_wstring()));
                    Need(!names.contains(virtual_directory), "Original provider file/directory namespace collision.");
                    Need(!it->is_symlink(), "Original provider directory symlink unsupported."); continue;
                }
                Need(it->is_regular_file() && admitted.contains(it->path()), "Unlisted original provider file.");
                Need(++scanned <= options.max_files, "Provider tree file budget exceeded.");
            }
        }
        Need(scanned == originals.size(), "Original provider file inventory differs from tree.");
        const auto& executable = Object(document, "executable"); provider.executable = Virtual(executable.GetString("virtual_path"));
        const auto executable_file = Bind(provider.managed_root, executable.GetString("member"));
        const auto executable_found = admitted.find(executable_file); Need(executable_found != admitted.end(), "Provider executable is not admitted.");
        const auto& original_executable = originals[executable_found->second];
        Need(original_executable.virtual_path == provider.executable && original_executable.sha256 == Digest(executable, "sha256"), "Provider executable identity differs from original file.");
        DarwinImage image; std::string image_error;
        Need(ReadDarwinImage(original_executable.physical, 0x0100000c, image, image_error) && image.file_type == 2
            && image.sha256 == original_executable.sha256, "Provider executable is not original ARM64 Mach-O MH_EXECUTE.");
        std::vector<std::string> directories;
        for (const auto& value : Array(document, "plugin_directories")) {
            Need(value.IsString(), "Invalid provider plugin directory."); const auto directory = Virtual(value.StringValue());
            Need(std::find(directories.begin(), directories.end(), directory) == directories.end(), "Duplicate provider plugin directory."); directories.push_back(directory);
        }
        Need(!directories.empty(), "Provider plugin directories required."); std::set<std::string> modules;
        // Directories are in search precedence order, as compiler plugin paths
        // are: a module in an earlier directory shadows the same module later.
        // Within one directory the same module twice remains ambiguous.
        for (const auto& directory : directories) {
          std::set<std::string> local;
          for (const auto& file : originals) {
            if (!file.virtual_path.starts_with(directory + '/')) continue;
            const auto filename = file.virtual_path.substr(file.virtual_path.rfind('/') + 1);
            if (!filename.starts_with("lib") || !filename.ends_with(".dylib") || filename.size() <= 9) continue;
            const auto module = filename.substr(3, filename.size() - 9);
            Need(module.front() < '0' || module.front() > '9', "Unsupported plugin module identifier.");
            Need(std::all_of(module.begin(), module.end(), [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c >= 128;
            }), "Unsupported plugin module identifier.");
            Need(local.insert(module).second, "Ambiguous original plugin module.");
            if (modules.insert(module).second) provider.plugins.push_back({module, file.virtual_path, file.sha256, file.physical});
          }
        }
        Need(!provider.plugins.empty(), "No original provider plugin library admitted.");
        const auto& cache = Object(document, "cache"); std::set<std::string> cache_names;
        std::set<fs::path, PathLess> cache_reports, cache_payloads; std::string source_hash;
        auto cache_input = [&](const JsonValue& value) {
            Active(options); Need(value.IsObject(), "Invalid provider cache descriptor.");
            const auto report = Canonical(Bind(provider.managed_root, value.GetString("report")));
            Need(cache_reports.insert(report).second, "Duplicate provider cache report.");
            const auto held = Open(report, provider, options); Verify(held, Digest(value, "report_sha256"), options);
            const auto descriptor = ReadJson(held, 1024 * 1024, options);
            for (const char* key : {"complete", "file_contents_verified", "metadata_verified", "volume_trees_verified", "quarantined"}) {
                const auto* flag = descriptor.Get(key); Need(flag && flag->IsBoolean() && flag->Bool(), "Verified quarantined provider cache descriptor required.");
            }
            Need(descriptor.GetString("scope") == "selected-original-apfs-file-decoded-data-hashes", "Unsupported provider cache descriptor scope.");
            const auto payload = Canonical(Bind(provider.managed_root, value.GetString("payload")));
            const fs::path embedded(Win32Process::ToWide(descriptor.GetString("path")));
            Need(embedded.is_absolute() && Same(Canonical(embedded), payload), "Provider cache embedded payload binding mismatch.");
            Need(cache_payloads.insert(payload).second, "Duplicate provider cache payload.");
            const auto virtual_path = Virtual(value.GetString("virtual_path")); Need(cache_names.insert(virtual_path).second, "Duplicate provider cache virtual path.");
            Need(descriptor.GetString("virtual_path") == virtual_path && Digest(descriptor, "sha256") == Digest(value, "sha256")
                && Digest(descriptor, "source_sha256") == Digest(value, "source_sha256"), "Provider cache digest/virtual identity mismatch.");
            const auto original_source = Digest(value, "source_sha256");
            if (source_hash.empty()) source_hash = original_source;
            Need(source_hash == original_source, "Provider cache parent/child source mismatch.");
            const auto bytes = Number(value, "bytes"); Need(bytes >= 512 && bytes <= 16ULL * 1024 * 1024 * 1024
                && Number(descriptor, "decoded_bytes") == bytes, "Provider cache descriptor size mismatch.");
            // Hold the backing file and bind its size, but defer its potentially
            // multi-gigabyte hash/ABI/set verification to existing DyldCacheView.
            Need(Open(payload, provider, options).bytes == bytes, "Provider cache payload size mismatch."); return report;
        };
        provider.parent_cache_report = cache_input(Object(cache, "parent"));
        const auto& children = Array(cache, "children"); Need(children.size() <= options.max_files, "Provider cache descriptor budget exceeded.");
        for (const auto& child : children) provider.child_cache_reports.push_back(cache_input(child));
        provider.provenance = Object(document, "provenance"); Active(options); output = std::move(provider); return true;
    } catch (const std::exception& failure) { output = {}; error = failure.what(); return false; }
}

fs::path FindDarwinMacroProviderReceipt(const fs::path& managed_root, const fs::path& selected_sdk) {
    try {
        if (!managed_root.is_absolute() || !selected_sdk.is_absolute()) return {};
        const auto root = Canonical(managed_root); auto parent = Canonical(selected_sdk);
        if (!Within(root, parent) || !fs::is_directory(parent)) return {};
        for (;;) {
            const auto receipt = parent / "darwin-provider" / kDarwinMacroProviderReceipt;
            if (fs::exists(receipt)) return receipt;
            if (Same(parent, root)) break;
            parent = parent.parent_path();
        }
    } catch (...) {}
    return {};
}

bool DarwinMacroProvider::TranslateLibraryPath(const std::string& requested, std::string& virtual_path) const {
    virtual_path.clear();
    try {
        if (requested.empty() || requested.size() > 32768 || requested.find('\0') != std::string::npos) return false;
        if (requested.front() == '/' && requested.find('\\') == std::string::npos && requested.find(':') == std::string::npos) {
            const auto normalized = Virtual(requested);
            for (const auto& plugin : plugins) if (plugin.virtual_path == normalized) { virtual_path = normalized; return true; }
            return false;
        }
        const fs::path path(Win32Process::ToWide(requested)); if (!path.is_absolute() || !Within(managed_root, path.lexically_normal())) return false;
        const auto resolved = Canonical(path); if (!Within(managed_root, resolved)) return false;
        for (const auto& plugin : plugins) if (Same(plugin.file, resolved)) { virtual_path = plugin.virtual_path; return true; }
    } catch (...) {}
    return false;
}
}
