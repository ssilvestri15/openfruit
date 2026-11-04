#include "darwin_macro_provider_import.hpp"
#include "darwin_macro_provider.hpp"
#include "artifact_store.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <charconv>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>

namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
void Need(bool ok, const char* error) { if (!ok) throw std::runtime_error(error); }
bool Same(const fs::path& a, const fs::path& b) { return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL; }
struct PathLess { bool operator()(const fs::path& a, const fs::path& b) const { return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_LESS_THAN; } };
bool Within(const fs::path& root, const fs::path& value) {
    auto actual = value.begin(); for (const auto& expected : root) {
        if (actual == value.end() || !Same(expected, *actual)) return false; ++actual;
    } return true;
}
void Active() {
    const auto context = CurrentOperationContext();
    Need(!context || !context->CancellationRequested(), "Darwin provider import cancelled.");
    Need(!context || !context->DeadlineExceeded(), "Darwin provider import deadline exceeded.");
}
fs::path Relative(const std::string& text) {
    Need(!text.empty() && text.size() <= 32768 && text.find('\0') == std::string::npos && text.find(':') == std::string::npos, "Invalid provider import relative path.");
    const fs::path path(Win32Process::ToWide(text)); Need(!path.has_root_path(), "Absolute provider import destination rejected.");
    for (const auto& part : path) Need(part != L"." && part != L".." && !part.empty(), "Provider import path traversal rejected.");
    return path.lexically_normal();
}
fs::path Canonical(const fs::path& path) {
    std::error_code ec; const auto result = fs::canonical(path, ec); Need(!ec && result.is_absolute(), "Provider import path unavailable."); return result;
}
void SafeDestination(const fs::path& root, const fs::path& destination) {
    Need(Within(root, destination) && !Same(root, destination), "Provider import destination escapes managed root.");
    auto path = root;
    for (const auto& part : destination.lexically_relative(root)) {
        path /= part; const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = GetLastError(); Need(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND, "Provider import destination cannot be inspected.");
        } else Need(!(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "Provider import destination reparse point rejected.");
    }
    std::error_code ec; const auto resolved = fs::weakly_canonical(destination, ec);
    Need(!ec && Within(root, resolved), "Provider import canonical destination escapes managed root.");
}
const JsonValue& Object(const JsonValue& object, const char* key) {
    const auto* value = object.Get(key); Need(value && value->IsObject(), "Provider import object field missing."); return *value;
}
const JsonValue::Array& Array(const JsonValue& object, const char* key) {
    const auto* value = object.Get(key); Need(value && value->IsArray(), "Provider import array field missing."); return value->ArrayItems();
}
std::uint64_t Number(const JsonValue& object, const char* key) {
    const auto* value = object.Get(key); Need(value && value->IsNumber(), "Provider import integer missing.");
    const auto text = value->Serialize(); std::uint64_t number = 0; const auto result = std::from_chars(text.data(), text.data() + text.size(), number);
    Need(result.ec == std::errc{} && result.ptr == text.data() + text.size(), "Provider import unsigned integer invalid."); return number;
}
bool Hash(const std::string& value) {
    if (value.size() != 64) return false;
    for (char c : value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false; return true;
}
std::shared_ptr<void> Hold(const fs::path& path, bool directory = false, bool lock = false) {
    const DWORD access = lock ? GENERIC_READ | GENERIC_WRITE : directory ? FILE_READ_ATTRIBUTES : GENERIC_READ;
    const DWORD share = directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ;
    HANDLE file = CreateFileW(path.c_str(), access, share, nullptr, lock ? OPEN_ALWAYS : OPEN_EXISTING,
        directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL, nullptr);
    Need(file != INVALID_HANDLE_VALUE, "Provider import stable input/destination lease unavailable.");
    return std::shared_ptr<void>(file, [](void* value) { CloseHandle(value); });
}
JsonValue ReadObject(const fs::path& path) {
    auto lease = Hold(path); LARGE_INTEGER size{}; Need(GetFileSizeEx(lease.get(), &size) && size.QuadPart > 0 && size.QuadPart <= 64 * 1024 * 1024, "Provider import JSON byte budget invalid.");
    std::string text(static_cast<std::size_t>(size.QuadPart), '\0'); DWORD got = 0;
    Need(ReadFile(lease.get(), text.data(), static_cast<DWORD>(text.size()), &got, nullptr) && got == text.size(), "Provider import JSON read failed.");
    if (text.starts_with("\xef\xbb\xbf")) text.erase(0, 3); const auto value = JsonValue::Parse(text);
    Need(value && value->IsObject(), "Provider import JSON object invalid."); return *value;
}
bool Equal(const JsonValue& a, const JsonValue& b) {
    if (a.type() != b.type()) return false;
    if (a.IsObject()) {
        if (a.ObjectItems().size() != b.ObjectItems().size()) return false;
        for (const auto& [key, value] : a.ObjectItems()) { const auto* other = b.Get(key); if (!other || !Equal(value, *other)) return false; } return true;
    }
    if (a.IsArray()) {
        if (a.ArrayItems().size() != b.ArrayItems().size()) return false;
        for (std::size_t i = 0; i < a.ArrayItems().size(); ++i) if (!Equal(a.ArrayItems()[i], b.ArrayItems()[i])) return false; return true;
    }
    return a.Serialize() == b.Serialize();
}
struct Expected { std::string sha256; std::uint64_t bytes = 0; };
using Inventory = std::map<fs::path, Expected, PathLess>;
bool ValidateTree(const fs::path& tree, const Inventory& expected) {
    try {
        Active(); const auto root = Canonical(tree); std::size_t count = 0, directories = 0;
        for (fs::recursive_directory_iterator it(tree), end; it != end; ++it) {
            Active(); Need(it.depth() < 64 && ++directories <= 200000, "Provider import tree budget exceeded.");
            Need(Within(root, Canonical(it->path())), "Provider import source link escapes tree.");
            if (it->is_directory()) { Need(!it->is_symlink(), "Provider import directory symlink unsupported."); continue; }
            Need(it->is_regular_file(), "Provider import original entry is not a file.");
            const auto found = expected.find(it->path().lexically_relative(tree)); Need(found != expected.end(), "Unlisted provider import original file.");
            auto handle = Hold(it->path()); LARGE_INTEGER size{};
            Need(GetFileSizeEx(handle.get(), &size) && size.QuadPart >= 0 && static_cast<std::uint64_t>(size.QuadPart) == found->second.bytes, "Provider import original size mismatch.");
            const auto hash = Sha256FileHandle(handle.get()); Active(); Need(hash && *hash == found->second.sha256, "Provider import original SHA256 mismatch."); ++count;
        }
        return count == expected.size();
    } catch (...) { return false; }
}
bool ReportMatches(const fs::path& path, const std::string& expected) {
    auto lease = Hold(path); LARGE_INTEGER bytes{};
    Need(GetFileSizeEx(lease.get(), &bytes) && bytes.QuadPart > 0 && bytes.QuadPart <= 1024 * 1024,
        "Provider cache report byte budget exceeded.");
    const auto hash = Sha256FileHandle(lease.get()); Active(); return hash && *hash == expected;
}
struct TemporaryFile {
    fs::path path;
    ~TemporaryFile() { if (!path.empty()) { std::error_code ignored; fs::remove(path, ignored); } }
};
}

bool ImportDarwinMacroProvider(const fs::path& specification, const fs::path& managed_root, const fs::path& selected_sdk, std::string& error) {
    error.clear();
    try {
        Active(); Need(specification.is_absolute() && managed_root.is_absolute() && selected_sdk.is_absolute(), "Absolute provider import paths required.");
        const auto root = Canonical(managed_root), sdk = Canonical(selected_sdk);
        Need(Within(root, sdk) && fs::is_directory(sdk), "Provider import selected SDK is not managed.");
        const auto spec = ReadObject(specification);
        Need(spec.GetString("schema") == "openfruit.darwin-provider-import.v1", "Unsupported provider import specification schema.");
        const auto& receipt = Object(spec, "receipt");
        Need(receipt.GetString("schema") == "openfruit.darwin-provider.v1" && receipt.GetString("path_anchor") == "managed-home", "Unsupported imported provider receipt schema.");
        const auto& selection = Object(receipt, "selection");
        const auto declared_sdk = root / Relative(selection.GetString("sdk"));
        Need(Same(Canonical(declared_sdk), sdk), "Provider import does not match selected SDK.");
        const auto settings_hash = selection.GetString("sdk_settings_sha256");
        const auto settings = Canonical(sdk / "SDKSettings.json");
        Need(Within(root, settings), "Provider import SDKSettings escapes managed root.");
        Need(Hash(settings_hash) && Sha256File(settings) == std::optional<std::string>(settings_hash), "Provider import selected SDKSettings hash mismatch.");

        std::set<fs::path, PathLess> trees, reports;
        for (const auto& value : Array(receipt, "original_trees")) {
            Need(value.IsString(), "Invalid imported original tree."); Need(trees.insert(root / Relative(value.StringValue())).second, "Duplicate imported original tree.");
        }
        const auto& cache = Object(receipt, "cache");
        auto add_report = [&](const JsonValue& value) { Need(reports.insert(root / Relative(value.GetString("report"))).second, "Duplicate imported cache report."); };
        add_report(Object(cache, "parent")); for (const auto& child : Array(cache, "children")) add_report(child);
        Need(!trees.empty() && trees.size() <= 100000 && reports.size() <= 100000, "Provider import input budget exceeded.");
        fs::path provider_root;
        for (auto ancestor = sdk.parent_path(); Within(root, ancestor); ancestor = ancestor.parent_path()) {
            const auto candidate = ancestor / "darwin-provider"; bool contains = true;
            for (const auto& tree : trees) contains = contains && Within(candidate, tree) && !Same(candidate, tree);
            for (const auto& report : reports) contains = contains && Within(candidate, report) && !Same(candidate, report);
            if (contains) { provider_root = candidate; break; }
            if (Same(ancestor, root)) break;
        }
        Need(!provider_root.empty(), "Provider import destinations must share selected SDK ancestor provider root.");
        for (const auto& tree : trees) SafeDestination(root, tree);
        for (const auto& report : reports) SafeDestination(root, report);
        const auto destination = provider_root / kDarwinMacroProviderReceipt; SafeDestination(root, destination);

        struct Import { fs::path source, destination; };
        auto imports = [&](const char* key, const std::set<fs::path, PathLess>& expected) {
            std::vector<Import> result; std::set<fs::path, PathLess> assigned;
            for (const auto& value : Array(spec, key)) {
                Need(value.IsObject(), "Provider import mapping invalid."); const fs::path source(Win32Process::ToWide(value.GetString("source")));
                Need(source.is_absolute() && source.native().find(L'\0') == std::wstring::npos, "Absolute provider import source required.");
                const auto target = root / Relative(value.GetString("destination"));
                Need(expected.contains(target) && assigned.insert(target).second, "Provider import destination is unlisted or duplicated.");
                result.push_back({source, target});
            }
            Need(assigned.size() == expected.size(), "Provider import mappings do not cover receipt inputs."); return result;
        };
        const auto tree_imports = imports("original_trees", trees), report_imports = imports("cache_reports", reports);
        // No existing product is replaced, even when its receipt is malformed.
        if (fs::exists(destination)) {
            Need(Equal(ReadObject(destination), receipt), "Existing provider receipt differs; replacement is not authorized.");
            DarwinMacroProvider provider; Need(ReadDarwinMacroProvider(destination, root, provider, error, sdk), "Existing provider receipt is invalid."); return true;
        }
        SafeDestination(root, provider_root); fs::create_directories(provider_root); SafeDestination(root, provider_root);
        // Hold each ancestor against rename/reparse replacement during mutation.
        std::vector<std::shared_ptr<void>> directory_leases;
        for (auto path = provider_root; Within(root, path); path = path.parent_path()) {
            directory_leases.push_back(Hold(path, true)); if (Same(path, root)) break;
        }
        const auto lock_path = provider_root / ".provider-import-lock"; SafeDestination(root, lock_path); auto lock = Hold(lock_path, false, true);
        Need(!fs::exists(destination), "Provider receipt appeared during import; retry for validation.");
        Inventory originals;
        for (const auto& value : Array(receipt, "original_files")) {
            const auto path = root / Relative(value.GetString("path")); const auto hash = value.GetString("sha256");
            Need(Hash(hash) && originals.emplace(path, Expected{hash, Number(value, "bytes")}).second, "Invalid imported original inventory.");
        }
        Need(!originals.empty() && originals.size() <= 100000, "Provider import original file budget exceeded.");
        for (const auto& input : tree_imports) {
            Active(); SafeDestination(root, input.destination); Inventory expected;
            for (const auto& [path, metadata] : originals) if (Within(input.destination, path) && !Same(input.destination, path)) expected.emplace(path.lexically_relative(input.destination), metadata);
            Need(!expected.empty(), "Provider import tree has no assigned original files.");
            auto validate = [&](const fs::path& tree) { return ValidateTree(tree, expected); };
            if (fs::exists(input.destination)) Need(validate(input.destination), "Existing provider original tree is invalid; retained without replacement.");
            else Need(NativeArtifactStore::ImportTreeTransactional(input.source, input.destination, validate), "Provider original tree import/validation failed.");
        }
        auto report_hash = [&](const fs::path& path) {
            const auto& parent = Object(cache, "parent");
            if (Same(root / Relative(parent.GetString("report")), path)) return parent.GetString("report_sha256");
            for (const auto& child : Array(cache, "children")) if (Same(root / Relative(child.GetString("report")), path)) return child.GetString("report_sha256");
            return std::string{};
        };
        for (const auto& input : report_imports) {
            Active(); SafeDestination(root, input.destination); const auto expected = report_hash(input.destination); Need(Hash(expected), "Imported cache report digest missing.");
            if (fs::exists(input.destination)) Need(ReportMatches(input.destination, expected), "Existing provider cache report differs; retained without replacement.");
            else {
                auto source = Hold(input.source); Need(ReportMatches(input.source, expected), "Provider cache report source SHA256 mismatch.");
                Need(NativeArtifactStore::ImportFile(input.source, input.destination) && ReportMatches(input.destination, expected), "Provider cache report import/hash verification failed.");
            }
        }
        TemporaryFile candidate{provider_root / (".provider-candidate-" + NewOperationId() + ".json")};
        SafeDestination(root, candidate.path); Need(AtomicFile::Publish(candidate.path, receipt.Serialize(true)), "Provider candidate receipt staging failed.");
        DarwinMacroProvider admitted;
        Need(ReadDarwinMacroProvider(candidate.path, root, admitted, error, sdk), "Complete imported provider receipt validation failed.");
        Active(); SafeDestination(root, destination); Need(!fs::exists(destination), "Provider receipt appeared before publication.");
        Need(AtomicFile::Publish(destination, receipt.Serialize(true)), "Provider receipt atomic publication failed."); return true;
    } catch (const std::exception& failure) { if (error.empty()) error = failure.what(); return false; }
}
}
