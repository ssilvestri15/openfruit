#include "bundle_resources.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <plist/plist.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <map>
#include <memory>
#include <regex>
#include <vector>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
constexpr std::size_t plist_limit = 16 * 1024 * 1024, entry_limit = 100000;
bool Active(std::string& error) {
    const auto context = CurrentOperationContext();
    if (context && (context->CancellationRequested() || context->DeadlineExceeded())) {
        error = "Bundle resource operation cancelled or deadline exceeded."; return false;
    }
    return true;
}
struct Plist {
    plist_t value = nullptr;
    ~Plist() { if (value) plist_free(value); }
    bool Parse(std::string_view bytes) {
        return !bytes.empty() && bytes.size() <= plist_limit &&
            plist_from_memory(bytes.data(), static_cast<uint32_t>(bytes.size()), &value, nullptr) == PLIST_ERR_SUCCESS &&
            plist_get_node_type(value) == PLIST_DICT;
    }
};
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool OpenRegular(const fs::path& path, Handle& file) {
    file.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    return file.value != INVALID_HANDLE_VALUE && GetFileType(file.value) == FILE_TYPE_DISK &&
        GetFileInformationByHandle(file.value, &info) && !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}
bool ReadSmall(const fs::path& path, std::string& result) {
    Handle file; LARGE_INTEGER size{}; result.clear();
    if (!OpenRegular(path, file) || !GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 || size.QuadPart > plist_limit) return false;
    result.resize(static_cast<std::size_t>(size.QuadPart)); DWORD read = 0;
    return ReadFile(file.value, result.data(), static_cast<DWORD>(result.size()), &read, nullptr) && read == result.size();
}
std::string Text(plist_t node) {
    if (!node || plist_get_node_type(node) != PLIST_STRING) return {};
    uint64_t length = 0; const auto bytes = plist_get_string_ptr(node, &length);
    return bytes ? std::string(bytes, static_cast<std::size_t>(length)) : std::string{};
}
bool Utf8(std::string_view value) {
    return value.find('\0') == std::string_view::npos && (value.empty() || (value.size() <= 32768 &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0) > 0));
}
std::string PathText(const fs::path& path) {
    const auto value = path.generic_u8string(); return std::string(reinterpret_cast<const char*>(value.data()), value.size());
}
bool RelativeKey(const std::string& key) {
    if (key.empty() || !Utf8(key) || key.front() == '/' || key.find_first_of("\\:") != std::string::npos) return false;
    std::size_t start = 0;
    while (start < key.size()) {
        const auto end = key.find('/', start);
        const auto part = key.substr(start, end == std::string::npos ? end : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string::npos) return true;
        start = end + 1;
    }
    return false;
}
struct Rule {
    const char* pattern; unsigned weight; bool optional, omit;
    std::regex compiled;
    Rule(const char* expression, unsigned priority, bool is_optional = false, bool is_omitted = false)
        : pattern(expression), weight(priority), optional(is_optional), omit(is_omitted), compiled(expression, std::regex::extended) {}
};
const std::vector<Rule>& Rules(bool modern) {
    static const std::vector<Rule> legacy{
        {"^version\\.plist$", 1}, {"^.*", 1}, {"^.*\\.lproj/", 1000, true},
        {"^Base\\.lproj/", 1010}, {"^.*\\.lproj/locversion\\.plist$", 1100, false, true}
    };
    static const std::vector<Rule> current{
        {"^.*", 1}, {".*\\.dSYM($|/)", 11}, {"^(.*/)?\\.DS_Store$", 2000, false, true},
        {"^Info\\.plist$", 20, false, true}, {"^version\\.plist$", 20}, {"^embedded\\.provisionprofile$", 20},
        {"^PkgInfo$", 20, false, true}, {"^.*\\.lproj/", 1000, true},
        {"^Base\\.lproj/", 1010}, {"^.*\\.lproj/locversion\\.plist$", 1100, false, true}
    };
    return modern ? current : legacy;
}
struct Policy { bool included = true, optional = false; };
Policy Select(const std::string& key, bool modern) {
    const Rule* best = nullptr;
    for (const auto& rule : Rules(modern))
        if ((!best || rule.weight > best->weight) && std::regex_search(key, rule.compiled)) best = &rule;
    return best ? Policy{!best->omit, best->optional} : Policy{false, false};
}
bool Excluded(const std::string& key, const std::string& executable) {
    const auto first = key.substr(0, key.find('/'));
    return key == executable || first == "_CodeSignature" || first == "_MASReceipt" || first == "CodeResources";
}
bool BundleInfo(const fs::path& bundle, BundleResourceSeal& result, std::string& executable, std::string& error) {
    const auto attributes = GetFileAttributesW(bundle.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !ReadSmall(bundle / "Info.plist", result.info_plist)) {
        error = "Resource signing requires a physical bundle and regular bounded Info.plist."; return false;
    }
    Plist info;
    if (!info.Parse(result.info_plist)) { error = "Resource bundle Info.plist is invalid."; return false; }
    executable = Text(plist_dict_get_item(info.value, "CFBundleExecutable"));
    if (!RelativeKey(executable) || executable.find('/') != std::string::npos || executable.size() > 255) {
        error = "Flat bundle CFBundleExecutable must identify one concrete root file."; return false;
    }
    if (plist_dict_get_item(info.value, "CFBundleResourceSpecification")) {
        error = "Custom resource specifications require an additional explicit signing policy."; return false;
    }
    if (fs::exists(bundle / "Contents") || fs::exists(bundle / "Versions" / "Current") || fs::exists(bundle / "Support Files")) {
        error = "Versioned/macOS bundle resource layouts require a separate policy."; return false;
    }
    result.executable_path = bundle / fs::path(std::u8string(executable.begin(), executable.end()));
    Handle main;
    if (!OpenRegular(result.executable_path, main)) { error = "Flat bundle main executable is missing or not a regular file."; return false; }
    return true;
}
struct Entry { fs::path path; bool symlink = false; std::string target; };
using Inventory = std::map<std::string, Entry>;
bool Scan(const fs::path& bundle, const std::string& executable, Inventory& inventory, std::string& error) {
    inventory.clear(); std::size_t visited = 0, name_bytes = 0;
    for (fs::recursive_directory_iterator iterator(bundle), end; iterator != end; ++iterator) {
        if (!Active(error)) return false;
        if (++visited > entry_limit || iterator.depth() > 128) { error = "Bundle resource inventory exceeds entry/depth limits."; return false; }
        const auto path = iterator->path();
        const auto key = PathText(path.lexically_relative(bundle));
        if (!RelativeKey(key)) { error = "Bundle contains a nonportable resource path."; return false; }
        if (Excluded(key, executable)) { iterator.disable_recursion_pending(); continue; }
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) { error = "Resource disappeared during inventory."; return false; }
        Entry entry{path};
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            Handle metadata;
            metadata.value = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            FILE_ATTRIBUTE_TAG_INFO tag{};
            if (metadata.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(metadata.value, FileAttributeTagInfo, &tag, sizeof(tag)) ||
                tag.ReparseTag != IO_REPARSE_TAG_SYMLINK) { error = "Non-symbolic reparse resources require explicit portable metadata."; return false; }
            const auto status = fs::symlink_status(path);
            if (!fs::is_symlink(status)) { error = "Non-symbolic reparse resources require explicit portable metadata."; return false; }
            iterator.disable_recursion_pending(); entry.symlink = true; entry.target = PathText(fs::read_symlink(path));
            if (!Utf8(entry.target) || entry.target.empty() || entry.target.find(':') != std::string::npos ||
                entry.target.starts_with("//")) { error = "Resource symlink target is not portable to the Apple bundle."; return false; }
            if (_wcsicmp(path.filename().c_str(), L".DS_Store") == 0) { error = "A .DS_Store resource cannot be a symlink."; return false; }
        } else if (attributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!Select(key, true).included && (entry.symlink || !Select(key, false).included)) continue;
        if (key.size() + entry.target.size() > plist_limit - name_bytes) { error = "Resource name/link metadata exceeds its supported bounds."; return false; }
        name_bytes += key.size() + entry.target.size();
        if (!inventory.emplace(key, std::move(entry)).second) { error = "Resource paths are ambiguous."; return false; }
    }
    return true;
}
struct Hash {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE value = nullptr;
    ~Hash() { if (value) BCryptDestroyHash(value); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
    bool Create(LPCWSTR name) { return BCryptOpenAlgorithmProvider(&algorithm, name, nullptr, 0) >= 0 &&
        BCryptCreateHash(algorithm, &value, nullptr, 0, nullptr, 0, 0) >= 0; }
};
bool FileHashes(const fs::path& path, std::string& sha1, std::string& sha256, std::string& error) {
    Handle file; Hash first, second; LARGE_INTEGER size{};
    if (!OpenRegular(path, file) || !GetFileSizeEx(file.value, &size) || size.QuadPart < 0 || size.QuadPart > 8LL * 1024 * 1024 * 1024 ||
        !first.Create(BCRYPT_SHA1_ALGORITHM) || !second.Create(BCRYPT_SHA256_ALGORITHM)) {
        error = "Unable to open/hash a bounded regular bundle resource."; return false;
    }
    std::vector<unsigned char> buffer(1024 * 1024); uint64_t total = 0;
    for (;;) {
        if (!Active(error)) return false;
        DWORD read = 0;
        if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) { error = "Resource streaming read failed."; return false; }
        if (!read) break;
        total += read;
        if (total > static_cast<uint64_t>(size.QuadPart) || BCryptHashData(first.value, buffer.data(), read, 0) < 0 ||
            BCryptHashData(second.value, buffer.data(), read, 0) < 0) { error = "Resource changed during hashing or hash operation failed."; return false; }
    }
    sha1.assign(20, '\0'); sha256.assign(32, '\0');
    if (total != static_cast<uint64_t>(size.QuadPart) || BCryptFinishHash(first.value, reinterpret_cast<PUCHAR>(sha1.data()), 20, 0) < 0 ||
        BCryptFinishHash(second.value, reinterpret_cast<PUCHAR>(sha256.data()), 32, 0) < 0) { error = "Resource digest finalization failed."; return false; }
    return true;
}
plist_t RuleDictionary(bool modern) {
    const auto result = plist_new_dict();
    for (const auto& rule : Rules(modern)) {
        if (rule.weight == 1 && !rule.optional && !rule.omit) plist_dict_set_item(result, rule.pattern, plist_new_bool(1));
        else {
            const auto entry = plist_new_dict();
            plist_dict_set_item(entry, "weight", plist_new_uint(rule.weight));
            if (rule.optional) plist_dict_set_item(entry, "optional", plist_new_bool(1));
            if (rule.omit) plist_dict_set_item(entry, "omit", plist_new_bool(1));
            plist_dict_set_item(result, rule.pattern, entry);
        }
    }
    return result;
}
bool Bool(plist_t node, bool expected) {
    uint8_t value = 0;
    if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) return false;
    plist_get_bool_val(node, &value); return (value != 0) == expected;
}
bool RuleSchema(plist_t rules, bool modern) {
    if (!rules || plist_get_node_type(rules) != PLIST_DICT || plist_dict_get_size(rules) != Rules(modern).size()) return false;
    for (const auto& rule : Rules(modern)) {
        const auto node = plist_dict_get_item(rules, rule.pattern);
        if (rule.weight == 1 && !rule.optional && !rule.omit) { if (!Bool(node, true)) return false; continue; }
        if (!node || plist_get_node_type(node) != PLIST_DICT || plist_dict_get_size(node) != 1 + unsigned(rule.optional) + unsigned(rule.omit)) return false;
        const auto weight = plist_dict_get_item(node, "weight"); uint64_t value = 0;
        if (!weight || plist_get_node_type(weight) != PLIST_INT) return false;
        plist_get_uint_val(weight, &value);
        if (value != rule.weight || (rule.optional && !Bool(plist_dict_get_item(node, "optional"), true)) ||
            (rule.omit && !Bool(plist_dict_get_item(node, "omit"), true))) return false;
    }
    return true;
}
bool Data(plist_t node, std::string_view bytes) {
    if (!node || plist_get_node_type(node) != PLIST_DATA) return false;
    uint64_t size = 0; const auto data = plist_get_data_ptr(node, &size);
    return size == bytes.size() && data && std::string_view(data, static_cast<std::size_t>(size)) == bytes;
}
bool DigestSchema(plist_t node, std::size_t expected) {
    if (!node || plist_get_node_type(node) != PLIST_DATA) return false;
    uint64_t size = 0; plist_get_data_ptr(node, &size); return size == expected;
}
bool VerifyFiles(plist_t files, const Inventory& inventory, const std::string& executable, bool modern, std::string& error) {
    if (!files || plist_get_node_type(files) != PLIST_DICT || plist_dict_get_size(files) > entry_limit) return false;
    // Check seals independently; deleted optional files remain permitted, but
    // no missing required, additional or incorrectly classified file is hidden.
    plist_dict_iter iterator = nullptr; plist_dict_new_iter(files, &iterator);
    const auto release = [](void* value) { std::free(value); };
    std::unique_ptr<void, decltype(release)> owner(iterator, release);
    for (;;) {
        char* raw_key = nullptr; plist_t node = nullptr;
        plist_dict_next_item(files, iterator, &raw_key, &node);
        std::string key = raw_key ? raw_key : ""; std::free(raw_key);
        if (!node) break;
        if (!Active(error) || !RelativeKey(key) || Excluded(key, executable)) return false;
        const auto policy = Select(key, modern);
        if (!policy.included) return false;
        const auto found = inventory.find(key);
        if (found == inventory.end()) {
            if (!policy.optional || plist_get_node_type(node) != PLIST_DICT || !Bool(plist_dict_get_item(node, "optional"), true)) return false;
            const auto link = plist_dict_get_item(node, "symlink");
            if (modern && link) {
                const auto target = Text(link);
                if (plist_dict_get_size(node) != 2 || target.empty() || !Utf8(target) || target.find(':') != std::string::npos || target.starts_with("//")) return false;
            } else if (plist_dict_get_size(node) != (modern ? 3u : 2u) ||
                !DigestSchema(plist_dict_get_item(node, "hash"), 20) || (modern && !DigestSchema(plist_dict_get_item(node, "hash2"), 32))) return false;
            continue;
        }
        const auto& entry = found->second;
        if (!modern && entry.symlink) return false;
        if (modern || policy.optional) {
            const auto expected_count = (entry.symlink ? 1u : modern ? 2u : 1u) + unsigned(policy.optional);
            if (plist_get_node_type(node) != PLIST_DICT || plist_dict_get_size(node) != expected_count ||
                (policy.optional && !Bool(plist_dict_get_item(node, "optional"), true))) return false;
        }
        if (entry.symlink) { if (Text(plist_dict_get_item(node, "symlink")) != entry.target) return false; }
        else {
            std::string sha1, sha256;
            if (!FileHashes(entry.path, sha1, sha256, error)) return false;
            if (!Data(modern || policy.optional ? plist_dict_get_item(node, "hash") : node, sha1) ||
                (modern && !Data(plist_dict_get_item(node, "hash2"), sha256))) return false;
        }
    }
    for (const auto& [key, entry] : inventory)
        if (Select(key, modern).included && (modern || !entry.symlink) && !plist_dict_get_item(files, key.c_str())) return false;
    return true;
}
}
bool VerifyFlatBundleResourceSeal(const fs::path& bundle, std::string_view code_resources, std::string& error) {
    bool verified = false;
    OperationSpan phase("signing.resources-verify", JsonValue::ObjectValue(), [&] { return verified; });
    error.clear();
    try {
        if (!Active(error)) return false;
        if (code_resources.empty() || code_resources.size() > plist_limit) { error = "CodeResources input exceeds its supported bounds."; return false; }
        BundleResourceSeal info; std::string executable; Inventory inventory; Plist resources;
        if (!BundleInfo(bundle, info, executable, error) || !Scan(bundle, executable, inventory, error)) return false;
        if (!resources.Parse(code_resources) || plist_dict_get_size(resources.value) != 4 ||
            !RuleSchema(plist_dict_get_item(resources.value, "rules"), false) || !RuleSchema(plist_dict_get_item(resources.value, "rules2"), true) ||
            !VerifyFiles(plist_dict_get_item(resources.value, "files"), inventory, executable, false, error) ||
            !VerifyFiles(plist_dict_get_item(resources.value, "files2"), inventory, executable, true, error)) {
            if (error.empty()) error = "CodeResources policy/schema/inventory/digests do not match the physical flat bundle.";
            return false;
        }
        verified = Active(error); return verified;
    } catch (const std::exception&) { error = "Unable to inspect the complete bundle resource tree."; return false; }
}
bool BuildFlatBundleResourceSeal(const fs::path& bundle, BundleResourceSeal& seal, std::string& error) {
    bool completed = false;
    OperationSpan phase("signing.resources-build", JsonValue::ObjectValue(), [&] { return completed; });
    seal = {}; error.clear();
    try {
        if (!Active(error)) return false;
        BundleResourceSeal result; std::string executable; Inventory inventory;
        if (!BundleInfo(bundle, result, executable, error) || !Scan(bundle, executable, inventory, error)) return false;
        Plist resources; resources.value = plist_new_dict();
        const auto legacy = plist_new_dict(), current = plist_new_dict();
        plist_dict_set_item(resources.value, "files", legacy); plist_dict_set_item(resources.value, "files2", current);
        plist_dict_set_item(resources.value, "rules", RuleDictionary(false)); plist_dict_set_item(resources.value, "rules2", RuleDictionary(true));
        for (const auto& [key, entry] : inventory) {
            if (!Active(error)) return false;
            const auto old_policy = Select(key, false), policy = Select(key, true);
            if (!policy.included && (!old_policy.included || entry.symlink)) continue;
            std::string sha1, sha256;
            if (!entry.symlink && !FileHashes(entry.path, sha1, sha256, error)) return false;
            if (old_policy.included && !entry.symlink) {
                const auto data = plist_new_data(sha1.data(), sha1.size());
                if (!old_policy.optional) plist_dict_set_item(legacy, key.c_str(), data);
                else {
                    const auto value = plist_new_dict(); plist_dict_set_item(value, "hash", data);
                    plist_dict_set_item(value, "optional", plist_new_bool(1)); plist_dict_set_item(legacy, key.c_str(), value);
                }
            }
            if (policy.included) {
                const auto value = plist_new_dict();
                if (entry.symlink) plist_dict_set_item(value, "symlink", plist_new_string(entry.target.c_str()));
                else {
                    plist_dict_set_item(value, "hash", plist_new_data(sha1.data(), sha1.size()));
                    plist_dict_set_item(value, "hash2", plist_new_data(sha256.data(), sha256.size()));
                }
                if (policy.optional) plist_dict_set_item(value, "optional", plist_new_bool(1));
                plist_dict_set_item(current, key.c_str(), value);
            }
        }
        char* xml = nullptr; uint32_t size = 0;
        const auto status = plist_to_xml(resources.value, &xml, &size);
        const auto release = [](char* value) { plist_mem_free(value); };
        std::unique_ptr<char, decltype(release)> owner(xml, release);
        if (status != PLIST_ERR_SUCCESS || !xml || !size || size > plist_limit) { error = "CodeResources serialization exceeds the supported bounds."; return false; }
        result.code_resources.assign(xml, size);
        if (!VerifyFlatBundleResourceSeal(bundle, result.code_resources, error)) return false;
        std::string current_info;
        if (!ReadSmall(bundle / "Info.plist", current_info) || current_info != result.info_plist) { error = "Bundle Info.plist changed during resource production."; return false; }
        seal = std::move(result); completed = true; return true;
    } catch (const std::exception&) { error = "Unable to produce the complete bundle resource seal."; return false; }
}
}
