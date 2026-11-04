#include "carthage_resolver.hpp"

#include "archive_shim.hpp"
#include "json_value.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <urlmon.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

struct BinarySpec {
    std::string metadata_url;
    std::string version;
};

std::wstring ExtendedWin32Path(const fs::path& input) {
    fs::path absolute = input;
    std::error_code ec;
    if (!absolute.is_absolute()) {
        absolute = fs::absolute(absolute, ec);
        if (ec) absolute = input;
    }

    const std::wstring value = absolute.lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) == 0) return value;
    if (value.rfind(L"\\\\", 0) == 0) {
        return L"\\\\?\\UNC\\" + value.substr(2);
    }
    return L"\\\\?\\" + value;
}

fs::path ExtendedFsPath(const fs::path& input) {
    return fs::path(ExtendedWin32Path(input));
}

fs::path LogicalFsPath(const fs::path& input) {
    const std::wstring value = input.lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        return fs::path(L"\\\\" + value.substr(8));
    }
    if (value.rfind(L"\\\\?\\", 0) == 0) {
        return fs::path(value.substr(4));
    }
    return input.lexically_normal();
}

std::string Sha256Bytes(const void* data, std::size_t size) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD result_size = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest(32);
    std::string result;

    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return {};
    }
    if (BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
            &result_size, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    object.resize(object_size);
    if (BCryptCreateHash(
            algorithm, &hash, object.data(), object_size,
            nullptr, 0, 0) != 0 ||
        BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
            static_cast<ULONG>(size), 0) != 0 ||
        BCryptFinishHash(hash, digest.data(),
                         static_cast<ULONG>(digest.size()), 0) != 0) {
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    static constexpr char hex[] = "0123456789abcdef";
    result.reserve(digest.size() * 2);
    for (unsigned char byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}

std::string Sha256String(const std::string& value) {
    return Sha256Bytes(value.data(), value.size());
}

std::string Sha256File(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD result_size = 0;
    std::vector<unsigned char> object;
    std::vector<unsigned char> digest(32);
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 ||
        BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
            &result_size, 0) != 0) {
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    object.resize(object_size);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size,
                         nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    std::vector<char> buffer(1024 * 1024);
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0 && BCryptHashData(
                hash, reinterpret_cast<PUCHAR>(buffer.data()),
                static_cast<ULONG>(count), 0) != 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }
    }
    if (BCryptFinishHash(hash, digest.data(),
                         static_cast<ULONG>(digest.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}

std::string UrlEncode(const std::string& value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            result.push_back(static_cast<char>(c));
        } else {
            result.push_back('%');
            result.push_back(hex[c >> 4]);
            result.push_back(hex[c & 0x0f]);
        }
    }
    return result;
}

std::optional<std::string> GitLabRawApiUrl(const std::string& url) {
    const std::size_t scheme = url.find("://");
    if (scheme == std::string::npos) return std::nullopt;
    const std::size_t path_start = url.find('/', scheme + 3);
    if (path_start == std::string::npos) return std::nullopt;
    const std::string origin = url.substr(0, path_start);
    std::string path = url.substr(path_start + 1);
    std::size_t raw = path.find("/-/raw/");
    std::size_t marker_size = 7;
    if (raw == std::string::npos) {
        raw = path.find("/raw/");
        marker_size = 5;
    }
    if (raw == std::string::npos || raw == 0) return std::nullopt;
    const std::string project = path.substr(0, raw);
    const std::string tail = path.substr(raw + marker_size);
    const std::size_t slash = tail.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= tail.size()) {
        return std::nullopt;
    }
    const std::string ref = tail.substr(0, slash);
    const std::string file = tail.substr(slash + 1);
    return origin + "/api/v4/projects/" + UrlEncode(project) +
        "/repository/files/" + UrlEncode(file) + "/raw?ref=" + UrlEncode(ref);
}

bool Download(const std::string& source, const fs::path& destination) {
    std::error_code ec;
    fs::remove(destination, ec);
    const fs::path local(source);
    if (source.find("://") == std::string::npos &&
        fs::is_regular_file(local, ec) && !ec) {
        return fs::copy_file(local, destination,
                             fs::copy_options::overwrite_existing, ec) && !ec;
    }
    return SUCCEEDED(URLDownloadToFileW(
        nullptr,
        Win32Process::ToWide(source).c_str(),
        destination.c_str(), 0, nullptr
    ));
}

std::vector<BinarySpec> ParseCartfile(const fs::path& cartfile) {
    std::vector<BinarySpec> result;
    std::ifstream input(cartfile, std::ios::binary);
    std::string line;
    const std::regex exact(
        R"cart(^\s*binary\s+"([^"]+)"\s*==\s*"?([^\s"]+)"?\s*(?:#.*)?$)cart",
        std::regex::icase
    );
    while (std::getline(input, line)) {
        std::smatch match;
        if (std::regex_match(line, match, exact) && match.size() >= 3) {
            result.push_back({match[1].str(), match[2].str()});
        }
    }
    return result;
}

std::optional<JsonValue> FetchMetadata(
    const BinarySpec& spec,
    const fs::path& destination
) {
    if (!Download(spec.metadata_url, destination)) return std::nullopt;
    std::string parse_error;
    auto parsed = JsonValue::Parse(ReadFileText(destination), &parse_error);
    if (parsed && parsed->IsObject()) return parsed;

    const auto fallback = GitLabRawApiUrl(spec.metadata_url);
    if (!fallback || !Download(*fallback, destination)) return std::nullopt;
    parsed = JsonValue::Parse(ReadFileText(destination), &parse_error);
    if (!parsed || !parsed->IsObject()) return std::nullopt;
    return parsed;
}

std::vector<fs::path> FindXcframeworks(const fs::path& root) {
    std::vector<fs::path> result;
    std::error_code ec;
    const fs::path native_root = ExtendedFsPath(root);
    if (!fs::is_directory(native_root, ec) || ec) return result;
    for (fs::recursive_directory_iterator it(
             native_root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (it->is_directory(ec) && !ec &&
            ToLowerAscii(it->path().extension().string()) == ".xcframework") {
            if (fs::is_regular_file(it->path() / "Info.plist", ec) && !ec) {
                result.push_back(LogicalFsPath(it->path()));
            }
            it.disable_recursion_pending();
        }
        ec.clear();
    }
    return result;
}

std::vector<fs::path> FindIosDeviceFrameworks(
    const std::vector<fs::path>& xcframeworks
) {
    std::vector<fs::path> result;
    std::unordered_set<std::wstring> seen;
    for (const auto& xcframework : xcframeworks) {
        std::error_code ec;
        const fs::path native_xcframework = ExtendedFsPath(xcframework);
        for (fs::directory_iterator slice(
                 native_xcframework,
                 fs::directory_options::skip_permission_denied, ec);
             slice != fs::directory_iterator(); slice.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!slice->is_directory(ec) || ec) {
                ec.clear();
                continue;
            }
            const std::string identifier =
                ToLowerAscii(slice->path().filename().string());
            if (identifier.rfind("ios-", 0) != 0 ||
                identifier.find("simulator") != std::string::npos ||
                identifier.find("maccatalyst") != std::string::npos) {
                continue;
            }

            std::error_code framework_ec;
            for (fs::directory_iterator framework(
                     slice->path(),
                     fs::directory_options::skip_permission_denied,
                     framework_ec);
                 framework != fs::directory_iterator();
                 framework.increment(framework_ec)) {
                if (framework_ec) { framework_ec.clear(); continue; }
                if (!framework->is_directory(framework_ec) || framework_ec ||
                    ToLowerAscii(framework->path().extension().string()) !=
                        ".framework") {
                    framework_ec.clear();
                    continue;
                }
                const fs::path normalized =
                    LogicalFsPath(framework->path());
                std::wstring key = normalized.wstring();
                std::transform(
                    key.begin(), key.end(), key.begin(), ::towlower);
                if (seen.insert(std::move(key)).second) {
                    result.push_back(normalized);
                }
            }
        }
    }
    return result;
}

bool InstallBinarySpec(
    const BinarySpec& spec,
    const fs::path& slot,
    std::vector<fs::path>& installed,
    std::string& error
) {
    const fs::path contents = slot / "contents";
    const fs::path archive = slot / "download.archive";
    const fs::path digest_file = slot / "artifact.sha256";
    installed = FindXcframeworks(contents);
    if (!installed.empty()) {
        std::string expected = ReadFileText(digest_file);
        expected.erase(std::remove_if(expected.begin(), expected.end(),
            [](unsigned char c) { return std::isspace(c) != 0; }), expected.end());
        if (expected.size() == 64 && Sha256File(archive) == expected) {
            return true;
        }

        // An extraction without its verified source archive has uncertain
        // provenance. Discard only this OPENFRUIT-owned cache entry and resolve
        // it again; correctness takes precedence over reuse.
        std::error_code invalid_ec;
        fs::remove_all(ExtendedFsPath(contents), invalid_ec);
        installed.clear();
    }

    std::error_code ec;
    fs::create_directories(ExtendedFsPath(slot), ec);
    if (ec) { error = "cannot create Carthage artifact cache"; return false; }

    const fs::path metadata_file = slot / "metadata.json";
    const auto metadata = FetchMetadata(spec, metadata_file);
    if (!metadata) {
        error = "binary Cartfile metadata is unavailable or not valid JSON: " +
            spec.metadata_url;
        return false;
    }
    const JsonValue* version = metadata->Get(spec.version);
    if (!version || !version->IsString() || version->StringValue().empty()) {
        error = "binary Cartfile metadata has no requested version " + spec.version;
        return false;
    }

    if (!Download(version->StringValue(), archive)) {
        error = "failed downloading Carthage binary artifact: " +
            version->StringValue();
        return false;
    }
    const std::string content_hash = Sha256File(archive);
    if (content_hash.empty()) {
        error = "failed hashing downloaded Carthage binary artifact";
        return false;
    }

    const fs::path temporary = slot /
        ("extract.tmp-" + std::to_string(GetCurrentProcessId()));
    fs::remove_all(ExtendedFsPath(temporary), ec);
    fs::create_directories(ExtendedFsPath(temporary), ec);
    std::size_t links = 0;
    if (ec || !ArchiveShim::ExtractArchiveCompat(archive, temporary, &links)) {
        fs::remove_all(ExtendedFsPath(temporary), ec);
        error = "failed extracting Carthage binary artifact";
        return false;
    }
    installed = FindXcframeworks(temporary);
    if (installed.empty()) {
        fs::remove_all(ExtendedFsPath(temporary), ec);
        error = "Carthage binary artifact contains no valid XCFramework";
        return false;
    }

    fs::remove_all(ExtendedFsPath(contents), ec);
    ec.clear();
    fs::rename(ExtendedFsPath(temporary), ExtendedFsPath(contents), ec);
    if (ec) {
        fs::remove_all(ExtendedFsPath(temporary), ec);
        error = "failed committing extracted Carthage artifact atomically";
        return false;
    }
    installed = FindXcframeworks(contents);
    std::ofstream marker(digest_file, std::ios::binary | std::ios::trunc);
    marker << content_hash << "\n";
    std::cout << "OPENFRUIT Carthage: cached exact binary " << spec.version
              << " as sha256:" << content_hash << " (" << links
              << " Unix symlink(s) materialized)." << std::endl;
    return !installed.empty();
}

} // namespace

CarthageResolveResult ResolveCarthageBinaryFrameworks(
    const fs::path& source_root,
    const std::vector<fs::path>& declared_frameworks
) {
    CarthageResolveResult result;
    result.success = true;
    const fs::path cartfile = source_root / "Cartfile";
    if (!fs::is_regular_file(cartfile)) return result;

    std::unordered_map<std::string, fs::path> missing;
    for (const auto& framework : declared_frameworks) {
        if (ToLowerAscii(framework.extension().string()) == ".xcframework" &&
            !fs::exists(framework)) {
            missing.emplace(ToLowerAscii(framework.filename().string()), framework);
        }
    }
    if (missing.empty()) return result;

    const auto specs = ParseCartfile(cartfile);
    for (const auto& spec : specs) {
        const std::string identity = Sha256String(
            "carthage-binary-v1\n" + spec.metadata_url + "\n" + spec.version
        );
        if (identity.empty()) {
            result.success = false;
            result.error = "failed deriving Carthage cache identity";
            return result;
        }
        const fs::path slot = ToolPaths::CacheRoot() / "artifacts" /
            "carthage" / "v1" / identity;
        const std::wstring mutex_name = L"Local\\OPENFRUIT-Carthage-" +
            Win32Process::ToWide(identity.substr(0, 24));
        HANDLE mutex = CreateMutexW(nullptr, FALSE, mutex_name.c_str());
        if (!mutex) {
            result.success = false;
            result.error = "failed creating Carthage cache lock";
            return result;
        }
        const DWORD wait = WaitForSingleObject(mutex, 30 * 60 * 1000);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
            CloseHandle(mutex);
            result.success = false;
            result.error = "timed out waiting for Carthage cache lock";
            return result;
        }
        std::vector<fs::path> installed;
        std::string error;
        const bool ok = InstallBinarySpec(spec, slot, installed, error);
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        if (!ok) {
            result.success = false;
            result.error = std::move(error);
            return result;
        }
        for (const auto& framework : installed) {
            const std::string name = ToLowerAscii(framework.filename().string());
            if (missing.erase(name) > 0) {
                result.frameworks.push_back(framework);
                const auto slices = FindIosDeviceFrameworks({framework});
                result.device_frameworks.insert(
                    result.device_frameworks.end(), slices.begin(), slices.end());
            }
        }
        if (missing.empty()) break;
    }

    if (!missing.empty()) {
        result.success = false;
        result.error = "Cartfile did not resolve every missing XCFramework declared by the selected target";
    } else if (!result.frameworks.empty() && result.device_frameworks.empty()) {
        result.success = false;
        result.error = "resolved Carthage XCFramework has no iOS device framework slice";
    }
    return result;
}

} // namespace OpenFruit
