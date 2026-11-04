#include "content_hash.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <algorithm>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include "operation_events.hpp"
namespace OpenFruit {
namespace {
struct Hash {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    Hash() {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0)
            BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    }
    ~Hash() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    bool Add(const char* bytes, DWORD size) {
        return hash && BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes)), size, 0) >= 0;
    }
    std::optional<std::string> Finish() {
        std::array<UCHAR, 32> digest{};
        if (!hash || BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) return {};
        constexpr char hex[] = "0123456789abcdef";
        std::string result;
        for (const auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
        return result;
    }
};
}
std::optional<std::string> Sha256(std::string_view bytes) {
    Hash hash;
    for (std::size_t offset = 0; offset < bytes.size();) {
        const auto count = static_cast<DWORD>((bytes.size() - offset) > 1024 * 1024 ? 1024 * 1024 : bytes.size() - offset);
        if (!hash.Add(bytes.data() + offset, count)) return {};
        offset += count;
    }
    return hash.Finish();
}
struct Sha256Stream::Impl {Hash hash;bool finished=false;};
Sha256Stream::Sha256Stream():state_(std::make_unique<Impl>()){}
Sha256Stream::~Sha256Stream()=default;
bool Sha256Stream::Update(std::string_view bytes){if(state_->finished)return false;for(std::size_t p=0;p<bytes.size();){const auto n=static_cast<DWORD>(std::min<std::size_t>(1024*1024,bytes.size()-p));if(!state_->hash.Add(bytes.data()+p,n))return false;p+=n;}return true;}
std::optional<std::string> Sha256Stream::Finish(){if(state_->finished)return {};state_->finished=true;return state_->hash.Finish();}
std::optional<std::string> Sha256File(const std::filesystem::path& path, CancellationToken cancellation,
    std::chrono::steady_clock::time_point deadline) {
    std::error_code path_error;
    auto absolute = std::filesystem::absolute(path, path_error).lexically_normal().wstring();
    if (path.empty() || path_error) return {};
    if (absolute.rfind(L"\\\\?\\", 0) != 0)
        absolute = absolute.rfind(L"\\\\", 0) == 0 ? L"\\\\?\\UNC\\" + absolute.substr(2) : L"\\\\?\\" + absolute;
    HANDLE file = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    const auto result=Sha256FileHandle(file,cancellation,deadline);
    CloseHandle(file);return result;
}
namespace {
struct FileStat {
    unsigned long long size = 0, write = 0, change = 0, volume = 0, index = 0;
    bool operator==(const FileStat&) const = default;
};
struct StatDigests {
    std::mutex mutex;
    std::filesystem::path loaded;
    std::unordered_map<std::wstring, std::pair<FileStat, std::string>> entries;
};
StatDigests& SharedStatDigests() { static StatDigests digests; return digests; }

// `key` names the file in the cache; an empty key names it by its identity.
std::optional<std::string> CachedHandleDigest(HANDLE file, std::wstring key, const std::filesystem::path& cache_file,
    CancellationToken cancellation, std::chrono::steady_clock::time_point deadline) {
    FILE_BASIC_INFO basic{};
    BY_HANDLE_FILE_INFORMATION info{};
    std::optional<FileStat> stat;
    if (GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) && GetFileInformationByHandle(file, &info)) {
        stat = FileStat{(static_cast<unsigned long long>(info.nFileSizeHigh) << 32) | info.nFileSizeLow,
            static_cast<unsigned long long>(basic.LastWriteTime.QuadPart), static_cast<unsigned long long>(basic.ChangeTime.QuadPart),
            info.dwVolumeSerialNumber, (static_cast<unsigned long long>(info.nFileIndexHigh) << 32) | info.nFileIndexLow};
        if (key.empty()) key = L"file-id:" + std::to_wstring(stat->volume) + L":" + std::to_wstring(stat->index);
    }
    auto& digests = SharedStatDigests();
    if (stat && !cache_file.empty()) {
        std::lock_guard lock(digests.mutex);
        if (digests.loaded != cache_file) {
            digests.entries.clear();
            digests.loaded = cache_file;
            std::ifstream input(cache_file, std::ios::binary);
            for (std::string line; std::getline(input, line);) {
                std::istringstream fields(line);
                FileStat known;
                std::string digest, name;
                if (!(fields >> known.size >> known.write >> known.change >> known.volume >> known.index >> digest)) continue;
                fields.get();
                std::getline(fields, name);
                if (digest.size() == 64 && !name.empty())
                    digests.entries[std::filesystem::u8path(name).wstring()] = {known, digest};
            }
        }
        if (const auto found = digests.entries.find(key); found != digests.entries.end() && found->second.first == *stat)
            return found->second.second;
    }
    const auto result = Sha256FileHandle(file, cancellation, deadline);
    if (result && stat && !cache_file.empty()) {
        std::lock_guard lock(digests.mutex);
        digests.entries[key] = {*stat, *result};
        std::error_code ignored;
        std::filesystem::create_directories(cache_file.parent_path(), ignored);
        // Appending keeps concurrent writers safe; a later line for the same file wins on load.
        std::string name(static_cast<std::size_t>(WideCharToMultiByte(CP_UTF8, 0, key.c_str(), static_cast<int>(key.size()),
            nullptr, 0, nullptr, nullptr)), '\0');
        WideCharToMultiByte(CP_UTF8, 0, key.c_str(), static_cast<int>(key.size()), name.data(), static_cast<int>(name.size()),
            nullptr, nullptr);
        std::ofstream output(cache_file, std::ios::binary | std::ios::app);
        output << stat->size << ' ' << stat->write << ' ' << stat->change << ' ' << stat->volume << ' ' << stat->index
               << ' ' << *result << ' ' << name << '\n';
    }
    return result;
}
}
std::optional<std::string> Sha256FileStatCached(const std::filesystem::path& path, const std::filesystem::path& cache_file,
    std::chrono::steady_clock::time_point deadline) {
    std::error_code path_error;
    auto absolute = std::filesystem::absolute(path, path_error).lexically_normal().wstring();
    if (path.empty() || path_error) return {};
    const auto key = absolute;
    if (absolute.rfind(L"\\\\?\\", 0) != 0)
        absolute = absolute.rfind(L"\\\\", 0) == 0 ? L"\\\\?\\UNC\\" + absolute.substr(2) : L"\\\\?\\" + absolute;
    HANDLE file = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    const auto result = CachedHandleDigest(file, key, cache_file, {}, deadline);
    CloseHandle(file);
    return result;
}
std::optional<std::string> Sha256FileHandleStatCached(void* native_handle, const std::filesystem::path& cache_file,
    CancellationToken cancellation, std::chrono::steady_clock::time_point deadline) {
    const auto file = static_cast<HANDLE>(native_handle);
    if (!file || file == INVALID_HANDLE_VALUE || GetFileType(file) != FILE_TYPE_DISK) return {};
    return CachedHandleDigest(file, {}, cache_file, cancellation, deadline);
}
std::optional<std::string> Sha256FileHandle(void* native_handle,CancellationToken cancellation,
    std::chrono::steady_clock::time_point deadline){
    const auto file=static_cast<HANDLE>(native_handle);if(!file||file==INVALID_HANDLE_VALUE||GetFileType(file)!=FILE_TYPE_DISK)return {};
    LARGE_INTEGER start{};if(!SetFilePointerEx(file,start,nullptr,FILE_BEGIN))return {};
    Hash hash;const auto context=CurrentOperationContext();
    std::array<char, 64 * 1024> bytes{};
    bool good = true;
    for (;;) {
        if (cancellation.Requested() || std::chrono::steady_clock::now() >= deadline ||
            (context&&(context->CancellationRequested()||context->DeadlineExceeded()))) { good = false; break; }
        DWORD count = 0;
        if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)) { good = false; break; }
        if (!count) break;
        if (!hash.Add(bytes.data(), count)) { good = false; break; }
    }
    return good ? hash.Finish() : std::nullopt;
}
}
