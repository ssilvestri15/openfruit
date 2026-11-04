#include "compiler_module_cache.hpp"

#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
constexpr const char* kSchema = "openfruit.compiler-module-cache-context.v1";
constexpr const char* kReceipt = "cache-context.json";

class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return value_; }
private:
    HANDLE value_;
};

void Check() {
    if (const auto operation = CurrentOperationContext()) {
        if (operation->CancellationRequested())
            throw std::runtime_error("compiler module cache preparation cancelled");
        if (operation->DeadlineExceeded())
            throw std::runtime_error("compiler module cache preparation deadline exceeded");
    }
}

std::wstring Extended(const fs::path& path) {
    const auto absolute = fs::absolute(path).wstring();
    if (absolute.starts_with(L"\\\\?\\")) return absolute;
    if (absolute.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + absolute.substr(2);
    return L"\\\\?\\" + absolute;
}

fs::path PhysicalPath(HANDLE handle) {
    std::vector<wchar_t> buffer(512);
    for (;;) {
        const DWORD length = GetFinalPathNameByHandleW(handle, buffer.data(),
            static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!length) throw std::runtime_error("cannot resolve physical compiler/cache/SDK path");
        if (length >= buffer.size()) {
            if (length > 32768) throw std::runtime_error("physical compiler/cache/SDK path exceeds supported length");
            buffer.resize(static_cast<std::size_t>(length) + 1);
            continue;
        }
        std::wstring value(buffer.data(), length);
        if (value.starts_with(L"\\\\?\\UNC\\")) value = L"\\\\" + value.substr(8);
        else if (value.starts_with(L"\\\\?\\") && value.size() > 5 && value[5] == L':')
            value.erase(0, 4);
        else throw std::runtime_error("physical path has no supported DOS/UNC representation");
        return fs::path(value).lexically_normal();
    }
}

fs::path PhysicalDirectory(const fs::path& path) {
    Check();
    const Handle directory(CreateFileW(Extended(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (directory.Get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot open required compiler cache/SDK directory");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(directory.Get(), &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        throw std::runtime_error("required compiler cache/SDK path is not a directory");
    return PhysicalPath(directory.Get());
}

struct FileIdentity { fs::path path; std::string sha256; };
FileIdentity DescribeFile(const fs::path& path) {
    Check();
    // Hash the same physical object whose spelling was resolved. Deny mutation
    // and replacement while reading rather than reopening an unchecked alias.
    const Handle file(CreateFileW(Extended(path).c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.Get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot read required compiler/SDK identity file: " +
                                 Win32Process::ToNarrow(path.wstring()));
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.Get(), &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        throw std::runtime_error("required compiler/SDK identity input is not a regular file");
    FileIdentity result{PhysicalPath(file.Get()), {}};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    if (const auto operation = CurrentOperationContext(); operation && operation->control)
        deadline = std::min(deadline, operation->control->deadline);
    const auto digest = Sha256FileHandle(file.Get(), {}, deadline);
    Check();
    if (!digest) throw std::runtime_error("cannot hash required compiler/SDK identity file");
    result.sha256 = *digest;
    return result;
}

std::string Utf8(const fs::path& path) { return Win32Process::ToNarrow(path.wstring()); }

// Length-prefix both names and values; embedded delimiters cannot alias another
// context. Sorted field names keep the encoding independent of JSON key order.
std::string ContextKey(const std::map<std::string, std::string>& fields) {
    std::string encoded;
    const auto append = [&](std::string_view text) {
        std::uint64_t size = static_cast<std::uint64_t>(text.size());
        for (unsigned byte = 0; byte != 8; ++byte)
            encoded.push_back(static_cast<char>((size >> (byte * 8)) & 0xff));
        encoded.append(text);
    };
    for (const auto& [name, value] : fields) { append(name); append(value); }
    const auto digest = Sha256(encoded);
    if (!digest) throw std::runtime_error("cannot hash compiler module context");
    return *digest;
}

class InitializerLease {
public:
    explicit InitializerLease(const std::string& key)
        : mutex_(CreateMutexW(nullptr, FALSE,
              (L"Local\\OPENFRUIT.CompilerModuleCache." + Win32Process::ToWide(key)).c_str())) {
        if (!mutex_.Get()) throw std::runtime_error("cannot create compiler module cache initialization lease");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        for (;;) {
            Check();
            const DWORD wait = WaitForSingleObject(mutex_.Get(), 100);
            if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
                acquired_ = true;
                return;
            }
            if (wait != WAIT_TIMEOUT) throw std::runtime_error("cannot acquire compiler module cache initialization lease");
            if (std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error("compiler module cache initialization wait exceeded 30 seconds");
        }
    }
    ~InitializerLease() { if (acquired_) ReleaseMutex(mutex_.Get()); }
private:
    Handle mutex_;
    bool acquired_ = false;
};

void ValidateReceipt(const fs::path& receipt, const std::string& key,
                     const std::string& path_hash, const fs::path& physical,
                     const std::map<std::string, std::string>& fields) {
    const auto status = fs::symlink_status(receipt);
    if (!fs::is_regular_file(status) || fs::file_size(receipt) > 64 * 1024)
        throw std::runtime_error("compiler module cache context receipt is not a bounded regular file");
    std::ifstream input(receipt, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read compiler module cache context receipt");
    std::vector<char> buffer(64 * 1024 + 1);
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto count = static_cast<std::size_t>(input.gcount());
    if (input.bad() || count > 64 * 1024)
        throw std::runtime_error("cannot read bounded compiler module cache context receipt");
    const std::string bytes(buffer.data(), count);
    const auto document = JsonValue::Parse(bytes);
    if (!document || !document->IsObject() || document->GetString("schema") != kSchema ||
        document->GetString("key") != key || document->GetString("path_sha256") != path_hash ||
        document->GetString("physical_path") != Utf8(physical))
        throw std::runtime_error("compiler module cache context receipt identity mismatch");
    const auto* context = document->Get("input_context");
    if (!context || !context->IsObject() || context->ObjectItems().size() != fields.size())
        throw std::runtime_error("compiler module cache context receipt inputs mismatch");
    for (const auto& [name, value] : fields) {
        const auto* entry = context->Get(name);
        if (!entry || !entry->IsString() || entry->StringValue() != value)
            throw std::runtime_error("compiler module cache context receipt inputs mismatch");
    }
}
} // namespace

CompilerModuleCacheResult PrepareCompilerModuleCache(
    const fs::path& cache_root, const fs::path& swiftc, const fs::path& sdk_root,
    const std::wstring& target, const std::wstring& configuration,
    const std::wstring& module_name, const std::string& sdk_input_policy) {
    CompilerModuleCacheResult result;
    try {
        Check();
        if (cache_root.empty() || swiftc.empty() || sdk_root.empty() || target.empty() ||
            configuration.empty() || module_name.empty() || sdk_input_policy.empty())
            throw std::runtime_error("compiler module cache identity requires every input");
        const auto compiler = DescribeFile(swiftc);
        const auto frontend = DescribeFile(compiler.path.parent_path() / "swift-frontend.exe");
        const auto sdk = PhysicalDirectory(sdk_root);
        const auto settings_json = sdk / "SDKSettings.json";
        const auto settings = DescribeFile(fs::exists(settings_json)
            ? settings_json : sdk / "SDKSettings.plist");
        const auto requested_prefix = cache_root / "modules" / "apps" / "clang-identity-v1";
        fs::create_directories(requested_prefix);
        const auto prefix = PhysicalDirectory(requested_prefix);
        const std::map<std::string, std::string> fields = {
            {"schema", kSchema}, {"physical_prefix", Utf8(prefix)},
            // The caller still forwards these argument spellings. Until the
            // compiler/SDK arguments themselves are normalized, do not share
            // serialized header/resource references across their aliases.
            {"swiftc_argument", Utf8(swiftc)}, {"sdk_argument", Utf8(sdk_root)},
            {"swiftc_path", Utf8(compiler.path)}, {"swiftc_sha256", compiler.sha256},
            {"frontend_path", Utf8(frontend.path)}, {"frontend_sha256", frontend.sha256},
            {"sdk_root", Utf8(sdk)}, {"sdk_settings_path", Utf8(settings.path)},
            {"sdk_settings_sha256", settings.sha256},
            {"target", Win32Process::ToNarrow(target)},
            {"configuration", Win32Process::ToNarrow(configuration)},
            {"module_name", Win32Process::ToNarrow(module_name)},
            {"sdk_input_policy", sdk_input_policy}
        };
        const auto key = ContextKey(fields);
        // This lease protects only directory/receipt admission. It is released
        // before returning; Clang owns the actual PCM construction locks.
        const InitializerLease initializer(key);
        Check();
        const auto requested_path = prefix / key;
        fs::create_directory(requested_path);
        const auto physical = PhysicalDirectory(requested_path);
        if (physical.parent_path() != prefix || physical.filename() != fs::path(key))
            throw std::runtime_error("compiler module cache namespace redirects outside its identity directory");
        const auto path_hash = Sha256(Utf8(physical));
        if (!path_hash) throw std::runtime_error("cannot hash physical compiler module cache path");
        const auto receipt = physical / kReceipt;
        const auto receipt_status = fs::symlink_status(receipt);
        if (fs::exists(receipt_status)) {
            ValidateReceipt(receipt, key, *path_hash, physical, fields);
        } else {
            if (!fs::is_empty(physical))
                throw std::runtime_error("compiler module cache contains files without a verified context receipt");
            auto document = JsonValue::ObjectValue();
            document.Set("schema", JsonValue::String(kSchema));
            document.Set("key", JsonValue::String(key));
            document.Set("path_sha256", JsonValue::String(*path_hash));
            document.Set("physical_path", JsonValue::String(Utf8(physical)));
            auto context = JsonValue::ObjectValue();
            for (const auto& [name, value] : fields) context.Set(name, JsonValue::String(value));
            document.Set("input_context", std::move(context));
            Check();
            if (!AtomicFile::Publish(receipt, document.Serialize(true)))
                throw std::runtime_error("cannot atomically publish compiler module cache context receipt");
            ValidateReceipt(receipt, key, *path_hash, physical, fields);
        }
        Check();
        result.path = physical;
        result.key = key;
        result.success = true;
    } catch (const std::exception& error) {
        result.error = error.what();
    }
    return result;
}
} // namespace OpenFruit
