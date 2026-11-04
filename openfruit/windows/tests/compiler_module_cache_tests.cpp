#include "compiler_module_cache.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"

#include <winioctl.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* error) { if (!value) throw std::runtime_error(error); }
void Write(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Require(static_cast<bool>(output), "Cannot write owned identity fixture");
}
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    Require(static_cast<bool>(input), "Cannot read owned fixture");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
struct Fixture {
    fs::path root = fs::temp_directory_path() / ("OPENFRUIT-module-cache-" + NewOperationId());
    fs::path cache = root / "Cache";
    fs::path compiler = root / "Toolchain" / "swiftc.exe";
    fs::path frontend = compiler.parent_path() / "swift-frontend.exe";
    fs::path sdk = root / "Owned.sdk";
    Fixture() {
        // These are inert identity inputs, never launched as compiler binaries.
        Write(compiler, "owned-compiler-identity-v1");
        Write(frontend, "owned-frontend-identity-v1");
        Write(sdk / "SDKSettings.json", "{\"CanonicalName\":\"owned-test-sdk\",\"Version\":\"1.0\"}\n");
        fs::create_directories(cache);
    }
    ~Fixture() { std::error_code error; fs::remove_all(root, error); }
    CompilerModuleCacheResult Prepare(const std::wstring& target = L"arm64-apple-ios17.0",
                                      const std::wstring& configuration = L"Debug",
                                      const std::wstring& module = L"OwnedModule",
                                      const std::string& policy = "unmodified-sdk-v2") const {
        return PrepareCompilerModuleCache(cache, compiler, sdk, target, configuration, module, policy);
    }
};
void CheckSuccess(const CompilerModuleCacheResult& result) {
    if (!result.success) throw std::runtime_error("Module cache preparation failed: " + result.error);
    Require(!result.key.empty() && !result.path.empty() && fs::is_directory(result.path), "Successful cache has no identity/directory");
    const auto marker = JsonValue::Parse(Read(result.path / "cache-context.json"));
    Require(marker && marker->IsObject(), "Cache marker is not JSON");
    Require(marker->GetString("key") == result.key, "Cache marker key disagrees with selected namespace");
    Require(!marker->GetString("schema").empty(), "Cache marker lacks a schema");
}
void Different(const CompilerModuleCacheResult& before, const CompilerModuleCacheResult& after, const char* error) {
    CheckSuccess(after);
    Require(before.key != after.key && before.path != after.path, error);
}
void TestIdentityDimensionsAndWarmReuse() {
    Fixture fixture;
    const auto first = fixture.Prepare();
    CheckSuccess(first);
    const auto marker = Read(first.path / "cache-context.json");
    const auto marker_time = fs::last_write_time(first.path / "cache-context.json");
    Write(first.path / "Owned.pcm", "owned-warm-pcm-sentinel");
    Write(fixture.cache / "modules" / "apps" / "unmodified-sdk-v2" / "Legacy.pcm", "owned-legacy-cache-sentinel");
    const auto legacy = fixture.cache / "modules" / "apps" / "unmodified-sdk-v2" / "Legacy.pcm";
    const auto legacy_digest = Sha256File(legacy);
    const auto compiler_digest = Sha256File(fixture.compiler);
    const auto frontend_digest = Sha256File(fixture.frontend);
    const auto sdk_digest = Sha256File(fixture.sdk / "SDKSettings.json");
    const auto warm = fixture.Prepare();
    CheckSuccess(warm);
    Require(first.key == warm.key && first.path == warm.path, "Warm cache did not reuse canonical namespace");
    Require(Read(warm.path / "cache-context.json") == marker && fs::last_write_time(warm.path / "cache-context.json") == marker_time,
            "Warm preparation rewrote valid marker");
    Require(Read(warm.path / "Owned.pcm") == "owned-warm-pcm-sentinel", "Warm cache data was erased");
    Require(first.path != legacy.parent_path() && Sha256File(legacy) == legacy_digest, "Legacy cache was admitted or changed");
    Write(fixture.root / "unrelated.txt", "owned-unrelated-change");
    const auto unrelated = fixture.Prepare();
    CheckSuccess(unrelated);
    Require(unrelated.key == first.key && unrelated.path == first.path, "Unrelated file invalidated compiler cache");
    const auto sdk_alias = fixture.sdk.parent_path() / "owned.sdk";
    std::error_code alias_error;
    if (fs::equivalent(fixture.sdk, sdk_alias, alias_error) && !alias_error) {
        const auto alternate_sdk = PrepareCompilerModuleCache(fixture.cache, fixture.compiler, sdk_alias,
            L"arm64-apple-ios17.0", L"Debug", L"OwnedModule", "unmodified-sdk-v2");
        Different(first, alternate_sdk, "Different forwarded SDK spelling admitted old serialized header paths");
    }
    Different(first, fixture.Prepare(L"arm64-apple-ios18.0"), "Deployment target did not separate cache");
    Different(first, fixture.Prepare(L"x86_64-apple-ios17.0-simulator"), "Architecture/platform did not separate cache");
    Different(first, fixture.Prepare(L"arm64-apple-ios17.0", L"Release"), "Configuration did not separate cache");
    Different(first, fixture.Prepare(L"arm64-apple-ios17.0", L"Debug", L"OtherOwnedModule"), "Module did not separate cache");
    Different(first, fixture.Prepare(L"arm64-apple-ios17.0", L"Debug", L"OwnedModule", "owned-policy-v3"), "SDK input policy did not separate cache");
    Require(Sha256File(fixture.compiler) == compiler_digest && Sha256File(fixture.frontend) == frontend_digest &&
            Sha256File(fixture.sdk / "SDKSettings.json") == sdk_digest, "Cache preparation modified identity inputs");
}
void TestSamePathContentReplacement() {
    Fixture fixture;
    const auto original = fixture.Prepare(); CheckSuccess(original);
    Write(fixture.compiler, "owned-compiler-identity-v2");
    const auto compiler_changed = fixture.Prepare();
    Different(original, compiler_changed, "Compiler content replacement retained cache identity");
    Write(fixture.frontend, "owned-frontend-identity-v2");
    const auto frontend_changed = fixture.Prepare();
    Different(compiler_changed, frontend_changed, "Frontend content replacement retained cache identity");
    Write(fixture.sdk / "SDKSettings.json", "{\"CanonicalName\":\"owned-test-sdk\",\"Version\":\"2.0\"}\n");
    Different(frontend_changed, fixture.Prepare(), "SDK settings replacement retained cache identity");
}
void TestMissingIdentityAndMarkerAdmission() {
    for (const int identity : {0, 1, 2}) {
        Fixture fixture;
        fs::remove(identity == 0 ? fixture.compiler : identity == 1 ? fixture.frontend : fixture.sdk / "SDKSettings.json");
        const auto rejected = fixture.Prepare();
        Require(!rejected.success && !rejected.error.empty(), "Missing compiler/frontend/SDK identity was accepted");
    }
    for (const bool corrupt_marker : {false, true}) {
        Fixture fixture;
        const auto first = fixture.Prepare(); CheckSuccess(first);
        Write(first.path / "Owned.pcm", "owned-untrusted-namespace-sentinel");
        if (corrupt_marker) Write(first.path / "cache-context.json", "{\"schema\":\"owned-invalid\",\"key\":\"wrong\"}");
        else fs::remove(first.path / "cache-context.json");
        const auto rejected = fixture.Prepare();
        Require(!rejected.success && !rejected.error.empty(), "Nonempty cache with missing/bad ownership marker was admitted");
        Require(Read(first.path / "Owned.pcm") == "owned-untrusted-namespace-sentinel", "Rejected namespace was erased");
        Require(corrupt_marker ? Read(first.path / "cache-context.json").find("owned-invalid") != std::string::npos :
                !fs::exists(first.path / "cache-context.json"), "Rejected ownership marker was overwritten");
    }
}

// Create an actual directory junction without requiring developer-mode symlinks.
// A restricted filesystem may decline it; that capability is reported explicitly.
bool MakeJunction(const fs::path& link, const fs::path& target) {
    std::error_code error;
    if (!fs::create_directory(link, error)) return false;
    const HANDLE handle = CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { fs::remove(link, error); return false; }
    struct MountPointBuffer {
        DWORD tag; WORD bytes; WORD reserved;
        WORD substitute_offset; WORD substitute_bytes; WORD print_offset; WORD print_bytes;
        wchar_t paths[32768];
    } buffer{};
    const auto printable = fs::absolute(target).wstring();
    const auto substitute = std::wstring(L"\\??\\") + printable;
    const auto count = substitute.size() + 1 + printable.size() + 1;
    Require(count < 32768, "Owned junction target exceeds test bound");
    buffer.tag = IO_REPARSE_TAG_MOUNT_POINT;
    buffer.substitute_bytes = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    buffer.print_offset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
    buffer.print_bytes = static_cast<WORD>(printable.size() * sizeof(wchar_t));
    std::memcpy(buffer.paths, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
    std::memcpy(reinterpret_cast<char*>(buffer.paths) + buffer.print_offset, printable.c_str(), (printable.size() + 1) * sizeof(wchar_t));
    buffer.bytes = static_cast<WORD>(8 + count * sizeof(wchar_t));
    DWORD returned = 0;
    const bool success = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, &buffer, 8 + buffer.bytes,
                                         nullptr, 0, &returned, nullptr) != FALSE;
    CloseHandle(handle);
    if (!success) fs::remove(link, error);
    return success;
}
void TestPhysicalRootAliases() {
    Fixture fixture;
    const auto original = fixture.Prepare(); CheckSuccess(original);
    auto alternate_name = fixture.cache.filename().wstring();
    for (auto& letter : alternate_name) if (letter >= L'A' && letter <= L'Z') letter += L'a' - L'A';
    const auto alternate_root = fixture.cache.parent_path() / alternate_name;
    std::error_code error;
    const bool same_physical = fs::equivalent(fixture.cache, alternate_root, error);
    if (!same_physical) fs::create_directories(alternate_root);
    const auto alternate = PrepareCompilerModuleCache(alternate_root, fixture.compiler, fixture.sdk,
        L"arm64-apple-ios17.0", L"Debug", L"OwnedModule", "unmodified-sdk-v2");
    CheckSuccess(alternate);
    if (same_physical) Require(alternate.key == original.key && alternate.path == original.path,
                              "Physical root casing alias created a second cache namespace");
    else Different(original, alternate, "Distinct case-sensitive roots collapsed into one cache namespace");
    const auto junction = fixture.root / "CacheJunction";
    if (MakeJunction(junction, fixture.cache)) {
        const auto aliased = PrepareCompilerModuleCache(junction, fixture.compiler, fixture.sdk,
            L"arm64-apple-ios17.0", L"Debug", L"OwnedModule", "unmodified-sdk-v2");
        fs::remove(junction, error);
        CheckSuccess(aliased);
        Require(aliased.path == original.path && aliased.key == original.key, "Junction alias did not reuse physical cache namespace");
    } else std::cout << "Directory junction unavailable: junction-only alias check skipped\n";
    Fixture other;
    Different(original, other.Prepare(), "Physically distinct roots with identical file bytes collapsed together");
}
void TestConcurrentPreparation() {
    Fixture fixture;
    const auto compiler = Sha256File(fixture.compiler);
    const auto frontend = Sha256File(fixture.frontend);
    const auto sdk = Sha256File(fixture.sdk / "SDKSettings.json");
    std::vector<CompilerModuleCacheResult> results(12);
    std::vector<std::thread> workers;
    for (std::size_t index = 0; index < results.size(); ++index)
        workers.emplace_back([&, index] { results[index] = fixture.Prepare(); });
    for (auto& worker : workers) worker.join();
    CheckSuccess(results.front());
    const auto marker = Read(results.front().path / "cache-context.json");
    for (const auto& result : results) {
        CheckSuccess(result);
        Require(result.key == results.front().key && result.path == results.front().path,
                "Concurrent preparations selected duplicate namespaces");
        Require(Read(result.path / "cache-context.json") == marker, "Concurrent marker publication was incoherent");
    }
    Require(Sha256File(fixture.compiler) == compiler && Sha256File(fixture.frontend) == frontend &&
            Sha256File(fixture.sdk / "SDKSettings.json") == sdk, "Concurrent preparation modified identity inputs");
}
}

int main() {
    try {
        TestIdentityDimensionsAndWarmReuse();
        TestSamePathContentReplacement();
        TestMissingIdentityAndMarkerAdmission();
        TestPhysicalRootAliases();
        TestConcurrentPreparation();
        std::cout << "Compiler module cache identity, ownership and concurrency contracts: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
