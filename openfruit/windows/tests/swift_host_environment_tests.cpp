#include "utf8_path.hpp"
#include "environment_manager.hpp"
#include "artifact_store.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <regex>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
std::wstring Env(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    const auto written = GetEnvironmentVariableW(name, value.data(), size);
    Require(written < size, "Environment changed during observation");
    value.resize(written);
    return value;
}
struct ScopedEnv {
    std::wstring name, previous;
    bool present;
    ScopedEnv(const wchar_t* key, const fs::path& value) : name(key) {
        SetLastError(ERROR_SUCCESS);
        const DWORD size = GetEnvironmentVariableW(key, nullptr, 0);
        present = size != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
        previous = Env(key);
        Require(SetEnvironmentVariableW(key, value.c_str()) != FALSE, "Cannot set child test environment");
    }
    ~ScopedEnv() { SetEnvironmentVariableW(name.c_str(), present ? previous.c_str() : nullptr); }
};
}

int main(int argc, char** argv) {
    fs::path root;
    try {
        if (argc == 4 && std::string(argv[1]) == "--crash-after-import-copy") {
            const bool imported = NativeArtifactStore::ImportTreeTransactional(
                Utf8Path(argv[2]), Utf8Path(argv[3]), [](const fs::path&) -> bool {
                    // Abrupt process death leaves the real prepublication owner
                    // receipt and copied original files; no stack cleanup runs.
                    ExitProcess(23);
                    return false;
                });
            return imported ? 24 : 25;
        }
        Require(argc == 1 || argc == 2, "usage: swift_host_environment_tests [input-toolchain-bin]");
        const auto config = Config::Load(L"", false);
        fs::path bin = argc == 2 ? Utf8Path(argv[1]) : fs::path(config.toolchain_path);
        if (argc == 1 && (!fs::is_regular_file(bin / "swift.exe") || !fs::is_regular_file(bin / "swiftc.exe")))
            bin = ToolPaths::SwiftBin({});
        if (!fs::is_regular_file(bin / "swift.exe") || !fs::is_regular_file(bin / "swiftc.exe")) {
            std::cerr << "SKIP: installed Windows Swift prerequisites unavailable\n";
            return 77;
        }
        bin = fs::absolute(bin).lexically_normal();
        const auto compiler_hash = Sha256File(bin / "swiftc.exe");
        Require(compiler_hash.has_value(), "Cannot record original compiler identity");
        root = fs::temp_directory_path() / ("OPENFRUIT-host-environment-" + NewOperationId());
        Require(fs::create_directory(root), "Cannot reserve owned host test workspace");
        const auto package = root / "package";
        fs::create_directory(package);
        { std::ofstream manifest(package / "Package.swift");
          manifest << "// swift-tools-version: 6.0\nimport PackageDescription\n"
                      "let package = Package(name: \"OwnedBootstrapHost\")\n"; }
        const ScopedEnv user_state(L"OPENFRUIT_USER_STATE", root / "user-state");
        const ScopedEnv stale_sdk(L"SDKROOT", root / "deleted-host-sdk");
        const auto original_path = Env(L"PATH");
        const auto stale_value = Env(L"SDKROOT");

        // A controlled bad ambient input is the negative control. Neither SDK
        // nor runtime paths are supplied to the candidate service below.
        ProcessRunOptions controls;
        controls.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
        const auto swift = bin / "swift.exe";
        const auto baseline = Win32Process::Run(swift.wstring(),
            {swift.wstring(), L"package", L"--package-path", package.wstring(),
             L"--cache-path", (root / "baseline-cache").wstring(), L"dump-package"},
            root.wstring(), {}, nullptr, nullptr, controls);
        Require(!baseline.success && baseline.std_err.find("unable to load standard library") != std::string::npos,
                "Bad ambient SDK did not reproduce the original host standard-library failure");
        const auto platform = EnvironmentManager::ResolveSwiftHostPlatform(bin);
        Require(!platform.windows_sdk.empty() && !platform.runtime_bin.empty(),
                "Production environment service did not derive a matching host platform");
        const auto runtime_hash = Sha256File(platform.runtime_bin / "swiftCore.dll");
        Require(runtime_hash.has_value(), "Cannot record original host runtime identity");
        Require(EnvironmentManager::ValidateSwiftHostToolchain(bin),
                "Real bootstrap host validation failed with stale ambient SDKROOT");
        fs::path emitted_manifest;
        for (const auto& entry : fs::recursive_directory_iterator(
                 ToolPaths::UserStateRoot() / "state" / "swift-host-smoke")) {
            if (entry.is_regular_file() && entry.path().filename() == "Package.swift") {
                Require(emitted_manifest.empty(), "Host probe created ambiguous manifest roots");
                emitted_manifest = entry.path();
            }
        }
        Require(!emitted_manifest.empty(), "Host validation left no owned manifest evidence");
        const auto manifest_time = fs::last_write_time(emitted_manifest);
        Require(EnvironmentManager::ValidateSwiftHostToolchain(bin),
                "Warm bootstrap host validation failed");
        auto first = std::async(std::launch::async, [&] { return EnvironmentManager::ValidateSwiftHostToolchain(bin); });
        auto second = std::async(std::launch::async, [&] { return EnvironmentManager::ValidateSwiftHostToolchain(bin); });
        Require(first.get() && second.get(), "Concurrent host validation failed to coordinate manifest ownership");
        Require(fs::last_write_time(emitted_manifest) == manifest_time,
                "Unchanged host validation rewrote the manifest and invalidated warm state");
        Require(Env(L"PATH") == original_path && Env(L"SDKROOT") == stale_value,
                "Host validation changed the parent environment");
        Require(Sha256File(bin / "swiftc.exe") == compiler_hash &&
                Sha256File(platform.runtime_bin / "swiftCore.dll") == runtime_hash,
                "Host validation changed original compiler/runtime bytes");
        Require(!EnvironmentManager::ValidateSwiftHostToolchain(root / "missing") &&
                EnvironmentManager::ResolveSwiftHostPlatform(root / "missing").windows_sdk.empty(),
                "Missing compiler was accepted as a valid host platform");

        // Cross the storage/host boundary using original immutable compiler
        // files. Reuse the recovered publication for discovery admission below.
        const auto managed_home = root / "managed-home";
        const auto slots = managed_home / "toolchains" / "swift";
        const auto published = slots / "owned-compiler";
        fs::create_directories(slots);
        std::wstring executable(32768, L'\0');
        const DWORD executable_size = GetModuleFileNameW(nullptr, executable.data(),
            static_cast<DWORD>(executable.size()));
        Require(executable_size != 0 && executable_size < executable.size(),
                "Cannot locate recovery test child executable");
        executable.resize(executable_size);
        ProcessRunOptions crash_controls;
        crash_controls.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(3);
        const auto crashed = Win32Process::Run(executable,
            {executable, L"--crash-after-import-copy", bin.parent_path().parent_path().wstring(),
             published.wstring()}, root.wstring(), {}, nullptr, nullptr, crash_controls);
        Require(crashed.launched && crashed.exit_code == 23 && !crashed.timed_out,
                "Import child did not crash after copying the original Swift tree");
        Require(!fs::exists(published), "Crash child published the unvalidated Swift tree");
        fs::path abandoned;
        for (const auto& entry : fs::directory_iterator(slots)) {
            if (entry.is_directory() && entry.path().filename().string().find("owned-compiler.partial-") == 0) {
                Require(abandoned.empty(), "Crash child left ambiguous staging roots");
                abandoned = entry.path();
            }
        }
        Require(!abandoned.empty() && Sha256File(abandoned / "usr" / "bin" / "swiftc.exe") == compiler_hash,
                "Crash child did not preserve the complete original compiler copy");
        bool validated_stage = false, validated_publication = false;
        Require(NativeArtifactStore::ImportTreeTransactional(bin.parent_path().parent_path(), published,
            [&](const fs::path& candidate) {
                Require(!fs::exists(abandoned), "New import did not recover the abandoned private stage first");
                if (!EnvironmentManager::ValidateSwiftHostToolchain(candidate / "usr" / "bin")) return false;
                if (candidate == published) validated_publication = true;
                else validated_stage = true;
                return true;
            }), "Recovered transactional import failed real Swift host validation");
        Require(validated_stage && validated_publication && !fs::exists(abandoned),
                "Recovery did not validate both private staging and published Swift");
        for (const auto& entry : fs::directory_iterator(slots)) {
            Require(entry.path().filename().string().find(".OPENFRUIT-import-") != 0,
                    "Recovered publication left a private staging owner receipt");
        }
        Require(Env(L"PATH") == original_path && Env(L"SDKROOT") == stale_value,
                "Recovery validation changed the parent environment");
        const auto validity = published / ".openfruit-relocatable-ok";
        if (!fs::exists(validity)) { std::ofstream out(validity); out << "fixture publication marker\n"; }
        Require(ToolPaths::IsPublishedSwiftBin(published / "usr" / "bin"),
                "Ordinary published compiler slot was rejected");
        const auto partial = slots / "owned-compiler.partial-00000000000000000000000000000000";
        fs::rename(published, partial);
        Require(!ToolPaths::IsPublishedSwiftBin(partial / "usr" / "bin"),
                "Copied marker made a private staging compiler selectable");
        const auto current = slots / "current";
        Require(CreateSymbolicLinkW(current.c_str(), partial.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE,
                "Cannot create owned current-to-staging alias");
        Require(!ToolPaths::IsPublishedSwiftBin(current / "usr" / "bin"),
                "Current alias bypassed staging publication checks");
        fs::remove(current);
        {
            const ScopedEnv home(L"OPENFRUIT_HOME", managed_home);
            const ScopedEnv override_path(L"OPENFRUIT_SWIFT_BIN", partial / "usr" / "bin");
            Require(ToolPaths::SwiftBin({}).lexically_normal() != (partial / "usr" / "bin").lexically_normal(),
                    "Default discovery selected a private staging compiler");
            const auto version = Win32Process::Run((bin / "swiftc.exe").wstring(),
                {(bin / "swiftc.exe").wstring(), L"--version"});
            std::smatch found;
            Require(std::regex_search(version.std_out, found, std::regex(R"(Swift version ([0-9]+\.[0-9]+))")),
                    "Cannot derive the real compiler version for selection");
            auto selection = config;
            selection.toolchain_path = (partial / "usr" / "bin").wstring();
            const auto selected = EnvironmentManager::SelectSwiftToolchain(selection, Win32Process::ToWide(found[1].str()));
            Require(selected.lexically_normal() != (partial / "usr" / "bin").lexically_normal(),
                    "SDK-driven discovery selected a private staging compiler");
        }
        const auto previous = slots / "owned-compiler.previous-00000000000000000000000000000000";
        fs::rename(partial, previous);
        Require(!ToolPaths::IsPublishedSwiftBin(previous / "usr" / "bin"),
                "Transaction backup compiler became a published selection");

        // LLVM discovery must obey the same private staging/backup boundary.
        Require(ToolPaths::IsImportScratchPath(slots / "owned.PARTIAL-ABCDEF0123456789ABCDEF0123456789" / "bin") &&
                ToolPaths::IsImportScratchPath(slots / "owned.PREVIOUS-ABCDEF0123456789ABCDEF0123456789" / "bin"),
                "Windows casing bypassed staging/backup discovery exclusion");
        // Only the immutable original executable is linked into this tiny tree.
        const auto original_llvm = ToolPaths::LlvmBin({}) / "ld64.lld.exe";
        const auto linker_hash = Sha256File(original_llvm);
        Require(linker_hash.has_value(), "Original ld64.lld.exe unavailable for LLVM admission test");
        const auto llvm_slots = managed_home / "toolchains" / "llvm";
        const auto llvm_published = llvm_slots / "owned-linker";
        const auto llvm_partial = llvm_slots / "owned-linker.partial-00000000000000000000000000000000";
        const auto llvm_previous = llvm_slots / "owned-linker.previous-00000000000000000000000000000000";
        fs::create_directories(llvm_published / "bin");
        Require(NativeArtifactStore::CreateNtfsHardLink(original_llvm, llvm_published / "bin" / "ld64.lld.exe"),
                "Cannot hardlink original LLVM executable into owned admission fixture");
        {
            const ScopedEnv home(L"OPENFRUIT_HOME", managed_home);
            const ScopedEnv override_path(L"OPENFRUIT_LLVM_BIN", root / "missing-llvm");
            Require(ToolPaths::LlvmBin({}) == llvm_published / "bin",
                    "Ordinary published LLVM slot was rejected");
            fs::rename(llvm_published, llvm_partial);
            const auto llvm_current = llvm_slots / "current";
            Require(NativeArtifactStore::CreateDirectoryJunction(llvm_current, llvm_partial),
                    "Cannot create owned LLVM current-to-staging alias");
            {
                const ScopedEnv scratch_override(L"OPENFRUIT_LLVM_BIN", llvm_partial / "bin");
                const auto selected = ToolPaths::LlvmBin({});
                Require(selected != llvm_partial / "bin" && selected != llvm_current / "bin" &&
                        !ToolPaths::IsImportScratchPath(selected),
                        "LLVM discovery selected private staging via override, version scan or current alias");
            }
            {
                const ScopedEnv alias_override(L"OPENFRUIT_LLVM_BIN", llvm_current / "bin");
                const auto selected = ToolPaths::LlvmBin({});
                Require(selected != llvm_current / "bin" && !ToolPaths::IsImportScratchPath(selected),
                        "LLVM environment override selected current-to-staging alias");
            }
            // Remove the alias itself before recursive owned-root cleanup.
            Require(RemoveDirectoryW(llvm_current.c_str()) != FALSE,
                    "Cannot unlink owned LLVM current alias");
            fs::rename(llvm_partial, llvm_previous);
            const ScopedEnv backup_override(L"OPENFRUIT_LLVM_BIN", llvm_previous / "bin");
            const auto selected = ToolPaths::LlvmBin({});
            Require(selected != llvm_previous / "bin" && !ToolPaths::IsImportScratchPath(selected),
                    "LLVM discovery selected a transaction backup");
        }
        Require(Sha256File(original_llvm) == linker_hash,
                "LLVM admission fixture modified the original linker");
        Require(Sha256File(bin / "swiftc.exe") == compiler_hash &&
                Sha256File(platform.runtime_bin / "swiftCore.dll") == runtime_hash,
                "Recovery/admission fixture modified the original compiler/runtime");
        std::cout << "PASS: original host baseline fails; native cold/warm validation derives "
                  << platform.windows_sdk.string()
                  << "; crash recovery validates real Swift staging/publication; Swift/LLVM admission excludes scratch\n";
        fs::remove_all(root);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nOwned evidence: " << root.string() << '\n';
        return 1;
    }
}
