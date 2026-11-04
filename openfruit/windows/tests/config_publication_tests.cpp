#include "config.hpp"
#include "operation_events.hpp"
#include "artifact_store.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::wstring ReadWin32Env(const wchar_t* name) {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) return {};
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0) return {};
    value.resize(written);
    return value;
}
void WriteEnvBoth(const wchar_t* name, const std::wstring& value) {
    _wputenv_s(name, value.c_str());
    if (value.empty()) {
        SetEnvironmentVariableW(name, nullptr);
    } else {
        SetEnvironmentVariableW(name, value.c_str());
    }
}
struct ScopedEnvironmentRestore {
    std::vector<std::pair<std::wstring, std::wstring>> saved;
    explicit ScopedEnvironmentRestore(std::initializer_list<const wchar_t*> keys) {
        for (const wchar_t* key : keys) {
            saved.emplace_back(key, ReadWin32Env(key));
        }
    }
    ~ScopedEnvironmentRestore() {
        for (const auto& [key, val] : saved) {
            WriteEnvBoth(key.c_str(), val);
        }
    }
};
void TestPureBuildEnvironmentVariables() {
    ScopedEnvironmentRestore restore({
        L"OPENFRUIT_HOME", L"OPENFRUIT_USER_STATE", L"OPENFRUIT_CACHE_ROOT",
        L"OPENFRUIT_IOS_SDK", L"OPENFRUIT_XCODE_PATH", L"OPENFRUIT_SWIFT_BIN",
        L"OPENFRUIT_LLVM_BIN", L"OPENFRUIT_ZSIGN", L"OPENFRUIT_PYMOBILEDEVICE3",
        L"OPENFRUIT_IPSW", L"OPENFRUIT_DARLING_TOOLS", L"OPENFRUIT_WSL_DISTRO",
        L"PATH"
    });
    WriteEnvBoth(L"OPENFRUIT_HOME", L"C:\\OriginalHome");
    WriteEnvBoth(L"PATH", L"C:\\Windows\\System32");
    Config cfg;
    cfg.OPENFRUIT_home = L"C:\\Managed\\OPENFRUIT";
    cfg.user_state_root = L"C:\\Users\\Test\\.OPENFRUIT";
    cfg.cache_root = L"C:\\Managed\\OPENFRUIT\\cache";
    cfg.sdk_path = L"C:\\Managed\\OPENFRUIT\\sdk\\iPhoneOS26.4.sdk";
    cfg.xcode_path = L"C:\\Managed\\OPENFRUIT\\xcode";
    cfg.toolchain_path = L"C:\\Managed\\OPENFRUIT\\toolchains\\swift\\usr\\bin";
    cfg.llvm_path = L"C:\\Managed\\OPENFRUIT\\toolchains\\llvm\\bin";
    cfg.git_path = L"C:\\Managed\\OPENFRUIT\\tools\\git\\cmd\\git.exe";
    cfg.zsign_path = L"C:\\Managed\\OPENFRUIT\\tools\\zsign\\zsign.exe";
    cfg.pymobiledevice3_path = L"";
    cfg.ipsw_path = L"C:\\Managed\\OPENFRUIT\\tools\\ipsw\\ipsw.exe";
    cfg.darling_tools_path = L"C:\\Managed\\OPENFRUIT\\toolchains\\darling";
    cfg.wsl_distro = L"Ubuntu-24.04";
    const auto env = cfg.BuildEnvironmentVariables(L"C:\\Windows\\System32;C:\\Windows");
    Require(ReadWin32Env(L"OPENFRUIT_HOME") == L"C:\\OriginalHome",
        "BuildEnvironmentVariables mutated process OPENFRUIT_HOME");
    Require(ReadWin32Env(L"PATH") == L"C:\\Windows\\System32",
        "BuildEnvironmentVariables mutated process PATH");
    Require(env.at(L"OPENFRUIT_HOME") == cfg.OPENFRUIT_home, "OPENFRUIT_HOME mismatch");
    Require(env.at(L"OPENFRUIT_USER_STATE") == cfg.user_state_root, "OPENFRUIT_USER_STATE mismatch");
    Require(env.at(L"OPENFRUIT_CACHE_ROOT") == cfg.cache_root, "OPENFRUIT_CACHE_ROOT mismatch");
    Require(env.at(L"OPENFRUIT_IOS_SDK") == cfg.sdk_path, "OPENFRUIT_IOS_SDK mismatch");
    Require(env.at(L"OPENFRUIT_XCODE_PATH") == cfg.xcode_path, "OPENFRUIT_XCODE_PATH mismatch");
    Require(env.at(L"OPENFRUIT_SWIFT_BIN") == cfg.toolchain_path, "OPENFRUIT_SWIFT_BIN mismatch");
    Require(env.at(L"OPENFRUIT_LLVM_BIN") == cfg.llvm_path, "OPENFRUIT_LLVM_BIN mismatch");
    Require(env.at(L"OPENFRUIT_ZSIGN") == cfg.zsign_path, "OPENFRUIT_ZSIGN mismatch");
    Require(env.find(L"OPENFRUIT_PYMOBILEDEVICE3") == env.end(),
        "Empty pymobiledevice3_path should not be emitted");
    Require(env.at(L"OPENFRUIT_IPSW") == cfg.ipsw_path, "OPENFRUIT_IPSW mismatch");
    Require(env.at(L"OPENFRUIT_DARLING_TOOLS") == cfg.darling_tools_path, "OPENFRUIT_DARLING_TOOLS mismatch");
    Require(env.at(L"OPENFRUIT_WSL_DISTRO") == cfg.wsl_distro, "OPENFRUIT_WSL_DISTRO mismatch");
    const std::wstring expected_path = L"C:\\Managed\\OPENFRUIT\\tools\\git\\cmd;C:\\Windows\\System32;C:\\Windows";
    Require(env.at(L"PATH") == expected_path, "First PATH prepend mismatch");
    const auto env_second = cfg.BuildEnvironmentVariables(env.at(L"PATH"));
    Require(env_second.at(L"PATH") == expected_path,
        "BuildEnvironmentVariables duplicated git_dir on second call");
    const std::wstring variant_path = L"C:\\Windows\\System32;\"c:/managed/openfruit/tools/git/cmd/\";C:\\Windows";
    const auto env_variant = cfg.BuildEnvironmentVariables(variant_path);
    Require(env_variant.at(L"PATH") == variant_path,
        "BuildEnvironmentVariables did not recognize case/slash/quote-equivalent git_dir in PATH");
    const auto env_empty_path = cfg.BuildEnvironmentVariables(L"");
    Require(env_empty_path.at(L"PATH") == L"C:\\Managed\\OPENFRUIT\\tools\\git\\cmd",
        "Empty initial PATH did not resolve to git_dir");
}
void TestApplyEnvironmentIdempotence() {
    ScopedEnvironmentRestore restore({
        L"OPENFRUIT_HOME", L"OPENFRUIT_IOS_SDK", L"OPENFRUIT_WSL_DISTRO", L"PATH"
    });
    WriteEnvBoth(L"PATH", L"C:\\Windows\\System32;C:\\Windows");
    Config cfg;
    cfg.OPENFRUIT_home = L"C:\\Managed\\OPENFRUIT";
    cfg.sdk_path = L"C:\\Managed\\OPENFRUIT\\sdk\\iPhoneOS26.4.sdk";
    cfg.git_path = L"C:\\Managed\\OPENFRUIT\\tools\\git\\cmd\\git.exe";
    cfg.wsl_distro = L"Ubuntu";
    cfg.ApplyEnvironment();
    const std::wstring expected_path = L"C:\\Managed\\OPENFRUIT\\tools\\git\\cmd;C:\\Windows\\System32;C:\\Windows";
    Require(ReadWin32Env(L"PATH") == expected_path,
        "First ApplyEnvironment did not update Win32 PATH");
    Require(ReadWin32Env(L"OPENFRUIT_HOME") == cfg.OPENFRUIT_home,
        "ApplyEnvironment did not set OPENFRUIT_HOME");
    cfg.ApplyEnvironment();
    cfg.ApplyEnvironment();
    Require(ReadWin32Env(L"PATH") == expected_path,
        "Repeated ApplyEnvironment duplicated git_dir in Win32 PATH");
}
std::string Read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
std::string Digest(const fs::path& path) {
    const auto digest = Sha256File(path);
    Require(digest.has_value(), "owned config digest failed");
    return *digest;
}
struct NativeHandle {
    HANDLE value = nullptr;
    ~NativeHandle() { if (value) CloseHandle(value); }
};
struct Child {
    PROCESS_INFORMATION process{};
    Child(const std::wstring& executable, const std::vector<std::wstring>& arguments) {
        auto command = Win32Process::BuildCommandLine(arguments);
        STARTUPINFOW startup{sizeof(startup)};
        Require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE, "owned config child launch failed");
    }
    ~Child() {
        if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process.hProcess, 99);
            WaitForSingleObject(process.hProcess, 5000);
        }
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
    }
    DWORD Result() {
        Require(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0, "owned config child timed out");
        DWORD result = 99;
        Require(GetExitCodeProcess(process.hProcess, &result) != FALSE, "owned config child result failed");
        return result;
    }
};
int ConditionalChild(char** argv) {
    const fs::path path(Win32Process::ToWide(argv[2]));
    auto config = Config::Load(path.wstring(), false);
    config.ios_sdk_version = Win32Process::ToWide(argv[5]);
    const auto gate_name = Win32Process::ToWide(argv[4]);
    NativeHandle gate{OpenEventW(SYNCHRONIZE, FALSE, gate_name.c_str())};
    NativeHandle ready{OpenEventW(EVENT_MODIFY_STATE, FALSE, (gate_name + L"-" + config.ios_sdk_version).c_str())};
    if (!gate.value || !ready.value || !SetEvent(ready.value) ||
        WaitForSingleObject(gate.value, 10000) != WAIT_OBJECT_0) return 20;
    return config.SaveIfUnchanged(path.wstring(), argv[3]) ? 0 : 10;
}
void CompetingProcesses(const fs::path& path, const std::wstring& executable) {
    const auto expected = Digest(path);
    const auto gate_name = L"Local\\OPENFRUIT-config-publication-" + Win32Process::ToWide(NewOperationId());
    NativeHandle gate{CreateEventW(nullptr, TRUE, FALSE, gate_name.c_str())};
    NativeHandle ready_a{CreateEventW(nullptr, TRUE, FALSE, (gate_name + L"-27").c_str())};
    NativeHandle ready_b{CreateEventW(nullptr, TRUE, FALSE, (gate_name + L"-28").c_str())};
    Require(gate.value && ready_a.value && ready_b.value, "owned process barrier creation failed");
    Child a(executable, {executable, L"--conditional", path.wstring(), Win32Process::ToWide(expected), gate_name, L"27"});
    Child b(executable, {executable, L"--conditional", path.wstring(), Win32Process::ToWide(expected), gate_name, L"28"});
    HANDLE ready[] = {ready_a.value, ready_b.value};
    Require(WaitForMultipleObjects(2, ready, TRUE, 10000) == WAIT_OBJECT_0 && SetEvent(gate.value),
        "owned competing writers did not reach the shared before-image barrier");
    const auto left = a.Result(), right = b.Result();
    Require((left == 0 && right == 10) || (left == 10 && right == 0),
        "exactly one conditional native writer must publish the shared before-image");
    const auto current = Config::Load(path.wstring(), false);
    Require(current.ios_sdk_version == (left == 0 ? L"27" : L"28"), "conditional winner does not match persisted bytes");
}
}
int main(int argc, char** argv) {
    if (argc == 6 && std::string(argv[1]) == "--conditional") return ConditionalChild(argv);
    TestPureBuildEnvironmentVariables();
    TestApplyEnvironmentIdempotence();
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-config-publication-" + NewOperationId());
    try {
        const auto path = root / "config.toml";
        Config config; config.ios_sdk_version = L"26";
        Require(config.Save(path.wstring()), "initial ordinary publication failed");
        const auto previous = Read(path);
        const auto before = Digest(path);
        HANDLE reader = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(reader != INVALID_HANDLE_VALUE, "owned replacement-denial reader failed");
        config.ios_sdk_version = L"27";
        const bool ordinary_denied = !config.Save(path.wstring());
        const bool conditional_denied = !config.SaveIfUnchanged(path.wstring(), before);
        const bool unchanged = Read(path) == previous;
        CloseHandle(reader);
        Require(ordinary_denied && conditional_denied && unchanged, "denied replacement changed previous configuration");
        Require(config.SaveIfUnchanged(path.wstring(), before) && Config::Load(path.wstring(), false).ios_sdk_version == L"27",
            "conditional retry failed after replacement denial");
        const auto current_bytes = Read(path);
        Require(!config.SaveIfUnchanged(path.wstring(), before) && Read(path) == current_bytes,
            "stale digest replaced a newer configuration");
        for (const auto& invalid : {std::string{}, std::string(63, 'a'), std::string(64, 'g'), std::string(64, 'A')})
            Require(!config.SaveIfUnchanged(path.wstring(), invalid) && Read(path) == current_bytes,
                "malformed expected digest was accepted");
        const auto absent = root / "missing.toml";
        Require(!config.SaveIfUnchanged(absent.wstring(), Sha256("").value_or("")) && !fs::exists(absent),
            "conditional publication adopted a missing before-image");
        auto expected = Digest(path);
        {
            const auto owner = ArtifactLease::Acquire(path);
            Require(!config.Save(path.wstring()) && !config.SaveIfUnchanged(path.wstring(), expected) && Read(path) == current_bytes,
                "native writer bypassed the existing configuration lease");
        }
        Require(config.SaveIfUnchanged(path.wstring(), expected), "conditional retry failed after lease release");
        const auto alias = root / "config-alias.toml";
        fs::create_hard_link(path, alias);
        const auto linked_bytes = Read(path);
        expected = Digest(path);
        Require(!config.SaveIfUnchanged(path.wstring(), expected) && Read(path) == linked_bytes && Read(alias) == linked_bytes,
            "conditional writer adopted hardlinked metadata");
        fs::remove(alias);
        Require(config.SaveIfUnchanged(path.wstring(), expected), "conditional retry failed after owned alias removal");
        const auto ordinary_directory = root / "ordinary-directory";
        fs::create_directory(ordinary_directory);
        const auto junction = root / "reparse.toml";
        Require(NativeArtifactStore::CreateDirectoryJunction(junction, ordinary_directory), "owned reparse fixture failed");
        Require(!config.SaveIfUnchanged(junction.wstring(), Digest(path)) && fs::is_directory(ordinary_directory),
            "conditional publication adopted a reparse root");
        fs::remove(junction);
        config.ios_sdk_version = L"26";
        Require(config.Save(path.wstring()), "owned concurrent fixture reset failed");
        CompetingProcesses(path, fs::absolute(Win32Process::ToWide(argv[0])).wstring());
        const auto winner_bytes = Read(path);
        expected = Digest(path);
        config.ios_sdk_version = L"29";
        Require(config.Save(path.wstring()) && !config.SaveIfUnchanged(path.wstring(), expected) && Read(path) != winner_bytes &&
            Config::Load(path.wstring(), false).ios_sdk_version == L"29",
            "ordinary native writer was overwritten by a stale conditional writer");
        fs::remove_all(root); // Unique owned fixtures only.
        std::cout << "Configuration atomic replacement, conditional publication and competing native writers passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; retained owned fixture: " << root << '\n';
        return 1;
    }
}
