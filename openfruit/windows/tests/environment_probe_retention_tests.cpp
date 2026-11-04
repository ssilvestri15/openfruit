#include "artifact_store.hpp"
#include "config.hpp"
#include "environment_manager.hpp"
#include "operation_events.hpp"
#include "tool_paths.hpp"

#include <windows.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

struct EnvironmentValue {
    std::wstring name, value;
    bool existed = false;
    EnvironmentValue(const wchar_t* key, const fs::path& replacement) : name(key) {
        const DWORD count = GetEnvironmentVariableW(key, nullptr, 0);
        if (count) {
            existed = true;
            value.resize(count);
            value.resize(GetEnvironmentVariableW(key, value.data(), count));
        }
        Require(SetEnvironmentVariableW(key, replacement.c_str()) != FALSE,
                "Cannot isolate test environment.");
    }
    ~EnvironmentValue() { SetEnvironmentVariableW(name.c_str(), existed ? value.c_str() : nullptr); }
};

void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    Require(static_cast<bool>(out), "Cannot write owned test fixture.");
}

std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    Require(static_cast<bool>(in), "Expected diagnostic/output is missing: " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

fs::path Lock(const fs::path& entry) { return fs::path(entry.wstring() + L".import-lock"); }

bool IsProbe(const fs::path& path) {
    const auto name = path.filename().string();
    if (name.size() != 32) return false;
    for (char c : name) if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return false;
    return true;
}

void RequireMachO(const fs::path& path) {
    const auto bytes = Read(path);
    Require(bytes.size() >= 32 && static_cast<unsigned char>(bytes[0]) == 0xcf &&
            static_cast<unsigned char>(bytes[1]) == 0xfa &&
            static_cast<unsigned char>(bytes[2]) == 0xed &&
            static_cast<unsigned char>(bytes[3]) == 0xfe,
            "Original LLVM did not produce a real Mach-O image.");
}

void Age(const fs::path& entry) {
    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(24 * 9);
    for (const auto& child : fs::recursive_directory_iterator(entry)) fs::last_write_time(child.path(), old);
    fs::last_write_time(entry, old);
    if (fs::exists(Lock(entry))) fs::last_write_time(Lock(entry), old);
}

fs::path Seed(const fs::path& category, const std::string& name, bool owned) {
    const auto entry = category / name;
    if (owned) { auto lease = ArtifactLease::Acquire(entry); Write(entry / "old.txt", "expired owned fixture"); }
    else Write(entry / "old.txt", "legacy fixture");
    Age(entry);
    return entry;
}

// Observe the actual linker launch, while the production scope still owns its
// scratch. A quota-zero competing collector must fail to acquire that scope.
class ProbeObserver final : public EventSink {
public:
    fs::path category, probe, active, expired;
    std::set<fs::path> before;
    std::string failure;
    unsigned launches = 0, completions = 0;
    bool expect_success;

    ProbeObserver(fs::path root, fs::path live, fs::path stale, bool success)
        : category(std::move(root)), active(std::move(live)), expired(std::move(stale)), expect_success(success) {
        for (const auto& entry : fs::directory_iterator(category)) before.insert(entry.path());
    }

    void Emit(OperationEvent event) noexcept override {
        const bool completed = event.kind == "task.completed" && event.data.GetString("name") == "process";
        if (event.kind != "process.started" && !completed) return;
        try {
            if (completed) {
                ++completions;
                if (expect_success) RequireMachO(probe / "probe.dylib");
            } else {
                ++launches;
                for (const auto& entry : fs::directory_iterator(category)) {
                    if (entry.is_directory() && IsProbe(entry.path()) && !before.count(entry.path())) {
                        Require(probe.empty(), "One validation launch created multiple scratch scopes.");
                        probe = entry.path();
                    }
                }
            }
            Require(!probe.empty(), "Actual linker launch has no private probe directory.");
            Require(!fs::exists(expired), "Production validation did not collect expired owned probe before launch.");
            Require(fs::is_regular_file(Lock(probe)), "Probe ownership marker missing before linker launch.");
            Require(!ArtifactLease::TryAcquire(probe), "Running linker probe is not leased.");
            const auto report = NativeArtifactStore::PruneCache(category, 0, 0, true, IsProbe);
            Require(report.success, "Competing collector failed: " + report.error_message);
            Require(fs::is_directory(probe), "Competing collector removed running probe.");
            Require(fs::is_directory(active) && !ArtifactLease::TryAcquire(active),
                    "Competing collector removed/released another active consumer.");
        } catch (const std::exception& error) { failure = error.what(); }
        catch (...) { failure = "Unexpected observer exception."; }
    }
};

fs::path Validate(Config& config, const fs::path& sdk, const fs::path& category,
                  const fs::path& active, const fs::path& expired, bool expected_success) {
    auto observer = std::make_shared<ProbeObserver>(category, active, expired, expected_success);
    auto context = std::make_shared<OperationContext>();
    context->sink = observer;
    context->control = std::make_shared<OperationControl>(
        std::chrono::steady_clock::now() + std::chrono::seconds(40));
    std::string error;
    bool success;
    {
        OperationBinding binding(context);
        success = EnvironmentManager::EnsureCompatibleLlvm(config, sdk, L"18.0", L"arm64", false, error);
    }
    Require(observer->failure.empty(), observer->failure);
    Require(observer->launches == 1, "Expected one actual LLVM linker launch: " + error);
    Require(observer->completions == 1, "Expected one actual LLVM linker completion: " + error);
    Require(success == expected_success, "Unexpected production LLVM validation result: " + error);
    Require(fs::is_regular_file(Lock(observer->probe)), "Returned probe lost ownership marker.");
    Require(static_cast<bool>(ArtifactLease::TryAcquire(observer->probe)), "Returned probe retained its active lease.");
    if (expected_success) {
        Require(!fs::exists(observer->probe), "Successful probe output was not collected after validation.");
        Require(error.empty(), "Successful validation retained an error.");
    } else {
        Require(fs::is_regular_file(observer->probe / "stdout.log"), "Probe stdout was not retained.");
        const auto diagnostics = Read(observer->probe / "stderr.log");
        Require(!diagnostics.empty(), "Failed linker diagnostic was not retained.");
        Require(error.find((observer->probe / "stderr.log").string()) != std::string::npos,
                "Failed validation did not identify retained diagnostics.");
    }
    return observer->probe;
}
} // namespace

int main() {
    try {
        // Resolve the real original tool before isolating configuration. No
        // replacement executable or handcrafted linker invocation is used.
        const auto llvm = ToolPaths::LlvmBin({});
        if (!fs::is_regular_file(llvm / "ld64.lld.exe")) {
            std::cout << "SKIP: original LLVM ld64.lld unavailable\n";
            return 77;
        }
        const auto root = fs::temp_directory_path() / ("openfruit-probe-retention-" + NewOperationId());
        fs::create_directories(root);
        EnvironmentValue home(L"OPENFRUIT_HOME", root / "managed");
        EnvironmentValue user(L"OPENFRUIT_USER_STATE", root / "user");
        EnvironmentValue cache(L"OPENFRUIT_CACHE_ROOT", root / "cache");
        EnvironmentValue tool(L"OPENFRUIT_LLVM_BIN", llvm);

        Config config;
        config.OPENFRUIT_home = (root / "managed").wstring();
        config.user_state_root = (root / "user").wstring();
        config.cache_root = (root / "cache").wstring();
        config.llvm_path = llvm.wstring();
        config.bootstrap_auto_install = false;
        const auto sdk = root / "owned.sdk";
        fs::create_directories(sdk / "System" / "Library" / "Frameworks");
        Write(sdk / "SDKSettings.json", "{\"Version\":\"27.0\"}\n");
        const std::string valid_tbd =
            "--- !tapi-tbd-v3\narchs: [ arm64 ]\nplatform: ios\n"
            "install-name: '/usr/lib/libSystem.B.dylib'\n"
            "exports:\n  - archs: [ arm64 ]\n    symbols: [ _owned_probe_symbol ]\n...\n";
        Write(sdk / "usr" / "lib" / "libSystem.tbd", valid_tbd);
        const auto category = ToolPaths::CacheRoot() / "llvm-sdk-probes";
        const auto expired = Seed(category, std::string(32, '1'), true);
        const auto legacy = Seed(category, std::string(32, '2'), false);
        const auto unknown = Seed(category, "unknown-owned-name", true);
        const auto active = Seed(category, std::string(32, '3'), true);
        auto active_lease = ArtifactLease::Acquire(active);
        Validate(config, sdk, category, active, expired, true);
        Require(!fs::exists(expired), "Production validation did not collect expired owned probe.");
        Require(fs::exists(legacy / "old.txt") && !fs::exists(Lock(legacy)), "Legacy probe was changed or adopted.");
        Require(fs::exists(unknown / "old.txt"), "Unknown category child was removed.");

        const auto second_expired = Seed(category, std::string(32, '4'), true);
        Write(sdk / "usr" / "lib" / "libSystem.tbd", "owned deliberately invalid TextAPI fixture\n");
        const auto failed = Validate(config, sdk, category, active, second_expired, false);
        Age(failed);
        Write(sdk / "usr" / "lib" / "libSystem.tbd", valid_tbd);
        const auto final_probe = Validate(config, sdk, category, active, failed, true);
        Require(!fs::exists(failed), "Next validation retained expired released failure diagnostics.");
        Require(fs::exists(legacy / "old.txt") && !fs::exists(Lock(legacy)) &&
                fs::exists(unknown / "old.txt") && fs::exists(active / "old.txt"),
                "Retention changed protected fixture entries.");
        Require(!fs::exists(final_probe), "Latest successful output was not collected.");
        active_lease.reset();
        fs::remove_all(root); // Only the unique ordinary, entirely owned fixture tree.
        std::cout << "Environment probe runtime retention tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
