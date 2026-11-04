#include "sdk_selection.hpp"
#include "sdk_usage.hpp"
#include "artifact_store.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary); output << bytes; output.close();
    Require(static_cast<bool>(output), "owned fixture write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void MakeSdk(const fs::path& sdk) {
    fs::create_directories(sdk / "usr/lib");
    fs::create_directories(sdk / "System/Library/Frameworks");
    Write(sdk / "SDKSettings.json", "{}");
    Write(sdk / "usr/lib/owned", "owned immutable SDK payload");
}
std::uint64_t Identity(const fs::path& root) {
    HANDLE handle = CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    Require(handle != INVALID_HANDLE_VALUE, "owned identity handle failed");
    BY_HANDLE_FILE_INFORMATION info{};
    const auto good = GetFileInformationByHandle(handle, &info);
    CloseHandle(handle);
    Require(good != FALSE, "owned identity query failed");
    return (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
}
struct Sink : EventSink {
    fs::path target;
    bool detached = false, readers_excluded = false;
    bool cleanup_reported = false;
    bool hold_child_after_detach = false;
    HANDLE child = INVALID_HANDLE_VALUE;
    ~Sink() { ReleaseChild(); }
    void ReleaseChild() { if (child != INVALID_HANDLE_VALUE) { CloseHandle(child); child = INVALID_HANDLE_VALUE; } }
    fs::path retained;
    void Emit(OperationEvent event) noexcept override {
        try {
            if (event.kind == "sdk.removal.detached") {
                const fs::path quarantine(event.data.GetString("quarantine"));
                SDKUsage original(target), moved(quarantine);
                detached = !fs::exists(target) && fs::exists(quarantine / "SDKSettings.json");
                readers_excluded = !original.Held() && !moved.Held();
                if (hold_child_after_detach)
                    child = CreateFileW((quarantine / "usr/lib/owned").c_str(), GENERIC_READ,
                        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            if (event.kind == "task.completed") {
                const auto* pending = event.data.Get("cleanup_pending");
                if (pending && pending->Bool()) {
                    cleanup_reported = true;
                    retained = event.data.GetString("retained_directory");
                }
            }
        } catch (...) {}
    }
};
struct CrashSink : EventSink {
    std::string boundary;
    explicit CrashSink(std::string at) : boundary(std::move(at)) {}
    void Emit(OperationEvent event) noexcept override {
        if (event.kind == boundary) {
            // Intentionally bypass every destructor to model process death.
            TerminateProcess(GetCurrentProcess(), 71);
        }
    }
};
struct CrashFixture {
    fs::path root, sdk, configuration;
    Config config;
    std::string before;
    std::uint64_t original_identity = 0;
    CrashFixture(const fs::path& base, const std::string& name) : root(base / name),
        sdk(root / "sdk"), configuration(root / "state/config.toml") {
        MakeSdk(sdk);
        config.OPENFRUIT_home = (root / "home").wstring();
        config.user_state_root = (root / "state").wstring();
        config.ios_sdk_paths[L"27"] = sdk.wstring();
        config.ios_sdk_version = L"27";
        config.sdk_path = sdk.wstring();
        fs::create_directories(configuration.parent_path());
        Require(config.Save(configuration.wstring()), "crash fixture config publication failed");
        before = Read(configuration);
        original_identity = Identity(sdk);
    }
    fs::path Crash(const std::wstring& executable, const std::wstring& event = L"sdk.removal.detached") {
        ProcessRunOptions control;
        control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        const auto result = Win32Process::Run(executable,
            {executable, L"--crash-removal", configuration.wstring(), event}, L"", {}, nullptr, nullptr, control);
        Require(result.launched && !result.timed_out && result.exit_code == 71,
            "production removal did not reach the requested crash boundary");
        const bool detached = event != L"sdk.removal.prepared";
        Require(fs::exists(sdk) != detached, "crash did not retain the expected original/detached SDK");
        fs::path receipt;
        for (const auto& entry : fs::directory_iterator(root))
            if (entry.path().filename().wstring().starts_with(L"sdk.sdk-removal-") && entry.path().extension() == ".json") {
                Require(receipt.empty(), "crash produced ambiguous owned receipts");
                receipt = entry.path();
            }
        Require(!receipt.empty(), "crash did not retain an ownership receipt");
        const auto record = JsonValue::Parse(Read(receipt));
        Require(record && record->GetString("schema") == "openfruit.sdk-removal.v3" &&
            record->GetString("phase") == "prepared" &&
            record->GetString("configuration_before_sha256") == Sha256(before).value_or(""),
            "crash receipt is not bound to the original configuration");
        const auto quarantine = fs::path(Win32Process::ToWide(record->GetString("quarantine")));
        const auto payload = detached ? quarantine : sdk;
        Require(Identity(payload) == original_identity &&
            Read(payload / "usr/lib/owned") == "owned immutable SDK payload" &&
            (detached || !fs::exists(quarantine)), "crash changed original SDK identity or bytes");
        return receipt;
    }
    void Refused() {
        const auto config_bytes = Read(configuration);
        Require(!SDKSelection::Select(config, L"27", configuration).Succeeded() &&
            !SDKRemoval::Remove(config, L"27", configuration).Succeeded() &&
            !fs::exists(sdk) && Read(configuration) == config_bytes,
            "unproven crash recovery changed registration or original destination");
    }
};
fs::path Quarantine(const fs::path& receipt) {
    return fs::path(receipt.wstring().substr(0, receipt.wstring().size() - 5));
}
void CrashRecoveryTests(const fs::path& base, const std::wstring& executable, const std::wstring& native_cli) {
    {
        CrashFixture fixture(base, "stale-removal-snapshot");
        const auto replacement = fixture.root / "new-registration";
        MakeSdk(replacement);
        auto actual = fixture.config;
        actual.ios_sdk_paths[L"27"] = replacement.wstring();
        actual.sdk_path = replacement.wstring();
        Require(actual.Save(fixture.configuration.wstring()), "stale-snapshot setup failed");
        const auto actual_bytes = Read(fixture.configuration);
        Require(SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).status == SDKRemovalStatus::PublicationFailed &&
            Read(fixture.configuration) == actual_bytes && Identity(fixture.sdk) == fixture.original_identity &&
            Read(replacement / "usr/lib/owned") == "owned immutable SDK payload",
            "stale removal snapshot detached an SDK against different persisted registration");
    }
    {
        CrashFixture fixture(base, "new-overlapping-registration");
        auto actual = fixture.config;
        actual.ios_sdk_paths[L"28"] = fixture.sdk.wstring();
        Require(actual.Save(fixture.configuration.wstring()), "overlap config publication failed");
        const auto actual_bytes = Read(fixture.configuration);
        Require(SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).status == SDKRemovalStatus::PublicationFailed &&
            Read(fixture.configuration) == actual_bytes && Identity(fixture.sdk) == fixture.original_identity &&
            Read(fixture.sdk / "usr/lib/owned") == "owned immutable SDK payload" &&
            Config::Load(fixture.configuration.wstring(), false).ios_sdk_paths.count(L"28") == 1,
            "stale removal snapshot discarded another SDK registration or payload");
    }
    {
        CrashFixture fixture(base, "preserve-unrelated-config");
        auto actual = fixture.config; actual.default_jobs = 19;
        Require(actual.Save(fixture.configuration.wstring()), "unrelated config publication failed");
        Require(SDKSelection::Select(fixture.config, L"27", fixture.configuration).Succeeded() &&
            Config::Load(fixture.configuration.wstring(), false).default_jobs == 19 && fixture.config.default_jobs == 19,
            "selection overwrote unrelated persisted configuration");
        actual = fixture.config; actual.default_jobs = 23;
        Require(actual.Save(fixture.configuration.wstring()), "unrelated remove config publication failed");
        Require(SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded() &&
            Config::Load(fixture.configuration.wstring(), false).default_jobs == 23 && fixture.config.default_jobs == 23,
            "removal overwrote unrelated persisted configuration");
    }
    for (const auto& mutation : {L"jobs", L"overlap"}) {
        CrashFixture fixture(base, std::wstring(mutation) == L"jobs" ? "detached-config-jobs" : "detached-config-overlap");
        struct WriterSink : EventSink {
            std::wstring executable, mutation;
            fs::path configuration;
            bool invoked = false, succeeded = false;
            std::string published;
            void Emit(OperationEvent event) noexcept override {
                if (invoked || event.kind != "sdk.removal.detached") return;
                invoked = true;
                try {
                    ProcessRunOptions control;
                    control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                    const auto result = Win32Process::Run(executable,
                        {executable, L"--write-config", configuration.wstring(), mutation}, L"", {}, nullptr, nullptr, control);
                    succeeded = result.launched && !result.timed_out && result.exit_code == 0;
                    published = Read(configuration);
                } catch (...) {}
            }
        };
        auto sink = std::make_shared<WriterSink>();
        sink->executable = executable; sink->configuration = fixture.configuration; sink->mutation = mutation;
        auto context = std::make_shared<OperationContext>(); context->sink = sink;
        OperationBinding binding(context);
        const auto result = SDKRemoval::Remove(fixture.config, L"27", fixture.configuration);
        Require(sink->invoked && sink->succeeded && sink->published != fixture.before &&
            result.status == SDKRemovalStatus::PublicationFailed && !result.cleanup_pending &&
            result.retained_directory.empty() && Identity(fixture.sdk) == fixture.original_identity &&
            Read(fixture.sdk / "usr/lib/owned") == "owned immutable SDK payload" &&
            Read(fixture.configuration) == sink->published,
            "competing native configuration writer was overwritten or original SDK was not restored");
        auto current = Config::Load(fixture.configuration.wstring(), false);
        if (std::wstring(mutation) == L"jobs") {
            Require(current.default_jobs == 47 &&
                SDKRemoval::Remove(current, L"27", fixture.configuration).Succeeded(),
                "removal could not retry after a preserved unrelated writer update");
        } else {
            Require(current.ios_sdk_paths.at(L"28") == fixture.sdk.wstring() &&
                SDKRemoval::Remove(current, L"27", fixture.configuration).status == SDKRemovalStatus::InvalidPath &&
                Identity(fixture.sdk) == fixture.original_identity && Read(fixture.configuration) == sink->published,
                "new overlapping registration did not protect the rolled-back SDK");
        }
    }
    {
        CrashFixture fixture(base, "select-lifetime");
        struct SelectionSink : EventSink {
            Config* config = nullptr;
            fs::path configuration;
            bool checked = false, excluded = false;
            void Emit(OperationEvent event) noexcept override {
                if (checked || event.kind != "sdk.usage.acquired" || event.data.GetString("status") != "held") return;
                checked = true;
                try { excluded = SDKRemoval::Remove(*config, L"27", configuration).status == SDKRemovalStatus::InUse; }
                catch (...) {}
            }
        };
        auto sink = std::make_shared<SelectionSink>();
        sink->config = &fixture.config; sink->configuration = fixture.configuration;
        auto context = std::make_shared<OperationContext>(); context->sink = sink;
        OperationBinding binding(context);
        Require(SDKSelection::Select(fixture.config, L"27", fixture.configuration).Succeeded() &&
            sink->checked && sink->excluded && Identity(fixture.sdk) == fixture.original_identity,
            "SDK selection did not retain its usage pin through publication");
    }
    {
        CrashFixture fixture(base, "prepared-before-detach");
        const auto receipt = fixture.Crash(executable, L"sdk.removal.prepared");
        {
            SDKUsage active(fixture.sdk);
            Require(active.Held() && !SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded() &&
                Read(fixture.configuration) == fixture.before && fs::exists(receipt),
                "before-detach recovery ignored an SDK reader");
        }
        {
            auto publisher = ArtifactLease::Acquire(fixture.sdk);
            Require(!SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded() &&
                Read(fixture.configuration) == fixture.before && fs::exists(receipt),
                "before-detach recovery ignored an active publisher");
        }
        HANDLE reader = CreateFileW(fixture.configuration.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(reader != INVALID_HANDLE_VALUE, "before-detach config reader failed");
        const auto selection = SDKSelection::Select(fixture.config, L"27", fixture.configuration);
        CloseHandle(reader);
        Require(selection.status == SDKSelectionStatus::PublicationFailed && !fs::exists(receipt) &&
            Read(fixture.configuration) == fixture.before && Identity(fixture.sdk) == fixture.original_identity &&
            Read(fixture.sdk / "usr/lib/owned") == "owned immutable SDK payload",
            "before-detach recovery did not retire only the proven receipt");
        // A second real death after detachment must leave one recoverable receipt,
        // not ambiguous metadata accumulated by our previous prepared transaction.
        const auto second = fixture.Crash(executable);
        Require(SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded() &&
            !fs::exists(second) && !fs::exists(fixture.sdk), "retry after prepared death accumulated ambiguous receipts");
    }
    {
        CrashFixture fixture(base, "prepared-before-detach-remove");
        const auto receipt = fixture.Crash(executable, L"sdk.removal.prepared");
        Require(SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded() &&
            !fs::exists(receipt) && !fs::exists(fixture.sdk), "remove did not reconcile a pre-detach crash receipt");
    }
    for (const bool legacy_v2 : {false, true}) {
        CrashFixture fixture(base, legacy_v2 ? "v2-prepared-select" : "prepared-select");
        const auto receipt = fixture.Crash(executable);
        if (legacy_v2) {
            auto record = *JsonValue::Parse(Read(receipt));
            record.Set("schema", JsonValue::String("openfruit.sdk-removal.v2"));
            Write(receipt, record.Serialize());
        }
        // Force selection Save to fail after production recovery: the before
        // config must remain byte-for-byte identical while SDK identity returns.
        HANDLE reader = CreateFileW(fixture.configuration.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(reader != INVALID_HANDLE_VALUE, "crash recovery config reader failed");
        const auto result = SDKSelection::Select(fixture.config, L"27", fixture.configuration);
        CloseHandle(reader);
        Require(result.status == SDKSelectionStatus::PublicationFailed &&
            Identity(fixture.sdk) == fixture.original_identity && Read(fixture.configuration) == fixture.before &&
            !fs::exists(receipt) && Read(fixture.sdk / "usr/lib/owned") == "owned immutable SDK payload",
            "prepared selection retry failed to restore exact SDK identity without changing config");
        Require(SDKSelection::Select(fixture.config, L"27", fixture.configuration).Succeeded(),
            "selection failed after crash recovery");
    }
    {
        CrashFixture fixture(base, "prepared-remove");
        const auto receipt = fixture.Crash(executable);
        const auto quarantine = Quarantine(receipt);
        {
            SDKUsage reader(quarantine);
            Require(reader.Held(), "crashed payload reader failed");
            fixture.Refused();
        }
        {
            auto publisher = ArtifactLease::Acquire(fixture.sdk);
            fixture.Refused();
        }
        Require(Read(fixture.configuration) == fixture.before &&
            SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded() &&
            !fs::exists(fixture.sdk) && !fs::exists(quarantine) && !fs::exists(receipt) &&
            Config::Load(fixture.configuration.wstring(), false).ios_sdk_paths.count(L"27") == 0,
            "remove retry did not recover then complete production removal");
    }
    {
        CrashFixture fixture(base, "after-save-before-phase");
        const auto receipt = fixture.Crash(executable, L"sdk.removal.configuration_committed");
        const auto quarantine = Quarantine(receipt);
        const auto committed = Read(fixture.configuration);
        Require(committed != fixture.before &&
            Config::Load(fixture.configuration.wstring(), false).ios_sdk_paths.count(L"27") == 0,
            "post-Save crash did not commit registration removal");
        fixture.Refused(); // Deliberately stale caller snapshot cannot resurrect it.
        Require(Read(fixture.configuration) == committed && Identity(quarantine) == fixture.original_identity &&
            fs::exists(receipt), "postcommit prepared receipt was adopted or deleted");
    }
    {
        CrashFixture fixture(base, "postcommit-new-root-stale-select");
        const auto receipt = fixture.Crash(executable, L"sdk.removal.configuration_committed");
        const auto committed = Read(fixture.configuration);
        MakeSdk(fixture.sdk);
        Write(fixture.sdk / "usr/lib/owned", "new independently published SDK");
        const auto new_identity = Identity(fixture.sdk);
        Require(SDKSelection::Select(fixture.config, L"27", fixture.configuration).status == SDKSelectionStatus::PublicationFailed &&
            Read(fixture.configuration) == committed && Identity(fixture.sdk) == new_identity &&
            Read(fixture.sdk / "usr/lib/owned") == "new independently published SDK" && fs::exists(receipt) &&
            Config::Load(fixture.configuration.wstring(), false).ios_sdk_paths.count(L"27") == 0,
            "stale selection resurrected a committed registration against a new root");
    }
    for (const auto& action : {L"select", L"remove"}) {
        CrashFixture fixture(base, std::wstring(action) == L"select" ? "cli-select-recovery" : "cli-remove-recovery");
        const auto receipt = fixture.Crash(executable);
        ProcessRunOptions control;
        control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        const auto result = Win32Process::Run(native_cli, {native_cli, L"sdk", action, L"27"}, L"",
            {{L"OPENFRUIT_USER_STATE", fixture.configuration.parent_path().wstring()},
             {L"OPENFRUIT_HOME", fixture.config.OPENFRUIT_home}}, nullptr, nullptr, control);
        Require(result.launched && !result.timed_out && result.exit_code == 0 && !fs::exists(receipt),
            "native CLI did not complete production SDK crash recovery");
        const auto selected = Config::Load(fixture.configuration.wstring(), false);
        if (std::wstring(action) == L"select")
            Require(Identity(fixture.sdk) == fixture.original_identity && selected.ios_sdk_version == L"27" &&
                selected.sdk_path == fixture.sdk.wstring() &&
                Read(fixture.sdk / "usr/lib/owned") == "owned immutable SDK payload",
                "CLI select recovery lost original SDK identity, bytes or selection");
        else Require(!fs::exists(fixture.sdk) && selected.ios_sdk_paths.count(L"27") == 0 &&
            selected.ios_sdk_version.empty() && selected.sdk_path.empty(), "CLI remove recovery did not commit removal");
    }
    {
        CrashFixture fixture(base, "modified-config");
        const auto receipt = fixture.Crash(executable);
        Write(fixture.configuration, fixture.before + "\n# unrelated user modification\n");
        fixture.Refused();
        Require(Identity(Quarantine(receipt)) == fixture.original_identity && fs::exists(receipt),
            "modified configuration was treated as an exact before-image");
    }
    {
        CrashFixture fixture(base, "new-destination");
        const auto receipt = fixture.Crash(executable);
        MakeSdk(fixture.sdk);
        Write(fixture.sdk / "usr/lib/owned", "new independently published SDK");
        const auto replacement = Identity(fixture.sdk);
        Require(replacement != fixture.original_identity &&
            SDKSelection::Select(fixture.config, L"27", fixture.configuration).Succeeded() &&
            Identity(fixture.sdk) == replacement && Identity(Quarantine(receipt)) == fixture.original_identity &&
            Read(fixture.sdk / "usr/lib/owned") == "new independently published SDK" && fs::exists(receipt) &&
            !SDKRemoval::Remove(fixture.config, L"27", fixture.configuration).Succeeded(),
            "recovery touched a newly published SDK root");
    }
    for (const auto& reason : {"legacy", "wrong-identity", "ambiguous", "wrong-config", "committed-phase", "receipt-hardlink", "payload-reparse", "replaced-payload", "config-hardlink", "missing-lease", "lease-hardlink"}) {
        CrashFixture fixture(base, reason);
        const auto receipt = fixture.Crash(executable);
        const auto quarantine = Quarantine(receipt);
        auto record = *JsonValue::Parse(Read(receipt));
        if (std::string(reason) == "legacy") record.Set("schema", JsonValue::String("openfruit.sdk-removal.v1"));
        else if (std::string(reason) == "wrong-identity") record.Set("file_index_low", JsonValue::String("4294967296"));
        else if (std::string(reason) == "wrong-config") record.Set("configuration", JsonValue::String((fixture.root / "other.toml").string()));
        else if (std::string(reason) == "committed-phase") record.Set("phase", JsonValue::String("committed"));
        else if (std::string(reason) == "ambiguous") {
            const auto second = fs::path(fixture.sdk.wstring() + L".sdk-removal-" + Win32Process::ToWide(NewOperationId()) + L".json");
            Write(second, Read(receipt));
        } else if (std::string(reason) == "receipt-hardlink") {
            fs::create_hard_link(receipt, fixture.root / "receipt-alias.json");
        } else if (std::string(reason) == "payload-reparse" || std::string(reason) == "replaced-payload") {
            const auto held = fixture.root / "owned-original";
            fs::rename(quarantine, held);
            if (std::string(reason) == "payload-reparse")
                Require(NativeArtifactStore::CreateDirectoryJunction(quarantine, held), "recovery junction fixture failed");
            else MakeSdk(quarantine);
        } else if (std::string(reason) == "config-hardlink") {
            fs::create_hard_link(fixture.configuration, fixture.root / "config-alias.toml");
        } else if (std::string(reason) == "missing-lease") {
            Require(fs::remove(fs::path(fixture.sdk.wstring() + L".import-lock")), "owned recovery marker removal failed");
        } else if (std::string(reason) == "lease-hardlink") {
            fs::create_hard_link(fs::path(fixture.sdk.wstring() + L".import-lock"), fixture.root / "lease-alias");
        }
        if (std::string(reason) != "receipt-hardlink") Write(receipt, record.Serialize());
        const auto receipt_bytes = Read(receipt);
        fixture.Refused();
        Require(Read(receipt) == receipt_bytes &&
            Read(quarantine / "usr/lib/owned") == "owned immutable SDK payload",
            "unproven receipt or retained payload bytes were changed");
    }
    {
        CrashFixture fixture(base, "bounded-scan");
        const auto receipt = fixture.Crash(executable);
        for (unsigned i = 0; i < 257; ++i)
            Write(fs::path(fixture.sdk.wstring() + L".sdk-removal-" + Win32Process::ToWide(NewOperationId()) + L".json"), "{}");
        fixture.Refused();
        Require(fs::exists(receipt) && Read(Quarantine(receipt) / "usr/lib/owned") == "owned immutable SDK payload",
            "bounded scan changed retained SDK");
    }
}
}
int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--write-config") {
        const fs::path configuration(Win32Process::ToWide(argv[2]));
        auto config = Config::Load(configuration.wstring(), false);
        if (std::string(argv[3]) == "jobs") config.default_jobs = 47;
        else if (std::string(argv[3]) == "overlap") config.ios_sdk_paths[L"28"] = config.ios_sdk_paths.at(L"27");
        else return 74;
        return config.Save(configuration.wstring()) ? 0 : 73;
    }
    if (argc == 4 && std::string(argv[1]) == "--crash-removal") {
        const fs::path configuration(Win32Process::ToWide(argv[2]));
        auto config = Config::Load(configuration.wstring(), false);
        auto context = std::make_shared<OperationContext>();
        context->sink = std::make_shared<CrashSink>(argv[3]);
        OperationBinding binding(context);
        SDKRemoval::Remove(config, L"27", configuration);
        return 72; // Boundary not reached; the parent rejects this result.
    }
    if (argc != 2) return 2;
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-removal-" + NewOperationId());
    try {
        const auto sdk = root / "sdk";
        const auto configuration = root / "state/config.toml";
        MakeSdk(sdk);
        Config config;
        config.OPENFRUIT_home = (root / "home").wstring();
        config.user_state_root = (root / "state").wstring();
        config.ios_sdk_paths[L"27"] = sdk.wstring();
        config.ios_sdk_version = L"27";
        config.sdk_path = sdk.wstring();
        fs::create_directories(configuration.parent_path());
        Require(config.Save(configuration.wstring()), "owned config publication failed");
        const auto previous = Read(configuration);
        const auto original_id = Identity(sdk);
        auto sink = std::make_shared<Sink>(); sink->target = sdk;
        auto context = std::make_shared<OperationContext>(); context->sink = sink;
        OperationBinding binding(context);
        {
            SDKUsage active(sdk);
            Require(active.Held(), "owned active SDK lease failed");
            Require(SDKRemoval::Remove(config, L"27", configuration).status == SDKRemovalStatus::InUse &&
                Read(configuration) == previous && Identity(sdk) == original_id &&
                Read(sdk / "usr/lib/owned") == "owned immutable SDK payload", "active SDK was changed");
        }
        {
            auto writer = ArtifactLease::Acquire(sdk);
            Require(SDKRemoval::Remove(config, L"27", configuration).status == SDKRemovalStatus::InUse &&
                fs::exists(sdk / "SDKSettings.json"), "publisher ownership bypassed");
        }
        {
            HANDLE reader = CreateFileW(configuration.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Require(reader != INVALID_HANDLE_VALUE, "owned config reader failed");
            const auto result = SDKRemoval::Remove(config, L"27", configuration);
            CloseHandle(reader);
            Require(result.status == SDKRemovalStatus::PublicationFailed && !result.cleanup_pending &&
                sink->detached && sink->readers_excluded && Identity(sdk) == original_id &&
                Read(sdk / "usr/lib/owned") == "owned immutable SDK payload" && Read(configuration) == previous &&
                config.ios_sdk_paths.count(L"27") == 1, "failed publication did not restore original SDK identity");
            for (const auto& entry : fs::directory_iterator(root))
                Require(entry.path().filename().wstring().find(L".sdk-removal-") == std::wstring::npos,
                    "successful rollback retained quarantine");
        }
        const auto expect_invalid = [&](Config invalid, const fs::path& path) {
            Require(SDKRemoval::Remove(invalid, L"27", path).status == SDKRemovalStatus::InvalidPath &&
                Read(sdk / "usr/lib/owned") == "owned immutable SDK payload" && Read(configuration) == previous,
                "unsafe removal path was admitted");
        };
        {
            Config invalid = config; invalid.ios_sdk_paths[L"27"] = L"relative-sdk";
            expect_invalid(invalid, configuration);
            invalid = config; invalid.ios_sdk_paths[L"27"] = sdk.root_path().wstring();
            expect_invalid(invalid, configuration);
            invalid = config; invalid.ios_sdk_paths[L"28"] = (sdk / "../sdk").wstring();
            expect_invalid(invalid, configuration);
            invalid = config; invalid.macos_sdk_paths[L"15"] = (sdk / "nested").wstring();
            expect_invalid(invalid, configuration);
            invalid = config; invalid.OPENFRUIT_home = (sdk / "managed-home").wstring();
            expect_invalid(invalid, configuration);
            expect_invalid(config, sdk / "config.toml");
            fs::create_directory(root / "incomplete");
            invalid = config; invalid.ios_sdk_paths[L"27"] = (root / "incomplete").wstring();
            expect_invalid(invalid, configuration);
            const auto link = root / "sdk-link";
            Require(NativeArtifactStore::CreateDirectoryJunction(link, sdk), "owned junction failed");
            invalid = config; invalid.ios_sdk_paths[L"27"] = link.wstring();
            expect_invalid(invalid, configuration);
            fs::remove(link);
        }
        {
            // Child sharing failures occur only after registration commits. They
            // must be reported, with the original bytes left in owned quarantine.
            HANDLE child = CreateFileW((sdk / "usr/lib/owned").c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Require(child != INVALID_HANDLE_VALUE, "owned child reader failed");
            const auto blocked = SDKRemoval::Remove(config, L"27", configuration);
            CloseHandle(child);
            Require(!blocked.Succeeded() && fs::exists(sdk) && Read(configuration) == previous,
                "Pre-detach child lock did not preserve SDK and registration");
            sink->hold_child_after_detach = true;
            const auto result = SDKRemoval::Remove(config, L"27", configuration);
            Require(sink->child != INVALID_HANDLE_VALUE, "Post-detach child sharing test unavailable");
            sink->ReleaseChild();
            sink->hold_child_after_detach = false;
            Require(result.Succeeded() && result.cleanup_pending && !result.retained_directory.empty() &&
                !fs::exists(sdk) && !config.ios_sdk_paths.count(L"27") && config.ios_sdk_version.empty() &&
                config.sdk_path.empty() && sink->cleanup_reported && sink->retained == result.retained_directory &&
                Read(result.retained_directory / "usr/lib/owned") == "owned immutable SDK payload" &&
                fs::exists(fs::path(result.retained_directory.wstring() + L".json")), "deferred cleanup was hidden or payload lost");
            Require(Config::Load(configuration.wstring()).ios_sdk_paths.count(L"27") == 0,
                "deferred cleanup did not commit registration removal");
        }
        {
            // The earlier root retains an explicitly deferred committed removal.
            // Exercise unrelated ordinary removal without adopting that metadata.
            const auto ordinary = root / "ordinary-sdk";
            MakeSdk(ordinary);
            config.ios_sdk_paths[L"27"] = ordinary.wstring();
            config.ios_sdk_version = L"27";
            config.sdk_path = (ordinary / ".." / "ordinary-sdk").wstring();
            Require(config.Save(configuration.wstring()), "owned config reset failed");
            const auto result = SDKRemoval::Remove(config, L"27", configuration);
            Require(result.Succeeded() && !result.cleanup_pending && result.retained_directory.empty() && !fs::exists(ordinary) &&
                config.ios_sdk_version.empty() && config.sdk_path.empty(),
                "ordinary removal did not purge directory or clear selected alias");
            fs::create_directory(root / "external-incomplete");
            config.ios_sdk_paths[L"28"] = (root / "external-incomplete").wstring();
            Require(config.Save(configuration.wstring()), "owned unregister setup failed");
            Require(SDKRemoval::Remove(config, L"28", configuration, false).Succeeded() &&
                fs::is_directory(root / "external-incomplete"), "unregister-only deleted external payload");
            config.ios_sdk_paths[L"missing"] = (root / "positively-missing").wstring();
            Require(config.Save(configuration.wstring()), "owned absent registration setup failed");
            Require(SDKRemoval::Remove(config, L"missing", configuration).Succeeded(), "absent registration repair failed");
        }
        CrashRecoveryTests(root / "crash-recovery", fs::absolute(Win32Process::ToWide(argv[0])).wstring(),
            fs::absolute(Win32Process::ToWide(argv[1])).wstring());
        fs::remove_all(root); // Unique owned fixture; no installed SDK is touched.
        std::cout << "SDK removal admission, lifetime, rollback, crash recovery and deferred cleanup passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; retained owned fixture: " << root << '\n';
        return 1;
    }
}
