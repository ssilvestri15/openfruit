#include "utf8_path.hpp"
#include "artifact_store.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "json_value.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <future>
#include <stdexcept>
#include <thread>
#include <map>
#include <optional>
namespace fs = std::filesystem;
namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct Child {
    PROCESS_INFORMATION process{};
    Child(const std::wstring& executable, const std::vector<std::wstring>& args) {
        auto command = OpenFruit::Win32Process::BuildCommandLine(args);
        STARTUPINFOW startup{sizeof(startup)};
        Require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE, "Cannot launch owned lease child.");
    }
    ~Child() {
        if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process.hProcess, 99);
            WaitForSingleObject(process.hProcess, 5000);
        }
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
    }
    bool ExitZero() {
        if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) return false;
        DWORD code = 99;
        return GetExitCodeProcess(process.hProcess, &code) && code == 0;
    }
};
void LeaseTests(const fs::path& root, const std::wstring& executable) {
    using OpenFruit::ArtifactLease;
    const auto artifact = root / "leased-artifact";
    {
        auto lease = ArtifactLease::Acquire(artifact);
        Require(!ArtifactLease::TryAcquire(artifact), "Second owner acquired active lease.");
        OpenFruit::ProcessRunOptions cancelled;
        cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
        bool rejected = false;
        try { (void)ArtifactLease::Acquire(artifact, cancelled); }
        catch (const std::runtime_error& error) { rejected = std::string(error.what()).find("cancelled") != std::string::npos; }
        Require(rejected, "Cancelled lease acquisition did not report cancellation.");
        OpenFruit::ProcessRunOptions cancelled_wait;
        cancelled_wait.cancellation = std::make_shared<std::atomic<bool>>(false);
        cancelled_wait.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        auto interrupted = std::async(std::launch::async, [&] {
            try { (void)ArtifactLease::Acquire(artifact, cancelled_wait); }
            catch (const std::runtime_error& error) { return std::string(error.what()).find("cancelled") != std::string::npos; }
            return false;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        cancelled_wait.cancellation->store(true);
        Require(interrupted.get(), "Waiting lease acquisition did not observe cancellation.");
        OpenFruit::ProcessRunOptions bounded;
        bounded.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(75);
        rejected = false;
        try { (void)ArtifactLease::Acquire(artifact, bounded); }
        catch (const std::runtime_error& error) { rejected = std::string(error.what()).find("deadline") != std::string::npos; }
        Require(rejected, "Contended lease acquisition ignored deadline.");
        auto waiting = std::async(std::launch::async, [&] {
            OpenFruit::ProcessRunOptions control;
            control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            return ArtifactLease::Acquire(artifact, control);
        });
        Require(waiting.wait_for(std::chrono::milliseconds(60)) == std::future_status::timeout,
            "Waiting owner acquired lease before release.");
        lease.reset();
        Require(static_cast<bool>(waiting.get()), "Waiting owner failed after normal release.");
    }
    for (const bool crash : {false, true}) {
        const auto ready = root / (crash ? "child-crash.ready" : "child-release.ready");
        const auto release = root / (crash ? "child-crash.release" : "child-release.release");
        Child child(executable, {executable, L"--lease-holder", artifact.wstring(), ready.wstring(), release.wstring()});
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!fs::exists(ready) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        Require(fs::exists(ready), "Lease holder did not become ready.");
        Require(!ArtifactLease::TryAcquire(artifact), "Cross-process lease did not exclude parent.");
        if (crash) {
            Require(TerminateProcess(child.process.hProcess, 47) != FALSE, "Cannot terminate owned lease child.");
            Require(WaitForSingleObject(child.process.hProcess, 5000) == WAIT_OBJECT_0, "Owned lease child did not terminate.");
        } else {
            std::ofstream(release) << "release";
            Require(child.ExitZero(), "Lease child failed normal release.");
        }
        Require(static_cast<bool>(ArtifactLease::TryAcquire(artifact)), "Exited process left lease locked.");
    }
    bool rejected = false;
    try { (void)ArtifactLease::TryAcquire({}); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected, "Empty lease destination was admitted.");
    const auto blocked_parent = root / "ordinary-file";
    std::ofstream(blocked_parent) << "not a directory";
    rejected = false;
    try { (void)ArtifactLease::TryAcquire(blocked_parent / "child"); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected, "Lease I/O failure was confused with contention.");

    const auto cache = root / "leased-cache", live = cache / "live", stale = cache / "stale";
    fs::create_directories(live); fs::create_directories(stale);
    std::ofstream(live / "payload") << std::string(1024, 'L');
    std::ofstream(stale / "payload") << std::string(1024, 'S');
    fs::last_write_time(live / "payload", fs::file_time_type::clock::now() - std::chrono::hours(48));
    fs::last_write_time(live, fs::file_time_type::clock::now() - std::chrono::hours(48));
    auto held = ArtifactLease::Acquire(live);
    const auto pruned = OpenFruit::NativeArtifactStore::PruneCache(cache, 1);
    Require(pruned.success && pruned.entries_skipped_in_use == 1 && pruned.entries_removed == 1 &&
        fs::is_regular_file(live / "payload") && !fs::exists(stale), "Retention removed active entry or failed to prune inactive entry.");
    held.reset();
    Require(OpenFruit::NativeArtifactStore::PruneCache(cache, 1).entries_removed == 1,
        "Released entry could not be pruned.");

    const auto participating = root / "participating-cache";
    const auto legacy = participating / "legacy", owned = participating / "owned";
    fs::create_directories(legacy); fs::create_directories(owned);
    std::ofstream(legacy / "payload") << std::string(2048, 'U');
    std::ofstream(owned / "payload") << std::string(2048, 'O');
    auto owned_lease = ArtifactLease::Acquire(owned);
    const auto protected_pass = OpenFruit::NativeArtifactStore::PruneCache(participating, 1, 0, true);
    Require(protected_pass.success && protected_pass.entries_removed == 0 &&
        protected_pass.entries_skipped_in_use == 1 && protected_pass.entries_skipped_unmanaged == 1 &&
        fs::exists(legacy / "payload") && fs::exists(owned / "payload") &&
        !fs::exists(fs::path(legacy.wstring() + L".import-lock")),
        "Opt-in retention deleted legacy/live state or fabricated legacy ownership.");
    owned_lease.reset();
    const auto unadmitted = participating / "legacy-with-marker";
    fs::create_directories(unadmitted);
    std::ofstream(unadmitted / "payload") << "preserve";
    ArtifactLease::Acquire(unadmitted).reset();
    const auto opted_in = OpenFruit::NativeArtifactStore::PruneCache(participating, 1, 0, true,
        [](const fs::path& path) { return path.filename() == "owned"; });
    Require(opted_in.success && opted_in.entries_removed == 1 && opted_in.entries_skipped_unmanaged == 2 &&
        opted_in.bytes_reclaimed == 2048 && !fs::exists(owned) && fs::exists(legacy / "payload") &&
        fs::exists(unadmitted / "payload"),
        "Opt-in retention failed to delete only the released participating entry.");

    const auto outside = root / "outside", linked = cache / "links";
    fs::create_directories(outside); fs::create_directories(linked);
    std::ofstream(outside / "untouched") << "external target";
    std::ofstream(linked / "payload") << "owned link container";
    Require(CreateSymbolicLinkW((linked / "external").c_str(), outside.c_str(),
        SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE, "Cannot create owned external-alias fixture.");
    Require(CreateSymbolicLinkW((linked / "cycle").c_str(), L".",
        SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE, "Cannot create owned internal-cycle fixture.");
    const auto link_prune = OpenFruit::NativeArtifactStore::PruneCache(cache, 1);
    Require(link_prune.success && link_prune.entries_removed == 1 && !fs::exists(linked) &&
        fs::is_regular_file(outside / "untouched"), "Retention followed a reparse target or failed to unlink owned aliases.");
    const auto alias_root = root / "alias-root";
    Require(CreateSymbolicLinkW(alias_root.c_str(), outside.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE,
        "Cannot create owned reparse-root fixture.");
    const auto refused = OpenFruit::NativeArtifactStore::PruneCache(alias_root, 1);
    Require(!refused.success && refused.entries_removed == 0 && fs::is_regular_file(outside / "untouched"),
        "Retention admitted a reparse root.");

    // Last-use retention keeps old immutable bytes that were recently used.
    // A nonblocking inspection must not refresh an unused entry.
    const auto age_cache = root / "last-use-cache";
    const auto recent = age_cache / "recent", unused = age_cache / "unused";
    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(48);
    for (const auto& entry : {recent, unused}) {
        fs::create_directories(entry);
        std::ofstream(entry / "payload") << std::string(1024, 'A');
        fs::last_write_time(entry / "payload", old);
        fs::last_write_time(entry, old);
    }
    { auto used = ArtifactLease::Acquire(recent); }
    { auto inspected = ArtifactLease::TryAcquire(unused); Require(static_cast<bool>(inspected), "Cannot inspect unused entry."); }
    const auto unused_lock = fs::path(unused.wstring() + L".import-lock");
    const auto initial_stamp = fs::last_write_time(unused_lock);
    { auto inspected = ArtifactLease::TryAcquire(unused); Require(static_cast<bool>(inspected), "Cannot reinspect unused entry."); }
    Require(fs::last_write_time(unused_lock) == initial_stamp,
        "Nonblocking retention lease refreshed last-use timestamp.");
    const auto aged = OpenFruit::NativeArtifactStore::PruneCache(age_cache, std::nullopt, 3600);
    Require(aged.success && aged.entries_removed == 1 && fs::exists(recent / "payload") &&
        !fs::exists(unused) && fs::last_write_time(recent / "payload") == old,
        "Last-use retention removed recently consumed immutable bytes or rejuvenated unused entry.");
}

std::string FileBytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    Require(static_cast<bool>(input), "Cannot read owned imported-file fixture.");
    return std::string(std::istreambuf_iterator<char>(input), {});
}
void WriteBytes(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    Require(static_cast<bool>(output), "Cannot write owned imported-file fixture.");
}
void SharedReadLeaseTests(const fs::path& root, const std::wstring& executable) {
    using OpenFruit::ArtifactLease;
    const auto area = root / "shared-reader-tests", cache = area / "cache", artifact = cache / "artifact";
    WriteBytes(artifact / "payload", "shared reader payload");
    ArtifactLease::Acquire(artifact).reset();
    const auto lock = fs::path(artifact.wstring() + L".import-lock");
    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(48);
    fs::last_write_time(lock, old);
    {
        auto inspection = ArtifactLease::TryAcquireSharedRead(artifact);
        Require(static_cast<bool>(inspection) && fs::last_write_time(lock) == old,
                "Nonblocking shared read refreshed last use or rejected an ordinary existing lock.");
    }
    auto first = ArtifactLease::AcquireSharedRead(artifact);
    auto second = ArtifactLease::TryAcquireSharedRead(artifact);
    Require(first && second && fs::last_write_time(lock) > old,
            "Shared readers could not coexist or blocking acquisition did not record last use.");
    Require(!ArtifactLease::TryAcquire(artifact), "Writer acquired an artifact with two shared readers.");
    const auto pruned = OpenFruit::NativeArtifactStore::PruneCache(cache, 0, 0, true);
    Require(pruned.success && pruned.entries_removed == 0 && pruned.entries_skipped_in_use == 1 &&
        FileBytes(artifact / "payload") == "shared reader payload", "Prune removed an artifact with shared readers.");
    auto copied = first;
    first.reset();
    second.reset();
    Require(!ArtifactLease::TryAcquire(artifact), "Copied shared lease lost native handle ownership.");
    second = ArtifactLease::TryAcquireSharedRead(artifact);
    Require(static_cast<bool>(second), "Independent reader could not join the copied lease.");
    auto released_on_thread = std::async(std::launch::async, [lease = std::move(copied)]() mutable { lease.reset(); });
    released_on_thread.get();
    Require(!ArtifactLease::TryAcquire(artifact), "Writer entered before the last independent reader released.");
    second.reset();
    Require(static_cast<bool>(ArtifactLease::TryAcquire(artifact)), "Shared lease released on another thread stranded the writer lock.");

    for (const bool crash : {false, true}) {
        auto parent = ArtifactLease::AcquireSharedRead(artifact);
        const auto ready = area / (crash ? "reader-crash.ready" : "reader-release.ready");
        const auto release = area / (crash ? "reader-crash.release" : "reader-release.release");
        Child child(executable, {executable, crash ? L"--shared-reader-crash" : L"--shared-reader-holder",
            artifact.wstring(), ready.wstring(), release.wstring()});
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!fs::exists(ready) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        Require(fs::exists(ready), "Child reader could not share the parent's artifact lease.");
        parent.reset();
        Require(!ArtifactLease::TryAcquire(artifact), "Parent release bypassed an active child reader.");
        WriteBytes(release, "release");
        if (crash) {
            Require(WaitForSingleObject(child.process.hProcess, 5000) == WAIT_OBJECT_0, "Crash reader did not exit.");
            DWORD code = 0;
            Require(GetExitCodeProcess(child.process.hProcess, &code) && code == 23,
                    "Shared reader child did not use abrupt native process exit.");
        } else Require(child.ExitZero(), "Shared reader child failed normal release.");
        Require(static_cast<bool>(ArtifactLease::TryAcquire(artifact)), "Exited child reader stranded a native shared handle.");
    }
    {
        auto writer = ArtifactLease::Acquire(artifact);
        Require(!ArtifactLease::TryAcquireSharedRead(artifact), "Shared reader bypassed an exclusive writer.");
        OpenFruit::ProcessRunOptions cancelled;
        cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
        bool rejected = false;
        try { (void)ArtifactLease::AcquireSharedRead(artifact, cancelled); }
        catch (const std::runtime_error& error) { rejected = std::string(error.what()).find("cancelled") != std::string::npos; }
        Require(rejected, "Shared acquisition ignored cancellation.");
        cancelled.cancellation->store(false);
        cancelled.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        auto waiting = std::async(std::launch::async, [&] {
            try { (void)ArtifactLease::AcquireSharedRead(artifact, cancelled); }
            catch (const std::runtime_error& error) { return std::string(error.what()).find("cancelled") != std::string::npos; }
            return false;
        });
        const bool waited = waiting.wait_for(std::chrono::milliseconds(60)) == std::future_status::timeout;
        cancelled.cancellation->store(true);
        Require(waiting.get() && waited, "Waiting shared reader failed to observe cancellation under a writer.");
        OpenFruit::ProcessRunOptions bounded;
        bounded.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(75);
        rejected = false;
        try { (void)ArtifactLease::AcquireSharedRead(artifact, bounded); }
        catch (const std::runtime_error& error) { rejected = std::string(error.what()).find("deadline") != std::string::npos; }
        Require(rejected, "Shared acquisition ignored its deadline under a writer.");
    }
    const auto missing = area / "missing-parent" / "artifact";
    bool rejected = false;
    try { (void)ArtifactLease::TryAcquireSharedRead(missing); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected && !fs::exists(missing.parent_path()), "Shared read created missing directories or admitted missing ownership.");
    const auto no_marker = area / "no-marker";
    fs::create_directory(no_marker);
    rejected = false;
    try { (void)ArtifactLease::AcquireSharedRead(no_marker); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected && !fs::exists(fs::path(no_marker.wstring() + L".import-lock")),
            "Shared read fabricated a missing consumer marker.");
    const auto alias = area / "aliased-artifact", alias_lock = fs::path(alias.wstring() + L".import-lock");
    const auto stamp = fs::last_write_time(lock);
    Require(CreateSymbolicLinkW(alias_lock.c_str(), lock.c_str(), 0x2) != FALSE, "Cannot create owned shared-lock reparse fixture.");
    rejected = false;
    try { (void)ArtifactLease::TryAcquireSharedRead(alias); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected && fs::last_write_time(lock) == stamp, "Shared reader followed a reparse lock or refreshed its target.");
    fs::remove(alias_lock);
    const auto shared_lock_source = area / "external-lock-source";
    const auto hardlinked_artifact = area / "hardlinked-artifact";
    const auto hardlinked_lock = fs::path(hardlinked_artifact.wstring() + L".import-lock");
    WriteBytes(shared_lock_source, "owned source lock bytes stay unchanged");
    fs::last_write_time(shared_lock_source, old);
    Require(CreateHardLinkW(hardlinked_lock.c_str(), shared_lock_source.c_str(), nullptr) != FALSE,
            "Cannot create owned hardlinked lease marker fixture.");
    const auto reject_shared_lock = [&](const auto& acquire) {
        bool refused = false;
        try { (void)acquire(); }
        catch (const std::runtime_error&) { refused = true; }
        Require(refused && FileBytes(shared_lock_source) == "owned source lock bytes stay unchanged" &&
            fs::last_write_time(shared_lock_source) == old,
            "Lease acquisition admitted a hardlinked marker or changed shared source bytes/time.");
    };
    reject_shared_lock([&] { return ArtifactLease::TryAcquireSharedRead(hardlinked_artifact); });
    reject_shared_lock([&] { return ArtifactLease::AcquireSharedRead(hardlinked_artifact); });
    reject_shared_lock([&] { return ArtifactLease::TryAcquire(hardlinked_artifact); });
    reject_shared_lock([&] { return ArtifactLease::Acquire(hardlinked_artifact); });
    Require(fs::remove(hardlinked_lock), "Cannot explicitly unlink the owned hardlinked lease marker.");
    Require(FileBytes(shared_lock_source) == "owned source lock bytes stay unchanged" &&
        fs::last_write_time(shared_lock_source) == old,
        "Unlinking the rejected lease marker changed the original source.");
    const auto released = OpenFruit::NativeArtifactStore::PruneCache(cache, 0, 0, true);
    Require(released.success && released.entries_removed == 1 && !fs::exists(artifact),
            "Shared-read lifecycle left the released artifact unprunable.");
}
void QuotaPolicyTests(const fs::path& root) {
    using OpenFruit::ArtifactLease;
    using OpenFruit::NativeArtifactStore;
    const auto cache = root / "explicit-quota-cache";
    const auto inactive = cache / "r2-0000000000000001", live = cache / "r2-0000000000000002";
    const auto unowned = cache / "r2-0000000000000003", legacy = cache / "legacy-context";
    const auto eligible = [](const fs::path& path) {
        const auto name = path.filename().string();
        return name.size() == 19 && name.starts_with("r2-") &&
            name.substr(3).find_first_not_of("0123456789abcdef") == std::string::npos;
    };
    WriteBytes(inactive / "payload", std::string(31, 'I'));
    WriteBytes(live / "payload", std::string(47, 'L'));
    WriteBytes(unowned / "payload", "unowned context stays");
    WriteBytes(legacy / "payload", "legacy context stays");
    ArtifactLease::Acquire(inactive).reset();
    ArtifactLease::Acquire(legacy).reset(); // A marker alone does not admit a legacy context.
    auto held = ArtifactLease::Acquire(live);
    const auto no_quota = NativeArtifactStore::PruneCache(cache, std::nullopt, 0, true, eligible);
    Require(no_quota.success && no_quota.entries_removed == 0 && no_quota.bytes_reclaimed == 0 &&
        fs::exists(inactive / "payload") && fs::exists(live / "payload") &&
        FileBytes(unowned / "payload") == "unowned context stays" &&
        FileBytes(legacy / "payload") == "legacy context stays",
        "Disabled quota without an age limit removed cache state.");

    const auto zero_quota = NativeArtifactStore::PruneCache(cache, 0, 0, true, eligible);
    Require(zero_quota.success && zero_quota.entries_removed == 1 && zero_quota.bytes_reclaimed == 31 &&
        zero_quota.entries_skipped_in_use == 1 && zero_quota.entries_skipped_unmanaged == 2 &&
        !fs::exists(inactive) && FileBytes(live / "payload") == std::string(47, 'L') &&
        FileBytes(unowned / "payload") == "unowned context stays" &&
        FileBytes(legacy / "payload") == "legacy context stays" &&
        !fs::exists(fs::path(unowned.wstring() + L".import-lock")),
        "Zero quota failed to remove only inactive admitted state or fabricated ownership.");
    held.reset();
    const auto released = NativeArtifactStore::PruneCache(cache, 0, 0, true, eligible);
    Require(released.success && released.entries_removed == 1 && released.bytes_reclaimed == 47 &&
        released.entries_skipped_in_use == 0 && released.entries_skipped_unmanaged == 2 &&
        !fs::exists(live) && FileBytes(unowned / "payload") == "unowned context stays" &&
        FileBytes(legacy / "payload") == "legacy context stays" &&
        !fs::exists(fs::path(unowned.wstring() + L".import-lock")),
        "Zero quota did not reclaim the released admitted entry while preserving unowned/legacy state.");
}
void BoundedPruneTests(const fs::path& root) {
    using OpenFruit::ArtifactLease;
    using OpenFruit::CachePruneOptions;
    using OpenFruit::NativeArtifactStore;
    const auto eligible = [](const fs::path& path) {
        const auto name = path.filename().string();
        return name.size() == 19 && name.starts_with("r2-") &&
            name.substr(3).find_first_not_of("0123456789abcdef") == std::string::npos;
    };
    const auto delete_budget_cache = root / "bounded-delete-cache";
    const auto e1 = delete_budget_cache / "r2-0000000000000011";
    const auto e2 = delete_budget_cache / "r2-0000000000000012";
    const auto e3 = delete_budget_cache / "r2-0000000000000013";
    const auto unowned = delete_budget_cache / "r2-0000000000000014";
    const auto legacy = delete_budget_cache / "legacy-context";
    const auto now = fs::file_time_type::clock::now();
    const auto setup_leased = [&](const fs::path& entry, const std::string& content, std::chrono::hours age) {
        WriteBytes(entry / "payload", content);
        ArtifactLease::Acquire(entry).reset();
        const auto stamp = now - age;
        fs::last_write_time(entry / "payload", stamp);
        fs::last_write_time(entry, stamp);
        fs::last_write_time(fs::path(entry.wstring() + L".import-lock"), stamp);
    };
    setup_leased(e1, std::string(40, '1'), std::chrono::hours(72));
    setup_leased(e2, std::string(50, '2'), std::chrono::hours(48));
    setup_leased(e3, std::string(60, '3'), std::chrono::hours(24));
    WriteBytes(unowned / "payload", "unowned stays");
    WriteBytes(legacy / "payload", "legacy stays");
    ArtifactLease::Acquire(legacy).reset();

    // 1. Pre-triggered cancellation token leaves all entries untouched.
    {
        CachePruneOptions cancelled_opts;
        cancelled_opts.max_bytes_quota = 0;
        cancelled_opts.require_existing_consumer_lease = true;
        cancelled_opts.eligible_entry = eligible;
        cancelled_opts.control.cancellation = std::make_shared<std::atomic<bool>>(true);
        const auto rep = NativeArtifactStore::PruneCache(delete_budget_cache, cancelled_opts);
        Require(!rep.success && rep.cancelled && !rep.timed_out && rep.partial &&
            rep.entries_removed == 0 && !rep.error_message.empty() &&
            fs::exists(e1 / "payload") && fs::exists(e2 / "payload") && fs::exists(e3 / "payload"),
            "Pre-cancelled PruneCache did not abort cleanly before deleting entries.");
    }

    // 2. Expired deadline leaves all entries untouched.
    {
        CachePruneOptions timeout_opts;
        timeout_opts.max_bytes_quota = 0;
        timeout_opts.require_existing_consumer_lease = true;
        timeout_opts.eligible_entry = eligible;
        timeout_opts.control.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(10);
        const auto rep = NativeArtifactStore::PruneCache(delete_budget_cache, timeout_opts);
        Require(!rep.success && rep.timed_out && !rep.cancelled && rep.partial &&
            rep.entries_removed == 0 && !rep.error_message.empty() &&
            fs::exists(e1 / "payload") && fs::exists(e2 / "payload") && fs::exists(e3 / "payload"),
            "Expired-deadline PruneCache did not abort cleanly before deleting entries.");
    }

    // 3. Mid-scan cancellation stops before deleting any entry.
    {
        auto cancel_flag = std::make_shared<std::atomic<bool>>(false);
        CachePruneOptions mid_cancel_opts;
        mid_cancel_opts.max_bytes_quota = 0;
        mid_cancel_opts.require_existing_consumer_lease = true;
        mid_cancel_opts.control.cancellation = cancel_flag;
        mid_cancel_opts.eligible_entry = [&](const fs::path& path) {
            cancel_flag->store(true);
            return eligible(path);
        };
        const auto rep = NativeArtifactStore::PruneCache(delete_budget_cache, mid_cancel_opts);
        Require(!rep.success && rep.cancelled && rep.partial && rep.entries_removed == 0 &&
            fs::exists(e1 / "payload") && fs::exists(e2 / "payload") && fs::exists(e3 / "payload"),
            "Mid-enumeration cancellation deleted cache entries.");
    }

    // 4. max_entries_deleted budget removes only the oldest 1 entry and defers the rest.
    {
        CachePruneOptions delete_budget_opts;
        delete_budget_opts.max_bytes_quota = 0;
        delete_budget_opts.require_existing_consumer_lease = true;
        delete_budget_opts.eligible_entry = eligible;
        delete_budget_opts.max_entries_deleted = 1;
        const auto rep = NativeArtifactStore::PruneCache(delete_budget_cache, delete_budget_opts);
        Require(rep.success && rep.partial && !rep.cancelled && !rep.timed_out &&
            rep.entries_scanned == 5 && rep.entries_eligible == 3 &&
            rep.entries_removed == 1 && rep.bytes_reclaimed == 40 &&
            rep.entries_deferred_budget == 2 && rep.entries_skipped_unmanaged == 2 &&
            !fs::exists(e1) && fs::exists(e2 / "payload") && fs::exists(e3 / "payload") &&
            FileBytes(unowned / "payload") == "unowned stays" &&
            FileBytes(legacy / "payload") == "legacy stays",
            "max_entries_deleted budget failed to prune only the oldest eligible entry.");
    }

    // 5. Forward slashes in cache_root path succeed without ERROR_INVALID_NAME.
    {
        const fs::path slash_root(delete_budget_cache.generic_wstring());
        Require(slash_root.wstring().find(L'/') != std::wstring::npos,
            "Forward-slash cache_root fixture did not contain forward slashes.");
        CachePruneOptions slash_opts;
        slash_opts.max_bytes_quota = 0;
        slash_opts.require_existing_consumer_lease = true;
        slash_opts.eligible_entry = eligible;
        const auto rep = NativeArtifactStore::PruneCache(slash_root, slash_opts);
        Require(rep.success && !rep.partial && rep.entries_removed == 2 && rep.bytes_reclaimed == 110 &&
            !fs::exists(e2) && !fs::exists(e3) &&
            FileBytes(unowned / "payload") == "unowned stays" &&
            FileBytes(legacy / "payload") == "legacy stays",
            "Forward-slash cache_root failed during PruneCache.");
    }

    // 6. max_entries_scanned budget bounds directory inspection and marks partial.
    {
        const auto scan_budget_cache = root / "bounded-scan-cache";
        const auto s1 = scan_budget_cache / "r2-0000000000000021";
        const auto s2 = scan_budget_cache / "r2-0000000000000022";
        const auto s3 = scan_budget_cache / "r2-0000000000000023";
        setup_leased(s1, std::string(30, 'A'), std::chrono::hours(72));
        setup_leased(s2, std::string(30, 'B'), std::chrono::hours(48));
        setup_leased(s3, std::string(30, 'C'), std::chrono::hours(24));
        CachePruneOptions scan_opts;
        scan_opts.max_age_seconds = 3600;
        scan_opts.require_existing_consumer_lease = true;
        scan_opts.eligible_entry = eligible;
        scan_opts.max_entries_scanned = 2;
        const auto rep = NativeArtifactStore::PruneCache(scan_budget_cache, scan_opts);
        const std::size_t remaining = (fs::exists(s1) ? 1 : 0) + (fs::exists(s2) ? 1 : 0) + (fs::exists(s3) ? 1 : 0);
        Require(rep.success && rep.partial && !rep.cancelled && !rep.timed_out &&
            rep.entries_scanned == 2 && rep.entries_eligible == 2 &&
            rep.entries_deferred_budget >= 1 && rep.entries_removed == 2 && remaining == 1,
            "max_entries_scanned budget failed to bound enumeration to 2 entries.");
    }
}
void CliQuotaTests(const fs::path& root, const fs::path& cli) {
    using OpenFruit::ArtifactLease;
    const auto area = root / "native-cli-quota", state = area / "state", home = area / "home";
    const auto executions = state / "c" / "v";
    const auto inactive = executions / "r2-0000000000000001";
    const auto live = executions / "r2-0000000000000002";
    const auto unowned = executions / "r2-0000000000000003";
    const auto legacy = executions / "legacy-context";
    const std::vector<fs::path> protected_files{
        unowned / "payload", legacy / "payload",
        home / "cache" / "darwin-runtime-inputs" / "provider",
        home / "cache" / "sdk-downloads" / "archive.xip",
        home / "sdk" / "owned-sdk" / "payload",
        state / "c" / "s" / "resolver" / "payload"
    };
    for (const auto& file : protected_files) WriteBytes(file, "protected native CLI fixture");
    WriteBytes(inactive / "payload", "released native CLI context");
    WriteBytes(live / "payload", "live native CLI context");
    ArtifactLease::Acquire(inactive).reset();
    ArtifactLease::Acquire(legacy).reset();
    auto held = ArtifactLease::Acquire(live);
    const std::vector<std::pair<std::wstring, std::wstring>> child_environment{
        {L"OPENFRUIT_USER_STATE", state.wstring()}, {L"OPENFRUIT_HOME", home.wstring()},
        {L"OPENFRUIT_CACHE_ROOT", (home / "cache").wstring()}
    };
    const auto preserved = [&] {
        for (const auto& file : protected_files)
            Require(FileBytes(file) == "protected native CLI fixture", "Native CLI prune altered protected state.");
        Require(!fs::exists(fs::path(unowned.wstring() + L".import-lock")),
                "Native CLI prune fabricated ownership for an unowned context.");
    };
    const auto invoke = [&](const std::vector<std::wstring>& quota_arguments, int expected_exit) {
        std::vector<std::wstring> arguments{cli.wstring(), L"cache", L"prune"};
        arguments.insert(arguments.end(), quota_arguments.begin(), quota_arguments.end());
        OpenFruit::ProcessRunOptions control;
        control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        control.capture_limit_bytes = 64 * 1024;
        const auto result = OpenFruit::Win32Process::Run(cli.wstring(), arguments, area.wstring(),
            child_environment, nullptr, nullptr, control);
        Require(result.launched && !result.timed_out && !result.cancelled && result.exit_code == expected_exit,
                "Native CLI quota command failed or returned an unexpected exit code.");
    };
    const std::vector<std::vector<std::wstring>> invalid_arguments{
        {L"-1"}, {L"+1"}, {L"1tail"}, {L"18446744073709551616"}, {L""}, {}, {L"0", L"extra"}
    };
    for (const auto& arguments : invalid_arguments) {
        invoke(arguments, 2);
        Require(FileBytes(inactive / "payload") == "released native CLI context" &&
            FileBytes(live / "payload") == "live native CLI context",
            "Invalid native CLI quota arguments changed admitted state.");
        preserved();
    }
    invoke({L"0"}, 0);
    Require(!fs::exists(inactive) && FileBytes(live / "payload") == "live native CLI context",
            "Native CLI zero quota failed to prune inactive state or removed the leased context.");
    preserved();
    held.reset();
    invoke({L"0"}, 0);
    Require(!fs::exists(live), "Native CLI zero quota did not prune the released context.");
    preserved();
    fs::remove_all(area);
}
void ImportedFileTests(const fs::path& root) {
    using OpenFruit::NativeArtifactStore;
    const auto area = root / "imported-files", input = area / "upstream" / "lock";
    const auto output = area / "owned" / "lock", receipt = area / "owned" / "import.json";
    WriteBytes(input, "original pins\n");
    WriteBytes(output, "earlier solver output\n");
    Require(NativeArtifactStore::SynchronizeImportedFile(input, output, receipt), "Initial metadata import failed.");
    Require(FileBytes(output) == FileBytes(input), "Import did not copy complete original bytes.");
    const auto parsed = OpenFruit::JsonValue::Parse(FileBytes(receipt));
    Require(parsed && parsed->GetString("schema") == "openfruit.imported-file.v1" &&
        parsed->GetString("phase") == "complete" &&
        parsed->GetString("source") == OpenFruit::Win32Process::ToNarrow(fs::canonical(input).wstring()) &&
        parsed->GetString("destination") == OpenFruit::Win32Process::ToNarrow(fs::canonical(output).wstring()),
        "Import provenance is not bound to canonical source/destination.");
    const auto old = fs::file_time_type::clock::now() - std::chrono::hours(48);
    fs::last_write_time(output, old); fs::last_write_time(receipt, old);
    const auto record_bytes = FileBytes(receipt);
    Require(NativeArtifactStore::SynchronizeImportedFile(input, output, receipt) &&
        fs::last_write_time(output) == old && fs::last_write_time(receipt) == old &&
        FileBytes(receipt) == record_bytes, "Warm identical metadata import rewrote output/provenance.");

    WriteBytes(input, "updated original pins\n");
    Require(FileBytes(output) == "original pins\n", "Metadata import aliases upstream bytes.");
    const HANDLE pinned_output = CreateFileW(output.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(pinned_output != INVALID_HANDLE_VALUE, "Cannot pin owned output against replacement.");
    const bool interrupted_import = NativeArtifactStore::SynchronizeImportedFile(input, output, receipt);
    CloseHandle(pinned_output);
    Require(!interrupted_import && FileBytes(output) == "original pins\n" &&
        OpenFruit::JsonValue::Parse(FileBytes(receipt))->GetString("phase") == "importing",
        "Failed replacement did not preserve prior output and resumable ownership intent.");
    Require(NativeArtifactStore::SynchronizeImportedFile(input, output, receipt) &&
        FileBytes(output) == "updated original pins\n", "Changed upstream metadata did not propagate.");
    const auto good_receipt = FileBytes(receipt), good_output = FileBytes(output);
    const HANDLE writer = CreateFileW(input.c_str(), GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(writer != INVALID_HANDLE_VALUE, "Cannot create owned unreadable-source fixture.");
    const bool locked_import = NativeArtifactStore::SynchronizeImportedFile(input, output, receipt);
    CloseHandle(writer);
    Require(!locked_import && FileBytes(output) == good_output && FileBytes(receipt) == good_receipt,
        "Source-read failure mutated prior output/provenance.");
    Require(!NativeArtifactStore::SynchronizeImportedFile(area / "missing", output, receipt) &&
        FileBytes(output) == good_output && FileBytes(receipt) == good_receipt,
        "Missing nonempty source was treated as deletion or mutated prior data.");

    WriteBytes(receipt, "{ corrupt provenance");
    Require(!NativeArtifactStore::SynchronizeImportedFile(input, output, receipt) &&
        !NativeArtifactStore::SynchronizeImportedFile({}, output, receipt) && FileBytes(output) == good_output,
        "Corrupt receipt was adopted or authorized deletion.");
    auto mismatch = *OpenFruit::JsonValue::Parse(good_receipt);
    mismatch.Set("destination", OpenFruit::JsonValue::String(OpenFruit::Win32Process::ToNarrow((area / "other").wstring())));
    WriteBytes(receipt, mismatch.Serialize(true));
    Require(!NativeArtifactStore::SynchronizeImportedFile(input, output, receipt) &&
        !NativeArtifactStore::SynchronizeImportedFile({}, output, receipt) && FileBytes(output) == good_output,
        "Receipt for another destination was adopted.");
    WriteBytes(receipt, good_receipt);
    auto interrupted = *OpenFruit::JsonValue::Parse(good_receipt);
    interrupted.Set("phase", OpenFruit::JsonValue::String("importing"));
    WriteBytes(receipt, interrupted.Serialize(true));
    Require(NativeArtifactStore::SynchronizeImportedFile(input, output, receipt) &&
        OpenFruit::JsonValue::Parse(FileBytes(receipt))->GetString("phase") == "complete",
        "Interrupted import did not resume to a completed receipt.");
    WriteBytes(output, "solver changed imported pins\n");
    const HANDLE pinned_removal = CreateFileW(output.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(pinned_removal != INVALID_HANDLE_VALUE, "Cannot pin owned output against removal.");
    const bool interrupted_removal = NativeArtifactStore::SynchronizeImportedFile({}, output, receipt);
    CloseHandle(pinned_removal);
    Require(!interrupted_removal && FileBytes(output) == "solver changed imported pins\n" &&
        OpenFruit::JsonValue::Parse(FileBytes(receipt))->GetString("phase") == "removing",
        "Failed removal lost resumable ownership intent.");
    Require(NativeArtifactStore::SynchronizeImportedFile({}, output, receipt) &&
        !fs::exists(output) && !fs::exists(receipt) &&
        NativeArtifactStore::SynchronizeImportedFile({}, output, receipt),
        "Removal lost ownership after solver changes or was not repeatable.");
    WriteBytes(output, "solver-only pins\n");
    Require(NativeArtifactStore::SynchronizeImportedFile({}, output, receipt) &&
        FileBytes(output) == "solver-only pins\n" && !fs::exists(receipt),
        "Unreceipted solver output was deleted or adopted.");

    // Replay deletion after the data was removed but before receipt cleanup.
    interrupted.Set("phase", OpenFruit::JsonValue::String("removing"));
    WriteBytes(receipt, interrupted.Serialize(true));
    fs::remove(output);
    Require(NativeArtifactStore::SynchronizeImportedFile({}, output, receipt) && !fs::exists(receipt),
        "Interrupted deletion could not finish receipt cleanup.");

    const auto outside = area / "outside", alias = area / "owned" / "alias";
    WriteBytes(outside, "external bytes");
    Require(CreateSymbolicLinkW(alias.c_str(), outside.c_str(), 0x2) != FALSE,
        "Cannot create owned imported-output alias fixture.");
    Require(!NativeArtifactStore::SynchronizeImportedFile(input, alias, receipt) &&
        FileBytes(outside) == "external bytes" && !fs::exists(receipt), "Output alias was followed/adopted.");
    const auto record_target = area / "external-receipt";
    WriteBytes(record_target, good_receipt);
    Require(CreateSymbolicLinkW(receipt.c_str(), record_target.c_str(), 0x2) != FALSE,
        "Cannot create owned receipt-alias fixture.");
    Require(!NativeArtifactStore::SynchronizeImportedFile(input, output, receipt) &&
        FileBytes(record_target) == good_receipt && !fs::exists(output), "Receipt alias was followed/adopted.");
    fs::remove(receipt);
    Require(CreateHardLinkW(output.c_str(), input.c_str(), nullptr) != FALSE,
        "Cannot create owned hardlinked-output fixture.");
    Require(NativeArtifactStore::SynchronizeImportedFile(input, output, receipt), "Import could not detach shared output.");
    WriteBytes(input, "upstream changes after detachment\n");
    Require(FileBytes(output) == good_output, "Imported output retained a hardlink to upstream bytes.");
}

fs::path CrashPrivateImport(const fs::path& source, const fs::path& destination,
        const std::wstring& executable, const fs::path& ready, bool publishing = false) {
    Child process(executable, {executable, publishing ? L"--crash-publishing" : L"--crash-staging",
        source.wstring(), destination.wstring(), ready.wstring()});
    Require(WaitForSingleObject(process.process.hProcess, 5000) == WAIT_OBJECT_0,
            "Owned import child did not reach its forced crash");
    DWORD code = 0;
    Require(GetExitCodeProcess(process.process.hProcess, &code) && code == 23 && fs::is_regular_file(ready),
            "Owned import child failed before producing real staging ownership");
    return fs::path(OpenFruit::Win32Process::ToWide(FileBytes(ready)));
}

void ScratchRecoveryTests(const fs::path& root, const std::wstring& executable) {
    using OpenFruit::NativeArtifactStore;
    using OpenFruit::JsonValue;
    const auto area = root / "scratch-recovery", source = area / "source", destination = area / "installed";
    const auto outside = area / "outside";
    WriteBytes(source / "payload", "original owned source");
    WriteBytes(destination / "previous", "old committed product");
    WriteBytes(outside / "sentinel", "external target bytes");
    std::map<fs::path, fs::path> receipts;
    const auto owner = [&](const fs::path& stage) {
        if (const auto found = receipts.find(stage); found != receipts.end()) return found->second;
        for (const auto& item : fs::directory_iterator(stage.parent_path())) {
            if (!item.is_regular_file() || !item.path().filename().wstring().starts_with(L".OPENFRUIT-import-")) continue;
            const auto row = JsonValue::Parse(FileBytes(item.path()));
            if (row && row->GetString("staging") == OpenFruit::Win32Process::ToNarrow(stage.filename().wstring())) {
                receipts[stage] = item.path(); return item.path();
            }
        }
        throw std::runtime_error("Native import produced no staging ownership evidence");
    };
    const auto install = [&] { return NativeArtifactStore::ImportTreeTransactional(source, destination,
        [&](const fs::path& path) { return FileBytes(path / "payload") == "original owned source"; }); };
    const auto legacy = area / "installed.partial-00000000000000000000000000000000";
    WriteBytes(legacy / "unowned", "legacy stage without provenance");

    auto stage = CrashPrivateImport(source, destination, executable, area / "ready-first");
    Require(fs::is_regular_file(stage / "payload") && fs::is_regular_file(owner(stage)) &&
        FileBytes(destination / "previous") == "old committed product", "Crash changed the installed artifact");
    Require(CreateSymbolicLinkW((stage / "outside-link").c_str(), outside.c_str(),
        SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE, "Cannot create owned nested stage alias");
    Require(install() && !fs::exists(stage) && !fs::exists(owner(stage)) &&
        FileBytes(outside / "sentinel") == "external target bytes" && fs::exists(legacy / "unowned"),
        "Recovery failed to remove only the crashed, owned private stage");

    stage = CrashPrivateImport(source, destination, executable, area / "ready-source-overlap");
    Require(NativeArtifactStore::ImportTreeTransactional(stage, destination,
        [&](const fs::path& path) { return FileBytes(path / "payload") == "original owned source"; }) &&
        FileBytes(stage / "payload") == "original owned source" && fs::exists(owner(stage)),
        "Recovery removed its current source tree");
    WriteBytes(stage / "nested-input" / "payload", "nested source");
    Require(NativeArtifactStore::ImportTreeTransactional(stage / "nested-input", destination,
        [&](const fs::path& path) { return FileBytes(path / "payload") == "nested source"; }) &&
        FileBytes(stage / "nested-input" / "payload") == "nested source",
        "Recovery removed an ancestor of its current source tree");
    Require(install(), "Cannot restore installed source after source-overlap recovery checks");

    const auto rejected = [&](const char* name, const std::function<void(JsonValue&)>& mutate) {
        const auto pending = CrashPrivateImport(source, destination, executable, area / name);
        const auto record = owner(pending);
        const auto good = FileBytes(record);
        auto changed = *JsonValue::Parse(good); mutate(changed); WriteBytes(record, changed.Serialize(true));
        Require(install() && fs::is_regular_file(pending / "payload") && fs::is_regular_file(record),
                "Untrusted or publication-phase ownership authorized scratch deletion");
        WriteBytes(record, good);
        Require(install() && !fs::exists(pending) && !fs::exists(record), "Restored real ownership was not recoverable");
    };
    rejected("bad-owner", [&](JsonValue& row) { row.Set("destination", JsonValue::String((area / "other").string())); });
    rejected("relative-owner", [&](JsonValue& row) { row.Set("destination", JsonValue::String("relative-import")); });
    rejected("bad-schema", [&](JsonValue& row) { row.Set("schema", JsonValue::String("unknown producer")); });
    rejected("bad-stage", [&](JsonValue& row) { row.Set("staging", JsonValue::String(outside.string())); });
    rejected("bad-id", [&](JsonValue& row) { row.Set("identity", JsonValue::String("wrong directory object")); });
    rejected("publishing", [&](JsonValue& row) { row.Set("phase", JsonValue::String("publishing")); });

    stage = CrashPrivateImport(source, destination, executable, area / "ready-shared-record");
    auto record = owner(stage);
    const auto good = FileBytes(record);
    const auto shared = area / "external-record";
    WriteBytes(shared, good); fs::remove(record);
    Require(CreateHardLinkW(record.c_str(), shared.c_str(), nullptr) != FALSE, "Cannot create shared ownership fixture");
    Require(install() && fs::exists(stage) && FileBytes(shared) == good && fs::exists(record),
            "Shared ownership record was adopted or altered");
    fs::remove(record); WriteBytes(record, good);
    Require(install() && !fs::exists(stage), "Private ownership did not recover after shared alias removal");

    stage = CrashPrivateImport(source, destination, executable, area / "ready-root-alias");
    record = owner(stage); fs::remove_all(stage);
    Require(CreateSymbolicLinkW(stage.c_str(), outside.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2) != FALSE,
            "Cannot create replaced root alias fixture");
    Require(install() && fs::is_symlink(stage) && fs::exists(record) &&
        FileBytes(outside / "sentinel") == "external target bytes", "Recovery followed a replaced staging root");
    fs::remove(stage); fs::remove(record);

    stage = CrashPrivateImport(source, destination, executable, area / "ready-replaced-directory");
    record = owner(stage);
    const auto moved = fs::path(stage.wstring() + L".retained"); fs::rename(stage, moved);
    WriteBytes(stage / "payload", "unowned replacement");
    Require(install() && FileBytes(stage / "payload") == "unowned replacement" && fs::exists(record) &&
        FileBytes(moved / "payload") == "original owned source", "Directory identity mismatch authorized deletion");

    // A genuine crash after rename must preserve the previous valid artifact.
    // Publication/rollback recovery is outside private-stage reclamation.
    const auto publication = area / "publication", publication_source = publication / "source",
        publication_destination = publication / "installed";
    WriteBytes(publication_source / "payload", "new published bytes");
    WriteBytes(publication_destination / "previous", "old valid bytes");
    const auto published_stage = CrashPrivateImport(publication_source, publication_destination,
        executable, publication / "ready", true);
    const auto published_record = *JsonValue::Parse(FileBytes(owner(published_stage)));
    const auto backup = publication / published_record.GetString("backup");
    Require(published_record.GetString("phase") == "publishing" && !fs::exists(published_stage) &&
        FileBytes(backup / "previous") == "old valid bytes", "Publication crash lost its protected backup");
    Require(NativeArtifactStore::ImportTreeTransactional(publication_source, publication_destination, {}) &&
        fs::exists(owner(published_stage)) && FileBytes(backup / "previous") == "old valid bytes",
        "Private-stage recovery erased an uncertain publication or rollback input");
    Require(FileBytes(source / "payload") == "original owned source", "Recovery altered the immutable source");
}
}
int main(int argc, char** argv) {
    if (argc == 5 && (std::string(argv[1]) == "--shared-reader-holder" || std::string(argv[1]) == "--shared-reader-crash")) {
        auto lease = OpenFruit::ArtifactLease::AcquireSharedRead(fs::path(argv[2]));
        WriteBytes(fs::path(argv[3]), "ready");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!fs::exists(fs::path(argv[4])) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!fs::exists(fs::path(argv[4]))) return 10;
        if (std::string(argv[1]) == "--shared-reader-crash") ExitProcess(23);
        return 0;
    }
    if (argc == 5 && (std::string(argv[1]) == "--crash-staging" || std::string(argv[1]) == "--crash-publishing")) {
        const bool publishing = std::string(argv[1]) == "--crash-publishing";
        fs::path private_stage;
        OpenFruit::NativeArtifactStore::ImportTreeTransactional(fs::path(argv[2]), fs::path(argv[3]),
            [&](const fs::path& stage) {
                if (stage != fs::path(argv[3])) private_stage = stage;
                if (publishing && stage != fs::path(argv[3])) return true;
                WriteBytes(fs::path(argv[4]), OpenFruit::Win32Process::ToNarrow(private_stage.wstring()));
                ExitProcess(23); return false; });
        return 24;
    }
    if (argc == 5 && std::string(argv[1]) == "--lease-holder") {
        auto lease = OpenFruit::ArtifactLease::Acquire(fs::path(argv[2]));
        std::ofstream(fs::path(argv[3])) << "ready";
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!fs::exists(fs::path(argv[4])) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return fs::exists(fs::path(argv[4])) ? 0 : 10;
    }
    if (argc == 4 && std::string(argv[1]) == "--contender") {
        return OpenFruit::NativeArtifactStore::ImportTreeTransactional(fs::path(argv[2]), fs::path(argv[3]), {}) ? 1 : 0;
    }
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-artifact-tests-" + OpenFruit::NewOperationId());
    const auto source = root / "source", destination = root / "installed";
    fs::create_directories(source); fs::create_directories(destination);
    { std::ofstream file(source / "payload"); file << "owned new artifact"; }
    { std::ofstream file(destination / "previous"); file << "owned valid previous artifact"; }
    HANDLE held_staging = INVALID_HANDLE_VALUE;
    const bool imported = OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, destination,
        [&](const fs::path& staged) {
            held_staging = CreateFileW(staged.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            return held_staging != INVALID_HANDLE_VALUE;
        });
    if (held_staging != INVALID_HANDLE_VALUE) CloseHandle(held_staging);
    if (imported || !fs::is_regular_file(destination / "previous")) {
        std::cerr << "Failed publication lost the previous installed artifact.\n";
        return 1;
    }
    if (OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, destination,
            [&](const fs::path& path) { return path != destination; })
        || !fs::is_regular_file(destination / "previous")) return 2;
    if (OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, destination,
            [&](const fs::path& path) { if (path == destination) throw std::runtime_error("owned validator failure"); return true; })
        || !fs::is_regular_file(destination / "previous")) return 3;
    std::promise<void> ready, release;
    auto ready_signal = ready.get_future();
    auto release_signal = release.get_future();
    auto first = std::async(std::launch::async, [&] {
        return OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, destination,
            [&](const fs::path& path) {
                if (path != destination) { ready.set_value(); release_signal.wait(); }
                return fs::is_regular_file(path / "payload");
            });
    });
    if (ready_signal.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        release.set_value(); first.wait(); return 4;
    }
    const auto executable = fs::absolute(argv[0]).wstring();
    const auto contender = OpenFruit::Win32Process::Run(executable,
        {executable, L"--contender", source.wstring(), destination.wstring()});
    release.set_value();
    if (!contender.success || !first.get() || !fs::is_regular_file(destination / "payload")) return 5;
    if (!fs::is_regular_file(source / "payload")) return 6;
    if (OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, source, {})
        || OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, source / "nested", {})
        || !fs::is_regular_file(source / "payload")) return 7;

    // Test PruneCache functionality
    const auto cache_test_dir = root / "cache_test";
    fs::create_directories(cache_test_dir / "item1");
    fs::create_directories(cache_test_dir / "item2");
    {
        std::ofstream f1(cache_test_dir / "item1" / "data.bin");
        f1 << std::string(1024 * 1024, 'A'); // 1 MB
    }
    {
        std::ofstream f2(cache_test_dir / "item2" / "data.bin");
        f2 << std::string(1024 * 1024, 'B'); // 1 MB
    }
    // Prune with quota 1.5 MB -> should prune 1 item (oldest)
    const auto prune_rep = OpenFruit::NativeArtifactStore::PruneCache(cache_test_dir, 1500 * 1024);
    if (prune_rep.entries_removed != 1 || prune_rep.bytes_reclaimed < 1024 * 1024) {
        std::cerr << "PruneCache quota enforcement failed: entries_removed=" << prune_rep.entries_removed << "\n";
        return 8;
    }

    try {
        LeaseTests(root, executable); QuotaPolicyTests(root); BoundedPruneTests(root); ImportedFileTests(root); ScratchRecoveryTests(root, executable);
        SharedReadLeaseTests(root, executable);
        if (argc == 2) CliQuotaTests(root, fs::absolute(Utf8Path(argv[1])));
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 9; }
    return 0;
}

