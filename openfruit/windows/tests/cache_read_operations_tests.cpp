#include "cache_read_operations.hpp"
#include "artifact_store.hpp"
#include "operation_events.hpp"
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void Write(const fs::path& path, const std::string& value) {
    fs::create_directories(path.parent_path()); std::ofstream stream(path, std::ios::binary); stream << value;
    Require(stream.good(), "Cannot write owned inventory fixture");
}
std::string Read(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
const CacheNamespaceObservation& Namespace(const CacheReadResult& result, const std::string& name) {
    for (const auto& row : result.namespaces) if (row.name == name) return row;
    throw std::runtime_error("Inventory omitted namespace " + name);
}
const CacheEntryObservation& Entry(const CacheNamespaceObservation& row, const fs::path& name) {
    for (const auto& entry : row.entries) if (entry.path.filename() == name) return entry;
    throw std::runtime_error("Inventory omitted owned test entry");
}
struct Stamp {
    fs::path path; std::string bytes; fs::file_time_type modified;
    explicit Stamp(const fs::path& path) : path(path), bytes(Read(path)), modified(fs::last_write_time(path)) {}
    bool Unchanged() const { return Read(path) == bytes && fs::last_write_time(path) == modified; }
};
struct Sink : EventSink {
    std::vector<OperationEvent> events;
    void Emit(OperationEvent event) noexcept override { events.push_back(std::move(event)); }
};
}
int main() {
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-cache-read-" + NewOperationId());
    try {
        const auto user = root / "a" / "state", managed = root / "a" / "managed-cache";
        CacheReadRequest request; request.user_state_root = user; request.managed_cache_root = managed;
        const auto current = user / "c" / "v" / "r2-0123456789abcdef";
        Write(user / "c" / "s" / "resolver" / "package.txt", "12345");
        Write(current / "product.o", "abc");
        fs::create_hard_link(current / "product.o", current / "alias.o");
        Write(user / "c" / "v" / "legacy" / "old-product.o", "1234");
        Write(user / "w" / "r1-0123456789abcdef" / "root.o", "12");
        Write(user / "c" / "d" / "unclassified.bin", "retained fixture, never assumed disposable");
        Write(user / "c" / "unknown-context" / "not-traversed.bin", "unknown body must not be accessed");
        Write(user / "config.toml", "owned configuration must not be opened");
        Write(user / "credentials" / "private-never-enumerate.json", "owned-secret-not-for-inventory");
        Write(user / "certificates" / "private-never-enumerate.p12", "owned certificate");
        Write(user / "state" / "private-never-enumerate.json", "owned receipt outside this inventory");
        Write(managed / "darwin-runtime-inputs" / "input.bin", "1234567");
        fs::create_hard_link(managed / "darwin-runtime-inputs" / "input.bin", managed / "darwin-runtime-inputs" / "input-alias.bin");
        Write(managed / "unknown-provider" / "not-traversed.bin", "not an admitted source category");
        const Stamp configuration(user / "config.toml"), secret(user / "credentials" / "private-never-enumerate.json");
        const Stamp product(current / "product.o");
        auto active = ArtifactLease::Acquire(current);
        const Stamp marker(fs::path(current.wstring() + L".import-lock"));
        const auto missing_marker = fs::path((user / "c" / "v" / "legacy").wstring() + L".import-lock");
        auto sink = std::make_shared<Sink>(); auto context = std::make_shared<OperationContext>(); context->sink = sink;
        CacheReadResult result;
        {
            OperationBinding binding(context);
            result = CacheReadOperations::Inspect(request);
            Require(sink->events.empty(), "Metadata inventory emitted a mutation or process operation");
        }
        Require(result.status == CacheReadStatus::Partial && !result.limit_reached && !result.error_count,
            "Unclassified namespace measurement was advertised as complete or failed");
        const auto& execution = Namespace(result, "user.c.v");
        const auto& observed_current = Entry(execution, current.filename());
        Require(observed_current.classification == "current_execution_format_not_ownership" &&
            observed_current.consumer_marker == "ordinary_observed_not_ownership" && observed_current.measurement_complete &&
            observed_current.observed_logical_file_bytes == 6 && observed_current.observed_files == 2,
            "Hardlink names or the active consumer marker were misclassified");
        Require(Entry(execution, "legacy").classification == "legacy_or_unclassified_execution" &&
            Entry(execution, "legacy").consumer_marker == "missing" && !fs::exists(missing_marker),
            "Inventory adopted or created a consumer marker for a legacy entry");
        Require(Namespace(result, "managed.darwin-runtime-inputs").observed_logical_file_bytes == 14,
            "Logical namespace lengths were incorrectly deduplicated as physical bytes");
        Require(Namespace(result, "user.c.d").classification == "retained_workspace_unclassified" &&
            !Namespace(result, "user.c.d").observed_logical_file_bytes &&
            !Namespace(result, "managed.unknown-provider").observed_logical_file_bytes,
            "Unclassified input was inspected or reported as an empty namespace");
        auto mixed_request = request;
        mixed_request.user_state_root = fs::path(user.generic_wstring());
        mixed_request.managed_cache_root = fs::path(managed.generic_wstring());
        const auto mixed_result = CacheReadOperations::Inspect(mixed_request);
        Require(mixed_result.status == result.status && mixed_result.error_count == result.error_count &&
            Entry(Namespace(mixed_result, "user.c.v"), current.filename()).observed_logical_file_bytes == 6 &&
            Namespace(mixed_result, "managed.darwin-runtime-inputs").observed_logical_file_bytes == 14,
            "Public slash-separated roots changed native namespace observation");
        const auto json = result.ToJson(); const auto text = json.Serialize();
        Require(json.Get("physical_bytes")->type() == JsonValue::Type::Null &&
            json.Get("reclaimable_bytes")->type() == JsonValue::Type::Null &&
            json.Get("logical_total_bytes")->type() == JsonValue::Type::Null &&
            !json.Get("total_storage_denominator_complete")->Bool() && !json.Get("snapshot_atomic")->Bool(),
            "Inventory fabricated physical allocation, reclaimability or a global denominator");
        Require(text.find("owned-secret-not-for-inventory") == std::string::npos &&
            text.find("private-never-enumerate") == std::string::npos && text.find("config.toml") == std::string::npos,
            "Inventory accessed or exported paths outside cache/workspace scopes");
        for (const auto& row : json.Get("namespaces")->ArrayItems()) {
            Require(row.Get("protected")->Bool() && row.GetString("activity") == "unknown_not_probed",
                "Namespace was declared disposable or inactive");
            for (const auto& entry : row.Get("entries")->ArrayItems())
                Require(entry.Get("protected")->Bool() && entry.GetString("activity") == "unknown_not_probed",
                    "A consumer-marker observation was promoted to deletion authority");
        }
        Require(configuration.Unchanged() && secret.Unchanged() && product.Unchanged() && marker.Unchanged(),
            "Read-only inventory modified contents, last-use marker or timestamps");
        // Unknown categories do not create ownership. A held marker must remain
        // held by the actual consumer, even after repeated metadata observations.
        Require(!ArtifactLease::TryAcquire(current), "Inventory released the actual consumer lease");
        auto limited = request; limited.max_nodes = 1;
        const auto node_limited = CacheReadOperations::Inspect(limited);
        Require(node_limited.status == CacheReadStatus::Partial && node_limited.limit_reached && node_limited.visited_nodes <= 1,
            "Global metadata-node budget was ignored");
        limited = request; limited.max_entries = 1;
        const auto entry_limited = CacheReadOperations::Inspect(limited);
        Require(entry_limited.status == CacheReadStatus::Partial && entry_limited.limit_reached && entry_limited.entry_count <= 1,
            "Global enumeration-entry budget was ignored");
        limited = request; limited.max_depth = 0;
        const auto depth_limited = CacheReadOperations::Inspect(limited);
        Require(depth_limited.status == CacheReadStatus::Partial && depth_limited.limit_reached,
            "Traversal depth limit was ignored");
        limited = request; limited.control.cancellation = std::make_shared<std::atomic<bool>>(true);
        const auto cancelled = CacheReadOperations::Inspect(limited);
        Require(cancelled.status == CacheReadStatus::Cancelled && cancelled.visited_nodes == 0 && !cancelled.deadline_exceeded,
            "Cancelled request inspected filesystem state or reported a timeout");
        limited = request; limited.control.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        const auto timed_out = CacheReadOperations::Inspect(limited);
        Require(timed_out.status == CacheReadStatus::TimedOut && timed_out.visited_nodes == 0 && timed_out.deadline_exceeded &&
            timed_out.ToJson().GetString("status") == "timed_out", "Elapsed deadline was collapsed into user cancellation");
        limited = request; limited.user_state_root = ".";
        Require(CacheReadOperations::Inspect(limited).status == CacheReadStatus::InvalidRequest,
            "Relative root resolved through process working-directory state");
        limited = request; limited.managed_cache_root = root.root_path();
        Require(CacheReadOperations::Inspect(limited).status == CacheReadStatus::InvalidRequest,
            "Volume-wide root was accepted as a cache scope");
        // Every traversal level refuses reparse points, including ancestors of
        // the explicitly supplied root. Their target file names/bytes stay out.
        const auto outside = root / "outside";
        Write(outside / "external.bin", std::string(1000, 'x'));
        fs::create_directory_symlink(outside, current / "external-link");
        const auto linked = CacheReadOperations::Inspect(request);
        const auto& linked_current = Entry(Namespace(linked, "user.c.v"), current.filename());
        Require(linked_current.observed_logical_file_bytes == 6 && linked_current.skipped_reparse == 1 &&
            !linked_current.measurement_complete, "Nested reparse target was traversed or counted");
        fs::create_directory_symlink(outside, root / "alias-root");
        auto alias_request = request; alias_request.user_state_root = root / "alias-root" / "child-state";
        const auto alias_result = CacheReadOperations::Inspect(alias_request);
        Require(Namespace(alias_result, "user.c.v").observation == "reparse_blocked" &&
            !Namespace(alias_result, "user.c.v").observed_logical_file_bytes,
            "Ancestor reparse target was traversed");
        const auto other_user = root / "b" / "state", other_cache = root / "b" / "cache";
        fs::create_directories(other_user); fs::create_directories(other_cache);
        CacheReadRequest other; other.user_state_root = other_user; other.managed_cache_root = other_cache;
        auto a = std::async(std::launch::async, [&]() {
            for (int i = 0; i < 10; ++i)
                Require(Namespace(CacheReadOperations::Inspect(request), "managed.darwin-runtime-inputs").observed_logical_file_bytes == 14,
                    "Concurrent root A used another request's state");
        });
        auto b = std::async(std::launch::async, [&]() {
            for (int i = 0; i < 10; ++i) {
                const auto empty = CacheReadOperations::Inspect(other);
                Require(empty.status == CacheReadStatus::Complete &&
                    Namespace(empty, "managed.darwin-runtime-inputs").observation == "missing",
                    "Concurrent empty root B inherited another namespace");
            }
        });
        a.get(); b.get();
        auto absent = other; absent.user_state_root = root / "not-created-state"; absent.managed_cache_root = root / "not-created-cache";
        const auto absent_result = CacheReadOperations::Inspect(absent);
        Require(absent_result.status == CacheReadStatus::Complete && !fs::exists(absent.user_state_root) && !fs::exists(absent.managed_cache_root),
            "Missing read-only roots were initialized or treated as fabricated contents");
        // Prove real directory sharing protection, without a production hook.
        // This independent root has no pre-existing file or consumer handles
        // that could make an ineffective directory pin look correct.
        const auto pin_state = root / "rename-pin-state";
        const auto moved_state = root / "rename-pin-state-moved";
        for (int i = 0; i < 100; ++i) Write(pin_state / "c" / "s" / "resolver" / (std::to_string(i) + ".txt"), "owned metadata");
        HANDLE attributes = CreateFileW(pin_state.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Require(attributes != INVALID_HANDLE_VALUE, "Cannot prepare attribute-only directory negative control");
        const bool attribute_move = MoveFileExW(pin_state.c_str(), moved_state.c_str(), 0) != FALSE;
        const bool attribute_restore = attribute_move && MoveFileExW(moved_state.c_str(), pin_state.c_str(), 0) != FALSE;
        CloseHandle(attributes);
        Require(attribute_move && attribute_restore, "Attribute-only control does not establish directory sharing behavior");
        auto pin_request = request; pin_request.user_state_root = pin_state;
        pin_request.control.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        std::atomic<bool> stop{false}; std::promise<void> ready;
        auto pin_future = std::async(std::launch::async, [&]() {
            ready.set_value();
            while (!stop.load(std::memory_order_relaxed) && std::chrono::steady_clock::now() < pin_request.control.deadline)
                (void)CacheReadOperations::Inspect(pin_request);
        });
        ready.get_future().wait();
        bool sharing_observed = false, restore_failed = false;
        while (std::chrono::steady_clock::now() < pin_request.control.deadline && !sharing_observed && !restore_failed) {
            if (MoveFileExW(pin_state.c_str(), moved_state.c_str(), 0))
                restore_failed = MoveFileExW(moved_state.c_str(), pin_state.c_str(), 0) == FALSE;
            else {
                const auto error = GetLastError();
                sharing_observed = error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED;
            }
            SwitchToThread();
        }
        stop.store(true, std::memory_order_relaxed); pin_future.get();
        Require(!restore_failed && sharing_observed && fs::is_directory(pin_state) && !fs::exists(moved_state),
            "Inventory directory handles did not prevent concurrent ancestor rename");
        Require(marker.Unchanged() && configuration.Unchanged() && secret.Unchanged() && product.Unchanged(),
            "Repeated/bounded/parallel observations mutated owned inputs");
        active.reset(); // All test futures are joined and native consumers released.
        const auto resolved_root = fs::canonical(root);
        const auto resolved_temp = fs::canonical(fs::temp_directory_path());
        Require(resolved_root.parent_path() == resolved_temp &&
            root.filename().wstring().starts_with(L"OPENFRUIT-cache-read-") &&
            fs::symlink_status(root).type() == fs::file_type::directory,
            "Owned test cleanup escaped its unique ordinary TEMP root");
        std::error_code cleanup_error;
        fs::remove_all(root, cleanup_error); // Only this positively verified owned fixture.
        Require(!cleanup_error && !fs::exists(root), "Owned successful fixture cleanup failed");
        std::cout << "Bounded read-only cache namespace inventory: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; owned fixture retained: " << root << '\n'; return 1;
    }
}
