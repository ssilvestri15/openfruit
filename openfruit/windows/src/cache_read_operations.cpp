#include "cache_read_operations.hpp"
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <limits>
#include <memory>
#include <set>
#include <cwctype>
#include <string_view>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
JsonValue Number(std::uint64_t value) { return JsonValue::Number(std::to_string(value)); }
JsonValue Bytes(const std::optional<std::uint64_t>& value) { return value ? Number(*value) : JsonValue::Null(); }
std::string Text(const fs::path& path) { return Win32Process::ToNarrow(path.wstring()); }
std::wstring Extended(const fs::path& path) {
    // Extended-length Win32 paths do not translate forward slashes. Public
    // request paths and namespace suffixes may legitimately contain either.
    auto normalized = path.lexically_normal();
    normalized.make_preferred();
    auto value = normalized.wstring();
    if (value.starts_with(L"\\\\?\\")) return value;
    return value.starts_with(L"\\\\") ? L"\\\\?\\UNC\\" + value.substr(2) : L"\\\\?\\" + value;
}
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Node {
    std::shared_ptr<Handle> held;
    BY_HANDLE_FILE_INFORMATION info{};
    std::string observation;
};
struct State {
    const CacheReadRequest& request;
    CacheReadResult result;
    bool Active() {
        if (result.status == CacheReadStatus::Cancelled || result.status == CacheReadStatus::TimedOut) return false;
        if ((request.control.cancellation && request.control.cancellation->load(std::memory_order_relaxed)) ||
            std::chrono::steady_clock::now() >= request.control.deadline) {
            result.deadline_exceeded = std::chrono::steady_clock::now() >= request.control.deadline;
            result.status = result.deadline_exceeded ? CacheReadStatus::TimedOut : CacheReadStatus::Cancelled;
            return false;
        }
        return true;
    }
    bool NodeBudget() {
        if (!Active() || result.limit_reached) return false;
        if (result.visited_nodes >= request.max_nodes) { result.limit_reached = true; return false; }
        ++result.visited_nodes; return true;
    }
    bool EntryBudget() {
        if (!Active()) return false;
        if (result.entry_count >= request.max_entries) { result.limit_reached = true; return false; }
        ++result.entry_count; return true;
    }
    void Error() { ++result.error_count; }
    Node Open(const fs::path& path) {
        Node node;
        if (!NodeBudget()) { node.observation = "stopped"; return node; }
        node.held = std::make_shared<Handle>();
        // Deny rename of each held directory while examining its children. Open
        // links themselves and never follow a reparse target during traversal.
        node.held->value = CreateFileW(Extended(path).c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (node.held->value == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            node.observation = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? "missing" : "inaccessible";
            if (node.observation == "inaccessible") Error();
        } else if (!GetFileInformationByHandle(node.held->value, &node.info)) {
            node.observation = "inaccessible"; Error();
        } else if (node.info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) node.observation = "reparse_blocked";
        else {
            node.observation = "observed";
            if (node.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Attribute-only handles do not enforce sharing restrictions.
                // Pin the actual directory using read access, as SDKUsage does,
                // before enumerating any child by path. The metadata handle
                // alone is never treated as a rename barrier.
                auto pin = std::make_shared<Handle>();
                pin->value = CreateFileW(Extended(path).c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                BY_HANDLE_FILE_INFORMATION pinned{};
                if (pin->value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(pin->value, &pinned) ||
                    !(pinned.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                    (pinned.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
                    pinned.dwVolumeSerialNumber != node.info.dwVolumeSerialNumber ||
                    pinned.nFileIndexHigh != node.info.nFileIndexHigh || pinned.nFileIndexLow != node.info.nFileIndexLow) {
                    node.observation = "inaccessible"; Error();
                } else { node.info = pinned; node.held = std::move(pin); }
            }
        }
        return node;
    }
    template<class Visitor> bool Enumerate(const fs::path& path, Visitor visit) {
        if (!Active() || result.limit_reached) return false;
        WIN32_FIND_DATAW data{};
        const auto raw = FindFirstFileExW(Extended(path / L"*").c_str(), FindExInfoBasic, &data,
            FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (raw == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) return true;
            Error(); return false;
        }
        struct Search { HANDLE value; ~Search() { FindClose(value); } } search{raw};
        for (;;) {
            if (std::wstring_view(data.cFileName) != L"." && std::wstring_view(data.cFileName) != L"..") {
                if (!EntryBudget() || !visit(path / data.cFileName)) return false;
            }
            if (!Active()) return false;
            if (!FindNextFileW(raw, &data)) {
                if (GetLastError() == ERROR_NO_MORE_FILES) return true;
                Error(); return false;
            }
        }
    }
};
struct Root {
    fs::path path;
    std::vector<std::shared_ptr<Handle>> held;
    std::string observation;
};
Root RootPath(State& state, const fs::path& path) {
    Root result; result.path = path;
    auto current = path.root_path();
    std::vector<fs::path> components{current};
    for (const auto& part : path.relative_path()) { current /= part; components.push_back(current); }
    for (const auto& component : components) {
        auto node = state.Open(component);
        result.observation = node.observation;
        if (node.observation != "observed") return result;
        if (!(node.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { result.observation = "not_directory"; state.Error(); return result; }
        result.held.push_back(std::move(node.held));
    }
    return result;
}
Root ChildPath(State& state, const Root& root, const fs::path& relative) {
    Root result; result.path = root.path / relative; result.held = root.held; result.observation = root.observation;
    if (root.observation != "observed") return result;
    auto path = root.path;
    for (const auto& part : relative) {
        path /= part;
        auto node = state.Open(path); result.observation = node.observation;
        if (node.observation != "observed") return result;
        if (!(node.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { result.observation = "not_directory"; state.Error(); return result; }
        result.held.push_back(std::move(node.held));
    }
    return result;
}
std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return std::towlower(c); });
    return value;
}
bool Hex(const std::wstring& name, std::size_t length) {
    return name.size() == length && name.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
}
std::string EntryKind(const std::string& ns, const fs::path& path) {
    const auto name = path.filename().wstring();
    if (name.ends_with(L".import-lock")) return "consumer_lease_metadata";
    if (ns == "user.c.v") return name.starts_with(L"r2-") && Hex(name.substr(3), 16)
        ? "current_execution_format_not_ownership" : "legacy_or_unclassified_execution";
    if (ns == "user.w") return name.starts_with(L"r1-") && Hex(name.substr(3), 16)
        ? "current_workspace_format_not_ownership" : "legacy_or_unclassified_workspace";
    if (ns == "user.c.s") return "resolver_state_protected";
    if (ns.ends_with("-probes") || ns == "managed.llvm-acquisition")
        return Hex(name, 32) ? "participating_format_not_ownership" : "legacy_or_unclassified_scratch";
    return "namespace_content_not_ownership";
}
std::string Marker(State& state, const fs::path& path) {
    const auto marker = state.Open(fs::path(path.wstring() + L".import-lock"));
    if (marker.observation == "missing") return "missing";
    if (marker.observation == "stopped") return "not_inspected";
    if (marker.observation != "observed") return marker.observation == "inaccessible" ? "inaccessible" : "unsafe";
    if ((marker.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || marker.info.nNumberOfLinks != 1) return "unsafe";
    return "ordinary_observed_not_ownership";
}
bool Add(State& state, CacheEntryObservation& entry, std::uint64_t bytes) {
    if (bytes > std::numeric_limits<std::uint64_t>::max() - *entry.observed_logical_file_bytes) {
        state.result.overflow = true; ++entry.errors; state.Error(); return false;
    }
    *entry.observed_logical_file_bytes += bytes; return true;
}
bool Measure(State& state, const fs::path& path, CacheEntryObservation& entry, std::size_t depth) {
    const auto node = state.Open(path);
    if (node.observation == "reparse_blocked") { ++entry.skipped_reparse; return false; }
    if (node.observation != "observed") {
        if (node.observation != "stopped") { ++entry.errors; if (node.observation == "missing") state.Error(); }
        return false;
    }
    if (!(node.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        ++entry.observed_files;
        return Add(state, entry, (static_cast<std::uint64_t>(node.info.nFileSizeHigh) << 32) | node.info.nFileSizeLow);
    }
    if (depth >= state.request.max_depth) { state.result.limit_reached = true; return false; }
    bool complete = true;
    const auto enumerated = state.Enumerate(path, [&](const fs::path& child) {
        if (!Measure(state, child, entry, depth + 1)) complete = false;
        return state.Active() && !state.result.limit_reached;
    });
    return complete && enumerated;
}
struct Specification { const wchar_t* relative; const char* name; const char* kind; const char* policy; bool measure = true; };
CacheNamespaceObservation Observe(State& state, const Root& root, const Specification& spec) {
    CacheNamespaceObservation result;
    result.path = root.path / spec.relative; result.name = spec.name;
    result.classification = spec.kind; result.retention_scope = spec.policy;
    const auto directory = ChildPath(state, root, spec.relative);
    result.observation = directory.observation;
    if (directory.observation == "missing") {
        result.observed_logical_file_bytes = 0; result.measurement_complete = true; return result;
    }
    if (directory.observation != "observed") {
        if (directory.observation == "reparse_blocked") result.skipped_reparse = 1;
        else if (directory.observation != "stopped") result.errors = 1;
        return result;
    }
    if (!spec.measure) { result.observation = "not_measured_unclassified"; return result; }
    result.observed_logical_file_bytes = 0;
    const auto before_errors = state.result.error_count;
    const bool enumerated = state.Enumerate(result.path, [&](const fs::path& path) {
        CacheEntryObservation entry; entry.path = path; entry.classification = EntryKind(spec.name, path);
        entry.observed_logical_file_bytes = 0;
        if (entry.classification != "consumer_lease_metadata") entry.consumer_marker = Marker(state, path);
        entry.measurement_complete = Measure(state, path, entry, 0);
        if (!entry.measurement_complete && !entry.observed_files) entry.observed_logical_file_bytes.reset();
        if (entry.observed_logical_file_bytes && *entry.observed_logical_file_bytes > std::numeric_limits<std::uint64_t>::max() - *result.observed_logical_file_bytes) {
            state.result.overflow = true; state.Error(); entry.measurement_complete = false;
        } else if (entry.observed_logical_file_bytes) *result.observed_logical_file_bytes += *entry.observed_logical_file_bytes;
        result.observed_files += entry.observed_files;
        result.skipped_reparse += entry.skipped_reparse;
        result.entries.push_back(std::move(entry));
        return state.Active() && !state.result.limit_reached;
    });
    result.errors += state.result.error_count - before_errors;
    result.measurement_complete = enumerated && std::all_of(result.entries.begin(), result.entries.end(),
        [](const auto& entry) { return entry.measurement_complete; });
    if (!result.measurement_complete && !result.observed_files) result.observed_logical_file_bytes.reset();
    std::sort(result.entries.begin(), result.entries.end(), [](const auto& a, const auto& b) { return a.path.native() < b.path.native(); });
    return result;
}
void DiscoverUnknown(State& state, const Root& root, const fs::path& relative,
    const std::set<std::wstring>& known, const char* prefix) {
    const auto parent = ChildPath(state, root, relative);
    if (parent.observation != "observed") return;
    const bool complete = state.Enumerate(parent.path, [&](const fs::path& path) {
        if (known.contains(Lower(path.filename().wstring()))) return true;
        CacheNamespaceObservation entry; entry.path = path;
        entry.name = std::string(prefix) + Text(path.filename());
        entry.classification = "unclassified_protected"; entry.retention_scope = "not_admitted_by_inventory";
        const auto node = state.Open(path);
        entry.observation = node.observation == "observed" ? "not_measured_unclassified" : node.observation;
        if (node.observation == "reparse_blocked") entry.skipped_reparse = 1;
        if (node.observation == "inaccessible") entry.errors = 1;
        state.result.namespaces.push_back(std::move(entry));
        return state.Active() && !state.result.limit_reached;
    });
    if (!complete && state.result.status != CacheReadStatus::Cancelled && state.result.status != CacheReadStatus::TimedOut)
        state.result.status = CacheReadStatus::Partial;
}
}
JsonValue CacheEntryObservation::ToJson() const {
    auto result = JsonValue::ObjectValue(); result.Set("path", JsonValue::String(Text(path)));
    result.Set("classification", JsonValue::String(classification));
    result.Set("consumer_marker", JsonValue::String(consumer_marker));
    result.Set("activity", JsonValue::String("unknown_not_probed")); result.Set("protected", JsonValue::Boolean(true));
    result.Set("observed_logical_file_bytes", Bytes(observed_logical_file_bytes));
    result.Set("observed_files", Number(observed_files)); result.Set("measurement_complete", JsonValue::Boolean(measurement_complete));
    result.Set("skipped_reparse", Number(skipped_reparse)); result.Set("errors", Number(errors)); return result;
}
JsonValue CacheNamespaceObservation::ToJson() const {
    auto result = JsonValue::ObjectValue(); result.Set("path", JsonValue::String(Text(path)));
    result.Set("namespace", JsonValue::String(name)); result.Set("classification", JsonValue::String(classification));
    result.Set("retention_scope", JsonValue::String(retention_scope)); result.Set("observation", JsonValue::String(observation));
    result.Set("activity", JsonValue::String("unknown_not_probed")); result.Set("protected", JsonValue::Boolean(true));
    result.Set("observed_logical_file_bytes", Bytes(observed_logical_file_bytes)); result.Set("observed_files", Number(observed_files));
    result.Set("measurement_complete", JsonValue::Boolean(measurement_complete)); result.Set("skipped_reparse", Number(skipped_reparse));
    result.Set("errors", Number(errors)); auto rows = JsonValue::ArrayValue();
    for (const auto& entry : entries) rows.ArrayItems().push_back(entry.ToJson()); result.Set("entries", std::move(rows)); return result;
}
JsonValue CacheReadResult::ToJson() const {
    auto result = JsonValue::ObjectValue(); result.Set("schema", JsonValue::String("openfruit.cache-read.v1"));
    result.Set("status", JsonValue::String(status == CacheReadStatus::Complete ? "complete" :
        status == CacheReadStatus::Partial ? "partial" : status == CacheReadStatus::InvalidRequest ? "invalid_request" :
        status == CacheReadStatus::TimedOut ? "timed_out" : "cancelled"));
    result.Set("scope", JsonValue::String("known_cache_and_workspace_namespaces_only"));
    result.Set("snapshot_atomic", JsonValue::Boolean(false)); result.Set("total_storage_denominator_complete", JsonValue::Boolean(false));
    result.Set("byte_accounting", JsonValue::String("observed_logical_file_lengths_including_hardlink_names"));
    result.Set("physical_bytes", JsonValue::Null()); result.Set("reclaimable_bytes", JsonValue::Null()); result.Set("logical_total_bytes", JsonValue::Null());
    result.Set("visited_nodes", Number(visited_nodes)); result.Set("enumerated_entries", Number(entry_count)); result.Set("error_count", Number(error_count));
    result.Set("limit_reached", JsonValue::Boolean(limit_reached)); result.Set("deadline_exceeded", JsonValue::Boolean(deadline_exceeded));
    result.Set("overflow", JsonValue::Boolean(overflow)); auto rows = JsonValue::ArrayValue();
    for (const auto& entry : namespaces) rows.ArrayItems().push_back(entry.ToJson()); result.Set("namespaces", std::move(rows)); return result;
}
CacheReadResult CacheReadOperations::Inspect(const CacheReadRequest& request) {
    State state{request};
    const auto valid = [](const fs::path& path) { return !path.empty() && path.is_absolute() && path.lexically_normal() != path.root_path(); };
    if (!valid(request.user_state_root) || !valid(request.managed_cache_root) || !request.max_entries || !request.max_nodes || request.max_depth > 256) {
        state.result.status = CacheReadStatus::InvalidRequest; return state.result;
    }
    const auto user = RootPath(state, request.user_state_root.lexically_normal());
    const auto managed = RootPath(state, request.managed_cache_root.lexically_normal());
    const Specification user_specs[] = {
        {L"c/s", "user.c.s", "dependency_resolver", "protected_legacy_consumer_protocol"},
        {L"c/v", "user.c.v", "package_execution", "r2_format_and_existing_consumer_lease_required_by_prune"},
        {L"w", "user.w", "application_workspace", "protected_no_global_retention_policy"},
        {L"c/d", "user.c.d", "retained_workspace_unclassified", "protected_per_fixture_classification_required", false}
    };
    const Specification managed_specs[] = {
        {L"darwin-runtime-inputs", "managed.darwin-runtime-inputs", "installed_provider_and_source_inputs", "protected_reference_and_regeneration_inputs"},
        {L"sdk-downloads", "managed.sdk-downloads", "sdk_acquisition_sources", "protected_source_archives"},
        {L"llvm-downloads", "managed.llvm-downloads", "llvm_acquisition_sources", "protected_source_archives"},
        {L"swift-acquisition", "managed.swift-acquisition", "swift_installation_sources", "protected_installer_inputs"},
        {L"modules", "managed.modules", "compiler_module_products", "protected_consumer_scope_not_global_prune"},
        {L"llvm-acquisition", "managed.llvm-acquisition", "llvm_extraction_scratch", "participating_uuid_only_lazy_7d_512MiB_soft"},
        {L"compiler-sdk-probes", "managed.compiler-sdk-probes", "capability_probe_scratch", "participating_uuid_only_lazy_7d_512MiB_soft"},
        {L"llvm-sdk-probes", "managed.llvm-sdk-probes", "capability_probe_scratch", "participating_uuid_only_lazy_7d_512MiB_soft"},
        {L"asset-compiler-probes", "managed.asset-compiler-probes", "capability_probe_scratch", "participating_uuid_only_lazy_7d_512MiB_soft"},
        {L"host-sdk-projections", "managed.host-sdk-projections", "derived_host_sdk_inputs", "protected_active_inputs"},
        {L"compiler-rt", "managed.compiler-rt", "derived_runtime_objects", "protected_active_inputs"}
    };
    for (const auto& spec : user_specs) state.result.namespaces.push_back(Observe(state, user, spec));
    std::set<std::wstring> managed_names;
    for (const auto& spec : managed_specs) { managed_names.insert(spec.relative); state.result.namespaces.push_back(Observe(state, managed, spec)); }
    DiscoverUnknown(state, user, L"c", {L"s", L"v", L"d"}, "user.c.");
    DiscoverUnknown(state, managed, {}, managed_names, "managed.");
    if (state.result.status != CacheReadStatus::Cancelled && state.result.status != CacheReadStatus::TimedOut && (state.result.limit_reached || state.result.overflow || state.result.error_count ||
        std::any_of(state.result.namespaces.begin(), state.result.namespaces.end(), [](const auto& row) { return !row.measurement_complete; })))
        state.result.status = CacheReadStatus::Partial;
    std::sort(state.result.namespaces.begin(), state.result.namespaces.end(), [](const auto& a, const auto& b) {
        return a.name != b.name ? a.name < b.name : a.path.native() < b.path.native();
    });
    return state.result;
}
} // namespace OpenFruit
