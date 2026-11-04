#include "swiftpm_source_workspace.hpp"
#include "content_hash.hpp"
#include "atomic_file.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
void Check(const ProcessRunOptions& control) {
    const auto operation = CurrentOperationContext();
    if ((control.cancellation && control.cancellation->load()) ||
        (operation && operation->CancellationRequested()))
        throw std::runtime_error("OPENFRUIT SwiftPM source workspace: cancelled.");
    if (std::chrono::steady_clock::now() >= control.deadline ||
        (operation && operation->DeadlineExceeded()))
        throw std::runtime_error("OPENFRUIT SwiftPM source workspace: deadline exceeded.");
}
bool Within(const fs::path& path, const fs::path& root) {
    auto p = path.begin();
    for (auto r = root.begin(); r != root.end(); ++r, ++p)
        if (p == path.end() || *p != *r) return false;
    return true;
}
fs::path SourceKey(const fs::path& path) {
    auto normalized = path.lexically_normal();
    // GitSourceView records a root as destination / empty-relative, which
    // retains a trailing separator. It denotes the same admitted directory.
    if (normalized.filename().empty() && normalized != normalized.root_path())
        normalized = normalized.parent_path();
    return normalized;
}
std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot read SwiftPM snapshot metadata.");
    std::string bytes((std::istreambuf_iterator<char>(in)), {});
    if (in.bad()) throw std::runtime_error("Incomplete SwiftPM snapshot metadata.");
    return bytes;
}
void Copy(const fs::path& input, const fs::path& output, const fs::path& root,
          std::set<fs::path>& active, const ProcessRunOptions& control,
          bool omit_shared_cache = false) {
    Check(control);
    // Use the shared component-wise resolver, including native file-typed
    // symlinks to directories. Expand links before interpreting any "..".
    // This walker copies tool state/artifacts and .git metadata only. Package
    // sources are projected separately by the Git-aware CreateGitSourceView.
    const auto physical = ResolveGitSourcePath(root, input, control, false);
    if (!Within(physical, root)) throw std::runtime_error("SwiftPM snapshot link escapes input workspace.");
    if (fs::is_directory(physical)) {
        if (!active.insert(physical).second) throw std::runtime_error("SwiftPM snapshot directory cycle.");
        fs::create_directories(output);
        for (const auto& entry : fs::directory_iterator(physical)) {
            const auto name = entry.path().filename();
            // Checkout source semantics must be projected before SwiftPM even
            // reads the graph: public-header directories can be Git links.
            if (input == root && ((omit_shared_cache && name == L"shared-cache") ||
                name == L"ModuleCache" || name == L"checkouts" || name == L"arm64-apple-ios" ||
                name == L"x86_64-unknown-windows-msvc" || name == L"aarch64-unknown-windows-msvc" ||
                name == L"build.db" || name == L"debug.yaml" || name == L"release.yaml" ||
                name == L"plugin-tools.yaml" || name == L".buildSystem_debug" ||
                name == L".buildSystem_release" || name == L".lock" ||
                name == L"OPENFRUIT-sdk-module-warmup" || name == L"OPENFRUIT-ios-target-toolchain" ||
                name == L"OPENFRUIT-ios-target-toolset.json")) continue;
            Copy(entry.path(), output / name, root, active, control, omit_shared_cache);
        }
        active.erase(physical);
    } else if (fs::is_regular_file(physical)) {
        std::ifstream in(physical, std::ios::binary);
        std::ofstream out(output, std::ios::binary | std::ios::trunc);
        if (!in || !out) throw std::runtime_error("Cannot copy SwiftPM execution input.");
        std::vector<char> block(65536);
        while (in) { Check(control); in.read(block.data(), static_cast<std::streamsize>(block.size())); out.write(block.data(), in.gcount()); }
        out.close();
        if (in.bad() || !out) throw std::runtime_error("Incomplete SwiftPM execution snapshot.");
    } else throw std::runtime_error("Unsupported SwiftPM snapshot entry.");
}
void Relocate(JsonValue& value, const fs::path& original, const fs::path& projected) {
    if (value.IsString()) {
        const fs::path candidate(Win32Process::ToWide(value.StringValue()));
        if (candidate.is_absolute() && Within(candidate.lexically_normal(), original))
            value = JsonValue::String(Win32Process::ToNarrow(
                (projected / candidate.lexically_normal().lexically_relative(original)).wstring()));
    } else if (value.IsArray()) {
        for (auto& child : value.ArrayItems()) Relocate(child, original, projected);
    } else if (value.IsObject()) {
        for (auto& [key, child] : value.ObjectItems()) Relocate(child, original, projected);
    }
}
void GraphNodes(const JsonValue& node, std::map<std::string, fs::path>& nodes,
                std::set<std::string>& active, unsigned depth = 0) {
    const auto identity = node.GetString("identity"), path = node.GetString("path");
    const auto children = node.Get("dependencies");
    if (depth > 128 || identity.empty() || path.empty() || !children || !children->IsArray())
        throw std::runtime_error("Malformed SwiftPM dependency graph.");
    if (!active.insert(identity).second) throw std::runtime_error("SwiftPM dependency graph cycle.");
    const fs::path physical = fs::canonical(Win32Process::ToWide(path));
    const auto [found, added] = nodes.emplace(identity, physical);
    if (!added && found->second != physical) throw std::runtime_error("Ambiguous SwiftPM package identity.");
    if (nodes.size() > 50000) throw std::runtime_error("SwiftPM graph exceeds supported node budget.");
    for (const auto& child : children->ArrayItems()) GraphNodes(child, nodes, active, depth + 1);
    active.erase(identity);
}
JsonValue Graph(const fs::path& swift, const fs::path& package, const fs::path& scratch,
               const fs::path& cache_path,
               const std::vector<std::pair<std::wstring, std::wstring>>& env,
               const ProcessRunOptions& control) {
    const auto result = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
        L"--package-path", package.wstring(), L"--scratch-path", scratch.wstring(),
        L"--cache-path", cache_path.wstring(),
        L"show-dependencies", L"--format", L"json"}, package.wstring(), env, nullptr, nullptr, control);
    Check(control);
    const auto json = JsonValue::Parse(result.std_out);
    if (!result.success || result.output_truncated || !json || !json->IsObject())
        throw std::runtime_error("Cannot obtain complete official SwiftPM dependency graph: " + result.std_err);
    return *json;
}
// The official graph is a function of the toolchain, the environment, the
// resolved state and the manifests it reads. Every projected file is digested
// in the source view receipts, so an unchanged material reuses the graph that
// the last successful query of this workspace returned.
JsonValue CachedGraph(const fs::path& swift, const fs::path& package, const fs::path& scratch,
                      const fs::path& cache_path,
                      const std::vector<std::pair<std::wstring, std::wstring>>& env,
                      const ProcessRunOptions& control, const fs::path& receipts) {
    const auto stamp = [&]() -> std::string {
        std::string material = "openfruit.swiftpm-graph.v1\n";
        std::error_code ec;
        for (const auto& tool : {swift, swift.parent_path() / "swift-package.exe"}) {
            const auto size = fs::file_size(tool, ec);
            if (ec) return {};
            const auto written = fs::last_write_time(tool, ec);
            if (ec) return {};
            material += Win32Process::ToNarrow(tool.wstring()) + "|" + std::to_string(size) + "|" +
                std::to_string(written.time_since_epoch().count()) + "\n";
        }
        for (const auto& path : {package, scratch, cache_path})
            material += Win32Process::ToNarrow(path.wstring()) + "\n";
        for (const auto& [name, value] : env)
            material += "env:" + Win32Process::ToNarrow(name) + "=" + Win32Process::ToNarrow(value) + "\n";
        // SwiftPM records its dependency and artifact lists in no stable
        // order; their members, not their order, are the resolved state.
        const std::function<std::string(const JsonValue&)> canonical = [&](const JsonValue& value) {
            if (value.IsArray()) {
                std::vector<std::string> items;
                for (const auto& item : value.ArrayItems()) items.push_back(canonical(item));
                std::sort(items.begin(), items.end());
                std::string text = "[";
                for (const auto& item : items) text += item + ",";
                return text + "]";
            }
            if (value.IsObject()) {
                std::vector<std::string> members;
                for (const auto& [key, member] : value.ObjectItems()) members.push_back(JsonValue::String(key).Serialize(false) + ":" + canonical(member));
                std::sort(members.begin(), members.end());
                std::string text = "{";
                for (const auto& member : members) text += member + ",";
                return text + "}";
            }
            return value.Serialize(false);
        };
        for (const auto& state : {scratch / "workspace-state.json", scratch / "repositories" / "repository-state.json"})
            if (fs::is_regular_file(state, ec)) {
                const auto parsed = JsonValue::Parse(Read(state));
                if (!parsed) return {};
                material += "state:" + canonical(*parsed) + "\n";
            }
        std::vector<fs::path> listed;
        for (const auto& entry : fs::directory_iterator(receipts, ec))
            if (entry.path().extension() == ".json" && entry.path().filename() != "execution-dimensions.json")
                listed.push_back(entry.path());
        if (ec || listed.empty()) return {};
        std::sort(listed.begin(), listed.end());
        for (const auto& receipt : listed)
            material += "receipt:" + receipt.filename().string() + "\n" + Read(receipt) + "\n";
        return Sha256(material).value_or(std::string{});
    }();
    const auto record = receipts / "dependency-graph.cache";
    if (!stamp.empty() && fs::is_regular_file(record)) {
        const auto text = Read(record);
        const auto newline = text.find('\n');
        if (newline != std::string::npos && text.compare(0, newline, stamp) == 0)
            if (const auto json = JsonValue::Parse(text.substr(newline + 1)); json && json->IsObject()) return *json;
    }
    auto graph = Graph(swift, package, scratch, cache_path, env, control);
    std::error_code ec;
    fs::remove(record, ec);
    if (!stamp.empty()) AtomicFile::Publish(record, stamp + "\n" + graph.Serialize(false));
    return graph;
}
std::string TrimLine(std::string text) {
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) text.pop_back();
    return text;
}
bool ObjectName(const std::string& text) {
    return (text.size() == 40 || text.size() == 64) &&
        std::all_of(text.begin(), text.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; });
}
// The checked-out revision of an ordinary .git directory, resolved the way
// git resolves HEAD (detached object name, loose ref, then packed-refs).
// Anything else, such as a gitdir file, is left to git itself.
std::string NativeHead(const fs::path& repository) {
    const auto git = repository / ".git";
    std::error_code ec;
    if (!fs::is_directory(fs::symlink_status(git, ec)) || !fs::is_regular_file(git / "HEAD", ec)) return {};
    const auto head = TrimLine(Read(git / "HEAD"));
    if (ObjectName(head)) return head;
    if (head.rfind("ref: ", 0) != 0) return {};
    const auto ref = head.substr(5);
    if (ref.rfind("refs/", 0) != 0 || ref.find("..") != std::string::npos) return {};
    if (fs::is_regular_file(git / fs::u8path(ref), ec)) {
        const auto loose = TrimLine(Read(git / fs::u8path(ref)));
        return ObjectName(loose) ? loose : std::string{};
    }
    std::istringstream packed(Read(git / "packed-refs"));
    for (std::string line; std::getline(packed, line);) {
        line = TrimLine(line);
        const auto space = line.find(' ');
        if (space != std::string::npos && line.substr(space + 1) == ref && ObjectName(line.substr(0, space)))
            return line.substr(0, space);
    }
    return {};
}
std::string Head(const fs::path& repository, const ProcessRunOptions& control) {
    if (auto revision = NativeHead(repository); !revision.empty()) return revision;
    const auto result = Win32Process::Run(L"git.exe", {L"git.exe", L"-C", repository.wstring(),
        L"rev-parse", L"HEAD"}, L"", {}, nullptr, nullptr, control);
    Check(control);
    if (!result.success || result.output_truncated) throw std::runtime_error("Cannot validate SwiftPM checkout revision.");
    auto revision = result.std_out;
    while (!revision.empty() && (revision.back() == '\r' || revision.back() == '\n')) revision.pop_back();
    return revision;
}
void IsolateGitMetadata(const fs::path& backing, const fs::path& view,
    const fs::path& original, const fs::path& output, const ProcessRunOptions& control) {
    const auto metadata = view / ".git";
    if (fs::exists(metadata / "commondir"))
        throw std::runtime_error("SwiftPM checkout shared Git directories require owned relocation.");
    const auto alternates = metadata / "objects/info/alternates";
    if (fs::exists(alternates)) {
        std::istringstream lines(Read(alternates));
        std::string line, relocated;
        while (std::getline(lines, line)) {
            Check(control);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line.front() == '"')
                throw std::runtime_error("Unsupported Git alternate object path encoding.");
            auto target = fs::u8path(line);
            if (!target.is_absolute()) target = backing / ".git/objects" / target;
            target = fs::canonical(target);
            // Kept from an earlier synchronization: already relocated.
            if (Within(target, output) && fs::is_directory(target)) {
                relocated += Win32Process::ToNarrow(target.wstring()) + "\n";
                continue;
            }
            if (!Within(target, original))
                throw std::runtime_error("Git alternate object database escapes resolver workspace.");
            const auto owned = output / target.lexically_relative(original);
            if (!fs::is_directory(owned))
                throw std::runtime_error("Owned Git alternate object database is missing.");
            relocated += Win32Process::ToNarrow(owned.wstring()) + "\n";
        }
        if (Read(alternates) != relocated && !AtomicFile::Publish(alternates, relocated))
            throw std::runtime_error("Cannot relocate owned Git alternate object database.");
    }
    const auto config = metadata / "config";
    // One git process reads both keys. With --null each entry is
    // "key\nvalue\0"; like --get, the last value of a key wins.
    std::map<std::string, std::string> values;
    {
        const auto result = Win32Process::Run(L"git.exe", {L"git.exe", L"config", L"--file", config.wstring(),
            L"--null", L"--get-regexp", L"^(core\\.worktree|remote\\.origin\\.url)$"}, L"", {}, nullptr, nullptr, control);
        Check(control);
        if (result.output_truncated || (!result.success && result.exit_code != 1))
            throw std::runtime_error("Cannot inspect owned Git checkout configuration.");
        std::size_t begin = 0;
        while (begin < result.std_out.size()) {
            const auto end = result.std_out.find('\0', begin);
            if (end == std::string::npos) throw std::runtime_error("Malformed owned Git checkout configuration.");
            const auto entry = result.std_out.substr(begin, end - begin);
            const auto separator = entry.find('\n');
            values[entry.substr(0, separator)] = separator == std::string::npos ? std::string{} : entry.substr(separator + 1);
            begin = end + 1;
        }
    }
    auto query = [&](const char* key) {
        const auto found = values.find(key);
        return found == values.end() ? std::string{} : found->second;
    };
    auto assign = [&](const wchar_t* key, const fs::path& value) {
        // A relocation already recorded by an earlier build needs no write.
        if (query(Win32Process::ToNarrow(key).c_str()) == Win32Process::ToNarrow(value.wstring())) return;
        const auto result = Win32Process::Run(L"git.exe", {L"git.exe", L"config", L"--file", config.wstring(),
            key, value.wstring()}, L"", {}, nullptr, nullptr, control);
        Check(control);
        if (!result.success) throw std::runtime_error("Cannot relocate owned Git checkout configuration.");
    };
    const auto worktree = query("core.worktree");
    if (!worktree.empty()) {
        auto target = fs::u8path(worktree);
        if (!target.is_absolute()) target = backing / ".git" / target;
        const auto resolved = fs::canonical(target);
        // A worktree kept from an earlier synchronization already names the view.
        if (resolved != fs::canonical(view)) {
            if (resolved != backing)
                throw std::runtime_error("Git checkout worktree points outside its source root.");
            assign(L"core.worktree", view);
        }
    }
    const auto origin = fs::u8path(query("remote.origin.url"));
    if (origin.is_absolute() && Within(origin.lexically_normal(), original))
        assign(L"remote.origin.url", output / origin.lexically_normal().lexically_relative(original));
}
void AddStats(GitSourceViewSyncStats& total, const GitSourceViewSyncStats& added) {
    total.files_copied += added.files_copied;
    total.files_reused += added.files_reused;
    total.bytes_copied += added.bytes_copied;
    total.entries_removed += added.entries_removed;
}
void PublishChanged(const fs::path& path, const std::string& bytes) {
    if (fs::is_regular_file(fs::symlink_status(path)) && Read(path) == bytes) return;
    if (fs::is_symlink(fs::symlink_status(path)))
        throw std::runtime_error("SwiftPM owned metadata is an alias.");
    fs::create_directories(path.parent_path());
    if (!AtomicFile::Publish(path, bytes))
        throw std::runtime_error("Cannot publish SwiftPM execution metadata.");
}
bool Reparse(const fs::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}
} // namespace

SwiftPMSourceWorkspace PrepareSwiftPMSourceWorkspace(const fs::path& swift, const fs::path& package,
    const fs::path& resolver_scratch, const fs::path& destination,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment,
    const ProcessRunOptions& control, const GitSourceView* independent_sources,
    const fs::path& shared_cache, const std::string& reuse_context) {
    Check(control);
    const auto original = fs::canonical(resolver_scratch);
    const auto root = fs::canonical(package);
    const bool reuse = !reuse_context.empty();
    const auto requested = fs::absolute(destination).lexically_normal();
    if (reuse && Reparse(requested))
        throw std::runtime_error("SwiftPM reusable container is an alias.");
    const auto container = fs::weakly_canonical(requested);
    const auto output = reuse ? container / "s" : container;
    if (Within(output, original) || (reuse && Within(original, container)) || (!reuse && fs::exists(output)))
        throw std::runtime_error("SwiftPM execution destination must be fresh and outside input workspace.");
    const auto cache_path = shared_cache.empty() ? output / "shared-cache" : fs::canonical(shared_cache);
    if (!shared_cache.empty() && (!fs::is_directory(cache_path) ||
        Within(cache_path, output) || Within(output, cache_path) || (reuse && Within(cache_path, container))))
        throw std::runtime_error("SwiftPM shared cache must be an existing directory outside the execution workspace.");
    SwiftPMSourceWorkspace result;
    result.scratch = output;
    result.cache_path = cache_path;
    const auto receipts = container / "i";
    if (reuse) {
        result.lease = ArtifactLease::Acquire(container, control);
        Check(control);
        if (Reparse(output) || Reparse(receipts))
            throw std::runtime_error("SwiftPM reusable state or receipts are an alias.");
        const auto context_path = container / "OPENFRUIT-workspace-context.json";
        auto context = JsonValue::ObjectValue();
        context.Set("schema", JsonValue::Number("1"));
        context.Set("reuse_context", JsonValue::String(reuse_context));
        context.Set("original_package", JsonValue::String(Win32Process::ToNarrow(root.wstring())));
        const auto expected_context = context.Serialize(true);
        if (fs::exists(context_path)) {
            if (fs::is_symlink(fs::symlink_status(context_path)) || Read(context_path) != expected_context)
                throw std::runtime_error("SwiftPM reusable workspace context is incompatible or corrupt.");
        } else {
            if (fs::exists(container) && !fs::is_empty(container))
                throw std::runtime_error("SwiftPM reusable workspace has no ownership context.");
            PublishChanged(context_path, expected_context);
        }
        result.ready_metadata = output / "OPENFRUIT-source-workspace-ready.json";
        if (fs::is_regular_file(fs::symlink_status(result.ready_metadata))) {
            const auto old_ready = JsonValue::Parse(Read(result.ready_metadata));
            result.reused = old_ready && old_ready->GetString("reuse_context") == reuse_context &&
                old_ready->GetString("phase") == "source-routing-ready";
        }
        // A failed or interrupted synchronization must never leave a green marker.
        fs::remove(result.ready_metadata);
        GitSourceViewSyncOptions options;
        options.resolve_git_placeholders = false;
        options.include_git_metadata = true;
        options.source_identity = reuse_context + ":toolstate";
        options.excluded_root_entries = {"checkouts", "repositories", "shared-cache", "ModuleCache",
            "arm64-apple-ios", "x86_64-unknown-windows-msvc", "aarch64-unknown-windows-msvc",
            "build.db", "debug.yaml", "release.yaml", "plugin-tools.yaml", ".buildSystem_debug",
            ".buildSystem_release", ".lock", "OPENFRUIT-sdk-module-warmup", "OPENFRUIT-ios-target-toolchain",
            "OPENFRUIT-ios-target-toolset.json", "manifest.db", "manifest.db-shm", "manifest.db-wal", "manifest.db-journal",
            "manifest-validation-original-v1", "workspace-state.json", "OPENFRUIT-source-workspace-ready.json",
            "OPENFRUIT-git-symlink-canonical-roots.tsv"};
        const auto toolstate = SynchronizeGitSourceView(original, output, receipts / "toolstate.json", control, options);
        AddStats(result.toolstate_sync_stats, toolstate.stats);
        if (fs::is_directory(original / "repositories")) {
            options.source_identity = reuse_context + ":repositories";
            options.excluded_root_entries = {"repository-state.json"};
            const auto repositories = SynchronizeGitSourceView(original / "repositories", output / "repositories",
                receipts / "repositories.json", control, options);
            AddStats(result.toolstate_sync_stats, repositories.stats);
        }
    } else {
        fs::create_directories(output.parent_path());
        auto pending = output;
        pending += L".pending-" + Win32Process::ToWide(NewOperationId());
        if (!fs::create_directory(pending)) throw std::runtime_error("Cannot reserve SwiftPM snapshot staging.");
        try {
            std::set<fs::path> active;
            Copy(original, pending, original, active, control, !shared_cache.empty());
            fs::remove(pending / "OPENFRUIT-source-workspace-ready.json");
            fs::remove(pending / "OPENFRUIT-git-symlink-canonical-roots.tsv");
            Check(control);
            fs::rename(pending, output);
        } catch (...) {
            std::error_code ec; fs::remove_all(pending, ec);
            throw;
        }
    }
    // Relocate owned tool state only, never package sources/manifests/resources.
    for (const auto& name : {fs::path("workspace-state.json"), fs::path("repositories/repository-state.json")}) {
        const auto metadata = output / name;
        if (!fs::exists(original / name)) continue;
        auto json = JsonValue::Parse(Read(original / name));
        if (!json) throw std::runtime_error("Invalid SwiftPM execution-state metadata.");
        Relocate(*json, original, output);
        PublishChanged(metadata, json->Serialize(true));
    }
    if (reuse) {
        GitSourceViewSyncOptions options;
        options.source_identity = reuse_context + ":root";
        const auto source = SynchronizeGitSourceView(root, output / "OPENFRUIT-root-package" / root.filename(),
            receipts / "root.json", control, options);
        result.root_view = source.view;
        AddStats(result.source_sync_stats, source.stats);
    } else result.root_view = CreateGitSourceView(root, output / "OPENFRUIT-root-package" / root.filename(), control);
    result.package = result.root_view.root;
    const auto state = JsonValue::Parse(Read(original / "workspace-state.json"));
    const auto object = state ? state->Get("object") : nullptr;
    const auto dependencies = object ? object->Get("dependencies") : nullptr;
    if (!dependencies || !dependencies->IsArray())
        throw std::runtime_error("Malformed official SwiftPM resolved dependency state.");
    std::map<std::string, fs::path> expected;
    struct CheckoutJob { std::string identity; fs::path subpath; std::string revision, location; };
    std::vector<CheckoutJob> jobs;
    for (const auto& dependency : dependencies->ArrayItems()) {
        Check(control);
        const auto reference = dependency.Get("packageRef");
        const auto checkout = dependency.Get("state");
        const auto pinned = checkout ? checkout->Get("checkoutState") : nullptr;
        const auto identity = reference ? reference->GetString("identity") : std::string{};
        const auto kind = reference ? reference->GetString("kind") : std::string{};
        const auto subpath = fs::path(Win32Process::ToWide(dependency.GetString("subpath")));
        const auto revision = pinned ? pinned->GetString("revision") : std::string{};
        if (!identity.empty() && kind == "fileSystem" && checkout &&
            checkout->GetString("name") == "fileSystem") {
            // These paths originate in official resolved state. They can be
            // retained only when the caller explicitly owns their independent
            // Git-aware source projection; a local path alone is not admission.
            const fs::path location(Win32Process::ToWide(reference->GetString("location")));
            const fs::path state_path(Win32Process::ToWide(checkout->GetString("path")));
            if (!location.is_absolute() || !state_path.is_absolute() ||
                !fs::is_directory(location) || fs::canonical(location) != fs::canonical(state_path))
                throw std::runtime_error("SwiftPM local dependency requires an admitted independent source view: " + identity);
            const auto backing = fs::canonical(location);

            // A resolver-owned Git checkout can also appear as fileSystem in
            // the official graph (for example after sparse checkout recovery).
            // Directory containment alone does not establish source provenance.
            // Verify an independent repository root, then retain its actual
            // source identity: absolute manifest references still consume it.
            if (Within(backing, original) && fs::is_regular_file(backing / "Package.swift") &&
                fs::is_directory(backing / ".git") && !Reparse(backing / ".git") &&
                Within(fs::canonical(backing / ".git"), original)) {
                const auto top = Win32Process::Run(L"git.exe", {L"git.exe", L"-C", backing.wstring(),
                    L"rev-parse", L"--show-toplevel"}, L"", {}, nullptr, nullptr, control);
                Check(control);
                auto top_path = top.std_out;
                while (!top_path.empty() && (top_path.back() == '\r' || top_path.back() == '\n'))
                    top_path.pop_back();
                if (!top.success || top.output_truncated || top_path.empty() ||
                    fs::canonical(fs::u8path(top_path)) != backing || Head(backing, control).empty())
                    throw std::runtime_error("SwiftPM resolver-owned local package has invalid Git provenance: " + identity);
                GitSourceView view;
                view.root = backing;
                // This source is already owned by the leased resolver. These
                // are identity mappings, not a claim of a second source copy.
                view.mappings.push_back({backing, backing, backing});
                view.mappings.push_back({backing / "Package.swift", backing / "Package.swift",
                    backing / "Package.swift"});
                if (!expected.emplace(identity, backing).second)
                    throw std::runtime_error("Duplicate SwiftPM package identity in resolved state.");
                result.dependencies.emplace(identity, std::move(view));
                continue;
            }

            if (!independent_sources)
                throw std::runtime_error("SwiftPM local dependency requires an admitted independent source view: " + identity);
            GitSourceView view;
            view.root = backing;
            bool root_mapped = false, manifest_mapped = false;
            for (const auto& mapping : independent_sources->mappings) {
                Check(control);
                const auto projected = SourceKey(mapping.projected);
                if (!Within(projected, backing)) continue;
                if (SourceKey(mapping.original) == projected ||
                    SourceKey(mapping.resolved) == projected)
                    throw std::runtime_error("SwiftPM local source view aliases its original input: " + identity);
                if (projected == backing) root_mapped = true;
                if (projected == backing / "Package.swift") manifest_mapped = true;
                // Reject an admission directory replaced by an escaping link.
                if (!Within(fs::canonical(projected), backing))
                    throw std::runtime_error("SwiftPM local source view escapes its admitted root: " + identity);
                view.mappings.push_back(mapping);
            }
            if (!root_mapped || !manifest_mapped || !fs::is_regular_file(backing / "Package.swift"))
                throw std::runtime_error("SwiftPM local dependency is absent from the independent source mappings: " + identity);
            if (!expected.emplace(identity, backing).second)
                throw std::runtime_error("Duplicate SwiftPM package identity in resolved state.");
            result.dependencies.emplace(identity, std::move(view));
            continue;
        }
        if (identity.empty() || !checkout || checkout->GetString("name") != "sourceControlCheckout" ||
            (kind != "remoteSourceControl" && kind != "localSourceControl"))
            throw std::runtime_error("SwiftPM source workspace requires projection for external local/registry/edited dependency: " + identity);
        if (subpath.empty() || subpath.is_absolute() || subpath.has_root_name() || subpath.has_root_directory() ||
            subpath != subpath.lexically_normal() || subpath == L"." ||
            std::find(subpath.begin(), subpath.end(), fs::path(L"..")) != subpath.end() || revision.empty())
            throw std::runtime_error("Invalid SwiftPM checkout path or revision.");
        jobs.push_back({identity, subpath, revision, reference->GetString("location")});
    }
    // Checkouts are independent: verify and project them concurrently, then
    // admit them in resolved-state order.
    std::vector<GitSourceView> views(jobs.size());
    std::vector<GitSourceViewSyncStats> source_stats(jobs.size()), toolstate_stats(jobs.size());
    {
        std::atomic<std::size_t> next{0};
        std::exception_ptr failure;
        std::mutex failure_mutex;
        const auto operation = CurrentOperationContext();
        const auto project = [&] {
            OperationBinding binding(operation);
            try {
                for (std::size_t index; (index = next++) < jobs.size();) {
                    const auto& job = jobs[index];
                    const auto backing = fs::canonical(original / "checkouts" / job.subpath);
                    if (!Within(backing, fs::canonical(original / "checkouts")) ||
                        !fs::is_directory(backing / ".git") || Head(backing, control) != job.revision)
                        throw std::runtime_error("SwiftPM checkout does not match its authoritative resolved revision.");
                    GitSourceView view;
                    const auto source_identity = reuse_context + ":dependency:" + job.identity + ":" + job.location;
                    const auto identity_digest = Sha256(source_identity);
                    if (!identity_digest) throw std::runtime_error("Cannot hash SwiftPM dependency ownership identity.");
                    const auto& receipt_key = *identity_digest;
                    if (reuse) {
                        GitSourceViewSyncOptions options;
                        options.source_identity = source_identity;
                        const auto source = SynchronizeGitSourceView(backing, output / "checkouts" / job.subpath,
                            receipts / (receipt_key + "-sources.json"), control, options);
                        view = source.view;
                        source_stats[index] = source.stats;
                    } else view = CreateGitSourceView(backing, output / "checkouts" / job.subpath, control);
                    // SwiftPM expects source-control metadata at its checkout path. Copy
                    // metadata independently; do not bind it to the original repository.
                    if (reuse) {
                        GitSourceViewSyncOptions options;
                        options.source_identity = source_identity + ":git";
                        options.resolve_git_placeholders = false;
                        options.include_git_metadata = true;
                        // IsolateGitMetadata relocates these after each synchronization.
                        options.caller_maintained_files = {fs::path("config"), fs::path("objects") / "info" / "alternates"};
                        const auto metadata = SynchronizeGitSourceView(backing / ".git", view.root / ".git",
                            receipts / (receipt_key + "-git.json"), control, options);
                        toolstate_stats[index] = metadata.stats;
                    } else {
                        std::set<fs::path> metadata_active;
                        Copy(backing / ".git", view.root / ".git", backing, metadata_active, control);
                    }
                    IsolateGitMetadata(backing, view.root, original, output, control);
                    Check(control);
                    if (Head(backing, control) != job.revision || Head(view.root, control) != job.revision)
                        throw std::runtime_error("SwiftPM checkout revision changed while projecting source inputs.");
                    views[index] = std::move(view);
                }
            } catch (...) {
                next = jobs.size();
                std::lock_guard lock(failure_mutex);
                if (!failure) failure = std::current_exception();
            }
        };
        const std::size_t workers = std::min<std::size_t>(jobs.size(),
            std::max(1u, std::min(4u, std::thread::hardware_concurrency())));
        std::vector<std::thread> threads;
        for (std::size_t worker = 1; worker < workers; ++worker) threads.emplace_back(project);
        project();
        for (auto& thread : threads) thread.join();
        if (failure) std::rethrow_exception(failure);
    }
    for (std::size_t index = 0; index < jobs.size(); ++index) {
        AddStats(result.source_sync_stats, source_stats[index]);
        AddStats(result.toolstate_sync_stats, toolstate_stats[index]);
        if (!expected.emplace(jobs[index].identity, views[index].root).second)
            throw std::runtime_error("Duplicate SwiftPM package identity in resolved state.");
        result.dependencies.emplace(jobs[index].identity, std::move(views[index]));
    }
    std::map<std::string, fs::path> consumed;
    std::set<std::string> active;
    const auto graph = reuse
        ? CachedGraph(swift, result.package, output, result.cache_path, environment, control, receipts)
        : Graph(swift, result.package, output, result.cache_path, environment, control);
    GraphNodes(graph, consumed, active);
    const auto root_identity = graph.GetString("identity");
    if (root_identity.empty() || !expected.emplace(root_identity, result.package).second)
        throw std::runtime_error("Invalid or ambiguous SwiftPM root package identity.");
    if (consumed != expected) throw std::runtime_error("Official SwiftPM graph does not consume all projected package paths.");
    Check(control);
    auto ready = JsonValue::ObjectValue();
    ready.Set("schema", JsonValue::Number(reuse ? "2" : "1"));
    if (reuse) ready.Set("reuse_context", JsonValue::String(reuse_context));
    ready.Set("phase", JsonValue::String("source-routing-ready"));
    ready.Set("original_resolver_scratch", JsonValue::String(Win32Process::ToNarrow(original.wstring())));
    ready.Set("execution_scratch", JsonValue::String(Win32Process::ToNarrow(output.wstring())));
    ready.Set("cache_path", JsonValue::String(Win32Process::ToNarrow(result.cache_path.wstring())));
    ready.Set("package", JsonValue::String(Win32Process::ToNarrow(result.package.wstring())));
    ready.Set("original_package", JsonValue::String(Win32Process::ToNarrow(root.wstring())));
    auto bindings = JsonValue::ObjectValue();
    for (const auto& [identity, path] : consumed)
        bindings.Set(identity, JsonValue::String(Win32Process::ToNarrow(path.wstring())));
    ready.Set("verified_paths", std::move(bindings));
    auto sources = JsonValue::ObjectValue();
    for (const auto& [identity, view] : result.dependencies) {
        auto source = JsonValue::ObjectValue();
        source.Set("projected", JsonValue::String(Win32Process::ToNarrow(view.root.wstring())));
        if (view.mappings.empty())
            throw std::runtime_error("SwiftPM source view has no source-root provenance.");
        const fs::path orig_root = view.mappings.front().original;
        source.Set("original", JsonValue::String(Win32Process::ToNarrow(orig_root.wstring())));
        sources.Set(identity, std::move(source));
    }
    ready.Set("source_roots", std::move(sources));
    // Old checkout roots are retained, never recursively removed on a graph
    // change. Only the exact expected graph below is admitted for this build;
    // ownership receipts remain available for safe future synchronization.
    result.ready_metadata = output / "OPENFRUIT-source-workspace-ready.json";
    if (!AtomicFile::Publish(result.ready_metadata, ready.Serialize(true)))
        throw std::runtime_error("Cannot publish verified SwiftPM source-routing metadata.");
    return result;
}
} // namespace OpenFruit
