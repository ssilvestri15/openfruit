#include "swiftpm_source_workspace.hpp"
#include "package_engine.hpp"
#include "tool_paths.hpp"
#include "operation_events.hpp"
#include "json_value.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary); out << text;
    Require(static_cast<bool>(out), "fixture write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    Require(static_cast<bool>(in), "fixture read failed");
    return {(std::istreambuf_iterator<char>(in)), {}};
}
std::string Git(const fs::path& root, std::vector<std::wstring> args) {
    args.insert(args.begin(), {L"git.exe", L"-C", root.wstring()});
    const auto result = Win32Process::Run(L"git.exe", args);
    Require(result.success, "fixture Git command failed"); return result.std_out;
}
void Link(const fs::path& root, const fs::path& path, const std::string& text) {
    Write(root / path, text);
    auto oid = Git(root, {L"hash-object", L"-w", (root / path).wstring()});
    while (!oid.empty() && (oid.back() == '\r' || oid.back() == '\n')) oid.pop_back();
    Git(root, {L"update-index", L"--add", L"--cacheinfo", L"120000", Win32Process::ToWide(oid), path.wstring()});
}
bool NativeLink(const fs::path& link, const fs::path& target, bool directory) {
    const DWORD flags = directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
    if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags | 0x2)) return true;
    DWORD error = GetLastError();
    if (error == ERROR_INVALID_PARAMETER) {
        if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags)) return true;
        error = GetLastError();
    }
    if (error == ERROR_PRIVILEGE_NOT_HELD) {
        std::cerr << "SKIP native symlink subcase: Windows symlink privilege unavailable\n";
        return false;
    }
    throw std::runtime_error("native symlink fixture creation failed: " + std::to_string(error));
}
struct CancelOnProcess final : EventSink {
    std::weak_ptr<OperationContext> operation;
    fs::path checkout;
    bool observed = false;
    bool unchanged = false;
    void Emit(OperationEvent event) noexcept override {
        if (event.kind != "process.started" || observed) return;
        observed = true;
        try {
            unchanged = fs::is_regular_file(checkout / "Sources/Leaf/Leaf.c") &&
                Read(checkout / "Sources/Leaf/Leaf.c") == "private/real.c" &&
                Read(checkout / "Sources/Leaf/include") == "private/include" &&
                Read(checkout / "Sources/Leaf/private/include/Leaf.h") == "../real.h";
        } catch (...) { unchanged = false; }
        if (const auto context = operation.lock()) context->RequestCancellation();
    }
};
}
int main() {
    fs::path root;
    try {
        const auto swift = ToolPaths::SwiftBin({}) / "swift.exe";
        if (!fs::is_regular_file(swift)) { std::cerr << "Real Windows Swift prerequisite unavailable\n"; return 77; }
        root = fs::temp_directory_path() / ("OPENFRUIT-spm-view-" + NewOperationId());
        const auto leaf = root / "Leaf", consumer = root / "Consumer", primary = root / "primary";
        Write(leaf / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"Leaf\", products: [.library(name: \"Leaf\", targets: [\"Leaf\"])], "
            "targets: [.target(name: \"Leaf\", exclude: [\"private\"])])\n");
        Write(leaf / "Sources/Leaf/private/real.c", "int leaf(void) { return 17; }\n");
        Write(leaf / "Sources/Leaf/private/real.h", "int leaf(void);\n");
        Git(leaf, {L"init", L"-b", L"main", L"--quiet"});
        Git(leaf, {L"config", L"core.symlinks", L"false"});
        Git(leaf, {L"add", L"."});
        Link(leaf, "Sources/Leaf/Leaf.c", "private/real.c");
        Link(leaf, "Sources/Leaf/private/include/Leaf.h", "../real.h");
        Link(leaf, "Sources/Leaf/include", "private/include");
        Git(leaf, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"original owned package"});
        const auto location = leaf.generic_string();
        Write(consumer / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"Consumer\", dependencies: [.package(url: \"" + location +
            "\", branch: \"main\")], targets: [.executableTarget(name: \"Consumer\", dependencies: "
            "[.product(name: \"Leaf\", package: \"leaf\")], exclude: [\"private\"], "
            "resources: [.copy(\"Resources\")])])\n");
        Write(consumer / "Sources/Consumer/main.swift", "import Foundation\nimport Leaf\n"
            "let resource = Bundle.module.url(forResource: \"message\", withExtension: \"txt\", "
            "subdirectory: \"Resources\")!\n"
            "print(leaf())\nprint(try String(contentsOf: resource, encoding: .utf8))\n");
        Write(consumer / "Sources/Consumer/private/payload/message.txt", "original resource");
        Git(consumer, {L"init", L"-b", L"main", L"--quiet"});
        Git(consumer, {L"config", L"core.symlinks", L"false"});
        Git(consumer, {L"add", L"."});
        Link(consumer, "Sources/Consumer/Resources", "private/payload");
        Git(consumer, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"original owned consumer"});
        const auto env = PackageEngine::HostEnvironment(swift.parent_path());
        const auto resolve = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
            L"--package-path", consumer.wstring(), L"--scratch-path", primary.wstring(),
            L"--cache-path", (primary / "shared-cache").wstring(), L"resolve"},
            consumer.wstring(), env);
        if (!resolve.success) std::cerr << resolve.std_out << resolve.std_err;
        Require(resolve.success, "real SwiftPM resolve failed");
        // Derive the checkout path from official state, not a pre-resolved
        // include directory or manually injected graph binding.
        const auto state = JsonValue::Parse(Read(primary / "workspace-state.json"));
        Require(state && state->Get("object"), "real resolver state missing");
        const auto entries = state->Get("object")->Get("dependencies");
        Require(entries && entries->IsArray() && entries->ArrayItems().size() == 1, "unexpected resolved graph");
        const auto checkout = primary / "checkouts" /
            Win32Process::ToWide(entries->ArrayItems()[0].GetString("subpath"));
        Require(Read(checkout / "Sources/Leaf/Leaf.c") == "private/real.c", "Git did not produce source placeholder");
        const auto initial_status = Git(checkout, {L"status", L"--porcelain", L"-z"});
        // SwiftPM writes core.symlinks=true in its clone while the native host
        // environment overrides it to false. Preserve default status exactly;
        // check logical cleanliness under the same effective native policy.
        Require(Git(checkout, {L"-c", L"core.symlinks=false", L"status", L"--porcelain", L"-z"}).empty(),
                "resolver input is not pristine under native Git policy");
        const auto metadata = Read(primary / "workspace-state.json");
        const auto git_config = Read(checkout / ".git/config");
        const auto git_alternates = Read(checkout / ".git/objects/info/alternates");
        const auto root_manifest = Read(consumer / "Package.swift");
        // SwiftPM may create root-owned Package.resolved. Freeze status after
        // the resolver step whose behavior this test deliberately exercises.
        const auto root_status = Git(consumer, {L"status", L"--porcelain", L"-z"});
        // Additional resolver-owned inputs exercise the production scratch
        // copy. They are neither a dependency override nor compiler flags.
        const auto native_artifact = primary / "OPENFRUIT-test-link-input";
        Write(native_artifact / "Versions/A/Headers/API.h", "owned native header\n");
        Write(native_artifact / "Versions/A/marker.txt", "native resolved parent\n");
        Write(native_artifact / "marker.txt", "wrong lexical parent\n");
        Write(native_artifact / "ModuleCache/payload.txt", "preserve nested input\n");
        const bool native_links = NativeLink(native_artifact / "Versions/Current", "A", true) &&
            NativeLink(native_artifact / "Headers", "Versions/Current/Headers", false) &&
            NativeLink(native_artifact / "Jump", "Versions/A/Headers", true) &&
            NativeLink(native_artifact / "dotdot.txt", "Jump/../marker.txt", false);
        const auto shared_cache = fs::canonical(primary / "shared-cache");
        const auto cache_sentinel = shared_cache / "OPENFRUIT-cache-sentinel";
        Write(cache_sentinel, "retain the original warm cache\n");
        const auto sentinel_time = fs::last_write_time(cache_sentinel);
        const auto projected = PrepareSwiftPMSourceWorkspace(swift, consumer, primary,
            root / "execution", env, {}, nullptr, shared_cache);
        Require(projected.cache_path == shared_cache &&
                !fs::exists(projected.scratch / "shared-cache"),
                "shared mutable cache was copied into execution scratch or not returned");
        const auto copied_native = projected.scratch / native_artifact.filename();
        Require(Read(copied_native / "ModuleCache/payload.txt") == "preserve nested input\n",
                "nested input named ModuleCache was silently excluded");
        if (native_links) {
            Require(Read(copied_native / "Headers/API.h") == "owned native header\n",
                    "scratch projection failed file-typed framework header link");
            Require(Read(copied_native / "dotdot.txt") == "native resolved parent\n",
                    "scratch projection normalized dotdot before native link expansion");
        }
        Require(!fs::exists(projected.scratch / "OPENFRUIT-git-symlink-canonical-roots.tsv"),
                "projection emitted unproven whole-root include aliases");
        Require(projected.dependencies.size() == 1, "package view not derived from official graph");
        const auto ready = JsonValue::Parse(Read(projected.ready_metadata));
        Require(ready && ready->GetString("phase") == "source-routing-ready", "verified routing marker missing");
        Require(ready->GetString("cache_path") == Win32Process::ToNarrow(projected.cache_path.wstring()),
                "routing metadata lost the actual shared SwiftPM cache path");
        Require(ready->GetString("original_package") == Win32Process::ToNarrow(fs::canonical(consumer).wstring()) &&
            ready->Get("source_roots") && ready->Get("source_roots")->Get("leaf"),
            "published routing metadata lost original root/dependency provenance");
        Require(fs::is_directory(checkout), "SwiftPM edit removed the original checkout");
        Require(Read(checkout / "Sources/Leaf/Leaf.c") == "private/real.c", "original source was materialized");
        Require(Read(checkout / "Sources/Leaf/include") == "private/include", "original directory placeholder changed");
        Require(Read(checkout / "Sources/Leaf/private/include/Leaf.h") == "../real.h", "original header changed");
        Require(!projected.root_view.mappings.empty(), "root source-view provenance missing");
        Require(Read(projected.package / "Sources/Consumer/Resources/message.txt") == "original resource",
                "root resource directory was not projected");
        Require(metadata == Read(primary / "workspace-state.json"), "original resolver state changed");
        Require(root_manifest == Read(consumer / "Package.swift"), "original root manifest changed");
        const auto leaf_view = projected.dependencies.at("leaf").root;
        Require(fs::is_directory(leaf_view / "Sources/Leaf/include"), "header directory was not projected before graph read");
        const auto owned_alternates = Read(leaf_view / ".git/objects/info/alternates");
        Require(owned_alternates.find(Win32Process::ToNarrow(projected.scratch.wstring())) == 0 &&
            owned_alternates.find(Win32Process::ToNarrow(primary.wstring())) == std::string::npos,
            "projected checkout retained original mutable Git metadata binding");
        const auto build = Win32Process::Run(swift.wstring(), {swift.wstring(), L"build",
            L"--build-system", L"native",
            L"--package-path", projected.package.wstring(), L"--scratch-path", projected.scratch.wstring(),
            L"--cache-path", projected.cache_path.wstring()},
            projected.package.wstring(), env);
        if (!build.success) std::cerr << build.std_out << build.std_err;
        Require(build.success, "official SwiftPM cannot build its projected dependency graph");
        const auto bin = Win32Process::Run(swift.wstring(), {swift.wstring(), L"build", L"--show-bin-path",
            L"--build-system", L"native",
            L"--package-path", projected.package.wstring(), L"--scratch-path", projected.scratch.wstring(),
            L"--cache-path", projected.cache_path.wstring()},
            projected.package.wstring(), env);
        Require(bin.success, "SwiftPM cannot report product location");
        auto path = bin.std_out;
        while (!path.empty() && (path.back() == '\r' || path.back() == '\n')) path.pop_back();
        const auto executable = fs::path(Win32Process::ToWide(path)) / "Consumer.exe";
        const auto run = Win32Process::Run(executable.wstring(), {executable.wstring()}, L"", env);
        auto printed = run.std_out;
        while (!printed.empty() && (printed.back() == '\r' || printed.back() == '\n')) printed.pop_back();
        Require(run.success && (printed == "17\noriginal resource" || printed == "17\r\noriginal resource"),
                "consumer did not execute original projected package code/resources");
        Require(Git(checkout, {L"status", L"--porcelain", L"-z"}) == initial_status, "build changed original checkout status");
        Require(Git(leaf, {L"status", L"--porcelain", L"-z"}).empty(), "build changed source repository");
        Require(metadata == Read(primary / "workspace-state.json"), "build mutated original resolver state");
        Require(git_config == Read(checkout / ".git/config") &&
            git_alternates == Read(checkout / ".git/objects/info/alternates"),
            "build mutated original Git configuration/object metadata");
        Require(Read(consumer / "Sources/Consumer/Resources") == "private/payload" &&
            root_status == Git(consumer, {L"status", L"--porcelain", L"-z"}),
            "build mutated original root package or resource placeholder");
        Write(projected.package / "Sources/Consumer/Resources/message.txt", "view-only mutation");
        Require(Read(consumer / "Sources/Consumer/private/payload/message.txt") == "original resource",
                "root view mutation reached original resource through a mutable alias");
        const auto warm = PrepareSwiftPMSourceWorkspace(swift, consumer, primary,
            root / "execution-warm", env, {}, nullptr, projected.cache_path);
        Require(warm.cache_path == projected.cache_path && !fs::exists(warm.scratch / "shared-cache") &&
                Read(cache_sentinel) == "retain the original warm cache\n" &&
                fs::last_write_time(cache_sentinel) == sentinel_time,
                "warm preparation duplicated or modified the shared cache sentinel");
        Require(Read(primary / "workspace-state.json") == metadata &&
                Read(consumer / "Package.swift") == root_manifest &&
                Read(warm.package / "Sources/Consumer/Resources/message.txt") == "original resource",
                "warm shared-cache graph changed original inputs or reused a mutable source alias");
        bool invalid_cache_rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary,
            root / "cache-overlap", env, {}, nullptr, root); }
        catch (const std::exception&) { invalid_cache_rejected = true; }
        Require(invalid_cache_rejected && !fs::exists(root / "cache-overlap"),
                "execution nested inside its shared cache was accepted");

        // Stable execution keeps SwiftPM's real build database and absolute
        // product paths, while refreshing only independently owned sources.
        const auto stable_container = root / "stable-execution";
        const std::string reuse_context = "owned-native-host-debug-context-v1";
        auto prepare_stable = [&](const fs::path& resolver) {
            return PrepareSwiftPMSourceWorkspace(swift, consumer, resolver, stable_container,
                env, {}, nullptr, shared_cache, reuse_context);
        };
        auto build_stable = [&](const SwiftPMSourceWorkspace& workspace) {
            const auto built = Win32Process::Run(swift.wstring(), {swift.wstring(), L"build",
                L"--build-system", L"native", L"--package-path", workspace.package.wstring(),
                L"--scratch-path", workspace.scratch.wstring(), L"--cache-path", workspace.cache_path.wstring()},
                workspace.package.wstring(), env);
            if (!built.success) std::cerr << built.std_out << built.std_err;
            Require(built.success, "official SwiftPM stable workspace build failed");
            const auto bin = Win32Process::Run(swift.wstring(), {swift.wstring(), L"build", L"--show-bin-path",
                L"--build-system", L"native", L"--package-path", workspace.package.wstring(),
                L"--scratch-path", workspace.scratch.wstring(), L"--cache-path", workspace.cache_path.wstring()},
                workspace.package.wstring(), env);
            Require(bin.success, "stable product path discovery failed");
            auto text = bin.std_out;
            while (!text.empty() && (text.back() == '\r' || text.back() == '\n')) text.pop_back();
            return fs::path(Win32Process::ToWide(text));
        };
        auto stable = prepare_stable(primary);
        Require(stable.lease && !stable.reused && stable.scratch == stable_container / "s" &&
                stable.source_sync_stats.files_copied > 0,
                "first stable preparation did not acquire independent source ownership");
        const auto stable_package = stable.package;
        const auto stable_bin = build_stable(stable);
        const auto stable_executable = stable_bin / "Consumer.exe";
        const auto consumer_time = fs::last_write_time(stable_executable);
        std::map<fs::path, fs::file_time_type> leaf_products;
        for (const auto& entry : fs::recursive_directory_iterator(stable_bin / "Leaf.build"))
            if (entry.is_regular_file() && (entry.path().extension() == ".obj" || entry.path().extension() == ".o"))
                leaf_products.emplace(entry.path(), fs::last_write_time(entry.path()));
        Require(!leaf_products.empty(), "real Leaf object product was not produced");
        const auto unchanged_source = stable.dependencies.at("leaf").root / "Sources/Leaf/Leaf.c";
        const auto source_time = fs::last_write_time(unchanged_source);
        stable.lease.reset();
        stable = prepare_stable(primary);
        Require(stable.reused && stable.lease && stable.package == stable_package &&
                stable.source_sync_stats.files_copied == 0 && stable.source_sync_stats.bytes_copied == 0 &&
                fs::last_write_time(unchanged_source) == source_time,
                "warm stable preparation rewrote source bytes or changed absolute package paths");
        Require(build_stable(stable) == stable_bin && fs::last_write_time(stable_executable) == consumer_time,
                "unchanged official SwiftPM build rewrote its executable");
        for (const auto& [product, timestamp] : leaf_products)
            Require(fs::last_write_time(product) == timestamp, "warm preparation rebuilt an unchanged Leaf object");
        const auto original_main = Read(consumer / "Sources/Consumer/main.swift");
        Write(consumer / "Sources/Consumer/main.swift", original_main + "print(\"incremental change\")\n");
        stable.lease.reset();
        stable = prepare_stable(primary);
        Require(stable.source_sync_stats.files_copied == 1,
                "single root source edit did not remain a single projected file change");
        Require(build_stable(stable) == stable_bin && fs::last_write_time(stable_executable) != consumer_time,
                "changed Consumer source did not rebuild the real executable");
        for (const auto& [product, timestamp] : leaf_products)
            Require(fs::last_write_time(product) == timestamp, "root-only edit rebuilt an unchanged Leaf object");
        const auto changed_run = Win32Process::Run(stable_executable.wstring(), {stable_executable.wstring()}, L"", env);
        Require(changed_run.success && changed_run.std_out.find("incremental change") != std::string::npos,
                "incremental product did not execute the changed original source");
        Write(consumer / "Sources/Consumer/main.swift", original_main);
        const auto stable_ready = stable.ready_metadata;
        stable.lease.reset();
        bool wrong_context = false;
        try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary, stable_container,
            env, {}, nullptr, shared_cache, "different-context"); }
        catch (const std::exception&) { wrong_context = true; }
        Require(wrong_context, "incompatible stable build context was accepted");
        Write(stable_ready, "invalid receipt bytes");
        stable = prepare_stable(primary);
        Require(!stable.reused && fs::is_regular_file(stable.ready_metadata),
                "corrupt ready receipt prevented owned source revalidation");
        // A modified owned source is repaired without touching its upstream input.
        Write(stable.package / "Sources/Consumer/main.swift", "corrupt owned source\n");
        stable.lease.reset();
        stable = prepare_stable(primary);
        Require(stable.source_sync_stats.files_copied == 1 &&
                Read(stable.package / "Sources/Consumer/main.swift") == original_main &&
                Read(consumer / "Sources/Consumer/main.swift") == original_main,
                "owned source corruption was not repaired independently");
        stable.lease.reset();
        auto reuse_operation = std::make_shared<OperationContext>();
        auto reuse_observer = std::make_shared<CancelOnProcess>();
        reuse_observer->operation = reuse_operation; reuse_observer->checkout = checkout;
        reuse_operation->sink = reuse_observer;
        bool reuse_cancelled = false;
        { OperationBinding binding(reuse_operation);
          try { prepare_stable(primary); }
          catch (const std::exception&) { reuse_cancelled = true; }
        }
        Require(reuse_cancelled && reuse_observer->observed && reuse_observer->unchanged &&
                !fs::exists(stable_ready), "cancelled stable update retained a green marker or changed original inputs");
        stable = prepare_stable(primary);
        Require(!stable.reused && stable.source_sync_stats.files_copied == 0 && fs::exists(stable_ready),
                "interrupted stable preparation was not repaired without source recopy");
        stable.lease.reset();
        const auto moved_resolver = root / "relocated-resolver";
        const auto relocated_resolve = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
            L"--package-path", consumer.wstring(), L"--scratch-path", moved_resolver.wstring(),
            L"--cache-path", shared_cache.wstring(), L"resolve"}, consumer.wstring(), env);
        Require(relocated_resolve.success, "official resolver relocation fixture failed");
        stable = prepare_stable(moved_resolver);
        Require(stable.reused && stable.package == stable_package && stable.source_sync_stats.files_copied == 0 &&
                Read(stable.dependencies.at("leaf").root / ".git/objects/info/alternates").find(
                    Win32Process::ToNarrow(moved_resolver.wstring())) == std::string::npos,
                "resolver relocation lost source reuse or leaked mutable Git object binding");
        for (const auto& [product, timestamp] : leaf_products)
            Require(fs::last_write_time(product) == timestamp, "resolver relocation discarded an unchanged Leaf product");
        stable.lease.reset();
        // Change the graph through the real resolver, never by injecting a pin
        // or a projected checkout path. These repositories are owned fixtures.
        const auto original_lock = Read(consumer / "Package.resolved");
        Write(leaf / "Sources/Leaf/private/real.c", "int leaf(void) { return 18; }\n");
        Git(leaf, {L"add", L"Sources/Leaf/private/real.c"});
        Git(leaf, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"owned dependency source delta"});
        const auto updated_resolve = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
            L"--package-path", consumer.wstring(), L"--scratch-path", moved_resolver.wstring(),
            L"--cache-path", shared_cache.wstring(), L"update", L"leaf"}, consumer.wstring(), env);
        if (!updated_resolve.success) std::cerr << updated_resolve.std_out << updated_resolve.std_err;
        Require(updated_resolve.success, "official dependency pin update failed");
        stable = prepare_stable(moved_resolver);
        Require(stable.package == stable_package && stable.source_sync_stats.files_copied >= 2 &&
                Git(stable.dependencies.at("leaf").root, {L"rev-parse", L"HEAD"}) ==
                    Git(leaf, {L"rev-parse", L"HEAD"}),
                "new official dependency revision was not synchronized at stable paths");
        Require(fs::last_write_time(unchanged_source) != source_time,
                "changed canonical source retained obsolete file-alias metadata for the compiler");
        build_stable(stable);
        bool leaf_rebuilt = false;
        for (const auto& [product, timestamp] : leaf_products)
            leaf_rebuilt = leaf_rebuilt || fs::last_write_time(product) != timestamp;
        Require(leaf_rebuilt, "changed dependency source did not rebuild its real Leaf object");
        const auto updated_run = Win32Process::Run(stable_executable.wstring(), {stable_executable.wstring()}, L"", env);
        if (!updated_run.success || updated_run.std_out.rfind("18", 0) != 0)
            std::cerr << "Updated dependency execution stdout: " << updated_run.std_out
                      << "\nstderr: " << updated_run.std_err << '\n';
        Require(updated_run.success && updated_run.std_out.rfind("18", 0) == 0,
                "stable graph update executed an obsolete dependency product");
        stable.lease.reset();
        Write(leaf / "Sources/Leaf/private/real.c", "int leaf(void) { return 17; }\n");
        Git(leaf, {L"add", L"Sources/Leaf/private/real.c"});
        Git(leaf, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"restore owned dependency fixture behaviour"});
        Write(consumer / "Package.resolved", original_lock);
        const auto context_file = stable_container / "OPENFRUIT-workspace-context.json";
        const auto context_bytes = Read(context_file);
        Write(context_file, "corrupt ownership context");
        bool corrupt_context_rejected = false;
        try { prepare_stable(primary); }
        catch (const std::exception&) { corrupt_context_rejected = true; }
        Require(corrupt_context_rejected, "corrupt workspace ownership context was accepted");
        Write(context_file, context_bytes);
        const auto unknown_container = root / "unknown-stable";
        Write(unknown_container / "unowned.txt", "preserve unknown content");
        bool unknown_rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary, unknown_container,
            env, {}, nullptr, shared_cache, reuse_context); }
        catch (const std::exception&) { unknown_rejected = true; }
        Require(unknown_rejected && Read(unknown_container / "unowned.txt") == "preserve unknown content",
                "unowned existing workspace was adopted or altered");

        // Xcode local-package discovery already publishes independent Git
        // source views. Its generated aggregate uses their absolute paths;
        // SwiftPM must consume those exact admitted views without rewriting
        // manifests or silently treating an arbitrary upstream path as owned.
        const auto local_view = CreateGitSourceView(leaf, root / "independent-sources/Leaf");
        const auto local_consumer = root / "LocalConsumer";
        const auto local_primary = root / "local-primary";
        Write(local_consumer / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"LocalConsumer\", dependencies: [.package(path: \"" +
            local_view.root.generic_string() + "\")], targets: [.executableTarget(name: \"LocalConsumer\", "
            "dependencies: [.product(name: \"Leaf\", package: \"leaf\")])])\n");
        Write(local_consumer / "Sources/LocalConsumer/main.swift", "import Leaf\nprint(leaf())\n");
        const auto local_manifest = Read(local_consumer / "Package.swift");
        const auto leaf_manifest = Read(leaf / "Package.swift");
        const auto local_leaf_manifest = Read(local_view.root / "Package.swift");
        const auto local_source = Read(local_view.root / "Sources/Leaf/Leaf.c");
        const auto local_header = Read(local_view.root / "Sources/Leaf/include/Leaf.h");
        Require(local_source == Read(leaf / "Sources/Leaf/private/real.c") &&
            local_header == Read(leaf / "Sources/Leaf/private/real.h"),
            "independent local view did not materialize original Git aliases");
        const auto local_resolve = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
            L"--package-path", local_consumer.wstring(), L"--scratch-path", local_primary.wstring(),
            L"--cache-path", (local_primary / "shared-cache").wstring(), L"resolve"},
            local_consumer.wstring(), env);
        if (!local_resolve.success) std::cerr << local_resolve.std_out << local_resolve.std_err;
        Require(local_resolve.success, "real SwiftPM local-package resolve failed");
        const auto local_metadata = Read(local_primary / "workspace-state.json");
        const auto local_state = JsonValue::Parse(local_metadata);
        const auto local_object = local_state ? local_state->Get("object") : nullptr;
        const auto local_dependencies = local_object ? local_object->Get("dependencies") : nullptr;
        Require(local_dependencies && local_dependencies->IsArray() && local_dependencies->ArrayItems().size() == 1,
                "unexpected official local-package graph");
        const auto& local_dependency = local_dependencies->ArrayItems().front();
        const auto local_reference = local_dependency.Get("packageRef");
        Require(local_reference && local_reference->GetString("kind") == "fileSystem",
                "local fixture did not exercise official fileSystem state");
        const auto local_identity = local_reference->GetString("identity");
        Require(!local_identity.empty(), "official local-package identity missing");
        bool local_rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, local_consumer, local_primary,
            root / "local-unadmitted", env); }
        catch (const std::exception&) { local_rejected = true; }
        Require(local_rejected && !fs::exists(root / "local-unadmitted/OPENFRUIT-source-workspace-ready.json"),
                "unadmitted external local package was accepted or marked ready");
        auto incomplete_admission = local_view;
        incomplete_admission.mappings.erase(std::remove_if(incomplete_admission.mappings.begin(),
            incomplete_admission.mappings.end(), [&](const SourceViewMapping& mapping) {
                return mapping.projected == local_view.root / "Package.swift";
            }), incomplete_admission.mappings.end());
        local_rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, local_consumer, local_primary,
            root / "local-missing-manifest-admission", env, {}, &incomplete_admission); }
        catch (const std::exception&) { local_rejected = true; }
        Require(local_rejected && !fs::exists(root / "local-missing-manifest-admission/OPENFRUIT-source-workspace-ready.json"),
                "local package without admitted manifest was marked ready");
        auto aliased_admission = local_view;
        for (auto& mapping : aliased_admission.mappings) {
            mapping.original = mapping.projected;
            mapping.resolved = mapping.projected;
        }
        local_rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, local_consumer, local_primary,
            root / "local-upstream-alias", env, {}, &aliased_admission); }
        catch (const std::exception&) { local_rejected = true; }
        Require(local_rejected && !fs::exists(root / "local-upstream-alias/OPENFRUIT-source-workspace-ready.json"),
                "self-referential source ownership was accepted or marked ready");
        Write(local_primary / "shared-cache/OPENFRUIT-default-cache-sentinel", "independent default cache\n");
        const auto local_execution = PrepareSwiftPMSourceWorkspace(swift, local_consumer, local_primary,
            root / "local-execution", env, {}, &local_view);
        Require(local_execution.cache_path == local_execution.scratch / "shared-cache",
                "default execution cache path changed");
        Require(Read(local_execution.cache_path / "OPENFRUIT-default-cache-sentinel") == "independent default cache\n",
                "default cache was omitted from the independent snapshot");
        Write(local_execution.cache_path / "OPENFRUIT-default-cache-sentinel", "execution-only cache write\n");
        Require(Read(local_primary / "shared-cache/OPENFRUIT-default-cache-sentinel") == "independent default cache\n",
                "default mutable cache retained a writable link to the resolver cache");
        Require(local_execution.dependencies.size() == 1 &&
            local_execution.dependencies.at(local_identity).root == local_view.root,
            "local source handoff relocated an already independent view");
        Require(Read(local_execution.package / "Package.swift") == local_manifest &&
            Read(local_view.root / "Package.swift") == local_leaf_manifest,
            "local source handoff rewrote aggregate or dependency manifest");
        const auto local_ready = JsonValue::Parse(Read(local_execution.ready_metadata));
        const auto local_paths = local_ready ? local_ready->Get("verified_paths") : nullptr;
        Require(local_ready && local_ready->GetString("phase") == "source-routing-ready" && local_paths &&
            local_paths->GetString(local_identity) == Win32Process::ToNarrow(local_view.root.wstring()),
            "ready receipt did not verify the exact admitted local graph path");
        const auto local_build = Win32Process::Run(swift.wstring(), {swift.wstring(), L"build",
            L"--build-system", L"native", L"--package-path", local_execution.package.wstring(),
            L"--scratch-path", local_execution.scratch.wstring(), L"--cache-path", local_execution.cache_path.wstring()},
            local_execution.package.wstring(), env);
        if (!local_build.success) std::cerr << local_build.std_out << local_build.std_err;
        Require(local_build.success, "official SwiftPM cannot build admitted local source view");
        const auto local_bin = Win32Process::Run(swift.wstring(), {swift.wstring(), L"build", L"--show-bin-path",
            L"--build-system", L"native", L"--package-path", local_execution.package.wstring(),
            L"--scratch-path", local_execution.scratch.wstring(), L"--cache-path", local_execution.cache_path.wstring()},
            local_execution.package.wstring(), env);
        Require(local_bin.success, "SwiftPM cannot report local consumer product path");
        auto local_bin_path = local_bin.std_out;
        while (!local_bin_path.empty() && (local_bin_path.back() == '\r' || local_bin_path.back() == '\n'))
            local_bin_path.pop_back();
        const auto local_executable = fs::path(Win32Process::ToWide(local_bin_path)) / "LocalConsumer.exe";
        const auto local_run = Win32Process::Run(local_executable.wstring(), {local_executable.wstring()}, L"", env);
        auto local_printed = local_run.std_out;
        while (!local_printed.empty() && (local_printed.back() == '\r' || local_printed.back() == '\n'))
            local_printed.pop_back();
        Require(local_run.success && local_printed == "17", "local consumer did not execute original package code");
        Require(Read(local_primary / "workspace-state.json") == local_metadata &&
            Read(local_consumer / "Package.swift") == local_manifest &&
            Read(leaf / "Package.swift") == leaf_manifest &&
            Read(local_view.root / "Package.swift") == local_leaf_manifest &&
            Read(local_view.root / "Sources/Leaf/Leaf.c") == local_source &&
            Read(local_view.root / "Sources/Leaf/include/Leaf.h") == local_header &&
            Git(leaf, {L"status", L"--porcelain", L"-z"}).empty(),
            "local execution changed original metadata, manifests or admitted source bytes");
        Require(Read(leaf / "Sources/Leaf/Leaf.c") == "private/real.c" &&
            Read(leaf / "Sources/Leaf/include") == "private/include" &&
            Read(leaf / "Sources/Leaf/private/include/Leaf.h") == "../real.h",
            "local execution modified upstream Git alias placeholders");
        // Official SwiftPM records resolver-owned Git packages as fileSystem
        // when an aggregate references an already recovered checkout by path.
        // Exercise that graph without injecting source ownership mappings.
        const auto managed_scratch = root / "managed-resolver";
        const auto managed_leaf = managed_scratch / "recovered/ManagedLeaf";
        const auto managed_consumer = root / "ManagedConsumer";
        Write(managed_leaf / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"ManagedLeaf\", products: [.library(name: \"ManagedLeaf\", "
            "targets: [\"ManagedLeaf\"])], targets: [.target(name: \"ManagedLeaf\")])\n");
        Write(managed_leaf / "Sources/ManagedLeaf/Leaf.swift", "public let recoveredValue = 29\n");
        Write(managed_consumer / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"ManagedConsumer\", dependencies: [.package(path: \"" +
            managed_leaf.generic_string() + "\")], targets: [.executableTarget(name: \"ManagedConsumer\", "
            "dependencies: [\"ManagedLeaf\"])])\n");
        Write(managed_consumer / "Sources/ManagedConsumer/main.swift", "import ManagedLeaf\nprint(recoveredValue)\n");
        const auto managed_resolve = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
            L"--package-path", managed_consumer.wstring(), L"--scratch-path", managed_scratch.wstring(),
            L"resolve"}, managed_consumer.wstring(), env);
        Require(managed_resolve.success, "official managed fileSystem resolve failed");
        bool managed_rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, managed_consumer, managed_scratch,
            root / "managed-unowned", env); }
        catch (const std::exception&) { managed_rejected = true; }
        Require(managed_rejected && !fs::exists(root / "managed-unowned/OPENFRUIT-source-workspace-ready.json"),
            "scratch containment admitted a package without Git provenance");
        Git(managed_leaf, {L"init", L"-b", L"main", L"--quiet"});
        Git(managed_leaf, {L"add", L"."});
        Git(managed_leaf, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"resolver-owned original package"});
        const auto managed_execution = PrepareSwiftPMSourceWorkspace(swift, managed_consumer, managed_scratch,
            root / "managed-execution", env);
        Require(managed_execution.dependencies.size() == 1, "managed graph dependency missing");
        const auto& managed_view = managed_execution.dependencies.begin()->second;
        Require(managed_view.root == fs::canonical(managed_leaf) && !managed_view.mappings.empty() &&
            managed_view.mappings.front().original == fs::canonical(managed_leaf),
            "resolver-owned Git source lost its actual root provenance");
        const auto managed_ready = JsonValue::Parse(Read(managed_execution.ready_metadata));
        Require(managed_ready && managed_ready->Get("source_roots") &&
            managed_ready->Get("source_roots")->Get("managedleaf"),
            "verified source-routing receipt omitted managed Git provenance");
        Require(Git(managed_leaf, {L"status", L"--porcelain", L"-z"}).empty(),
            "managed source admission modified original Git inputs");
        Write(local_view.root / "Sources/Leaf/Leaf.c", "view-only local mutation\n");
        Require(Read(leaf / "Sources/Leaf/private/real.c") == local_source &&
            Read(leaf / "Sources/Leaf/Leaf.c") == "private/real.c",
            "admitted local view retained a mutable alias into upstream sources");
        if (native_links) {
            Require(NativeLink(native_artifact / "bad", "../../outside", false),
                    "native link prerequisite changed");
            bool native_rejected = false;
            try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary, root / "native-escape", env); }
            catch (const std::exception&) { native_rejected = true; }
            Require(native_rejected && !fs::exists(root / "native-escape/OPENFRUIT-source-workspace-ready.json"),
                    "escaping scratch link was marked source-routing-ready");
            fs::remove(native_artifact / "bad");
            Require(NativeLink(native_artifact / "bad", "bad", false), "native link prerequisite changed");
            native_rejected = false;
            try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary, root / "native-cycle", env); }
            catch (const std::exception&) { native_rejected = true; }
            Require(native_rejected && !fs::exists(root / "native-cycle/OPENFRUIT-source-workspace-ready.json"),
                    "cyclic scratch link was marked source-routing-ready");
            fs::remove(native_artifact / "bad");
        }
        ProcessRunOptions cancelled;
        cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
        bool rejected = false;
        try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary, root / "pre-cancel", env, cancelled); }
        catch (const std::exception& error) { rejected = std::string(error.what()).find("cancelled") != std::string::npos; }
        Require(rejected && !fs::exists(root / "pre-cancel"), "pre-cancelled snapshot published");
        auto operation = std::make_shared<OperationContext>();
        auto observer = std::make_shared<CancelOnProcess>();
        observer->operation = operation; observer->checkout = checkout; operation->sink = observer;
        rejected = false;
        { OperationBinding binding(operation);
          try { PrepareSwiftPMSourceWorkspace(swift, consumer, primary, root / "mid-cancel", env); }
          catch (const std::exception& error) { rejected = std::string(error.what()).find("cancelled") != std::string::npos; }
        }
        Require(rejected && observer->observed && observer->unchanged, "real process cancellation changed original checkout");
        Require(!fs::exists(root / "mid-cancel" / "OPENFRUIT-source-workspace-ready.json"), "cancelled routing marked ready");
        // SwiftPM makes resolver inputs read-only. Deliberately corrupt only
        // this owned fixture before the negative experiment begins.
        fs::permissions(checkout / "Sources/Leaf/Leaf.c", fs::perms::owner_write, fs::perm_options::add);
        Write(checkout / "Sources/Leaf/Leaf.c", "private/missing.c");
        const auto invalid_status = Git(checkout, {L"status", L"--porcelain", L"-z"});
        // A POSIX checkout keeps the link dangling; resolution succeeds and
        // only a consumer reading through it fails, so the view must not
        // materialize or invent a target for it.
        const auto invalid = PrepareSwiftPMSourceWorkspace(swift, consumer, primary, root / "invalid", env);
        const auto dangling = invalid.dependencies.at("leaf").root / "Sources/Leaf/Leaf.c";
        Require(fs::is_symlink(fs::symlink_status(dangling)) && !fs::exists(dangling) &&
                    fs::read_symlink(dangling) == fs::path("private/missing.c").make_preferred(),
                "missing original target was materialized instead of kept dangling");
        Require(Read(checkout / "Sources/Leaf/Leaf.c") == "private/missing.c" &&
            Git(checkout, {L"status", L"--porcelain", L"-z"}) == invalid_status,
            "failure repaired or modified original source input");
        Require(metadata == Read(primary / "workspace-state.json"), "failure/cancel changed original resolver state");
        std::cout << "PASS: official SwiftPM resolve -> preprojected checkout source/header/resource views -> compile/link/run; original checkout and Git metadata preserved\n";
        fs::remove_all(root); // Newly reserved owned fixture only.
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nEvidence: " << root.string() << '\n'; return 1;
    }
}
