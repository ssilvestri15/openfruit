#include "content_hash.hpp"
#include "event_journal.hpp"
#include "json_value.hpp"
#include "manifest_projection.hpp"
#include "operation_events.hpp"
#include "package_engine.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"

#include <algorithm>
#include <chrono>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Require(static_cast<bool>(output), "Cannot write owned manifest fixture");
}
using Environment = std::vector<std::pair<std::wstring, std::wstring>>;
class ProcessCollector final : public EventSink {
public:
    void Emit(OperationEvent event) noexcept override {
        if (event.kind == "task.started" && event.data.GetString("name") == "process") ++started;
    }
    unsigned started = 0;
};
void SetEnvironment(Environment& environment, const wchar_t* key, const std::wstring& value) {
    environment.erase(std::remove_if(environment.begin(), environment.end(),
        [&](const auto& pair) { return _wcsicmp(pair.first.c_str(), key) == 0; }), environment.end());
    environment.emplace_back(key, value);
}
std::wstring EnvironmentEntry(const Environment& environment, const wchar_t* key) {
    for (auto entry = environment.rbegin(); entry != environment.rend(); ++entry)
        if (_wcsicmp(entry->first.c_str(), key) == 0) return entry->second;
    return {};
}
void Equivalent(const fs::path& left, const fs::path& right, const char* message) {
    std::error_code error;
    Require(!left.empty() && !right.empty() && fs::equivalent(left, right, error) && !error, message);
}
const JsonValue& Field(const JsonValue& value, const char* name) {
    const auto* field = value.Get(name);
    Require(field != nullptr, std::string("Missing official manifest field: ") + name);
    return *field;
}
// Compare only semantic fields: independent package roots necessarily have
// different absolute paths in the official dump. Do not normalize source bytes.
JsonValue SemanticFields(const JsonValue& manifest) {
    auto fields = JsonValue::ObjectValue();
    fields.Set("name", Field(manifest, "name"));
    fields.Set("products", Field(manifest, "products"));
    const auto& targets = Field(manifest, "targets");
    Require(targets.IsArray() && targets.ArrayItems().size() == 1,
            "Owned manifest did not describe exactly one original target");
    const auto& target = targets.ArrayItems().front();
    auto projected_target = JsonValue::ObjectValue();
    for (const char* key : {"name", "exclude", "dependencies", "type"})
        projected_target.Set(key, Field(target, key));
    fields.Set("target", std::move(projected_target));
    return fields;
}
struct Variant {
    const char* name;
    std::string declaration;
    const char* expected_name;
    bool excluded_input = false;
    bool product_from_chosen_name = false;
};
std::string Manifest(const Variant& variant) {
    return std::string("// swift-tools-version: 6.0\nimport PackageDescription\n") +
        variant.declaration +
        "\nlet package = Package(name: chosenName, products: [\n"
        "    .library(name: " + std::string(variant.product_from_chosen_name ? "chosenName" : "\"ManifestProduct\"") +
        ", targets: [\"Probe\"])\n"
        "], targets: [.target(name: \"Probe\", exclude: " +
        (variant.excluded_input ? "[\"Excluded/\"]" : "[]") + ")])\n";
}
using Inputs = std::map<fs::path, std::string>;
Inputs Populate(const fs::path& package, const Variant& variant, bool initialize = true) {
    Inputs inputs;
    inputs.emplace("Package.swift", Manifest(variant));
    inputs.emplace("Sources/Probe/Probe.swift", "public let manifestProbe = 17\n");
    if (variant.excluded_input)
        inputs.emplace("Sources/Probe/Excluded/Excluded.swift",
                       "// Original input governed by the original exclude metadata.\n"
                       "public let excludedManifestProbe = 23\n");
    for (const auto& [relative, bytes] : inputs) {
        if (initialize) Write(package / relative, bytes);
        else Require(Sha256File(package / relative) == Sha256(bytes),
                     "Warm evaluation input does not match the unchanged original fixture");
    }
    return inputs;
}
void Unchanged(const fs::path& package, const Inputs& inputs) {
    for (const auto& [relative, bytes] : inputs) {
        const auto original = Sha256(bytes);
        const auto current = Sha256File(package / relative);
        Require(original && current && *original == *current,
                "Manifest evaluation changed original fixture bytes: " + relative.string());
    }
    Require(!fs::exists(package / "Package.resolved"),
            "Dependency-free dump unexpectedly produced a source lockfile");
}
JsonValue Dump(const fs::path& swift, const fs::path& compiler, const fs::path& root,
               const Variant& variant, Environment environment, bool initialize = true,
               const std::string& evidence_prefix = "dump-package", bool observe_files = false) {
    const auto package = root / "Package";
    const auto scratch = root / "Scratch";
    const auto cache = root / "Cache";
    fs::create_directories(scratch);
    fs::create_directories(cache);
    const auto inputs = Populate(package, variant, initialize);
    // All SDK/runtime/proxy real-compiler settings come from the production
    // HostEnvironment. The selected manifest executable is the only difference
    // between the two independently cached runs.
    SetEnvironment(environment, L"SWIFT_EXEC_MANIFEST", compiler.wstring());
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    options.capture_limit_bytes = 2 * 1024 * 1024;
    const auto journal = observe_files ? EventJournal::Create(root / "journal") : nullptr;
    ProcessResult result;
    {
    OperationBinding binding(journal ? journal->Context() : CurrentOperationContext());
    result = Win32Process::Run(swift.wstring(), {
        swift.wstring(), L"package", L"--package-path", package.wstring(),
        L"--scratch-path", scratch.wstring(), L"--cache-path", cache.wstring(),
        L"--manifest-cache", L"local", L"dump-package"
    }, package.wstring(), environment, nullptr, nullptr, options);
    }
    if (journal) journal->Flush();
    Write(root / (evidence_prefix + ".stdout.json"), result.std_out);
    Write(root / (evidence_prefix + ".stderr.log"), result.std_err);
    // Preserve the real diagnostics before checking integrity, including when
    // the compiler/proxy fails or modifies one of the original inputs.
    Unchanged(package, inputs);
    Require(result.success && !result.timed_out && !result.cancelled &&
                !result.output_truncated && !result.callback_failed,
            std::string(variant.name) + " manifest evaluation failed through " +
                compiler.filename().string() + ": " + result.std_err);
    const auto document = JsonValue::Parse(result.std_out);
    Require(document && document->IsObject(), "Official SwiftPM returned an invalid manifest dump");
    if (journal) {
        Require(!journal->HasErrors(), "Manifest observation journal failed");
        std::ifstream events(journal->Directory() / "events.jsonl");
        std::vector<JsonValue> observations;
        for (std::string line; std::getline(events, line);) {
            const auto event = JsonValue::Parse(line);
            if (event && event->GetString("kind") == "compiler.manifest.files")
                observations.push_back(Field(*event, "data"));
        }
        Require(observations.size() == 2, "Real manifest proxy did not publish paired file observations");
        Require(observations[0].GetString("phase") == "before" && observations[1].GetString("phase") == "after" &&
                !observations[0].GetString("invocation_id").empty() &&
                observations[0].GetString("invocation_id") == observations[1].GetString("invocation_id"),
                "Manifest file observations lost invocation identity or order");
        for (std::size_t phase = 0; phase < observations.size(); ++phase) {
            std::map<std::string, std::string> states;
            for (const auto& file : Field(observations[phase], "files").ArrayItems())
                states.emplace(file.GetString("role"), file.GetString("state"));
            Require(states["output_parent"] == "directory" && states["vfs_parent"] == "directory" &&
                    states["vfs_overlay"] == "file", "SwiftPM temporaries were absent while the proxy was alive");
            Require(states["output"] == (phase == 0 ? "missing" : "file"),
                    "Real compiler output was not observed before SwiftPM cleanup");
        }
    }
    return *document;
}

JsonValue InputSnapshot(const fs::path& package, const Inputs& inputs) {
    auto snapshot = JsonValue::ObjectValue();
    for (const auto& [relative, bytes] : inputs) {
        const auto digest = Sha256File(package / relative);
        Require(digest.has_value(), "Cannot hash warm manifest input");
        auto row = JsonValue::ObjectValue();
        row.Set("sha256", JsonValue::String(*digest));
        row.Set("mtime_ticks", JsonValue::Number(std::to_string(fs::last_write_time(package / relative).time_since_epoch().count())));
        snapshot.Set(Win32Process::ToNarrow(relative.generic_wstring()), std::move(row));
    }
    return snapshot;
}
void WarmManifestTransition(const fs::path& swift, const fs::path& candidate,
                            const fs::path& baseline, const fs::path& root,
                            const Variant& variant, const char* baseline_name,
                            const Environment& environment) {
    const auto selected = root / "Proxy" / "OPENFRUIT.exe";
    const auto dll_source = candidate.parent_path() / "unicorn.dll";
    Require(fs::is_regular_file(dll_source), "Real candidate unicorn.dll missing for owned proxy copy");
    fs::create_directories(selected.parent_path());
    fs::copy_file(dll_source, selected.parent_path() / "unicorn.dll");
    const auto dll_hash = Sha256File(dll_source);
    const auto copied_dll_hash = Sha256File(selected.parent_path() / "unicorn.dll");
    Require(dll_hash && copied_dll_hash && *dll_hash == *copied_dll_hash,
            "Owned proxy runtime DLL differs from candidate runtime");
    const auto package = root / "Package";
    auto warm_variant = variant;
    warm_variant.product_from_chosen_name = true;
    const auto inputs = Populate(package, warm_variant);
    const auto before = InputSnapshot(package, inputs);
    auto evidence = JsonValue::ObjectValue();
    evidence.Set("schema", JsonValue::String("openfruit.manifest-cache-transition.v1"));
    evidence.Set("variant", JsonValue::String(variant.name));
    evidence.Set("selected_proxy_path", JsonValue::String(Win32Process::ToNarrow(selected.wstring())));
    evidence.Set("package_path", JsonValue::String(Win32Process::ToNarrow(package.wstring())));
    evidence.Set("scratch_path", JsonValue::String(Win32Process::ToNarrow((root / "Scratch").wstring())));
    evidence.Set("cache_path", JsonValue::String(Win32Process::ToNarrow((root / "Cache").wstring())));
    evidence.Set("inputs_before", before);
    const auto baseline_hash = Sha256File(baseline);
    const auto candidate_hash = Sha256File(candidate);
    Require(baseline_hash && candidate_hash && *baseline_hash != *candidate_hash,
            "Warm transition requires two distinct real native candidates");
    evidence.Set("baseline_source_sha256", JsonValue::String(*baseline_hash));
    evidence.Set("candidate_source_sha256", JsonValue::String(*candidate_hash));
    evidence.Set("unicorn_sha256", JsonValue::String(*dll_hash));
    const auto publish = [&] { Write(root / "transition.json", evidence.Serialize(true)); };
    const auto has_product = [](const JsonValue& manifest, const std::string& name) {
        const auto& products = Field(manifest, "products");
        return products.IsArray() && std::any_of(products.ArrayItems().begin(), products.ArrayItems().end(),
            [&](const JsonValue& product) { return product.GetString("name") == name; });
    };
    const auto replace = [&](const fs::path& source, const std::string& hash, const char* phase) {
        fs::copy_file(source, selected, fs::copy_options::overwrite_existing);
        const auto actual = Sha256File(selected);
        Require(actual && *actual == hash, "Selected same-path proxy bytes differ from supplied native candidate");
        evidence.Set(std::string(phase) + "_selected_sha256", JsonValue::String(*actual));
        publish();
    };
    replace(baseline, *baseline_hash, "baseline");
    const auto old_manifest = Dump(swift, selected, root, warm_variant, environment, false, "baseline-dump-package");
    evidence.Set("baseline_observed_name", JsonValue::String(old_manifest.GetString("name")));
    evidence.Set("inputs_after_baseline", InputSnapshot(package, inputs));
    publish();
    Require(old_manifest.GetString("name") == baseline_name && has_product(old_manifest, baseline_name),
            "Historical native proxy did not establish the expected rewritten warm-cache baseline");
    Require(InputSnapshot(package, inputs).Serialize() == before.Serialize(), "Baseline evaluation changed input bytes or timestamps");

    // Only the executable bytes at the exact selected pathname change here.
    // Preserve package, scratch, cache and every source byte/timestamp.
    replace(candidate, *candidate_hash, "candidate");
    Require(InputSnapshot(package, inputs).Serialize() == before.Serialize(), "Candidate replacement touched package inputs");
    const auto new_manifest = Dump(swift, selected, root, warm_variant, environment, false, "candidate-dump-package");
    evidence.Set("candidate_observed_name", JsonValue::String(new_manifest.GetString("name")));
    const auto after = InputSnapshot(package, inputs);
    evidence.Set("inputs_after_candidate", after);
    evidence.Set("expected_candidate_name", JsonValue::String(variant.expected_name));
    evidence.Set("raw_same_cache_original_semantics", JsonValue::Boolean(new_manifest.GetString("name") == variant.expected_name));
    evidence.Set("raw_same_cache_stale_negative_control", JsonValue::Boolean(new_manifest.GetString("name") == baseline_name));
    publish();
    Require(after.Serialize() == before.Serialize(), "Warm candidate evaluation changed original input bytes or timestamps");
    Require(new_manifest.GetString("name") == baseline_name && has_product(new_manifest, baseline_name),
            "Historical same-cache reuse did not establish the expected stale negative control");

    const auto scratch = root / "Scratch";
    Inputs old_cache_files;
    for (const auto& entry : fs::recursive_directory_iterator(scratch))
        if (entry.is_regular_file() && entry.path().filename() == "manifest.db")
            old_cache_files.emplace(entry.path().lexically_relative(scratch), std::string{});
    Require(!old_cache_files.empty(), "Raw stale-cache control did not retain an inspectable manifest database");
    const auto old_cache_before = InputSnapshot(scratch, old_cache_files);
    evidence.Set("old_manifest_cache_before_admission", old_cache_before);
    publish();
    auto native_environment = environment;
    SetEnvironment(native_environment, L"SWIFT_EXEC_MANIFEST", selected.wstring());
    const std::string identity = "owned-warm-original-package";
    const std::vector<ManifestProjectionRequirement> requirements = {{identity, {variant.expected_name}}};
    const std::unordered_map<std::string, fs::path> overrides = {{identity, package}};
    bool native_policy_pass = true;
    for (const char* phase : {"cold", "warm"}) {
        // Exercise the production admission API with the very same scratch.
        // Its namespace and manifest-cache policy must be derived internally;
        // the test supplies no alternate --cache-path or manifest-cache flag.
        const auto admission = ManifestProjection::PrepareAppleHostOverlays(
            swift, scratch, requirements, native_environment, overrides);
        auto observed = JsonValue::ObjectValue();
        observed.Set("success", JsonValue::Boolean(admission.success));
        observed.Set("changed", JsonValue::Boolean(admission.changed));
        observed.Set("override_count", JsonValue::Number(std::to_string(admission.local_packages.size())));
        evidence.Set(std::string("native_policy_") + phase, std::move(observed));
        const auto original_after = InputSnapshot(package, inputs);
        const auto old_cache_after = InputSnapshot(scratch, old_cache_files);
        evidence.Set(std::string("inputs_after_native_policy_") + phase, original_after);
        evidence.Set(std::string("old_manifest_cache_after_") + phase, old_cache_after);
        const bool inputs_unchanged = original_after.Serialize() == before.Serialize();
        const bool old_cache_unchanged = old_cache_after.Serialize() == old_cache_before.Serialize();
        const bool no_adjacent_state = !fs::exists(package / ".build") && !fs::exists(package / ".swiftpm");
        native_policy_pass = native_policy_pass && admission.success && !admission.changed && admission.local_packages.empty() &&
                             inputs_unchanged && old_cache_unchanged && no_adjacent_state;
        evidence.Set("native_policy_admission_pass", JsonValue::Boolean(native_policy_pass));
        publish();
        Require(inputs_unchanged, "Native cache-policy admission changed original input bytes or timestamps");
        Require(old_cache_unchanged, "Native cache-policy admission mutated historical manifest cache");
        Require(admission.success && !admission.changed && admission.local_packages.empty(),
                "Native cache-policy admission did not expose the original product without rewriting");
        Require(no_adjacent_state,
                "Native cache-policy admission created state alongside original sources");
    }
}

void ValidateOriginalProducts(const fs::path& swift, const fs::path& proxy,
                              const fs::path& root, bool gated, bool local_override,
                              Environment environment) {
    const std::string identity = "owned-original-package";
    const auto scratch = root / "Workspace" / "Scratch";
    const auto original = local_override ? root / "Original" : scratch / "checkouts" / identity;
    const auto legacy = scratch.parent_path().parent_path() / ".OPENFRUIT-p" / scratch.filename() / identity;
    const auto executed = root / "legacy-manifest-executed.txt";
    fs::create_directories(scratch);
    Inputs original_inputs;
    original_inputs.emplace("Package.swift",
        "// swift-tools-version: 6.0\nimport PackageDescription\n"
        "var products: [Product] = []\n" +
        std::string(gated ? "#if os(macOS)\n" : "") +
        "products.append(.library(name: \"ManifestProduct\", targets: [\"Probe\"]))\n" +
        std::string(gated ? "#endif\n" : "") +
        "let package = Package(name: \"OriginalProductPackage\", products: products, "
        "targets: [.target(name: \"Probe\")])\n");
    original_inputs.emplace("Sources/Probe/Probe.swift", "public let originalProductProbe = 17\n");
    for (const auto& [relative, bytes] : original_inputs) Write(original / relative, bytes);

    // This is an intentionally stale OPENFRUIT-owned historical overlay. If
    // evaluated, its real manifest writes an owned receipt outside the overlay;
    // inspecting bytes alone would miss execution followed by no source change.
    const auto receipt_literal = JsonValue::String(Win32Process::ToNarrow(executed.wstring())).Serialize();
    Inputs legacy_inputs;
    legacy_inputs.emplace("Package.swift",
        "// swift-tools-version: 6.0\nimport PackageDescription\nimport Foundation\n"
        "let receiptWritten = FileManager.default.createFile(atPath: " + receipt_literal +
        ", contents: Data(\"owned-legacy-manifest-executed\".utf8))\n"
        "let package = Package(name: \"LegacyOverlayPackage\", "
        "products: [.library(name: \"ManifestProduct\", targets: [\"Probe\"])], "
        "targets: [.target(name: \"Probe\")])\n");
    legacy_inputs.emplace("Sources/Probe/Probe.swift", "public let legacyOverlayProbe = 23\n");
    legacy_inputs.emplace("legacy-sentinel.txt", "owned-legacy-overlay-must-remain-untouched\n");
    for (const auto& [relative, bytes] : legacy_inputs) Write(legacy / relative, bytes);
    std::map<fs::path, fs::file_time_type> legacy_times;
    for (const auto& [relative, bytes] : legacy_inputs)
        legacy_times.emplace(relative, fs::last_write_time(legacy / relative));
    const auto untouched = [&] {
        Unchanged(original, original_inputs);
        Unchanged(legacy, legacy_inputs);
        Require(!fs::exists(original / ".build") && !fs::exists(original / ".swiftpm"),
                "Original product validation created adjacent SwiftPM state in source inputs");
        Require(!fs::exists(legacy / ".build") && !fs::exists(legacy / ".swiftpm"),
                "Historical overlay acquired adjacent SwiftPM state");
        Require(!fs::exists(executed), "Historical rewritten overlay manifest was executed");
        for (const auto& [relative, time] : legacy_times)
            Require(fs::last_write_time(legacy / relative) == time, "Historical overlay input was rewritten");
    };
    SetEnvironment(environment, L"SWIFT_EXEC_MANIFEST", proxy.wstring());
    const std::vector<ManifestProjectionRequirement> requirements = {{identity, {"ManifestProduct"}}};
    auto processes = std::make_shared<ProcessCollector>();
    auto context = std::make_shared<OperationContext>(OperationContext{processes, NewOperationId(), NewOperationId(), {}});
    OperationBinding binding(context);
    const auto loaded = ManifestProjection::LoadExistingAppleHostOverlays(swift, scratch, requirements, environment);
    untouched();
    Require(processes->started == 0, "Historical overlay loading started a manifest evaluation process");
    Require(loaded.success && !loaded.changed && loaded.local_packages.empty(),
            "Historical rewritten overlay was admitted as a local package override");
    std::unordered_map<std::string, fs::path> overrides;
    if (local_override) overrides.emplace(identity, original);
    const auto validated = ManifestProjection::PrepareAppleHostOverlays(swift, scratch, requirements, environment, overrides);
    untouched();
    Require(processes->started == 1, "Product validation did not exclusively evaluate the original manifest");
    Require(validated.success == !gated,
            gated ? "macOS-gated original product fabricated Windows compatibility" :
                    "Product present in original manifest was rejected");
    Require(!validated.changed && validated.local_packages.empty(),
            "Original product validation created or selected a rewritten overlay");
}
} // namespace

int main(int argc, char** argv) {
    fs::path root;
    try {
        Require(argc == 2 || argc == 3,
                "usage: swiftpm_manifest_integrity_tests <native-OPENFRUIT.exe> [baseline-native.exe]");
        const auto swift_bin = ToolPaths::SwiftBin({});
        const auto swift = swift_bin / "swift.exe";
        const auto swiftc = swift_bin / "swiftc.exe";
        if (!fs::is_regular_file(swift) || !fs::is_regular_file(swiftc)) {
            std::cerr << "SKIP: real Windows Swift/SwiftPM prerequisites unavailable\n";
            return 77;
        }
        // Production routes manifest compilation through the installed CLI; on a
        // first install the tests run before anything is installed.
        if (!fs::is_regular_file(ToolPaths::LocalHome() / "bin" / "openfruit.exe")) {
            std::cerr << "SKIP: no installed OPENFRUIT CLI yet (first installation)\n";
            return 77;
        }
        const auto proxy = fs::absolute(fs::u8path(argv[1]));
        Require(fs::is_regular_file(proxy), "Requested native compiler proxy does not exist");
        const auto environment = PackageEngine::HostEnvironment(swift_bin);
        const auto derived_sdk = EnvironmentEntry(environment, L"OPENFRUIT_SWIFT_MANIFEST_SDK");
        const auto derived_compiler = EnvironmentEntry(environment, L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL");
        Require(!derived_sdk.empty() && fs::is_directory(derived_sdk),
                "Production HostEnvironment failed to derive the Windows manifest SDK");
        Require(!derived_compiler.empty() && fs::is_regular_file(derived_compiler),
                "Production HostEnvironment failed to derive the Windows manifest compiler");
        Equivalent(fs::path(derived_compiler), swiftc, "Manifest compiler differs from selected real Swift compiler");
        Equivalent(fs::path(EnvironmentEntry(environment, L"SDKROOT")), fs::path(derived_sdk),
                   "Direct manifest SDKROOT differs from proxy manifest SDK");
        root = fs::temp_directory_path() / ("OPENFRUIT-manifest-integrity-" + NewOperationId());
        Require(fs::create_directory(root), "Cannot reserve independent manifest test root");
        const std::vector<Variant> variants = {
            {"host-conditions",
             "#if os(Windows)\nlet chosenName = \"WindowsHost\"\n"
             "#elseif os(macOS)\nlet chosenName = \"AppleHost\"\n"
             "#else\nlet chosenName = \"OtherHost\"\n#endif\n", "WindowsHost"},
            {"literal-suffix",
             "let marker = \"sentinel/\"\n"
             "let chosenName = marker.hasSuffix(\"/\") ? \"OriginalLiteral\" : \"ChangedLiteral\"\n",
             "OriginalLiteral"},
            {"excluded-directory", "let chosenName = \"ExcludedDirectory\"\n",
             "ExcludedDirectory", true}
        };
        unsigned failures = 0;
        for (const auto& variant : variants) {
            try {
                const auto direct = Dump(swift, swiftc, root / variant.name / "direct", variant, environment);
                const auto proxied = Dump(swift, proxy, root / variant.name / "proxy", variant, environment,
                                          true, "dump-package", true);
                Require(direct.GetString("name") == variant.expected_name,
                        std::string(variant.name) + " direct real compiler violated fixture semantics");
                Require(proxied.GetString("name") == direct.GetString("name"),
                        std::string(variant.name) + " proxy changed the original host/literal semantics");
                Require(SemanticFields(direct).Serialize() == SemanticFields(proxied).Serialize(),
                        std::string(variant.name) + " proxy changed original manifest metadata");
                if (variant.excluded_input) {
                    const auto& excludes = Field(Field(direct, "targets").ArrayItems().front(), "exclude");
                    Require(excludes.IsArray() && excludes.ArrayItems().size() == 1,
                            "Official dump lost the original excluded-directory declaration");
                }
                std::cout << "PASS: " << variant.name << " direct/proxy original manifest semantics and bytes\n";
            } catch (const std::exception& error) {
                ++failures;
                std::cerr << "FAIL: " << error.what() << '\n';
            }
        }
        for (const bool gated : {false, true}) {
            for (const bool local_override : {false, true}) {
                const std::string name = std::string(gated ? "gated-product-" : "original-product-") +
                    (local_override ? "local-override" : "checkout");
                try {
                    ValidateOriginalProducts(swift, proxy, root / name, gated, local_override, environment);
                    std::cout << "PASS: " << name << " original products and ignored historical overlay\n";
                } catch (const std::exception& error) {
                    ++failures;
                    std::cerr << "FAIL: " << name << ": " << error.what() << '\n';
                }
            }
        }
        if (argc == 3) {
            const auto baseline = fs::absolute(fs::u8path(argv[2]));
            Require(fs::is_regular_file(baseline), "Requested real native baseline does not exist");
            for (std::size_t index = 0; index < 2; ++index) {
                try {
                    WarmManifestTransition(swift, proxy, baseline, root / "warm-transition" / variants[index].name,
                                           variants[index], index == 0 ? "AppleHost" : "ChangedLiteral", environment);
                    std::cout << "PASS: " << variants[index].name
                              << " native policy admission cold/warm; raw same-cache reuse remains stale negative control\n";
                } catch (const std::exception& error) {
                    ++failures;
                    std::cerr << "FAIL: warm transition " << variants[index].name << ": " << error.what() << '\n';
                }
            }
        }
        if (failures) {
            std::cerr << "Evidence: " << root.string() << '\n';
            return 1;
        }
        if (argc == 3) std::cout << "Preserved warm transition evidence: " << root.string() << '\n';
        else fs::remove_all(root); // Only this freshly reserved owned fixture tree.
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nEvidence: " << root.string() << '\n';
        return 1;
    }
}
