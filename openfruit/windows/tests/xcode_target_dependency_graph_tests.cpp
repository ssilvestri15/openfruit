#include "app_builder.hpp"
#include "build_workspace.hpp"
#include "universal_project.hpp"
#include "xcode_project.hpp"
#include "operation_events.hpp"
#include "content_hash.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
void Write(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    stream << contents;
    Require(static_cast<bool>(stream), "Unable to write owned PBX fixture");
}
std::string Read(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    Require(static_cast<bool>(stream), "Expected built resource missing");
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
struct Target {
    std::string id, name, product, dependencies;
    bool valid = true;
};
fs::path Project(const fs::path& bundle, const std::vector<Target>& targets,
                 const std::string& extra = {}) {
    std::string ids, objects;
    for (const auto& target : targets) {
        ids += target.id + ",";
        objects += target.id + " = {isa=PBXNativeTarget; name=\"" + target.name +
            "\"; productType=\"" + std::string(target.id == "ROOT" ? "com.apple.product-type.application" : "com.apple.product-type.bundle") + "\"; buildConfigurationList=CONFIGS; "
            "buildPhases=(" + (target.valid ? target.id + "PHASE," : "") + (target.id == "ROOT" ? "ROOTSOURCES," : "") +
            "); dependencies=(" + target.dependencies + "); productName=\"" + target.product + "\"; };\n";
        if (target.id == "ROOT") {
            // The public CLI workspace selector requires an application root.
            // Only its dependent resource bundles execute in these contract tests.
            objects += "ROOTSOURCES={isa=PBXSourcesBuildPhase; files=(ROOTSWIFTBUILD,);};\n";
            objects += "ROOTSWIFTBUILD={isa=PBXBuildFile; fileRef=ROOTSWIFTFILE;};\n";
            objects += "ROOTSWIFTFILE={isa=PBXFileReference; path=Root.swift; lastKnownFileType=sourcecode.swift; sourceTree=SOURCE_ROOT;};\n";
            Write(bundle.parent_path() / "Root.swift", "public let ownedRoot = 1\n");
        }
        if (target.valid) {
            objects += target.id + "PHASE = {isa=PBXResourcesBuildPhase; files=(" + target.id + "BUILD,);};\n";
            objects += target.id + "BUILD = {isa=PBXBuildFile; fileRef=" + target.id + "FILE;};\n";
            objects += target.id + "FILE = {isa=PBXFileReference; path=" + target.id + ".txt; sourceTree=SOURCE_ROOT;};\n";
            Write(bundle.parent_path() / (target.id + ".txt"), "owned resource " + target.id);
        }
    }
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={\n"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; buildConfigurationList=CONFIGS; targets=(" + ids + ");};\n"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};\n"
        "CONFIGS={isa=XCConfigurationList; buildConfigurations=(RELEASE,);};\n"
        "RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={};};\n" + objects + extra +
        "}; rootObject=PROJECT;}\n");
    return bundle;
}
std::string Local(const char* dependency, const char* target, const char* name = "") {
    return std::string(dependency) + "={isa=PBXTargetDependency; target=" + target +
        "; name=\"" + name + "\";};\n";
}
std::string Remote(const char* dependency, const char* project, const char* target, const char* name) {
    return std::string(dependency) + "={isa=PBXTargetDependency; targetProxy=" + dependency + "PROXY;};\n" +
        dependency + "PROXY={isa=PBXContainerItemProxy; containerPortal=" + dependency +
        "PROJECT; remoteGlobalIDString=\"" + target + "\"; remoteInfo=\"" + name + "\"; proxyType=1;};\n" +
        dependency + "PROJECT={isa=PBXFileReference; path=\"" + project + "\"; sourceTree=SOURCE_ROOT;};\n";
}
struct Outcome { bool success; PackageBuildResult packages; std::string output, error; fs::path products; };
Outcome Build(const fs::path& root, const fs::path& project_path, const char* root_id = "ROOT",
              std::shared_ptr<ArtifactLease> input_lease = {}) {
    const auto workspace = PrepareBuildWorkspace(project_path,
        root.parent_path() / (root.filename().wstring() + L"-workspace"), "Release");
    const auto& discovered = workspace.project;
    Require(discovered.target_id == root_id, "Production workspace inspection lost root UUID");
    SDKInfo sdk;
    sdk.target_triple = L"arm64-apple-ios18.0";
    Outcome result;
    if (input_lease) result.packages.artifact_leases.push_back(std::move(input_lease));
    result.products = discovered.build_products_root / "Release";
    std::ostringstream output, error;
    auto* old_output = std::cout.rdbuf(output.rdbuf());
    auto* old_error = std::cerr.rdbuf(error.rdbuf());
    try {
        const auto valid = AppBuilder::ValidateTargetDependencies(discovered, sdk, L"Release");
        Require(!fs::exists(result.products), "Preflight executed a target");
        result.success = valid && AppBuilder::BuildTargetDependencies(workspace.root.wstring(), discovered, sdk,
            L"Release", 2, result.packages);
    } catch (...) {
        std::cout.rdbuf(old_output); std::cerr.rdbuf(old_error); throw;
    }
    std::cout.rdbuf(old_output); std::cerr.rdbuf(old_error);
    result.output = output.str(); result.error = error.str();
    return result;
}
void NoProducts(const fs::path& root, const Outcome& outcome, const char* reason) {
    Require(!outcome.success, reason);
    Require(!outcome.error.empty(), "Graph failure lacks diagnostic");
    Require(!fs::exists(root / "build" / "Products") && !fs::exists(outcome.products),
        "A dependency executed before graph validation");
    Require(outcome.packages.resource_bundles.empty(), "Invalid graph published dependent products");
}
void SameName(const fs::path& root) {
    const auto child = Project(root / "Child/Child.xcodeproj", {{"CHILD", "Shared", "ChildResources", ""}});
    const auto parent = Project(root / "Root.xcodeproj", {{"ROOT", "Shared", "RootResources", "DEP,"}},
        Remote("DEP", "Child/Child.xcodeproj", "CHILD", "Shared"));
    const auto before = Sha256File(child / "project.pbxproj");
    const auto result = Build(root, parent);
    Require(result.success, "Same-name subproject was skipped or rejected");
    Require(Read(result.products / "ChildResources.bundle/CHILD.txt") == "owned resource CHILD",
            "Same-name dependency did not build its real resource");
    Require(result.packages.resource_bundles.size() == 1, "Same-name target result not propagated");
    Require(Sha256File(child / "project.pbxproj") == before, "Build modified original PBX source");
}
void Diamond(const fs::path& root) {
    const auto project = Project(root / "Graph.xcodeproj",
        {{"ROOT", "Root", "RootResources", "ROOTLEFT,ROOTRIGHT,"},
         {"LEFT", "Left", "LeftResources", "LEFTSHARED,"},
         {"RIGHT", "Right", "RightResources", "RIGHTSHARED,"},
         {"SHARED", "Shared", "SharedResources", ""}},
        Local("ROOTLEFT", "LEFT") + Local("ROOTRIGHT", "RIGHT") +
        Local("LEFTSHARED", "SHARED") + Local("RIGHTSHARED", "SHARED"));
    const auto result = Build(root, project);
    Require(result.success && result.packages.resource_bundles.size() == 3, "Diamond graph failed");
    const auto first = result.output.find("Building Target Dependency 'Shared'");
    Require(first != std::string::npos && result.output.find("Building Target Dependency 'Shared'", first + 1) == std::string::npos,
            "Shared dependency built more than once or not at all");
    Require(first < result.output.find("Building Target Dependency 'Left'") &&
            first < result.output.find("Building Target Dependency 'Right'"), "Dependencies built out of order");
    for (const auto* id : {"LEFT", "RIGHT", "SHARED"})
        Require(Read(result.products / (std::string(id == std::string("LEFT") ? "Left" :
            id == std::string("RIGHT") ? "Right" : "Shared") + "Resources.bundle") / (std::string(id) + ".txt")) ==
            std::string("owned resource ") + id, "Actual diamond resource wrong");
}
void HardLinkedProjectContexts(const fs::path& root) {
    const auto first = Project(root / "First/Provider.xcodeproj",
        {{"PROVIDER", "Provider", "ProviderResources", "CHILD,"}},
        Remote("CHILD", "Dependency.xcodeproj", "DEPENDENCY", "Dependency"));
    const auto second = Project(root / "Second/Provider.xcodeproj",
        {{"PROVIDER", "Provider", "ProviderResources", "CHILD,"}},
        Remote("CHILD", "Dependency.xcodeproj", "DEPENDENCY", "Dependency"));
    Project(root / "First/Dependency.xcodeproj", {{"DEPENDENCY", "Dependency", "DependencyResources", ""}});
    Project(root / "Second/Dependency.xcodeproj", {{"DEPENDENCY", "Dependency", "DependencyResources", "BACK,"}},
        Remote("BACK", "Provider.xcodeproj", "PROVIDER", "Provider"));
    const auto source = first / "project.pbxproj", destination = second / "project.pbxproj";
    Require(Read(source) == Read(destination), "Owned hard-link fixture PBX files differ");
    fs::remove(destination);
    fs::create_hard_link(source, destination);
    Require(fs::equivalent(source, destination), "Owned PBX hard link did not preserve file identity");
    const auto parent = Project(root / "Root.xcodeproj", {{"ROOT", "Root", "RootResources", "FIRST,SECOND,"}},
        Remote("FIRST", "First/Provider.xcodeproj", "PROVIDER", "Provider") +
        Remote("SECOND", "Second/Provider.xcodeproj", "PROVIDER", "Provider"));
    const auto before = Sha256File(source);
    const auto parsed = XcodeProject::Load(parent);
    Require(parsed.has_value(), "Owned hard-linked context root did not parse");
    const auto target = parsed->FindTarget("ROOT");
    Require(target.has_value(), "Owned hard-linked context root target missing");
    const auto discovered = UniversalProject::InspectTarget(*parsed, *target, "Release");
    SDKInfo sdk;
    sdk.target_triple = L"arm64-apple-ios18.0";
    // Inspect original owned paths: a copied source workspace would no longer
    // expose the actual shared PBX file identity under test. Both descriptors
    // come from production parsing, without manually injecting graph edges.
    // Only the second parent context contains a cycle; merging the two shared
    // PBX file IDs would incorrectly skip that context and report success.
    Require(!AppBuilder::ValidateTargetDependencies(discovered, sdk, L"Release"),
        "Hard-linked PBX parent contexts were merged and hid a real cycle");
    Require(!fs::exists(root / "build"), "Hard-linked graph validation executed a target");
    Require(fs::equivalent(source, destination) && Sha256File(source) == before,
        "Dependency planning modified owned hard-linked PBX inputs");
}
void SchemeActionGraphs(const fs::path& root) {
    for (const bool required : {false, true}) {
        const auto path = root / (required ? "required-product" : "test-only");
        const auto project = Project(path / "Graph.xcodeproj", {{"ROOT", "Root", "RootResources", ""}});
        Write(project / "xcshareddata/xcschemes/Root.xcscheme",
            std::string("<Scheme><BuildAction><BuildActionEntries><BuildActionEntry buildForRunning=\"") +
            (required ? "YES" : "NO") + "\" buildForProfiling=\"NO\" buildForArchiving=\"NO\" "
            "buildForAnalyzing=\"NO\" buildForTesting=\"YES\"><BuildableReference "
            "BlueprintIdentifier=\"MISSING\" BlueprintName=\"Missing\" "
            "ReferencedContainer=\"container:Graph.xcodeproj\"/></BuildActionEntry>"
            "</BuildActionEntries></BuildAction></Scheme>");
        const auto result = Build(path, project);
        if (required) {
            NoProducts(path, result, "Missing required scheme product target was skipped");
            Require(result.error.find("MISSING") != std::string::npos,
                "Required scheme target failure lost UUID identity");
        } else {
            Require(result.success && result.packages.resource_bundles.empty(),
                "Missing test-only scheme target blocked product graph");
            Require(result.output.find("Building Target Dependency") == std::string::npos,
                "Test-only scheme target was executed");
        }
    }
}

void SchemeErrorsOnlyOnSelectedRoot(const fs::path& root) {
    for (const bool selected : {false, true}) {
        for (const bool ambiguous : {false, true}) {
            const auto path = root / (selected ? "selected-root" : "unselected-child") /
                (ambiguous ? "ambiguous" : "malformed");
            const auto project = Project(path / "Graph.xcodeproj",
                {{"ROOT", "Root", "RootResources", "DEP,"},
                 {"CHILD", "Child", "ChildResources", ""}}, Local("DEP", "CHILD"));
            const auto name = selected ? "Root.xcscheme" : "Child.xcscheme";
            const std::string contents = ambiguous
                ? "<Scheme><BuildAction><BuildActionEntries></BuildActionEntries></BuildAction></Scheme>"
                : "<Scheme><BuildAction/></Scheme>";
            Write(project / "xcshareddata/xcschemes" / name, contents);
            if (ambiguous) {
                const auto workspace = path / "Owned.xcworkspace";
                Write(workspace / "contents.xcworkspacedata",
                    "<Workspace><FileRef location=\"group:Graph.xcodeproj\"/></Workspace>");
                Write(workspace / "xcshareddata/xcschemes" / name, contents);
            }
            const auto result = Build(path, project);
            if (selected) {
                NoProducts(path, result, "Selected root scheme errors did not block the graph");
            } else {
                Require(result.success && result.packages.resource_bundles.size() == 1,
                    "An unselected child scheme blocked an authoritative PBX dependency");
                Require(Read(result.products / "ChildResources.bundle/CHILD.txt") == "owned resource CHILD",
                    "Ignoring a child scheme lost the real PBX dependency resource");
            }
        }
    }
}

void Replace(std::string& text, const std::string& before, const std::string& after) {
    const auto offset = text.find(before);
    Require(offset != std::string::npos, "Owned aggregate fixture replacement missing");
    text.replace(offset, before.size(), after);
}
std::string Script(const char* id, const char* script, const char* outputs = "") {
    return std::string(id) + "={isa=PBXShellScriptBuildPhase; name=" + id +
        "; shellPath=\"/bin/sh\"; shellScript=\"" + script + "\"; outputPaths=(" + outputs + ");};\n";
}
struct LeaseCleanupEvidence {
    fs::path generated, preserved, destination;
    bool checked = false, cleaned = false, excluded = false;
};
struct LeaseCleanupObserver {
    std::shared_ptr<ArtifactLease> lease;
    std::shared_ptr<LeaseCleanupEvidence> evidence;
    ~LeaseCleanupObserver() {
        evidence->checked = true;
        try {
            evidence->cleaned = !evidence->preserved.empty() && !fs::exists(evidence->generated) &&
                Read(evidence->preserved) == "original preserved bytes";
            evidence->excluded = !ArtifactLease::TryAcquire(evidence->destination);
        } catch (...) {
            evidence->cleaned = false;
            evidence->excluded = false;
        }
    }
};
void AggregateProducer(const fs::path& root) {
    const auto project = Project(root / "Graph.xcodeproj",
        {{"ROOT", "Root", "RootResources", "TOLEFT,TORIGHT,TOCONSUMER,"},
         {"LEFT", "Left", "", "LEFTSHARED,", false},
         {"RIGHT", "Right", "", "RIGHTSHARED,", false},
         {"SHARED", "Shared", "", "SHAREDBEFORE,", false},
         {"BEFORE", "Before", "Before", ""},
         {"CONSUMER", "Consumer", "Consumed", "CONSUMERSHARED,"}},
        Local("TOLEFT", "LEFT") + Local("TORIGHT", "RIGHT") + Local("TOCONSUMER", "CONSUMER") +
        Local("LEFTSHARED", "SHARED") + Local("RIGHTSHARED", "SHARED") +
        Local("SHAREDBEFORE", "BEFORE") + Local("CONSUMERSHARED", "SHARED") +
        Script("FIRST", "test -f \\\"$BUILT_PRODUCTS_DIR/Before.bundle/BEFORE.txt\\\" || exit 4; printf first > \\\"$SRCROOT/generated.txt\\\"; printf changed > \\\"$SRCROOT/preserved.txt\\\"; printf S >> \\\"$BUILT_PRODUCTS_DIR/order.txt\\\"",
            "\"$(SRCROOT)/generated.txt\",\"$(SRCROOT)/preserved.txt\",") +
        Script("SECOND", "printf second >> \\\"$SRCROOT/generated.txt\\\"; printf T >> \\\"$BUILT_PRODUCTS_DIR/order.txt\\\"",
            "\"$(SRCROOT)/generated.txt\",") +
        Script("LEFTSCRIPT", "printf L >> \\\"$BUILT_PRODUCTS_DIR/order.txt\\\"; printf left > \\\"$SRCROOT/preserved.txt\\\"",
            "\"$(SRCROOT)/preserved.txt\",") +
        Script("RIGHTSCRIPT", "printf R >> \\\"$BUILT_PRODUCTS_DIR/order.txt\\\""));
    auto text = Read(project / "project.pbxproj");
    for (const auto* id : {"LEFT", "RIGHT", "SHARED"})
        Replace(text, std::string(id) + " = {isa=PBXNativeTarget;", std::string(id) + " = {isa=PBXAggregateTarget;");
    Replace(text, "buildPhases=(); dependencies=(LEFTSHARED,)", "buildPhases=(LEFTSCRIPT,); dependencies=(LEFTSHARED,)");
    Replace(text, "buildPhases=(); dependencies=(RIGHTSHARED,)", "buildPhases=(RIGHTSCRIPT,); dependencies=(RIGHTSHARED,)");
    Replace(text, "buildPhases=(); dependencies=(SHAREDBEFORE,)", "buildPhases=(FIRST,SECOND,); dependencies=(SHAREDBEFORE,)");
    Replace(text, "path=CONSUMER.txt;", "path=generated.txt;");
    Write(project / "project.pbxproj", text);
    Write(root / "preserved.txt", "original preserved bytes");
    const auto original = Sha256File(project / "project.pbxproj");
    auto evidence = std::make_shared<LeaseCleanupEvidence>();
    evidence->destination = root.parent_path() / "aggregate-consumer-input";
    auto observer = std::make_shared<LeaseCleanupObserver>();
    observer->lease = ArtifactLease::Acquire(evidence->destination);
    observer->evidence = evidence;
    // Alias the real OS-backed lease with an observer that records its final
    // release boundary. Production retains precisely this input lease owner.
    auto aliased_lease = std::shared_ptr<ArtifactLease>(observer, observer->lease.get());
    observer.reset();
    auto result = Build(root, project, "ROOT", std::move(aliased_lease));
    if (!result.success) throw std::runtime_error("Aggregate producer DAG failed:\n" + result.error + result.output);
    Require(result.packages.resource_bundles.size() == 2, "Aggregate published a fake product");
    Require(Read(result.products / "Consumed.bundle/generated.txt") == "firstsecond", "Generated SRCROOT resource did not reach consumer");
    const auto order = Read(result.products / "order.txt");
    Require(order.size() == 4 && order.starts_with("ST") && order.find('L') != std::string::npos && order.find('R') != std::string::npos,
        "Aggregate diamond ran shared producer twice or phase order changed");
    // Obtain the authoritative copied source root from a declared consumer path,
    // using normal workspace projection rather than supplying generated inputs.
    const auto workspace = root.parent_path() / (root.filename().wstring() + L"-workspace");
    fs::path generated, preserved;
    for (const auto& item : fs::recursive_directory_iterator(workspace)) {
        if (item.path().filename() == "preserved.txt" && item.path().string().find(".OPENFRUIT-source-output-backup") == std::string::npos)
            preserved = item.path();
        if (item.path().filename() == "generated.txt" && item.path().parent_path() == preserved.parent_path()) generated = item.path();
    }
    Require(!preserved.empty(), "Copied generated-output source context missing");
    generated = preserved.parent_path() / "generated.txt";
    Require(Read(generated) == "firstsecond" && Read(preserved) == "left", "Producer outputs expired before root consumer lifetime");
    evidence->generated = generated;
    evidence->preserved = preserved;
    auto retained = result.packages;
    result.packages = {};
    Require(fs::exists(generated), "Copying package result lost shared generated-output lifetime");
    retained = {};
    Require(evidence->checked && evidence->cleaned && evidence->excluded,
        "Generated-output cleanup released its real ArtifactLease prematurely");
    Require(static_cast<bool>(ArtifactLease::TryAcquire(evidence->destination)),
        "Generated-output scope retained an input lease after final release");
    Require(!fs::exists(generated) && Read(preserved) == "original preserved bytes", "Generated source guards did not restore in reverse production order");
    Require(!fs::exists(root / "generated.txt") && Read(root / "preserved.txt") == "original preserved bytes" &&
        Sha256File(project / "project.pbxproj") == original, "Aggregate execution modified original upstream inputs");
}
void AggregateFailures(const fs::path& root) {
    for (const auto* mode : {"failure", "output", "missing-phase", "unsupported-phase", "legacy", "empty", "cycle"}) {
        const auto path = root / mode;
        const auto project = Project(path / "Graph.xcodeproj",
            {{"ROOT", "Root", "RootResources", "TOAGG,"}, {"AGG", "Group", "", "", false}},
            Local("TOAGG", "AGG") + Script("SCRIPT", std::string(mode) == "failure" ? "exit 23" : "true",
                std::string(mode) == "output" ? "\"$(SRCROOT)/not-produced.txt\"," : "") +
            Local("BACK", "ROOT") + "UNSUPPORTED={isa=PBXCopyFilesBuildPhase; files=();};\n");
        auto text = Read(project / "project.pbxproj");
        Replace(text, "AGG = {isa=PBXNativeTarget;", std::string("AGG = {isa=") +
            (std::string(mode) == "legacy" ? "PBXLegacyTarget;" : "PBXAggregateTarget;"));
        const std::string phases = std::string(mode) == "empty" || std::string(mode) == "legacy" ? "" :
            std::string(mode) == "missing-phase" ? "ABSENT," : std::string(mode) == "unsupported-phase" ? "UNSUPPORTED," : "SCRIPT,";
        Replace(text, "buildPhases=(); dependencies=(); productName=\"\";", "buildPhases=(" + phases +
            "); dependencies=(" + (std::string(mode) == "cycle" ? "BACK," : "") + "); productName=\"\";");
        Write(project / "project.pbxproj", text);
        const auto result = Build(path, project);
        if (std::string(mode) == "empty") {
            Require(result.success && result.packages.resource_bundles.empty(), "Pure aggregate group was rejected or published a fake product");
        } else {
            Require(!result.success && !result.error.empty(), "Aggregate failure was hidden");
            Require(result.packages.resource_bundles.empty(), "Failed aggregate published products");
        }
        Require(!fs::exists(result.products / "Group.app") && !fs::exists(result.products / "Group.bundle"), "Aggregate staged a fake native product");
    }
}


void SameNameAggregateContexts(const fs::path& root) {
    std::vector<fs::path> originals;
    for (const auto* name : {"One", "Two"}) {
        const auto path = root / name;
        const auto project = Project(path / "Child.xcodeproj",
            {{"AGG", "Shared", "", "", false}, {"CONSUMER", "Consumer", name, "TOPRODUCER,"}},
            Local("TOPRODUCER", "AGG") + Script("SCRIPT",
                (std::string("printf ") + name + " > \\\"$SRCROOT/generated.txt\\\"").c_str(),
                "\"$(SRCROOT)/generated.txt\","));
        auto text = Read(project / "project.pbxproj");
        Replace(text, "AGG = {isa=PBXNativeTarget;", "AGG = {isa=PBXAggregateTarget;");
        Replace(text, "buildPhases=(); dependencies=(); productName=\"\";", "buildPhases=(SCRIPT,); dependencies=(); productName=\"\";");
        Replace(text, "path=CONSUMER.txt;", "path=generated.txt;");
        Write(project / "project.pbxproj", text);
        originals.push_back(project / "project.pbxproj");
    }
    const auto root_project = Project(root / "Root.xcodeproj", {{"ROOT", "Root", "RootResources", "ONE,TWO,"}},
        Remote("ONE", "One/Child.xcodeproj", "CONSUMER", "Consumer") +
        Remote("TWO", "Two/Child.xcodeproj", "CONSUMER", "Consumer"));
    auto result = Build(root, root_project);
    if (!result.success) throw std::runtime_error("Same-name aggregate context failed:\n" + result.error + result.output);
    Require(result.packages.resource_bundles.size() == 2,
        "Same-name aggregate project contexts were merged");
    Require(Read(result.products / "One.bundle/generated.txt") == "One" &&
        Read(result.products / "Two.bundle/generated.txt") == "Two", "Same-name producers did not reach their own consumers");
    const auto workspace = root.parent_path() / (root.filename().wstring() + L"-workspace");
    std::vector<fs::path> generated;
    std::size_t derived_roots = 0;
    for (const auto& item : fs::recursive_directory_iterator(workspace)) {
        if (item.is_directory() && item.path().filename().wstring().starts_with(L"Shared-aggregate-")) ++derived_roots;
        if (item.path().filename() == "generated.txt" &&
            (item.path().parent_path().filename() == "One" || item.path().parent_path().filename() == "Two"))
            generated.push_back(item.path());
    }
    Require(derived_roots == 2 && generated.size() == 2, "Aggregate derived guard directories collided");
    result.packages = {};
    for (const auto& path : generated) Require(!fs::exists(path), "Same-name aggregate source output was not retired");
    for (const auto* name : {"One", "Two"}) Require(!fs::exists(root / name / "generated.txt"), "Same-name aggregate modified original source tree");
}
void AggregateRootAndDeclaredInputs(const fs::path& root) {
    const auto project = Project(root / "Graph.xcodeproj", {{"ROOT", "Root", "RootResources", ""},
        {"AGG", "Group", "", "", false}},
        Script("SCRIPT", "printf generated > \\\"$SRCROOT/generated.txt\\\"", "\"$(SRCROOT)/generated.txt\",") +
        "GENERATEDSWIFTBUILD={isa=PBXBuildFile; fileRef=GENERATEDSWIFT;};\n"
        "GENERATEDSWIFT={isa=PBXFileReference; path=Generated.swift; sourceTree=SOURCE_ROOT;};\n"
        "GENERATEDCBUILD={isa=PBXBuildFile; fileRef=GENERATEDC;};\n"
        "GENERATEDC={isa=PBXFileReference; path=Generated.c; sourceTree=BUILT_PRODUCTS_DIR;};\n");
    auto text = Read(project / "project.pbxproj");
    Replace(text, "AGG = {isa=PBXNativeTarget;", "AGG = {isa=PBXAggregateTarget;");
    Replace(text, "buildPhases=(); dependencies=(); productName=\"\";", "buildPhases=(SCRIPT,); dependencies=(); productName=\"\";");
    Replace(text, "files=(ROOTSWIFTBUILD,)", "files=(ROOTSWIFTBUILD,GENERATEDSWIFTBUILD,GENERATEDCBUILD,)");
    Write(project / "project.pbxproj", text);
    const auto workspace = PrepareBuildWorkspace(project, root.parent_path() / "root-aggregate-workspace", "Release");
    Require(workspace.project.swift_sources.size() == 2 && workspace.project.c_sources.size() == 1,
        "Missing explicitly declared generated compile inputs were discarded");
    Require(fs::path(workspace.project.c_sources.front()) == workspace.project.build_products_root / "Release/Generated.c",
        "BUILT_PRODUCTS_DIR source reference was not derived from project context");
    const auto parsed = XcodeProject::Load(workspace.target, workspace.project.build_products_root);
    Require(parsed.has_value(), "Projected aggregate root project missing");
    const auto target = parsed->FindTarget("AGG");
    Require(target.has_value(), "Aggregate target omitted from parser inventory");
    const auto discovered = UniversalProject::InspectTarget(*parsed, *target, "Release");
    const auto spec = UniversalProject::ToAppBuildSpec(discovered);
    Require(discovered.is_valid && spec.target_kind == XcodeTargetKind::Aggregate,
        "Aggregate kind was lost between parser and build specification");
    SDKInfo sdk;
    PackageBuildResult packages;
    auto result = AppBuilder::Build(workspace.root.wstring(), spec, sdk, packages);
    const auto generated = fs::path(discovered.project_dir) / "generated.txt";
    Require(result.success && result.product_path.empty() && result.executable_path.empty() &&
        result.object_path.empty() && Read(generated) == "generated", "Aggregate root produced a fake native product or failed its real script");
    result = {};
    Require(!fs::exists(generated) && !fs::exists(root / "generated.txt"), "Aggregate root failed to release its generated source lifetime");
}
void InvalidGraphs(const fs::path& root) {
    {
        const auto path = root / "missing";
        auto project = Project(path / "Graph.xcodeproj",
            {{"ROOT", "Root", "RootResources", "GOODDEP,BADDEP,"}, {"GOOD", "Good", "GoodResources", ""}},
            Local("GOODDEP", "GOOD") + Local("BADDEP", "ABSENT"));
        NoProducts(path, Build(path, project), "Missing required PBX target accepted");
    }
    {
        const auto path = root / "missing-object";
        auto project = Project(path / "Graph.xcodeproj", {{"ROOT", "Root", "RootResources", "MISSINGOBJECT,"}});
        NoProducts(path, Build(path, project), "Missing PBX dependency object accepted");
    }
    {
        const auto path = root / "cycle";
        auto project = Project(path / "Graph.xcodeproj",
            {{"ROOT", "Root", "RootResources", "TOCHILD,"}, {"CHILD", "Child", "ChildResources", "TOROOT,"}},
            Local("TOCHILD", "CHILD") + Local("TOROOT", "ROOT"));
        const auto result = Build(path, project);
        NoProducts(path, result, "Cycle through root silently accepted");
        Require(result.error.find("cycle") != std::string::npos, "Cycle was not identified");
    }
    {
        const auto path = root / "self";
        auto project = Project(path / "Graph.xcodeproj", {{"ROOT", "Root", "RootResources", "SELF,"}}, Local("SELF", "ROOT"));
        NoProducts(path, Build(path, project), "Explicit self dependency accepted");
    }
    {
        const auto path = root / "invalid-target";
        auto project = Project(path / "Graph.xcodeproj",
            {{"ROOT", "Root", "RootResources", "TOGOOD,TOEMPTY,"},
             {"GOOD", "Good", "GoodResources", ""}, {"EMPTY", "Empty", "EmptyResources", "", false}},
            Local("TOGOOD", "GOOD") + Local("TOEMPTY", "EMPTY"));
        NoProducts(path, Build(path, project), "Invalid inspected dependency skipped");
    }
    {
        const auto path = root / "ambiguous";
        auto project = Project(path / "Graph.xcodeproj",
            {{"ROOT", "Root", "RootResources", "DUPDEP,"}, {"ONE", "Dup", "OneResources", ""},
             {"TWO", "Dup", "TwoResources", ""}},
            "DUPDEP={isa=PBXTargetDependency; targetProxy=PROXY;};\n"
            "PROXY={isa=PBXContainerItemProxy; containerPortal=PROJECT; remoteInfo=Dup; proxyType=1;};\n");
        const auto result = Build(path, project);
        NoProducts(path, result, "Ambiguous name-only dependency accepted");
        Require(result.error.find("ambiguous") != std::string::npos, "Ambiguity not identified");
    }
}

void FrozenSchemeGraph(const fs::path& root) {
    const auto bundle = Project(root / "Frozen.xcodeproj",
        {{"ROOT", "Root", "RootResources", ""}, {"CHILD", "Child", "ChildResources", ""}});
    // An unrelated implicit same-name scheme must not replace the admitted
    // explicit selection when the DAG traverses its root or descendants.
    Write(bundle / "xcshareddata/xcschemes/Root.xcscheme", "<broken");
    Write(bundle / "xcshareddata/xcschemes/Child.xcscheme", "<also-broken");
    const auto parsed = XcodeProject::Load(bundle, root / "isolated-products");
    Require(parsed.has_value(), "Frozen graph fixture did not parse");
    const auto target = parsed->FindTarget("ROOT");
    Require(target.has_value(), "Frozen graph root missing");
    auto discovered = UniversalProject::InspectTarget(*parsed, *target, "Release", {false, false, true});
    Require(discovered.is_valid, "Frozen root inspection failed");
    discovered.selection_frozen = true;
    discovered.build_implicit_dependencies = false;
    XcodeTargetDependency child;
    child.target_id = "CHILD";
    child.scheme_entry = true;
    discovered.target_dependencies = {child};
    SDKInfo sdk;
    sdk.target_triple = L"arm64-apple-ios18.0";
    Require(AppBuilder::ValidateTargetDependencies(discovered, sdk, L"Release"),
        "Frozen DAG re-inferred an unselected implicit scheme");
    PackageBuildResult packages;
    packages.success = true;
    Require(AppBuilder::BuildTargetDependencies(root.wstring(), discovered, sdk, L"Release", 1, packages),
        "Frozen co-build did not reach its real resource consumer");
    Require(Read(root / "isolated-products/Release/ChildResources.bundle/CHILD.txt") == "owned resource CHILD",
        "Frozen DAG ignored the admitted products root");
    Require(!fs::exists(root / "build/Products/Release/ChildResources.bundle"),
        "Frozen DAG wrote into the legacy product namespace");
}

void StaticLibraryPropagationAndArchiveLinkScoping(const fs::path& root) {
    const auto bundle = root / "StaticGraph.xcodeproj";
    Write(root / "Root.swift", "public let ownedRoot = 1\n");
    Write(root / "StaticLib.h", "#pragma once\n");
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={\n"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; buildConfigurationList=CONFIGS; targets=(ROOT,STATIC_LIB,);};\n"
        "GROUP={isa=PBXGroup; children=(ROOTSWIFT,LIBHEADER,LIBPRODUCT,); sourceTree=\"<group>\";};\n"
        "CONFIGS={isa=XCConfigurationList; buildConfigurations=(RELEASE,); defaultConfigurationName=Release;};\n"
        "RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={};};\n"
        "ROOTSWIFT={isa=PBXFileReference; path=Root.swift; lastKnownFileType=sourcecode.swift; sourceTree=SOURCE_ROOT;};\n"
        "ROOTSWIFTBUILD={isa=PBXBuildFile; fileRef=ROOTSWIFT;};\n"
        "ROOTSOURCES={isa=PBXSourcesBuildPhase; files=(ROOTSWIFTBUILD,);};\n"
        "LIBPRODUCT={isa=PBXFileReference; path=libStaticLib.a; sourceTree=BUILT_PRODUCTS_DIR;};\n"
        "ROOTLINKBUILD={isa=PBXBuildFile; fileRef=LIBPRODUCT;};\n"
        "ROOTFRAMEWORKS={isa=PBXFrameworksBuildPhase; files=(ROOTLINKBUILD,);};\n"
        "DEP_STATIC={isa=PBXTargetDependency; target=STATIC_LIB; name=StaticLib;};\n"
        "ROOT={isa=PBXNativeTarget; name=Root; productName=Root; productType=\"com.apple.product-type.application\"; "
        "buildConfigurationList=CONFIGS; buildPhases=(ROOTSOURCES,ROOTFRAMEWORKS,); dependencies=(DEP_STATIC,);};\n"
        "LIBHEADER={isa=PBXFileReference; path=StaticLib.h; lastKnownFileType=sourcecode.c.h; sourceTree=SOURCE_ROOT;};\n"
        "LIBHEADERBUILD={isa=PBXBuildFile; fileRef=LIBHEADER; settings={ATTRIBUTES=(Public,);};};\n"
        "LIBHEADERS={isa=PBXHeadersBuildPhase; files=(LIBHEADERBUILD,);};\n"
        "STATIC_LIB={isa=PBXNativeTarget; name=StaticLib; productName=StaticLib; productType=\"com.apple.product-type.library.static\"; "
        "buildConfigurationList=CONFIGS; buildPhases=(LIBHEADERS,); dependencies=();};\n"
        "}; rootObject=PROJECT;}\n");

    auto result = Build(root, bundle);
    Require(result.success, "Static library child target dependency failed to build");
    const auto built_static_lib = result.products / "libStaticLib.a";
    Require(fs::exists(built_static_lib), "Built static library archive missing from products directory");
    Require(result.packages.static_libraries.size() == 1 &&
        fs::equivalent(fs::path(result.packages.static_libraries.front()), built_static_lib),
        "Child static library target product_path was not propagated into pkg_res.static_libraries");

    const auto pkg_archive = result.products / "libOPENFRUITPackages.a";
    Write(pkg_archive, "!<arch>\n");
    result.packages.package_archive_path = pkg_archive.wstring();

    AppBuildSpec app_spec;
    app_spec.product_type = "com.apple.product-type.application";
    app_spec.link_libraries = {L"libStaticLib.a", L"StaticLib"};
    const auto app_link_inputs = AppBuilder::ResolveArchiveLinkInputs(
        app_spec, result.products.wstring(), result.packages);
    std::size_t static_lib_count = 0;
    bool app_has_force_load = false;
    for (std::size_t i = 0; i < app_link_inputs.size(); ++i) {
        if (fs::exists(app_link_inputs[i]) &&
            fs::equivalent(fs::path(app_link_inputs[i]), built_static_lib)) {
            ++static_lib_count;
        }
        if (app_link_inputs[i] == L"-force_load" && i + 1 < app_link_inputs.size() &&
            fs::exists(app_link_inputs[i + 1]) &&
            fs::equivalent(fs::path(app_link_inputs[i + 1]), pkg_archive)) {
            app_has_force_load = true;
        }
    }
    Require(static_lib_count == 1,
        "Static library archive was duplicated or missing across spec.link_libraries and pkg_res.static_libraries");
    Require(app_has_force_load,
        "Application target did not receive -force_load for unified package archive");

    for (const char* non_app_type : {"com.apple.product-type.app-extension", "com.apple.product-type.framework"}) {
        AppBuildSpec non_app_spec;
        non_app_spec.product_type = non_app_type;
        non_app_spec.link_libraries = {L"StaticLib"};
        const auto non_app_inputs = AppBuilder::ResolveArchiveLinkInputs(
            non_app_spec, result.products.wstring(), result.packages);
        Require(std::find(non_app_inputs.begin(), non_app_inputs.end(), L"-force_load") == non_app_inputs.end(),
            "Non-application target (.appex/.framework) erroneously received -force_load for unified package archive");
        const bool has_pkg_archive = std::any_of(non_app_inputs.begin(), non_app_inputs.end(), [&](const std::wstring& arg) {
            return fs::exists(arg) && fs::equivalent(fs::path(arg), pkg_archive);
        });
        Require(has_pkg_archive,
            "Non-application target (.appex/.framework) lost unified package archive input");
    }
}

void SchemeCoBuildStaticLibrarySelectionAndOrdering(const fs::path& root) {
    const auto bundle = root / "SchemeStatic.xcodeproj";
    Write(root / "Root.swift", "public let ownedRoot = 1\n");
    Write(root / "StaticLib.h", "#pragma once\n");
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={\n"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; buildConfigurationList=CONFIGS; targets=(ROOT,STATIC_LIB,);};\n"
        "GROUP={isa=PBXGroup; children=(ROOTSWIFT,LIBHEADER,); sourceTree=\"<group>\";};\n"
        "CONFIGS={isa=XCConfigurationList; buildConfigurations=(RELEASE,); defaultConfigurationName=Release;};\n"
        "RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={};};\n"
        "ROOTSWIFT={isa=PBXFileReference; path=Root.swift; lastKnownFileType=sourcecode.swift; sourceTree=SOURCE_ROOT;};\n"
        "ROOTSWIFTBUILD={isa=PBXBuildFile; fileRef=ROOTSWIFT;};\n"
        "ROOTSOURCES={isa=PBXSourcesBuildPhase; files=(ROOTSWIFTBUILD,);};\n"
        "DEP_STATIC={isa=PBXTargetDependency; target=STATIC_LIB; name=StaticLib;};\n"
        "ROOT={isa=PBXNativeTarget; name=Root; productName=Root; productType=\"com.apple.product-type.application\"; "
        "buildConfigurationList=CONFIGS; buildPhases=(ROOTSOURCES,); dependencies=(DEP_STATIC,);};\n"
        "LIBHEADER={isa=PBXFileReference; path=StaticLib.h; lastKnownFileType=sourcecode.c.h; sourceTree=SOURCE_ROOT;};\n"
        "LIBHEADERBUILD={isa=PBXBuildFile; fileRef=LIBHEADER; settings={ATTRIBUTES=(Public,);};};\n"
        "LIBHEADERS={isa=PBXHeadersBuildPhase; files=(LIBHEADERBUILD,);};\n"
        "STATIC_LIB={isa=PBXNativeTarget; name=StaticLib; productName=StaticLib; productType=\"com.apple.product-type.library.static\"; "
        "buildConfigurationList=CONFIGS; buildPhases=(LIBHEADERS,); dependencies=();};\n"
        "}; rootObject=PROJECT;}\n");

    const std::string scheme_xml =
        "<Scheme version=\"1.3\"><BuildAction parallelizeBuildables=\"NO\" buildImplicitDependencies=\"YES\">"
        "<BuildActionEntries>"
        "<BuildActionEntry buildForRunning=\"YES\" buildForTesting=\"YES\" buildForProfiling=\"YES\" buildForArchiving=\"YES\" buildForAnalyzing=\"YES\">"
        "<BuildableReference BlueprintIdentifier=\"ROOT\" BlueprintName=\"Root\" ReferencedContainer=\"container:SchemeStatic.xcodeproj\"/>"
        "</BuildActionEntry>"
        "<BuildActionEntry buildForRunning=\"YES\" buildForTesting=\"YES\" buildForProfiling=\"YES\" buildForArchiving=\"YES\" buildForAnalyzing=\"YES\">"
        "<BuildableReference BlueprintIdentifier=\"STATIC_LIB\" BlueprintName=\"StaticLib\" ReferencedContainer=\"container:SchemeStatic.xcodeproj\"/>"
        "</BuildActionEntry>"
        "</BuildActionEntries></BuildAction>"
        "<LaunchAction buildConfiguration=\"Release\">"
        "<BuildableProductRunnable><BuildableReference BlueprintIdentifier=\"ROOT\" BlueprintName=\"Root\" ReferencedContainer=\"container:SchemeStatic.xcodeproj\"/></BuildableProductRunnable>"
        "</LaunchAction></Scheme>";
    const auto scheme_file = bundle / "xcshareddata/xcschemes/Root.xcscheme";
    Write(scheme_file, scheme_xml);

    std::string scheme_error;
    const auto parsed_scheme = XcodeScheme::Parse(scheme_file, bundle, scheme_xml, ProjectBuildAction::Running, &scheme_error);
    Require(parsed_scheme.has_value() && scheme_error.empty(), "Scheme fixture failed to parse");

    const auto parsed = XcodeProject::Load(bundle, root / "isolated-products");
    Require(parsed.has_value(), "Scheme static project failed to load");
    const auto static_target = parsed->FindTarget("STATIC_LIB");
    Require(static_target.has_value(), "STATIC_LIB target missing");

    auto inspected_static = UniversalProject::InspectSelected(
        *parsed, *static_target, "Release", ProjectBuildAction::Running, parsed_scheme);
    Require(inspected_static.is_valid && inspected_static.selection_frozen,
        "InspectSelected failed for STATIC_LIB in [Root, StaticLib] scheme");
    Require(inspected_static.target_dependencies.empty(),
        "InspectSelected added upstream consumer Root as a dependency of selected StaticLib");

    SDKInfo sdk;
    sdk.target_triple = L"arm64-apple-ios18.0";
    Require(AppBuilder::ValidateTargetDependencies(inspected_static, sdk, L"Release"),
        "ValidateTargetDependencies rejected selected StaticLib inside [Root, StaticLib] scheme");

    // Even if a synthetic scheme_entry edge pointing to the upstream consumer Root is
    // present on the selected StaticLib root, BuildTargetDependencies must skip the
    // upstream consumer rather than reporting a false cycle or building Root before StaticLib.
    XcodeTargetDependency synthetic_consumer_entry;
    synthetic_consumer_entry.project_path = bundle;
    synthetic_consumer_entry.target_id = "ROOT";
    synthetic_consumer_entry.target_name = "Root";
    synthetic_consumer_entry.scheme_entry = true;
    inspected_static.target_dependencies.push_back(synthetic_consumer_entry);

    Require(AppBuilder::ValidateTargetDependencies(inspected_static, sdk, L"Release"),
        "Synthetic scheme_entry to upstream consumer caused a false dependency cycle");
    PackageBuildResult packages;
    packages.success = true;
    Require(AppBuilder::BuildTargetDependencies(root.wstring(), inspected_static, sdk, L"Release", 1, packages),
        "BuildTargetDependencies failed or attempted to build upstream consumer Root before StaticLib");
}
}
int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-target-graph-" + NewOperationId());
    try {
        SameName(root / "same-name");
        Diamond(root / "diamond");
        HardLinkedProjectContexts(root / "hard-linked-contexts");
        SchemeActionGraphs(root / "scheme-actions");
        SchemeErrorsOnlyOnSelectedRoot(root / "scheme-error-scope");
        InvalidGraphs(root / "invalid");
        FrozenSchemeGraph(root / "frozen-scheme");
        AggregateProducer(root / "aggregate-producer");
        AggregateFailures(root / "aggregate-failures");
        AggregateRootAndDeclaredInputs(root / "aggregate-root");
        SameNameAggregateContexts(root / "same-name-aggregate");
        StaticLibraryPropagationAndArchiveLinkScoping(root / "static-lib-propagation");
        SchemeCoBuildStaticLibrarySelectionAndOrdering(root / "scheme-cobuild-static-lib");
        std::error_code ec;
        fs::remove_all(root, ec);
        std::cout << "Xcode target dependency graph tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << "\nFixture retained: " << root << '\n';
        return 1;
    }
}
