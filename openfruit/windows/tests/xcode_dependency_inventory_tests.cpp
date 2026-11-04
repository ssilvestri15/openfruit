#include "universal_project.hpp"
#include "xcode_project.hpp"
#include "xcode_scheme.hpp"
#include "operation_events.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <tuple>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << text;
    output.close();
    Require(static_cast<bool>(output), "Owned dependency inventory fixture write failed");
}
void SchemeAndImplicitDependency(const fs::path& root, bool links_provider) {
    const auto consumer = root / "Consumer.xcodeproj";
    const auto provider = root / "Provider.xcodeproj";
    Write(provider / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(PROVIDER,);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};"
        "PROVIDER={isa=PBXNativeTarget; name=Provider; productName=Provider;"
        "productType=\"com.apple.product-type.framework\"; buildPhases=(); dependencies=();};"
        "}; rootObject=PROJECT;}");
    Write(consumer / "project.pbxproj",
        std::string("{archiveVersion=1; objectVersion=77; objects={") +
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(CONSUMER,);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};"
        "CONSUMER={isa=PBXNativeTarget; name=Consumer; productName=Consumer;"
        "productType=\"com.apple.product-type.framework\"; dependencies=(); buildPhases=(" +
        (links_provider ? "FRAMEWORKS," : "") + ");};"
        "FRAMEWORKS={isa=PBXFrameworksBuildPhase; files=(PROVIDERBUILD,);};"
        "PROVIDERBUILD={isa=PBXBuildFile; fileRef=PROVIDERFILE;};"
        "PROVIDERFILE={isa=PBXFileReference; path=Provider.framework; sourceTree=BUILT_PRODUCTS_DIR;};"
        "}; rootObject=PROJECT;}");
    Write(root / "Owned.xcworkspace/contents.xcworkspacedata",
        "<?xml version=\"1.0\"?><Workspace version=\"1.0\">"
        "<FileRef location=\"group:Consumer.xcodeproj\"/>"
        "<FileRef location=\"group:Provider.xcodeproj\"/></Workspace>");
    Write(consumer / "xcshareddata/xcschemes/Consumer.xcscheme",
        "<?xml version=\"1.0\"?><Scheme version=\"1.3\"><BuildAction><BuildActionEntries>"
        "<BuildActionEntry buildForRunning=\"YES\"><BuildableReference "
        "BlueprintIdentifier=\"CONSUMER\" BlueprintName=\"Consumer\" "
        "ReferencedContainer=\"container:Consumer.xcodeproj\"/></BuildActionEntry>"
        "<BuildActionEntry buildForRunning=\"YES\"><BuildableReference "
        "BlueprintIdentifier=\"PROVIDER\" BlueprintName=\"Provider\" "
        "ReferencedContainer=\"container:Provider.xcodeproj\"/></BuildActionEntry>"
        "</BuildActionEntries></BuildAction></Scheme>");

    const auto project = XcodeProject::Load(consumer);
    Require(project.has_value(), "Owned consumer project failed to parse");
    const auto target = project->FindTarget("CONSUMER");
    Require(target.has_value(), "Owned consumer target missing");
    // Production PBX/workspace/scheme inspection supplies all descriptors. When
    // this consumer is reached below the selected root, the DAG filters scheme-
    // only co-build entries; a real linked product must survive that filtering.
    const auto dependencies = project->ResolveTargetDependencies(*target);
    Require(dependencies.size() == 1, "Provider inventory was duplicated or lost");
    const auto& dependency = dependencies.front();
    Require(dependency.target_id == "PROVIDER" && dependency.target_name == "Provider" &&
        dependency.is_subproject && dependency.resolution_error.empty(),
        "Provider inventory lost authoritative identity");
    Require(fs::equivalent(dependency.project_path, provider), "Wrong project owns linked provider");
    Require(dependency.scheme_entry == !links_provider,
        "Scheme-only descriptor masked a required implicit framework dependency");
}
std::string Reference(const std::string& id, const std::string& container = "Consumer.xcodeproj") {
    return "<BuildableReference BlueprintIdentifier=\"" + id + "\" BlueprintName=\"" + id +
        "\" ReferencedContainer=\"container:" + container + "\"/>";
}
std::string Entry(const std::string& id, const std::string& flags,
                  const std::string& container = "Consumer.xcodeproj") {
    return "<BuildActionEntry " + flags + ">" + Reference(id, container) + "</BuildActionEntry>";
}
void ProductActionInventory(const fs::path& root) {
    SchemeAndImplicitDependency(root, false);
    const auto consumer = root / "Consumer.xcodeproj";
    const std::string disabled = "buildForRunning=\"NO\" buildForProfiling=\"NO\" "
        "buildForArchiving=\"NO\" buildForAnalyzing=\"NO\"";
    Write(consumer / "xcshareddata/xcschemes/Consumer.xcscheme",
        "<?xml version=\"1.0\"?><Scheme><BuildAction><BuildActionEntries>" +
        Entry("CONSUMER", "buildForRunning=\"YES\"") +
        Entry("PROVIDER", "buildForRunning=\"NO\" buildForProfiling=\"NO\" "
            "buildForArchiving=\"YES\" buildForAnalyzing=\"NO\"", "Provider.xcodeproj") +
        Entry("MISSING_TEST_ONLY", disabled + " buildForTesting=\"YES\"") +
        Entry("MISSING_DISABLED", disabled + " buildForTesting=\"NO\"") +
        Entry("MISSING_PARTIAL", "buildForRunning=\"NO\" buildForProfiling=\"NO\" buildForArchiving=\"NO\"") +
        Entry("MISSING_UNKNOWN", "buildForRunning=\"UNKNOWN\" buildForProfiling=\"NO\" "
            "buildForArchiving=\"NO\" buildForAnalyzing=\"NO\"") +
        Entry("MISSING_REQUIRED", "buildForRunning=\"YES\"") +
        Entry("MISSING_DEFAULT", "") +
        "</BuildActionEntries><MacroExpansion>" + Reference("MISSING_BUILD_MACRO") +
        "</MacroExpansion></BuildAction><TestAction><Testables><TestableReference>" +
        Reference("MISSING_TEST_ACTION") + "</TestableReference></Testables></TestAction>"
        "<LaunchAction><BuildableProductRunnable>" + Reference("MISSING_LAUNCH_ACTION") +
        "</BuildableProductRunnable></LaunchAction><ProfileAction><BuildableProductRunnable>" +
        Reference("MISSING_PROFILE_ACTION") + "</BuildableProductRunnable></ProfileAction></Scheme>");
    const auto project = XcodeProject::Load(consumer);
    Require(project.has_value(), "Product action fixture did not parse");
    const auto target = project->FindTarget("CONSUMER");
    Require(target.has_value(), "Product action fixture root missing");
    const auto dependencies = project->ResolveTargetDependencies(*target);
    Require(dependencies.size() == 5, "Product action filtering lost required entries or imported other actions");
    for (const auto* id : {"PROVIDER", "MISSING_PARTIAL", "MISSING_UNKNOWN", "MISSING_REQUIRED", "MISSING_DEFAULT"}) {
        bool found = false;
        for (const auto& dependency : dependencies)
            if (dependency.target_id == id && dependency.scheme_entry) found = true;
        Require(found, "Archive-only, missing or unknown product flag was incorrectly skipped");
    }
    // A missing product build target remains a real descriptor, so the shared
    // planner's UUID lookup rejects it instead of silently advancing the build.
    Require(!project->FindTarget("MISSING_REQUIRED"), "Negative product-action fixture unexpectedly has target");
    for (const auto& malformed : {
        std::string("<BuildActionEntry buildForRunning=\"YES\">") + Reference("MISSING_REQUIRED"),
        std::string("<BuildActionEntry buildForRunning=\"YES\"></BuildActionEntry>"),
        std::string("<BuildActionEntry buildForRunning=\"YES\"><BuildableReference/></BuildActionEntry>")}) {
        Write(consumer / "xcshareddata/xcschemes/Consumer.xcscheme",
            "<Scheme><BuildAction><BuildActionEntries>" + malformed +
            "</BuildActionEntries></BuildAction></Scheme>");
        const auto invalid = project->ResolveTargetDependencies(*target);
        Require(invalid.size() == 1 && invalid.front().scheme_entry && !invalid.front().resolution_error.empty(),
            "Malformed required scheme entry lost its scheme origin or disappeared");
    }
}

std::string OwnedTargetProject(const std::string& id, const std::string& name) {
    return "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(" + id + ",);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};" + id +
        "={isa=PBXNativeTarget; name=\"" + name + "\"; productType=\"com.apple.product-type.framework\";"
        "dependencies=(); buildPhases=();};}; rootObject=PROJECT;}";
}
void TargetIdentitySelection(const fs::path& root) {
    const auto bundle = root / "Owned.xcodeproj";
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(UUID,ALIAS,DUP1,DUP2,);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};"
        "UUID={isa=PBXNativeTarget; name=Zulu; buildPhases=();};"
        "ALIAS={isa=PBXNativeTarget; name=UUID; buildPhases=();};"
        "DUP1={isa=PBXNativeTarget; name=Shared; buildPhases=();};"
        "DUP2={isa=PBXAggregateTarget; name=shared; buildPhases=();};"
        "}; rootObject=PROJECT;}");
    const auto project = XcodeProject::Load(bundle);
    Require(project.has_value(), "Owned target selection project did not parse");
    std::string error = "previous diagnostic";
    const auto selected = project->FindTarget("UUID", &error);
    Require(selected && selected->id == "UUID" && error.empty(),
        "Name label masked authoritative target UUID");
    Require(!project->FindTarget("Shared", &error) && error.find("Ambiguous") != std::string::npos,
        "Ambiguous target label silently selected the first target");
    Require(project->FindTarget("DUP2", &error).has_value() && error.empty(),
        "Exact aggregate UUID failed due to duplicate display names");
    Require(!project->FindTarget("absent", &error) && error.find("not found") != std::string::npos,
        "Missing target lookup lost explicit diagnostic");
}
void ImplicitSchemeIdentity(const fs::path& root) {
    // This existing fixture discovers Consumer's same schema via both its own
    // project and workspace inventory. Repeated canonical paths are one choice.
    SchemeAndImplicitDependency(root, false);
    const auto consumer = root / "Consumer.xcodeproj";
    const auto project = XcodeProject::Load(consumer);
    Require(project.has_value(), "Owned scheme selection project did not parse");
    const auto target = project->FindTarget("CONSUMER");
    Require(target.has_value(), "Owned scheme selection target missing");
    const auto single = project->ResolveTargetDependencies(*target);
    Require(single.size() == 1 && single.front().resolution_error.empty(),
        "Repeated discovery of the same canonical scheme became ambiguous");
    const auto source = consumer / "xcshareddata/xcschemes/Consumer.xcscheme";
    std::ifstream input(source, std::ios::binary);
    const std::string same_bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    Require(!same_bytes.empty(), "Owned scheme source missing");
    // Same contents do not merge different owning containers.
    Write(root / "Provider.xcodeproj/xcshareddata/xcschemes/Consumer.xcscheme", same_bytes);
    const auto ambiguous = project->ResolveTargetDependencies(*target);
    Require(ambiguous.size() == 1 && ambiguous.front().scheme_entry &&
        ambiguous.front().resolution_error.find("Ambiguous implicit scheme") != std::string::npos,
        "Distinct identical schemes silently selected an arbitrary owner");
}
void WorkspaceSchemeContainer(const fs::path& root) {
    const auto consumer = root / "Apps/Consumer.xcodeproj";
    const auto provider = root / "Libraries/Provider.xcodeproj";
    const auto workspace = root / "Owned.xcworkspace";
    Write(consumer / "project.pbxproj", OwnedTargetProject("CONSUMER", "Consumer"));
    Write(provider / "project.pbxproj", OwnedTargetProject("PROVIDER", "Provider"));
    Write(workspace / "contents.xcworkspacedata", "<Workspace>"
        "<FileRef location=\"group:Apps/Consumer.xcodeproj\"/>"
        "<FileRef location=\"group:Libraries/Provider.xcodeproj\"/></Workspace>");
    const auto scheme = workspace / "xcshareddata/xcschemes/Consumer.xcscheme";
    const auto make_scheme = [](const std::string& provider_path) {
        return "<Scheme><BuildAction><BuildActionEntries>" +
            Entry("CONSUMER", "buildForRunning=\"YES\"", "Apps/Consumer.xcodeproj") +
            Entry("PROVIDER", "buildForRunning=\"YES\"", provider_path) +
            "</BuildActionEntries></BuildAction></Scheme>";
    };
    Write(scheme, make_scheme("Libraries/Provider.xcodeproj"));
    const auto project = XcodeProject::Load(consumer);
    Require(project.has_value(), "Nested workspace project did not parse");
    const auto target = project->FindTarget("CONSUMER");
    Require(target.has_value(), "Nested workspace target missing");
    const auto dependencies = project->ResolveTargetDependencies(*target);
    Require(dependencies.size() == 1 && dependencies.front().resolution_error.empty() &&
        fs::equivalent(dependencies.front().project_path, provider) && dependencies.front().target_id == "PROVIDER",
        "Workspace schema reference was resolved against the target's source root instead of its owner");
    // A nearby real provider with the same filename must not repair an invalid
    // authoritative reference through an invented basename match.
    Write(scheme, make_scheme("Missing/Provider.xcodeproj"));
    const auto absent = project->ResolveTargetDependencies(*target);
    Require(absent.size() == 1 && absent.front().scheme_entry && !absent.front().resolution_error.empty() &&
        absent.front().project_path == root / "Missing/Provider.xcodeproj",
        "Missing authoritative scheme project adopted another project's filename");
    Write(scheme, "<Scheme><BuildAction/></Scheme>");
    const auto malformed = project->ResolveTargetDependencies(*target);
    Require(malformed.size() == 1 && malformed.front().scheme_entry && !malformed.front().resolution_error.empty(),
        "Malformed selected implicit schema lost its origin or disappeared from the dependency inventory");
    auto unsupported_xml = make_scheme("Libraries/Provider.xcodeproj");
    const auto container_offset = unsupported_xml.find("container:Libraries/Provider.xcodeproj");
    Require(container_offset != std::string::npos, "Owned unsupported scheme fixture lost its container");
    unsupported_xml.replace(container_offset, std::string("container:").size(), "unsupported:");
    Write(scheme, unsupported_xml);
    const auto unsupported = project->ResolveTargetDependencies(*target);
    Require(unsupported.size() == 1 && unsupported.front().scheme_entry && !unsupported.front().resolution_error.empty(),
        "Unsupported scheme container diagnostic lost its scheme origin");
}
std::string SchemeEntry(const std::string& id, const std::string& flags,
    const std::string& project = "Consumer.xcodeproj") {
    return "<BuildActionEntry " + flags + "><BuildableReference BlueprintIdentifier=\"" + id +
        "\" BlueprintName=\"" + id + "\" ReferencedContainer=\"container:" + project + "\"/></BuildActionEntry>";
}
std::string Utf16(const std::string& ascii) {
    std::string result("\xff\xfe", 2);
    for (const unsigned char ch : ascii) { result.push_back(static_cast<char>(ch)); result.push_back('\0'); }
    return result;
}
std::string ReplaceOnce(std::string value, const std::string& from, const std::string& to) {
    const auto found = value.find(from);
    Require(found != std::string::npos, "Owned XML fixture replacement missing");
    value.replace(found, from.size(), to); return value;
}
void ExplicitSchemePurposes(const fs::path& root) {
    const auto owner = root / "Owned.xcworkspace", scheme = owner / "xcshareddata/xcschemes/DifferentName.xcscheme";
    const std::string run = "buildForRunning=\"YES\" buildForTesting=\"NO\" buildForProfiling=\"NO\" buildForArchiving=\"NO\" buildForAnalyzing=\"NO\"";
    const std::string archive = "buildForRunning=\"NO\" buildForTesting=\"NO\" buildForProfiling=\"YES\" buildForArchiving=\"YES\" buildForAnalyzing=\"NO\"";
    const std::string test = "buildForRunning=\"NO\" buildForTesting=\"YES\" buildForProfiling=\"NO\" buildForArchiving=\"NO\" buildForAnalyzing=\"NO\"";
    const std::string analyze = "buildForRunning=\"NO\" buildForTesting=\"NO\" buildForProfiling=\"NO\" buildForArchiving=\"NO\" buildForAnalyzing=\"YES\"";
    const std::string disabled = "buildForRunning=\"NO\" buildForTesting=\"NO\" buildForProfiling=\"NO\" buildForArchiving=\"NO\" buildForAnalyzing=\"NO\"";
    const std::string bytes = "<Scheme><BuildAction buildImplicitDependencies=\"YES\" parallelizeBuildables=\"NO\"><BuildActionEntries>" +
        SchemeEntry("RUN", run, "A&amp;B.xcodeproj") + SchemeEntry("ARCHIVE", archive) +
        SchemeEntry("TEST", test) + SchemeEntry("ANALYZE", analyze) +
        "<BuildActionEntry " + disabled + "><BuildableReference/></BuildActionEntry>"
        "</BuildActionEntries></BuildAction><LaunchAction buildConfiguration=\"Debug\">"
        "<PreActions><ExecutionAction/></PreActions><BuildableProductRunnable><BuildableReference "
        "BlueprintIdentifier=\"RUN\" BlueprintName=\"R&amp;D\" ReferencedContainer=\"container:A&amp;B.xcodeproj\"/>"
        "</BuildableProductRunnable></LaunchAction><TestAction buildConfiguration=\"Tests\"><Testables>"
        "<TestableReference><BuildableReference BlueprintIdentifier=\"NOT_A_BUILD_ENTRY\"/></TestableReference>"
        "</Testables></TestAction><ProfileAction buildConfiguration=\"Profile\"/>"
        "<AnalyzeAction buildConfiguration=\"Analyze\"/><ArchiveAction buildConfiguration=\"Production\"/></Scheme>";
    std::string error = "old diagnostic";
    for (const auto& [action, identity, configuration] : {
             std::tuple{ProjectBuildAction::Running, "RUN", "Debug"},
             std::tuple{ProjectBuildAction::Testing, "TEST", "Tests"},
             std::tuple{ProjectBuildAction::Profiling, "ARCHIVE", "Profile"},
             std::tuple{ProjectBuildAction::Analyzing, "ANALYZE", "Analyze"},
             std::tuple{ProjectBuildAction::Archiving, "ARCHIVE", "Production"}}) {
        const auto selected = XcodeScheme::Parse(scheme, owner, bytes, action, &error);
        Require(selected && error.empty() && selected->build_entries.size() == 1 &&
            selected->build_entries.front().target_id == identity && selected->configuration == configuration &&
            selected->content_sha256.size() == 64 && selected->build_implicit_dependencies == true &&
            selected->parallelize_buildables == false, "Explicit purpose mixed scheme targets, flags or configurations");
        if (action == ProjectBuildAction::Running)
            Require(selected->runnable && selected->runnable->target_name == "R&D" &&
                selected->build_entries.front().project_path == root / "A&B.xcodeproj", "XML entities changed target ownership");
    }
    const auto encoded = XcodeScheme::Parse(scheme, owner, Utf16(bytes), ProjectBuildAction::Running, &error);
    const auto plain = XcodeScheme::Parse(scheme, owner, bytes, ProjectBuildAction::Running, &error);
    Require(encoded && plain && encoded->build_entries.front().project_path == plain->build_entries.front().project_path &&
        encoded->content_sha256 != plain->content_sha256, "UTF-16 metadata was not parsed or raw content identities were conflated");
    const auto legacy = XcodeScheme::Parse(scheme, owner, bytes, ProjectBuildAction::LegacyProductBuild, &error);
    Require(legacy && legacy->build_entries.size() == 3 && legacy->build_entries[0].target_id == "RUN" &&
        legacy->build_entries[1].target_id == "ARCHIVE" && legacy->build_entries[2].target_id == "ANALYZE",
        "Compatibility product-purpose union changed or lost XML order");
    for (const auto& bad : {
        ReplaceOnce(bytes, "buildForRunning=\"YES\"", "buildForRunning=\"UNKNOWN\""),
        ReplaceOnce(bytes, "buildForRunning=\"YES\"", ""),
        ReplaceOnce(bytes, "BlueprintIdentifier=\"RUN\"", ""),
        ReplaceOnce(bytes, "</BuildActionEntries>", "</WrongElement>"),
        std::string("<!DOCTYPE Scheme [<!ENTITY unsafe SYSTEM 'file:///never-read'>]>") + bytes,
        ReplaceOnce(bytes, "<BuildActionEntries>", "<PreActions><ExecutionAction/></PreActions><BuildActionEntries>"),
        ReplaceOnce(bytes, "</BuildAction>", "<PostActions><ExecutionAction/></PostActions></BuildAction>")}) {
        error = "previous";
        Require(!XcodeScheme::Parse(scheme, owner, bad, ProjectBuildAction::Running, &error) && !error.empty() && error != "previous",
            "Malformed, unknown-purpose or unsupported scheme action fabricated a selected build");
    }
    std::string deep = "<Scheme>";
    for (unsigned depth = 0; depth < 70; ++depth) deep += "<Nested>";
    for (unsigned depth = 0; depth < 70; ++depth) deep += "</Nested>";
    deep += "</Scheme>";
    Require(!XcodeScheme::Parse(scheme, owner, deep, ProjectBuildAction::Running, &error) && !error.empty(),
        "Scheme XML depth limit was not enforced");
    const std::string oversized(8 * 1024 * 1024 + 1, ' ');
    Require(!XcodeScheme::Parse(scheme, owner, oversized, ProjectBuildAction::Running, &error) && !error.empty(),
        "Scheme XML byte limit was not enforced");
    const auto unknown = XcodeScheme::Parse(scheme, owner,
        ReplaceOnce(bytes, "buildImplicitDependencies=\"YES\"", "buildImplicitDependencies=\"UNKNOWN\""),
        ProjectBuildAction::Running, &error);
    Require(unknown && !unknown->build_implicit_dependencies && !unknown->diagnostics.empty(),
        "Unknown global scheme flag was converted to a claimed true/false value");
}
void WorkspaceMetadata(const fs::path& root) {
    const auto workspace = root / "Owned.xcworkspace";
    const auto absolute = root / "Absolute/Same.xcodeproj";
    const std::string bytes = "<Workspace><FileRef location=\"container:First.xcodeproj\"/>"
        "<Group location=\"group:Modules&amp;Views\"><FileRef location=\"group:A.xcodeproj\"/>"
        "<Group location=\"group:Nested\"><FileRef location=\"container:First.xcodeproj\"/>"
        "<FileRef location=\"group:Same.xcodeproj\"/></Group><FileRef location=\"absolute:" +
        absolute.generic_string() + "\"/><FileRef location=\"group:README.md\"/></Group>"
        "<FileRef location=\"container:Last.xcodeproj\"/></Workspace>";
    std::string error;
    const auto parsed = XcodeWorkspace::Parse(workspace, bytes, &error);
    Require(parsed && error.empty() && parsed->projects == std::vector<fs::path>{root / "First.xcodeproj",
        root / "Modules&Views/A.xcodeproj", root / "Modules&Views/Nested/Same.xcodeproj", absolute,
        root / "Last.xcodeproj"} && parsed->other_references == std::vector<fs::path>{root / "Modules&Views/README.md"},
        "Workspace ownership, nested group order, entity decoding or distinct same-name projects changed");
    const auto encoded = XcodeWorkspace::Parse(workspace, Utf16(bytes), &error);
    Require(encoded && encoded->projects == parsed->projects && encoded->other_references == parsed->other_references,
        "UTF-16 workspace metadata did not preserve qualified references");
    for (const auto& bad : {std::string("<Workspace><FileRef location=\"unknown:Other.xcodeproj\"/></Workspace>"),
        std::string("<Workspace><FileRef location=\"absolute:relative.xcodeproj\"/></Workspace>"),
        std::string("<Workspace><FileRef/></Workspace>"), std::string("<Workspace><Group></Workspace>"),
        std::string("<!DOCTYPE Workspace [<!ENTITY unsafe 'x'>]><Workspace/>")})
        Require(!XcodeWorkspace::Parse(workspace, bad, &error) && !error.empty(),
            "Malformed or unsupported workspace reference was silently adopted");
}

void ExplicitConfigurationMetadata(const fs::path& root) {
    const auto bundle = root / "Config.xcodeproj";
    const std::string pbx =
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(TARGET,); buildConfigurationList=CONFIGS;};"
        "GROUP={isa=PBXGroup; children=(BASE,); sourceTree=\"<group>\";};"
        "BASE={isa=PBXFileReference; path=Base.xcconfig; sourceTree=\"<group>\";};"
        "TARGET={isa=PBXNativeTarget; name=Config; buildPhases=(); dependencies=(); buildConfigurationList=CONFIGS;};"
        "CONFIGS={isa=XCConfigurationList; buildConfigurations=(DEBUG,RELEASE,); defaultConfigurationName=Release;};"
        "DEBUG={isa=XCBuildConfiguration; name=Debug; baseConfigurationReference=BASE; buildSettings={};};"
        "RELEASE={isa=XCBuildConfiguration; name=Release; baseConfigurationReference=BASE; buildSettings={};};"
        "}; rootObject=PROJECT;}";
    std::map<fs::path, std::string> metadata{
        {root / "Base.xcconfig", "#include? \"Absent.xcconfig\"\n#include \"Shared.xcconfig\"\n"
            "MODE = Base\nMODE[config=Debug] = DebugOnly\nMODE[config=Release] = ReleaseOnly\n"
            "LOWER = preserved\nLOWER[config=debug] = wrong\nPATTERN[config=De?u*] = matched\n"
            "#include \"End.xcconfig\"\n"},
        {root / "Shared.xcconfig", "SHARED[config=Debug] = inherited_debug\n"},
        {root / "End.xcconfig", "END[config=Debug] = final\n"}};
    unsigned reads = 0;
    const auto reader = [&](const fs::path& path) -> std::optional<std::string> {
        ++reads;
        const auto found = metadata.find(path.lexically_normal());
        return found == metadata.end() ? std::nullopt : std::optional(found->second);
    };
    const auto project = XcodeProject::LoadMetadata(bundle, pbx, {}, reader);
    Require(project.has_value() && reads == 0, "Metadata parse eagerly inspected configuration files");
    const auto target = project->FindTarget("TARGET");
    Require(target && target->id == "TARGET", "Configuration fixture target missing");
    std::string error;
    Require(project->ResolveConfigurationName(*target, "debug", &error) == "Debug" && error.empty(),
        "Unique case-insensitive configuration request was not canonicalized");
    Require(project->ResolveConfigurationName(*target, std::nullopt, &error) == "Release",
        "Authoritative default configuration was ignored");
    Require(!project->ResolveConfigurationName(*target, "Missing", &error) && !error.empty(),
        "Missing requested configuration fell back to an unrelated configuration");
    const XcodeDependencyOptions strict{false, false, true};
    const auto debug = project->ResolveTarget(*target, "Debug", strict);
    Require(debug && debug->build_settings.at("MODE") == "DebugOnly" &&
        debug->build_settings.at("LOWER") == "preserved" && debug->build_settings.at("PATTERN") == "matched" &&
        debug->build_settings.at("SHARED") == "inherited_debug" && debug->build_settings.at("END") == "final" && reads > 0,
        "Conditional xcconfig assignment, case-sensitive matching, include reader or configuration propagation failed");
    const auto canonical_debug = project->ResolveTarget(*target, "debug", strict);
    const auto default_release = project->ResolveTarget(*target, "", strict);
    Require(canonical_debug && canonical_debug->build_settings.at("CONFIGURATION") == "Debug" &&
        default_release && default_release->build_settings.at("CONFIGURATION") == "Release",
        "Strict target resolution did not retain canonical or authoritative default configuration");
    bool missing_configuration = false;
    try { (void)project->ResolveTarget(*target, "Missing", strict); }
    catch (const std::runtime_error&) { missing_configuration = true; }
    Require(missing_configuration, "Strict target resolution accepted a missing configuration");
    const auto release = project->ResolveTarget(*target, "Release", strict);
    Require(release && release->build_settings.at("MODE") == "ReleaseOnly" &&
        !release->build_settings.contains("SHARED"), "Configuration-specific values leaked between resolutions");
    const auto must_throw = [&](const std::string& base, const char* message) {
        metadata[root / "Base.xcconfig"] = base;
        bool failed = false;
        try { (void)project->ResolveTarget(*target, "Debug", strict); }
        catch (const std::runtime_error&) { failed = true; }
        Require(failed, message);
    };
    must_throw("VALUE[config=Debug][platform=unknown*] = unsafe\n",
        "Unknown condition parameter was applied without failing strict evaluation");
    must_throw("VALUE[custom=arm64] = unsafe\n", "Unknown condition qualifier was applied as unconditional");
    must_throw("VALUE[config=Debug = malformed\n", "Unterminated conditional assignment was silently ignored");
    metadata[root / "Base.xcconfig"] =
        "SDK_VAL = base\n"
        "SDK_VAL[config=Debug][sdk=iphoneos*] = $(inherited)_ios\n"
        "SDK_VAL[config=Debug][sdk=iphonesimulator*] = simulator_wrong\n"
        "ARCH_VAL[arch=arm64] = arm64_ok\n"
        "ARCH_VAL[arch=x86_64] = x86_wrong\n"
        "VAR_VAL[variant=normal] = normal_ok\n"
        "VAR_VAL[variant=profile] = profile_wrong\n";
    const auto cond_strict = project->ResolveTarget(*target, "Debug", strict);
    Require(cond_strict &&
        cond_strict->build_settings.at("SDK_VAL") == "base_ios" &&
        cond_strict->build_settings.at("ARCH_VAL") == "arm64_ok" &&
        cond_strict->build_settings.at("VAR_VAL") == "normal_ok",
        "Xcconfig conditional sdk/arch/variant matching failed in strict mode");
    metadata[root / "Base.xcconfig"] = "VALUE[config=Release][unknown=iphoneos*] = unreachable\n";
    Require(project->ResolveTarget(*target, "Debug", strict).has_value(),
        "Configuration-ineligible condition blocked a selected configuration");
    must_throw("#include \"Absent.xcconfig\"\n", "Required missing include was silently accepted");
    must_throw("VALUE[config=De\\bug] = unsupported\n", "Unsupported fnmatch syntax was claimed supported");
    metadata.erase(root / "Base.xcconfig");
    bool missing_base = false;
    try { (void)project->ResolveTarget(*target, "Debug", strict); }
    catch (const std::runtime_error&) { missing_base = true; }
    Require(missing_base, "Missing required base configuration was silently accepted");
    // Strict behavior must also survive ordinary filesystem-backed projection.
    Write(bundle / "project.pbxproj", pbx);
    Write(root / "Base.xcconfig",
        "SDK_VAL = base\n"
        "SDK_VAL[sdk=iphoneos*] = $(inherited)_ios\n"
        "SDK_VAL[sdk=iphonesimulator*] = simulator_wrong\n"
        "ARCH_VAL[arch=arm64] = arm64_ok\n"
        "ARCH_VAL[arch=x86_64] = x86_wrong\n");
    const auto filesystem_project = XcodeProject::Load(bundle);
    Require(filesystem_project.has_value(), "Filesystem-backed strict fixture did not load");
    const auto non_strict_resolved = filesystem_project->ResolveTarget(*filesystem_project->FindTarget("TARGET"), "Debug");
    Require(non_strict_resolved &&
        non_strict_resolved->build_settings.at("SDK_VAL") == "base_ios" &&
        non_strict_resolved->build_settings.at("ARCH_VAL") == "arm64_ok",
        "Non-strict xcconfig evaluation allowed simulator/x86_64 condition to overwrite iOS/arm64 setting");
    Write(root / "Base.xcconfig", "VALUE[unknown=iphoneos*] = unresolved\n");
    bool strict_projection = false;
    try { (void)filesystem_project->ResolveTarget(*filesystem_project->FindTarget("TARGET"), "Debug", strict); }
    catch (const std::runtime_error&) { strict_projection = true; }
    Require(strict_projection, "Strict selection disappeared when metadata reader was absent");
    auto ambiguous_pbx = pbx;
    const auto debug_name = ambiguous_pbx.find("name=Debug;");
    ambiguous_pbx.replace(debug_name, std::string("name=Debug;").size(), "name=DEBUG;");
    const auto release_name = ambiguous_pbx.find("name=Release;");
    ambiguous_pbx.replace(release_name, std::string("name=Release;").size(), "name=Debug;");
    const auto ambiguous = XcodeProject::LoadMetadata(bundle, ambiguous_pbx);
    Require(ambiguous && !ambiguous->ResolveConfigurationName(*ambiguous->FindTarget("TARGET"), "debug", &error),
        "Ambiguous case-folded configuration selected the first match");
    Require(ambiguous->ResolveConfigurationName(*ambiguous->FindTarget("TARGET"), "Debug", &error) == "Debug",
        "Exact configuration did not outrank case-folded alternatives");
}

void RequiredPbxDependency(const fs::path& root) {
    const auto bundle = root / "Consumer.xcodeproj";
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(CONSUMER,DEPENDENCY,);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};"
        "CONSUMER={isa=PBXNativeTarget; name=Consumer; dependencies=(REQUIRED,); buildPhases=();};"
        "DEPENDENCY={isa=PBXNativeTarget; name=Dependency; dependencies=(); buildPhases=();};"
        "REQUIRED={isa=PBXTargetDependency; target=DEPENDENCY;};}; rootObject=PROJECT;}");
    Write(bundle / "xcshareddata/xcschemes/Consumer.xcscheme",
        "<Scheme><BuildAction><BuildActionEntries>" + Entry("DEPENDENCY",
            "buildForRunning=\"NO\" buildForProfiling=\"NO\" buildForArchiving=\"NO\" "
            "buildForAnalyzing=\"NO\" buildForTesting=\"YES\"") +
        "</BuildActionEntries></BuildAction></Scheme>");
    const auto project = XcodeProject::Load(bundle);
    Require(project.has_value(), "Required PBX fixture did not parse");
    const auto target = project->FindTarget("CONSUMER");
    Require(target.has_value(), "Required PBX fixture root missing");
    const auto dependencies = project->ResolveTargetDependencies(*target);
    Require(dependencies.size() == 1 && dependencies.front().target_id == "DEPENDENCY" &&
        !dependencies.front().scheme_entry, "Disabled scheme entry erased required PBX dependency");
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(CONSUMER,);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};"
        "CONSUMER={isa=PBXNativeTarget; name=Consumer; dependencies=(ABSENT,); buildPhases=();};"
        "}; rootObject=PROJECT;}");
    const auto missing_project = XcodeProject::Load(bundle);
    Require(missing_project.has_value(), "Owned missing PBX dependency fixture did not parse");
    const auto missing_target = missing_project->FindTarget("CONSUMER");
    Require(missing_target.has_value(), "Owned missing PBX dependency target missing");
    const auto missing = missing_project->ResolveTargetDependencies(*missing_target);
    Require(missing.size() == 1 && !missing.front().scheme_entry && !missing.front().resolution_error.empty(),
        "Authoritative PBX error was incorrectly classified as scheme-only metadata");
}

void ProductAndModuleIdentityResolution(const fs::path& root) {
    const auto bundle = root / "Identity.xcodeproj";
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(FIRST,SECOND,); buildConfigurationList=CONFIGS;};"
        "GROUP={isa=PBXGroup; children=(APP_SWIFT,); sourceTree=\"<group>\";};"
        "APP_SWIFT={isa=PBXFileReference; path=App.swift; sourceTree=\"<group>\";};"
        "SOURCES_BUILD={isa=PBXBuildFile; fileRef=APP_SWIFT;};"
        "SOURCES={isa=PBXSourcesBuildPhase; files=(SOURCES_BUILD,);};"
        "FIRST={isa=PBXNativeTarget; name=First; productName=First; productType=\"com.apple.product-type.application\"; buildConfigurationList=CONFIGS; buildPhases=(SOURCES,);};"
        "SECOND={isa=PBXNativeTarget; name=Chosen; productName=SelectedProof; productType=\"com.apple.product-type.application\"; buildConfigurationList=SECOND_CONFIGS; buildPhases=(SOURCES,);};"
        "CONFIGS={isa=XCConfigurationList; buildConfigurations=(PROJ_DEBUG,PROJ_RELEASE,); defaultConfigurationName=Debug;};"
        "PROJ_DEBUG={isa=XCBuildConfiguration; name=Debug; buildSettings={PRODUCT_BUNDLE_IDENTIFIER=\"dev.openfruit.identity\";};};"
        "PROJ_RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={PRODUCT_BUNDLE_IDENTIFIER=\"dev.openfruit.identity\";};};"
        "SECOND_CONFIGS={isa=XCConfigurationList; buildConfigurations=(SEC_DEBUG,SEC_RELEASE,); defaultConfigurationName=Debug;};"
        "SEC_DEBUG={isa=XCBuildConfiguration; name=Debug; buildSettings={PRODUCT_NAME=SelectedProof;};};"
        "SEC_RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={"
        "PRODUCT_NAME=\"9Selected-Proof App\";"
        "EXECUTABLE_PREFIX=\"app_\";"
        "EXECUTABLE_SUFFIX=\"_bin\";"
        "INFOPLIST_KEY_CFBundleDisplayName=\"Chosen Display\";"
        "};};"
        "}; rootObject=PROJECT;}");
    Write(root / "App.swift", "import Foundation\n");

    const auto project = XcodeProject::Load(bundle);
    Require(project.has_value(), "Product identity fixture failed to load");
    const auto second = project->FindTarget("SECOND");
    Require(second.has_value() && second->name == "Chosen" && second->product_name == "SelectedProof",
        "Target metadata did not preserve distinct target name and productName");

    const XcodeDependencyOptions strict{false, false, true};
    const auto resolved_debug = project->ResolveTarget(*second, "Debug", strict);
    Require(resolved_debug.has_value(), "Debug target resolution failed");
    Require(resolved_debug->build_settings.at("TARGET_NAME") == "Chosen" &&
        resolved_debug->build_settings.at("PRODUCT_NAME") == "SelectedProof" &&
        resolved_debug->build_settings.at("PRODUCT_MODULE_NAME") == "SelectedProof" &&
        resolved_debug->build_settings.at("EXECUTABLE_NAME") == "SelectedProof",
        "Debug target resolution collapsed TARGET_NAME, PRODUCT_NAME, PRODUCT_MODULE_NAME, or EXECUTABLE_NAME");

    const auto inspected_debug = UniversalProject::InspectTarget(*project, *second, "Debug", strict);
    Require(inspected_debug.is_valid &&
        inspected_debug.project_name == L"Chosen" &&
        inspected_debug.product_name == L"SelectedProof" &&
        inspected_debug.module_name == L"SelectedProof" &&
        inspected_debug.display_name == L"SelectedProof",
        "UniversalProject::InspectTarget failed to separate project_name (Chosen) from product_name/module_name (SelectedProof)");

    const auto build_spec_debug = UniversalProject::ToAppBuildSpec(inspected_debug, 1);
    Require(build_spec_debug.app_name == L"Chosen" &&
        build_spec_debug.product_name == L"SelectedProof" &&
        build_spec_debug.module_name == L"SelectedProof",
        "ToAppBuildSpec failed to propagate distinct target/product/module identity");

    const auto pkg_spec_debug = UniversalProject::ToPackagingSpec(inspected_debug);
    Require(pkg_spec_debug.target_name == L"Chosen" &&
        pkg_spec_debug.product_name == L"SelectedProof" &&
        pkg_spec_debug.app_name == L"SelectedProof" &&
        pkg_spec_debug.module_name == L"SelectedProof" &&
        pkg_spec_debug.display_name == L"SelectedProof",
        "ToPackagingSpec failed to propagate distinct target/product/module/display identity");

    const auto resolved_release = project->ResolveTarget(*second, "Release", strict);
    Require(resolved_release.has_value(), "Release target resolution failed");
    Require(resolved_release->build_settings.at("TARGET_NAME") == "Chosen" &&
        resolved_release->build_settings.at("PRODUCT_NAME") == "9Selected-Proof App" &&
        resolved_release->build_settings.at("PRODUCT_MODULE_NAME") == "_9Selected_Proof_App" &&
        resolved_release->build_settings.at("EXECUTABLE_NAME") == "app_9Selected-Proof App_bin",
        "Release target resolution failed c99extidentifier expansion or executable prefix/suffix composition");

    const auto inspected_release = UniversalProject::InspectTarget(*project, *second, "Release", strict);
    Require(inspected_release.is_valid &&
        inspected_release.project_name == L"Chosen" &&
        inspected_release.product_name == L"9Selected-Proof App" &&
        inspected_release.module_name == L"_9Selected_Proof_App" &&
        inspected_release.display_name == L"Chosen Display",
        "UniversalProject::InspectTarget failed to preserve distinct target, product, sanitized module, and display names");

    const auto pkg_spec_release = UniversalProject::ToPackagingSpec(inspected_release);
    Require(pkg_spec_release.target_name == L"Chosen" &&
        pkg_spec_release.product_name == L"9Selected-Proof App" &&
        pkg_spec_release.app_name == L"9Selected-Proof App" &&
        pkg_spec_release.module_name == L"_9Selected_Proof_App" &&
        pkg_spec_release.display_name == L"Chosen Display",
        "ToPackagingSpec failed to preserve Release target, product, module, and display names");
}

void InlineConditionalPbxBuildSettings(const fs::path& root) {
    const auto bundle = root / "ConditionalPbx.xcodeproj";
    Write(bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(APP,); buildConfigurationList=PROJ_CONFIGS;};"
        "GROUP={isa=PBXGroup; children=(APP_SWIFT,); sourceTree=\"<group>\";};"
        "APP_SWIFT={isa=PBXFileReference; path=App.swift; sourceTree=\"<group>\";};"
        "SOURCES_BUILD={isa=PBXBuildFile; fileRef=APP_SWIFT;};"
        "SOURCES={isa=PBXSourcesBuildPhase; files=(SOURCES_BUILD,);};"
        "APP={isa=PBXNativeTarget; name=App; productName=App; productType=\"com.apple.product-type.application\"; buildConfigurationList=APP_CONFIGS; buildPhases=(SOURCES,);};"
        "PROJ_CONFIGS={isa=XCConfigurationList; buildConfigurations=(PROJ_DEBUG,PROJ_RELEASE,); defaultConfigurationName=Debug;};"
        "PROJ_DEBUG={isa=XCBuildConfiguration; name=Debug; buildSettings={"
        "OTHER_SWIFT_FLAGS=\"-DPROJ_BASE\";"
        "\"OTHER_SWIFT_FLAGS[sdk=iphoneos*]\"=\"$(inherited) -DPROJ_IOS\";"
        "\"OTHER_SWIFT_FLAGS[sdk=iphonesimulator*]\"=\"-DPROJ_SIM_WRONG\";"
        "};};"
        "PROJ_RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={"
        "OTHER_SWIFT_FLAGS=\"-DPROJ_REL\";"
        "};};"
        "APP_CONFIGS={isa=XCConfigurationList; buildConfigurations=(APP_DEBUG,APP_RELEASE,); defaultConfigurationName=Debug;};"
        "APP_DEBUG={isa=XCBuildConfiguration; name=Debug; buildSettings={"
        "OTHER_SWIFT_FLAGS=\"$(inherited) -DTARGET_BASE\";"
        "\"OTHER_SWIFT_FLAGS[sdk=iphoneos*]\"=\"$(inherited) -DTARGET_IOS\";"
        "\"OTHER_SWIFT_FLAGS[sdk=iphoneos*][arch=arm64]\"=\"$(inherited) -DTARGET_ARM64\";"
        "\"OTHER_SWIFT_FLAGS[sdk=iphonesimulator*]\"=\"-DSIM_WRONG\";"
        "\"OTHER_SWIFT_FLAGS[arch=x86_64]\"=\"-DX86_WRONG\";"
        "\"OTHER_SWIFT_FLAGS[config=Release]\"=\"-DRELEASE_WRONG\";"
        "\"OTHER_SWIFT_FLAGS[variant=profile]\"=\"-DPROFILE_WRONG\";"
        "\"VARIANT_FLAG[variant=normal]\"=\"normal_active\";"
        "\"CONFIG_FLAG[config=Debug]\"=\"debug_active\";"
        "\"PRODUCT_NAME[sdk=iphoneos*]\"=\"ConditionalProduct\";"
        "\"PRODUCT_NAME[sdk=iphonesimulator*]\"=\"SimulatorProduct\";"
        "};};"
        "APP_RELEASE={isa=XCBuildConfiguration; name=Release; buildSettings={"
        "\"CONFIG_FLAG[config=Release]\"=\"release_active\";"
        "\"CONFIG_FLAG[config=Debug]\"=\"debug_wrong\";"
        "};};"
        "}; rootObject=PROJECT;}");
    Write(root / "App.swift", "import Foundation\n");

    const auto project = XcodeProject::Load(bundle);
    Require(project.has_value(), "Inline conditional PBX fixture failed to load");
    const auto app = project->FindTarget("APP");
    Require(app.has_value(), "Inline conditional PBX target missing");

    const XcodeDependencyOptions strict{false, false, true};
    const auto debug_resolved = project->ResolveTarget(*app, "Debug", strict);
    Require(debug_resolved.has_value(), "Inline conditional Debug target failed to resolve");
    Require(debug_resolved->build_settings.at("OTHER_SWIFT_FLAGS") ==
        "-DPROJ_BASE -DPROJ_IOS -DTARGET_BASE -DTARGET_IOS -DTARGET_ARM64",
        "Inline conditional PBX buildSettings did not evaluate $(inherited) in deterministic specificity order");
    Require(debug_resolved->build_settings.at("VARIANT_FLAG") == "normal_active" &&
        debug_resolved->build_settings.at("CONFIG_FLAG") == "debug_active" &&
        debug_resolved->build_settings.at("PRODUCT_NAME") == "ConditionalProduct" &&
        debug_resolved->build_settings.at("PRODUCT_MODULE_NAME") == "ConditionalProduct" &&
        !debug_resolved->build_settings.contains("OTHER_SWIFT_FLAGS[sdk=iphoneos*]") &&
        !debug_resolved->build_settings.contains("OTHER_SWIFT_FLAGS[sdk=iphonesimulator*]"),
        "Inline conditional PBX buildSettings leaked raw bracketed keys or failed to apply conditional PRODUCT_NAME");

    const auto release_resolved = project->ResolveTarget(*app, "Release", strict);
    Require(release_resolved.has_value() &&
        release_resolved->build_settings.at("CONFIG_FLAG") == "release_active",
        "Inline conditional PBX buildSettings did not filter [config=Release] vs [config=Debug]");
}

void TransitiveSwiftPMPackageClosure(const fs::path& root) {
    const auto main_bundle = root / "Main.xcodeproj";
    const auto sub_bundle = root / "Sub" / "Sub.xcodeproj";
    Write(sub_bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(SUBLIB,UNRELATED_SUB,); packageReferences=(SUB_LOCAL_PKG,SHARED_LOCAL_PKG,);};"
        "GROUP={isa=PBXGroup; children=(); sourceTree=\"<group>\";};"
        "SUBLIB={isa=PBXNativeTarget; name=SubLib; productType=\"com.apple.product-type.library.static\"; buildPhases=(); dependencies=(); packageProductDependencies=(SUB_PROD,SHARED_SUB_PROD,);};"
        "UNRELATED_SUB={isa=PBXNativeTarget; name=UnrelatedSub; productType=\"com.apple.product-type.library.static\"; buildPhases=(); dependencies=(); packageProductDependencies=(UNRELATED_PROD,);};"
        "SUB_LOCAL_PKG={isa=XCLocalSwiftPackageReference; relativePath=\"../Packages/SubPkg\";};"
        "SHARED_LOCAL_PKG={isa=XCLocalSwiftPackageReference; relativePath=\"../Packages/SharedPkg\";};"
        "SUB_PROD={isa=XCSwiftPackageProductDependency; package=SUB_LOCAL_PKG; productName=SubProduct;};"
        "SHARED_SUB_PROD={isa=XCSwiftPackageProductDependency; package=SHARED_LOCAL_PKG; productName=SharedProduct;};"
        "UNRELATED_PROD={isa=XCSwiftPackageProductDependency; package=SUB_LOCAL_PKG; productName=UnrelatedProduct;};"
        "}; rootObject=PROJECT;}");

    Write(main_bundle / "project.pbxproj",
        "{archiveVersion=1; objectVersion=77; objects={"
        "PROJECT={isa=PBXProject; mainGroup=GROUP; targets=(APP,LOCAL_LIB,ISOLATED,); packageReferences=(APP_PKG,LIB_REMOTE_PKG,);};"
        "GROUP={isa=PBXGroup; children=(SUB_REF,); sourceTree=\"<group>\";};"
        "SUB_REF={isa=PBXFileReference; path=\"Sub/Sub.xcodeproj\"; sourceTree=\"<group>\";};"
        "APP={isa=PBXNativeTarget; name=App; productType=\"com.apple.product-type.application\"; buildPhases=(); dependencies=(DEP_LOCAL_LIB,); packageProductDependencies=(APP_PROD,);};"
        "LOCAL_LIB={isa=PBXNativeTarget; name=LocalLib; productType=\"com.apple.product-type.framework\"; buildPhases=(); dependencies=(DEP_SUBLIB,); packageProductDependencies=(LIB_REMOTE_PROD,APP_PROD,);};"
        "ISOLATED={isa=PBXNativeTarget; name=Isolated; productType=\"com.apple.product-type.application\"; buildPhases=(); dependencies=(); packageProductDependencies=();};"
        "DEP_LOCAL_LIB={isa=PBXTargetDependency; target=LOCAL_LIB;};"
        "PROXY_SUBLIB={isa=PBXContainerItemProxy; containerPortal=SUB_REF; proxyType=1; remoteGlobalIDString=SUBLIB; remoteInfo=SubLib;};"
        "DEP_SUBLIB={isa=PBXTargetDependency; name=SubLib; targetProxy=PROXY_SUBLIB;};"
        "APP_PKG={isa=XCLocalSwiftPackageReference; relativePath=\"Packages/SharedPkg\";};"
        "LIB_REMOTE_PKG={isa=XCRemoteSwiftPackageReference; repositoryURL=\"https://example.invalid/RemotePkg.git\"; requirement={kind=exactVersion; version=\"1.2.3\";};};"
        "APP_PROD={isa=XCSwiftPackageProductDependency; package=APP_PKG; productName=SharedProduct;};"
        "LIB_REMOTE_PROD={isa=XCSwiftPackageProductDependency; package=LIB_REMOTE_PKG; productName=RemoteProduct;};"
        "}; rootObject=PROJECT;}");

    const auto project = XcodeProject::Load(main_bundle);
    Require(project.has_value(), "Transitive package closure main project failed to load");
    const auto app = project->FindTarget("APP");
    const auto isolated = project->FindTarget("ISOLATED");
    Require(app.has_value() && isolated.has_value(), "Transitive package closure targets missing");

    const auto resolved_app = project->ResolveTarget(*app, "Debug");
    Require(resolved_app.has_value(), "Transitive package closure APP resolution failed");
    Require(resolved_app->package_products.size() == 3 &&
        resolved_app->package_products[0].product_name == "SharedProduct" &&
        resolved_app->package_products[1].product_name == "RemoteProduct" &&
        resolved_app->package_products[2].product_name == "SubProduct",
        "Transitive package product closure did not collect or deduplicate APP -> LOCAL_LIB -> SUBLIB products in deterministic DFS order");
    Require(resolved_app->package_references.size() == 3 &&
        resolved_app->package_references[0].is_local &&
        resolved_app->package_references[0].relative_path == "Packages/SharedPkg" &&
        !resolved_app->package_references[1].is_local &&
        resolved_app->package_references[1].identity == "remotepkg" &&
        resolved_app->package_references[2].is_local &&
        resolved_app->package_references[2].relative_path == "Packages/SubPkg",
        "Transitive package reference closure did not rebase subproject local package path or deduplicate shared local package");

    const auto resolved_isolated = project->ResolveTarget(*isolated, "Debug");
    Require(resolved_isolated.has_value() &&
        resolved_isolated->package_products.empty() &&
        resolved_isolated->package_references.empty(),
        "Unrelated target inherited transitive package products");
}

}

int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-dependency-inventory-" + NewOperationId());
    try {
        SchemeAndImplicitDependency(root / "scheme-only", false);
        SchemeAndImplicitDependency(root / "scheme-and-linked-product", true);
        ProductActionInventory(root / "product-actions");
        RequiredPbxDependency(root / "required-pbx");
        TargetIdentitySelection(root / "target-identity");
        ImplicitSchemeIdentity(root / "implicit-scheme-identity");
        WorkspaceSchemeContainer(root / "workspace-scheme-container");
        ExplicitSchemePurposes(root / "explicit-scheme");
        WorkspaceMetadata(root / "workspace-metadata");
        ExplicitConfigurationMetadata(root / "configuration-metadata");
        ProductAndModuleIdentityResolution(root / "product-identity");
        InlineConditionalPbxBuildSettings(root / "inline-conditional-pbx");
        TransitiveSwiftPMPackageClosure(root / "transitive-swiftpm-closure");
        fs::remove_all(root); // Unique OPENFRUIT-owned fixture only.
        std::cout << "Scheme and implicit dependency inventory promotion passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; owned fixture retained: " << root << '\n';
        return 1;
    }
}
