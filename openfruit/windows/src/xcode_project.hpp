#pragma once
#include "xcode_target_kind.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace OpenFruit {

/*
 * OPENFRUIT v4 native Xcode model.
 *
 * project.pbxproj is an ASCII/OpenStep property list, not JSON.  The parser
 * below builds one indexed in-memory graph once, then every target/settings/
 * package lookup is O(1) average through hash indexes instead of repeatedly
 * regex-scanning the entire project.
 */

using XcodeObjectId = std::string;
// Missing metadata is nullopt; unsafe/inaccessible input may throw a diagnostic
// supplied by the admitting application. Domain parsing never depends on Git.
using XcodeMetadataReader = std::function<std::optional<std::string>(const std::filesystem::path&)>;

struct XcodePackageRequirement {
    enum class Kind {
        UpToNextMajor,
        UpToNextMinor,
        Exact,
        Branch,
        Revision,
        Range,
        Unknown
    };

    Kind kind = Kind::Unknown;
    std::string lower_bound;
    std::string upper_bound;
    std::string value;
};

struct XcodePackageReference {
    XcodeObjectId id;
    std::string repository_url;
    std::string identity;
    XcodePackageRequirement requirement;
    bool is_local = false;
    std::string relative_path;
};

struct XcodeProductDependency {
    XcodeObjectId id;
    XcodeObjectId package_id;
    std::string product_name;
};

struct XcodeTargetDependency {
    std::string name;
    std::filesystem::path project_path; // empty if in the same .xcodeproj
    std::string target_name;
    XcodeObjectId target_id;
    bool is_subproject = false;
    // Scheme co-build membership is scheduling metadata, not a PBX dependency.
    bool scheme_entry = false;
    // Preserve invalid authoritative edges for preflight failure, never skip them.
    std::string resolution_error;
};

// Explicit selections supply scheme co-build entries once at the application
// boundary. Descendants still resolve PBX dependencies and, when enabled by the
// selected scheme, linked-product dependencies; they never reselect a scheme.
struct XcodeDependencyOptions {
    bool include_scheme = true;
    bool infer_linked_products = true;
    bool strict_build_settings = false;
};

struct XcodeTarget {
    XcodeTargetKind kind = XcodeTargetKind::Native;
    XcodeObjectId id;
    std::string name;
    std::string product_name;
    std::string product_type;
    XcodeObjectId build_configuration_list;

    std::vector<XcodeObjectId> build_phases;
    std::vector<XcodeObjectId> package_product_dependencies;
    std::vector<XcodeObjectId> synchronized_groups;
    std::vector<XcodeObjectId> dependencies;
};

struct XcodeShellScriptPhase {
    XcodeObjectId id;
    std::string name;
    std::string shell_path;
    std::string script;
    std::vector<std::string> input_paths;
    std::vector<std::string> output_paths;
    std::size_t order = 0;
    bool after_sources = false;
};

struct XcodeCoreDataModel {
    std::filesystem::path path;
    std::string current_version;
};

struct XcodeResolvedTarget {
    XcodeTarget target;

    std::unordered_map<std::string, std::string> build_settings;

    std::vector<std::filesystem::path> swift_sources;
    std::vector<std::filesystem::path> c_family_sources;
    // Per-file COMPILER_FLAGS of Sources build files, settings-expanded.
    std::vector<std::pair<std::filesystem::path, std::string>> source_compiler_flags;
    std::vector<std::filesystem::path> headers;
    std::vector<std::filesystem::path> resources;
    std::vector<std::filesystem::path> asset_catalogs;
    std::vector<std::filesystem::path> string_catalogs;
    std::vector<XcodeCoreDataModel> core_data_models;
    std::vector<std::filesystem::path> intent_definitions;
    std::vector<std::filesystem::path> frameworks;
    std::vector<std::string> system_frameworks;
    std::vector<std::string> system_libraries;
    std::vector<std::string> link_libraries;

    std::vector<XcodeProductDependency> package_products;
    std::vector<XcodePackageReference> package_references;
    std::vector<XcodeTargetDependency> target_dependencies;
    std::vector<XcodeShellScriptPhase> shell_script_phases;

    std::vector<std::string> excluded_source_file_names;
    std::vector<std::filesystem::path> project_headers;
};

class XcodeProject {
public:
    // Build settings given on the command line as NAME=value, as xcodebuild
    // accepts them: they take precedence over every project, xcconfig and
    // target level for all targets of the build.
    static void SetCommandLineBuildSettings(std::unordered_map<std::string, std::string> settings);
    static const std::unordered_map<std::string, std::string>& CommandLineBuildSettings();
    static std::optional<XcodeProject> Load(
        const std::filesystem::path& project_or_directory,
        const std::filesystem::path& build_products_root = {}
    );

    // Parse the same project format from already admitted metadata bytes. The
    // logical bundle remains the owner of relative references, including when
    // Git mode-120000 metadata resolves to content stored elsewhere.
    static std::optional<XcodeProject> LoadMetadata(
        const std::filesystem::path& logical_project_bundle,
        std::string_view pbx_bytes,
        const std::filesystem::path& build_products_root = {},
        XcodeMetadataReader reader = {}
    );

    const std::filesystem::path& SourceRoot() const noexcept {
        return source_root_;
    }

    const std::filesystem::path& ProjectBundle() const noexcept {
        return project_bundle_;
    }

    const std::filesystem::path& PbxprojPath() const noexcept {
        return pbxproj_path_;
    }

    const std::filesystem::path& BuildProductsRoot() const noexcept {
        return build_products_root_;
    }

    const std::string& Name() const noexcept {
        return project_name_;
    }

    std::vector<XcodeTarget> Targets() const;

    std::optional<XcodeTarget> MainApplicationTarget() const;

    // Exact UUID wins over labels. A name-only selection must be unique.
    std::optional<XcodeTarget> FindTarget(
        const std::string& name_or_id,
        std::string* error = nullptr
    ) const;

    std::vector<XcodeTargetDependency> ResolveTargetDependencies(
        const XcodeTarget& target,
        const XcodeDependencyOptions& options = {}
    ) const;

    // Explicit requests must identify an actual configuration. Empty selection
    // uses an authoritative default or a single available configuration.
    std::optional<std::string> ResolveConfigurationName(
        const XcodeTarget& target,
        const std::optional<std::string>& requested = std::nullopt,
        std::string* error = nullptr
    ) const;

    std::vector<std::filesystem::path> DiscoverWorkspaceProjects() const;

    std::optional<XcodeResolvedTarget> ResolveTarget(
        const XcodeTarget& target,
        std::string configuration,
        const XcodeDependencyOptions& options = {}
    ) const;

    std::vector<std::filesystem::path> CollectProjectHeaders(
        const XcodeTarget& target,
        const std::string& configuration
    ) const;

public:
    // Internal parsed OpenStep value type; public for the native parser implementation.
    struct Value {
        enum class Kind {
            Null,
            String,
            Array,
            Dictionary
        };

        Kind kind = Kind::Null;
        std::string string;
        std::vector<Value> array;
        std::unordered_map<std::string, Value> dictionary;

        const Value* Get(std::string_view key) const;
        std::string String(std::string_view key) const;
        std::vector<std::string> StringArray(std::string_view key) const;
    };

    struct ParsedProject {
        Value root;
        mutable const Value* objects = nullptr;

        const Value* Objects() const {
            if (!objects) {
                objects = root.Get("objects");
            }
            return objects;
        }

        ParsedProject() = default;
        ParsedProject(const ParsedProject& other) : root(other.root), objects(nullptr) {
            objects = root.Get("objects");
        }
        ParsedProject& operator=(const ParsedProject& other) {
            if (this != &other) {
                root = other.root;
                objects = root.Get("objects");
            }
            return *this;
        }
        ParsedProject(ParsedProject&& other) noexcept : root(std::move(other.root)), objects(nullptr) {
            objects = root.Get("objects");
            other.objects = nullptr;
        }
        ParsedProject& operator=(ParsedProject&& other) noexcept {
            if (this != &other) {
                root = std::move(other.root);
                objects = root.Get("objects");
                other.objects = nullptr;
            }
            return *this;
        }
    };

private:
    std::filesystem::path source_root_;
    std::filesystem::path build_products_root_;
    std::filesystem::path project_bundle_;
    std::filesystem::path pbxproj_path_;
    std::string project_name_;

    ParsedProject parsed_;

    // Reverse PBXGroup child -> parent group, constructed once.
    std::unordered_map<XcodeObjectId, XcodeObjectId> parent_group_;

    // Cached path lookup. PBX IDs are immutable, so memoization is safe.
    mutable std::unordered_map<XcodeObjectId, std::filesystem::path>
        resolved_file_paths_;

    XcodeMetadataReader metadata_reader_;
    std::optional<std::string> ReadMetadata(const std::filesystem::path& path) const;
    std::optional<XcodeProject> LoadRelatedProject(const std::filesystem::path& project_or_bundle) const;

    const Value* Object(const XcodeObjectId& id) const;

    std::filesystem::path ResolveFileReference(
        const XcodeObjectId& id
    ) const;

    std::filesystem::path ResolveGroupPath(
        const XcodeObjectId& id,
        std::unordered_set<XcodeObjectId>& recursion_guard
    ) const;

    std::unordered_map<std::string, std::string>
    ResolveBuildSettings(
        const XcodeTarget& target,
        const std::string& configuration,
        bool strict_build_settings = false
    ) const;

    std::unordered_map<std::string, std::string>
    ConfigurationSettings(
        const XcodeObjectId& configuration_list,
        const std::string& configuration,
        std::string* selected_name = nullptr,
        bool strict_build_settings = false
    ) const;

    void MergeXcconfig(
        const std::filesystem::path& xcconfig,
        std::unordered_map<std::string, std::string>& values,
        std::unordered_set<std::string>& visited,
        const std::string& configuration,
        bool strict_build_settings = false,
        bool optional = false
    ) const;

    std::string ExpandBuildSetting(
        std::string value,
        const std::unordered_map<std::string, std::string>& settings
    ) const;

    void BuildParentGroupIndex();

    void CollectBuildPhaseFiles(
        const XcodeTarget& target,
        XcodeResolvedTarget& result
    ) const;

    void CollectSynchronizedGroupFiles(
        const XcodeTarget& target,
        XcodeResolvedTarget& result
    ) const;

    void CollectPackageDependencies(
        const XcodeTarget& target,
        XcodeResolvedTarget& result
    ) const;
};

} // namespace OpenFruit
