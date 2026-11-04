#include "compiler_proxy.hpp"
#include "json_value.hpp"
#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "tool_paths.hpp"
#include "universal_project.hpp"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

namespace {

bool LongPathRegularFile(const fs::path& input) {
    std::wstring value = fs::absolute(input).lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) != 0) {
        value = L"\\\\?\\" + value;
    }
    const DWORD attributes = GetFileAttributesW(value.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool LongPathDirectory(const fs::path& input) {
    std::wstring value = fs::absolute(input).lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) != 0) {
        value = L"\\\\?\\" + value;
    }
    const DWORD attributes = GetFileAttributesW(value.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::string ReadText(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

std::size_t CountFlagValuePairs(
    const OpenFruit::JsonValue::Array& options,
    const std::string& flag,
    const std::string& value
) {
    std::size_t count = 0;
    for (std::size_t i = 0; i + 1 < options.size(); ++i) {
        if (options[i].IsString() && options[i + 1].IsString() &&
            options[i].StringValue() == flag &&
            options[i + 1].StringValue() == value) {
            ++count;
        }
    }
    return count;
}

const OpenFruit::JsonValue::Array* CompilerOptions(
    const OpenFruit::JsonValue& root,
    const std::string& compiler
) {
    const OpenFruit::JsonValue* compiler_value = root.Get(compiler);
    if (!compiler_value || !compiler_value->IsObject()) return nullptr;
    const OpenFruit::JsonValue* options =
        compiler_value->Get("extraCLIOptions");
    if (!options || !options->IsArray()) return nullptr;
    return &options->ArrayItems();
}

} // namespace

int main(int argc, char** argv) {
    if (OpenFruit::CompilerProxy::IsActive()) {
        return OpenFruit::CompilerProxy::Run(argc, argv);
    }

    if (argc != 3) {
        std::cerr << "usage: carthage_propagation_probe "
                     "<OPENFRUIT-repo-root> <fixture-xcodeproj>\n";
        return 2;
    }

    const fs::path repo_root =
        fs::absolute(fs::path(argv[1])).lexically_normal();
    const fs::path project_path =
        fs::absolute(fs::path(argv[2])).lexically_normal();

    const OpenFruit::DiscoveredProject project =
        OpenFruit::UniversalProject::Inspect(project_path.wstring());
    if (!project.is_valid) {
        std::cerr << "project discovery failed\n";
        return 3;
    }

    const OpenFruit::SDKInfo sdk = OpenFruit::SDKManager::DiscoverSDK(
        repo_root.wstring(), project.minimum_os_version);
    if (!sdk.is_valid) {
        std::cerr << "SDK discovery failed\n";
        return 4;
    }

    const OpenFruit::PackageBuildResult packages =
        OpenFruit::PackageEngine::BuildXcodePackages(
            repo_root.wstring(), project.project_dir, sdk, L"release", 2);
    if (!packages.success) {
        std::cerr << "PackageEngine failed before producing its model\n";
        return 5;
    }
    if (packages.frameworks.size() != 1) {
        std::cerr << "PackageEngine framework count: "
                  << packages.frameworks.size() << "\n";
        return 6;
    }

    const fs::path framework =
        fs::absolute(fs::path(packages.frameworks.front())).lexically_normal();
    const fs::path modulemap =
        framework / "Modules" / "module.modulemap";
    if (framework.extension() != ".framework" ||
        !LongPathRegularFile(modulemap)) {
        std::cerr << "PackageEngine did not retain a consumable framework "
                     "slice\n";
        return 7;
    }

    std::cout << "PACKAGE_FRAMEWORK=" << framework.string() << "\n";
    const fs::path framework_parent = framework.parent_path();
    const std::string expected = framework_parent.string();
    std::cout << "PACKAGE_FRAMEWORK_PARENT=" << expected << "\n";
    std::cout << "FRAMEWORK_PARENT_LENGTH=" << expected.size() << "\n";

    std::error_code standard_error;
    fs::path standard_path = fs::absolute(framework_parent, standard_error);
    if (standard_error) {
        standard_path = framework_parent;
        standard_error.clear();
    }
    standard_path = standard_path.lexically_normal();
    const bool standard_directory =
        fs::exists(standard_path, standard_error) && !standard_error &&
        fs::is_directory(standard_path, standard_error) && !standard_error;
    const int standard_error_value = standard_error.value();
    const bool extended_directory = LongPathDirectory(framework_parent);
    const bool logical_extended =
        framework_parent.wstring().rfind(L"\\\\?\\", 0) == 0;
    std::cout << "STANDARD_FILESYSTEM_DIRECTORY="
              << (standard_directory ? 1 : 0) << "\n";
    std::cout << "STANDARD_FILESYSTEM_ERROR="
              << standard_error_value << "\n";
    std::cout << "EXTENDED_WIN32_DIRECTORY="
              << (extended_directory ? 1 : 0) << "\n";
    std::cout << "LOGICAL_PATH_HAS_EXTENDED_PREFIX="
              << (logical_extended ? 1 : 0) << "\n";

    std::size_t toolset_occurrences = 0;
    fs::path toolset_path;
    std::error_code toolset_error;
    const fs::path swiftpm_root =
        OpenFruit::ToolPaths::CacheRoot() / "swiftpm";
    for (fs::directory_iterator it(
             swiftpm_root,
             fs::directory_options::skip_permission_denied,
             toolset_error);
         it != fs::directory_iterator();
         it.increment(toolset_error)) {
        if (toolset_error) {
            toolset_error.clear();
            continue;
        }
        if (!it->is_directory(toolset_error) || toolset_error) {
            toolset_error.clear();
            continue;
        }
        const fs::path candidate =
            it->path() / "OPENFRUIT-ios-target-toolset.json";
        if (fs::is_regular_file(candidate, toolset_error) &&
            !toolset_error) {
            std::string parse_error;
            const auto toolset = OpenFruit::JsonValue::Parse(
                ReadText(candidate), &parse_error);
            if (!toolset || !toolset->IsObject()) {
                std::cerr << "unable to parse target toolset: "
                          << parse_error << "\n";
                return 11;
            }
            const auto* options = CompilerOptions(*toolset, "swiftCompiler");
            const std::size_t count = options
                ? CountFlagValuePairs(*options, "-F", expected)
                : 0;
            if (count > toolset_occurrences) {
                toolset_occurrences = count;
                toolset_path = candidate;
            } else if (toolset_path.empty()) {
                toolset_path = candidate;
            }
        }
        toolset_error.clear();
    }

    std::cout << "PACKAGE_TOOLSET=" << toolset_path.string() << "\n";
    std::cout << "TOOLSET_FRAMEWORK_PARENT_OCCURRENCES="
              << toolset_occurrences << "\n";
    if (toolset_occurrences == 0) {
        std::cerr << "framework search path missing from PackageEngine "
                     "SwiftPM target toolset\n";
        return 10;
    }

    const fs::path description =
        toolset_path.parent_path() /
        "arm64-apple-ios" /
        "release" /
        "description.json";
    std::string description_error;
    const auto build_description = OpenFruit::JsonValue::Parse(
        ReadText(description), &description_error);
    if (!build_description || !build_description->IsObject()) {
        std::cerr << "unable to parse SwiftPM build description: "
                  << description_error << "\n";
        return 12;
    }
    const OpenFruit::JsonValue* swift_commands =
        build_description->Get("swiftCommands");
    if (!swift_commands || !swift_commands->IsObject()) {
        std::cerr << "SwiftPM build description has no Swift commands\n";
        return 13;
    }

    std::size_t command_count = 0;
    std::size_t commands_with_path = 0;
    std::size_t command_flag_pairs = 0;
    for (const auto& [name, command] : swift_commands->ObjectItems()) {
        (void)name;
        if (!command.IsObject()) continue;
        const OpenFruit::JsonValue* executable = command.Get("executable");
        const OpenFruit::JsonValue* arguments = command.Get("otherArguments");
        if (!executable || !executable->IsString() ||
            executable->StringValue().find("swiftc") == std::string::npos ||
            !arguments || !arguments->IsArray()) {
            continue;
        }
        ++command_count;
        const std::size_t count = CountFlagValuePairs(
            arguments->ArrayItems(), "-F", expected);
        command_flag_pairs += count;
        if (count > 0) ++commands_with_path;
    }

    std::cout << "SWIFT_BUILD_DESCRIPTION=" << description.string() << "\n";
    std::cout << "SWIFT_COMMAND_COUNT=" << command_count << "\n";
    std::cout << "SWIFT_COMMANDS_WITH_FRAMEWORK_PATH="
              << commands_with_path << "\n";
    std::cout << "SWIFT_FRAMEWORK_FLAG_PAIRS="
              << command_flag_pairs << "\n";
    if (command_count == 0 || commands_with_path != command_count ||
        command_flag_pairs != command_count) {
        std::cerr << "framework search path missing from generated Swift "
                     "command arguments\n";
        return 14;
    }

    std::cout << "FRAMEWORK_DIRECTORY_SOURCE="
                 "PackageBuildResult.frameworks[0].parent_path\n";
    std::cout << "FRAMEWORK_SEARCH_PATH_PROPAGATED=swift\n";
    return 0;
}
