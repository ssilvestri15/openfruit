#include "compiler_proxy.hpp"
#include "json_value.hpp"
#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "tool_paths.hpp"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

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

std::string ReadText(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void AppendWorkspaceStates(
    const fs::path& root,
    int remaining_depth,
    std::vector<fs::path>& states
) {
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) return;

    const fs::path state = root / "workspace-state.json";
    if (fs::is_regular_file(state, ec) && !ec) {
        states.push_back(state);
        return;
    }
    if (remaining_depth == 0) return;

    for (fs::directory_iterator it(
             root,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (it->is_directory(ec) && !ec) {
            AppendWorkspaceStates(it->path(), remaining_depth - 1, states);
        }
        ec.clear();
    }
}

fs::path FindArtifactPath(const std::string& package_identity) {
    std::vector<fs::path> states;
    const fs::path managed_cache =
        OpenFruit::ToolPaths::LocalHome() / "cache";
    AppendWorkspaceStates(managed_cache / "swiftpm-exec", 2, states);
    AppendWorkspaceStates(managed_cache / "s", 1, states);

    std::sort(
        states.begin(), states.end(),
        [](const fs::path& left, const fs::path& right) {
            std::error_code left_error;
            std::error_code right_error;
            const auto left_time = fs::last_write_time(left, left_error);
            const auto right_time = fs::last_write_time(right, right_error);
            if (left_error || right_error) return left.string() < right.string();
            return left_time > right_time;
        });
    for (const fs::path& state : states) {
        std::string parse_error;
        const auto root = OpenFruit::JsonValue::Parse(
            ReadText(state), &parse_error);
        if (!root || !root->IsObject()) continue;
        const OpenFruit::JsonValue* object = root->Get("object");
        const OpenFruit::JsonValue* artifacts =
            object && object->IsObject() ? object->Get("artifacts") : nullptr;
        if (!artifacts || !artifacts->IsArray()) continue;

        for (const OpenFruit::JsonValue& artifact : artifacts->ArrayItems()) {
            if (!artifact.IsObject()) continue;
            const OpenFruit::JsonValue* target = artifact.Get("targetName");
            const OpenFruit::JsonValue* path = artifact.Get("path");
            const OpenFruit::JsonValue* package_ref = artifact.Get("packageRef");
            const OpenFruit::JsonValue* identity =
                package_ref && package_ref->IsObject()
                ? package_ref->Get("identity")
                : nullptr;
            if (target && target->IsString() &&
                target->StringValue() == "openapi-generator" &&
                identity && identity->IsString() &&
                identity->StringValue() == package_identity &&
                path && path->IsString()) {
                return fs::path(path->StringValue());
            }
        }
    }
    return {};
}

} // namespace

int main(int argc, char** argv) {
    if (OpenFruit::CompilerProxy::IsActive()) {
        return OpenFruit::CompilerProxy::Run(argc, argv);
    }

    if (argc != 4) {
        std::cerr << "usage: swiftpm_binary_artifact_probe "
                     "<OPENFRUIT-repo-root> <package-path> "
                     "<artifact-package-identity>\n";
        return 2;
    }

    const fs::path repo_root =
        fs::absolute(fs::path(argv[1])).lexically_normal();
    const fs::path package =
        fs::absolute(fs::path(argv[2])).lexically_normal();
    const OpenFruit::SDKInfo sdk = OpenFruit::SDKManager::DiscoverSDK(
        repo_root.wstring(), L"18.6");
    if (!sdk.is_valid) {
        std::cerr << "SDK discovery failed\n";
        return 3;
    }

    const OpenFruit::PackageBuildResult result =
        OpenFruit::PackageEngine::BuildSwiftPMPackage(
            repo_root.wstring(), package.wstring(), sdk, L"release", 2);
    std::cout << "PACKAGE_RESULT_SUCCESS="
              << (result.success ? 1 : 0) << "\n";

    const fs::path artifact = FindArtifactPath(argv[3]);
    std::cout << "BINARY_ARTIFACT_PATH=" << artifact.string() << "\n";
    if (artifact.empty()) {
        std::cerr << "SwiftPM did not record the binary artifact path\n";
        return 4;
    }

    const fs::path resources =
        artifact /
        "openapi-generator-macos-arm64" /
        "bin" /
        "openapi-generator_OpenAPIGeneratorCore.bundle" /
        "Resources";
    const std::vector<std::string> expected = {
        "AnyJSON.swift",
        "Indirect.swift",
        "Paths.swift",
        "StringCodingKey.swift",
        "URLQueryEncoder.swift",
        "Version.swift"
    };

    std::size_t present = 0;
    std::size_t maximum_path_length = 0;
    for (const std::string& name : expected) {
        const fs::path path = resources / name;
        maximum_path_length = std::max(
            maximum_path_length, path.string().size());
        if (LongPathRegularFile(path)) ++present;
    }

    std::cout << "BINARY_ARTIFACT_RESOURCE_COUNT=" << present << "\n";
    std::cout << "BINARY_ARTIFACT_EXPECTED_RESOURCE_COUNT="
              << expected.size() << "\n";
    std::cout << "BINARY_ARTIFACT_MAXIMUM_PATH_LENGTH="
              << maximum_path_length << "\n";
    if (present != expected.size()) {
        std::cerr << "SwiftPM binary artifact copy is incomplete\n";
        return 5;
    }
    std::cout << "SWIFTPM_BINARY_ARTIFACT_COPY=pass\n";
    return 0;
}
