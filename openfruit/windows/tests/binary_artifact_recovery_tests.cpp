#include "package_engine.hpp"
#include "tool_paths.hpp"
#include "native_zip.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* text) { if (!value) throw std::runtime_error(text); }
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary); out << text;
    Require(bool(out), "fixture write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary); Require(bool(in), "fixture read failed");
    return {std::istreambuf_iterator<char>(in), {}};
}
void Git(const fs::path& root, std::vector<std::wstring> args) {
    args.insert(args.begin(), {L"git.exe", L"-C", root.wstring()});
    Require(Win32Process::Run(L"git.exe", args).success, "fixture Git failed");
}
std::string Manifest(const std::string& checksum) {
    // Expressions require official evaluation. The inactive literal must
    // never establish a binding; these are normative owned stage inputs.
    return "// swift-tools-version: 5.9\nimport PackageDescription\n"
        "let label = [\"Stage\", \"Binary\"].joined()\n"
        "let address = \"https://example.invalid/\" + \"stage.zip\"\n"
        "let digest = \"" + checksum + "\"\n"
        "#if os(Linux)\nlet targets: [Target] = [.binaryTarget(name: \"StageBinary\", "
        "url: \"https://example.invalid/inactive.zip\", checksum: \"" + std::string(64, '0') + "\")]\n"
        "#else\nlet targets: [Target] = [.binaryTarget(name: label, url: address, checksum: digest)]\n#endif\n"
        "let package = Package(name: \"OwnedLeaf\", targets: targets)\n";
}
}
int main() {
    fs::path root;
    try {
        const auto swift = ToolPaths::SwiftBin({}) / "swift.exe";
        if (!fs::is_regular_file(swift)) return 77;
        const auto env = PackageEngine::HostEnvironment(swift.parent_path());
        root = fs::temp_directory_path() / ("OPENFRUIT-binary-" + NewOperationId());
        const auto leaf = root / "OwnedLeaf", consumer = root / "Consumer", scratch = root / "scratch";
        Write(leaf / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"OwnedLeaf\", targets: [.target(name: \"Leaf\")])\n");
        Write(leaf / "Sources/Leaf/leaf.swift", "public let value = 17\n");
        Git(leaf, {L"init", L"-b", L"main", L"--quiet"});
        Git(leaf, {L"add", L"."});
        Git(leaf, {L"-c", L"user.name=Owned fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"stage input"});
        Write(consumer / "Package.swift", "// swift-tools-version: 5.9\nimport PackageDescription\n"
            "let package = Package(name: \"Consumer\", dependencies: [.package(url: \"" +
            leaf.generic_string() + "\", branch: \"main\")])\n");
        const auto resolve = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package",
            L"--package-path", consumer.wstring(), L"--scratch-path", scratch.wstring(), L"resolve"},
            consumer.wstring(), env);
        if (!resolve.success) std::cerr << resolve.std_out << resolve.std_err;
        Require(resolve.success, "official resolver fixture failed");
        const auto state = JsonValue::Parse(Read(scratch / "workspace-state.json"));
        Require(bool(state), "official state missing");
        const auto dependencies = state->Get("object")->Get("dependencies");
        Require(dependencies && dependencies->ArrayItems().size() == 1, "official dependency missing");
        const auto identity = dependencies->ArrayItems()[0].Get("packageRef")->GetString("identity");
        const auto checkout = scratch / "checkouts" / identity;
        Require(fs::is_directory(checkout), "official checkout missing");
        const auto archive = scratch / "shared-cache/artifacts/opaque-download-key";
        Write(root / "archive/Stage.xcframework/Info.plist", "owned stage metadata");
        Write(root / "archive/Stage.xcframework/bytes", "owned artifact sentinel");
        Require(NativeZipWriter::CreateFromDirectory(root / "archive", archive), "stage ZIP failed");
        // SwiftPM itself computes the normative manifest digest. It is never
        // supplied directly to recovery, which must derive it from dump-package.
        const auto zip = root / "checksum.zip";
        fs::copy_file(archive, zip);
        auto hash = Win32Process::Run(swift.wstring(), {swift.wstring(), L"package", L"compute-checksum",
            zip.wstring()}, root.wstring(), env);
        Require(hash.success, "official checksum failed");
        while (!hash.std_out.empty() && (hash.std_out.back() == '\n' || hash.std_out.back() == '\r')) hash.std_out.pop_back();
        Require(hash.std_out.size() == 64, "official checksum malformed");
        const auto manifest = checkout / "Package.swift";
        // Only this owned stage fixture is mutable: SwiftPM marks SCM checkout
        // files read-only. Production recovery never changes the manifest.
        fs::permissions(manifest, fs::perms::owner_write, fs::perm_options::add);
        const auto destination = scratch / "artifacts" / identity / "StageBinary/Stage.xcframework";
        ProcessResult failure;
        failure.std_err = "error: encountered an I/O error (code: 514) while reading " + destination.string();
        Write(manifest, Manifest(std::string(64, '0')));
        const auto original_state = Read(scratch / "workspace-state.json");
        Require(!fs::exists(checkout / ".build") && !fs::exists(checkout / ".swiftpm"),
                "resolver fixture polluted the original dependency checkout");
        Require(!PackageEngine::RecoverBinaryArtifacts(swift, scratch, env, failure), "wrong checksum accepted");
        Require(Read(scratch / "workspace-state.json") == original_state && !fs::exists(destination), "rejected input published");
        Require(!fs::exists(checkout / ".build") && !fs::exists(checkout / ".swiftpm"),
                "metadata recovery wrote build state into the original dependency checkout");
        Write(manifest, Manifest(hash.std_out));
        const auto original_manifest = Read(manifest), original_archive = Read(archive);
        Require(PackageEngine::RecoverBinaryArtifacts(swift, scratch, env, failure), "extensionless cache recovery failed");
        Require(Read(destination / "bytes") == "owned artifact sentinel", "recovered bytes differ");
        Require(Read(manifest) == original_manifest && Read(archive) == original_archive, "source/download changed");
        Require(!fs::exists(checkout / ".build") && !fs::exists(checkout / ".swiftpm"),
                "successful recovery polluted the original dependency checkout");
        const auto recovered = JsonValue::Parse(Read(scratch / "workspace-state.json"));
        const auto artifacts = recovered->Get("object")->Get("artifacts");
        Require(artifacts && artifacts->ArrayItems().size() == 1, "registration missing");
        const auto& record = artifacts->ArrayItems()[0];
        Require(record.Get("source")->GetString("url") == "https://example.invalid/stage.zip" &&
            record.Get("source")->GetString("checksum") == hash.std_out &&
            fs::equivalent(fs::path(record.GetString("path")), destination), "evaluated metadata not propagated");
        // Two real evaluated manifests claiming the same target/hash are
        // ambiguous when the original diagnostic contains no package identity.
        Write(scratch / "checkouts/second-owned/Package.swift", original_manifest);
        failure.std_err = "failed extracting 'https://example.invalid/stage.zip' which is required by binary target 'StageBinary'";
        const auto before_ambiguous = Read(scratch / "workspace-state.json");
        Require(!PackageEngine::RecoverBinaryArtifacts(swift, scratch, env, failure), "ambiguous ownership accepted");
        Require(Read(scratch / "workspace-state.json") == before_ambiguous, "ambiguous state changed");
        fs::remove_all(root);
        std::cout << "Official metadata -> verified extensionless archive -> recovery registration PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\nRetained fixture: " << root << '\n'; return 1;
    }
}
