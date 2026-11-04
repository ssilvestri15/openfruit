#include "environment_manager.hpp"
#include "artifact_store.hpp"
#include "atomic_file.hpp"

#include "sdk_acquisition.hpp"

#include "sdk_manager.hpp"
#include "sdk_catalog.hpp"
#include "system_info.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "macro_engine.hpp"
#include "archive_shim.hpp"
#include "http_transfer.hpp"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <functional>
#include <exception>
#include <iostream>
#include <iterator>
#include <cwctype>
#include <regex>
#include <set>
#include <sstream>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

bool ProbeEntry(const fs::path& path) {
    const auto name = path.filename().wstring();
    return name.size() == 32 && name.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
}

// These scopes contain private validation/extraction files, never installation inputs.
// Failed/crashed probes retain bounded evidence; successful probes can disappear
// only after their process, output readers and lifetime lease have finished.
struct ProbeWorkspace {
    fs::path path;
    std::shared_ptr<ArtifactLease> lease;
    bool succeeded = false;
    explicit ProbeWorkspace(fs::path destination) : path(std::move(destination)) {
        if (fs::exists(path) || fs::exists(fs::path(path.wstring() + L".import-lock")))
            throw std::runtime_error("Probe workspace already exists.");
        lease = ArtifactLease::Acquire(path);
        if (!fs::create_directory(path)) throw std::runtime_error("Cannot create private probe workspace.");
    }
    ProbeWorkspace(const ProbeWorkspace&) = delete;
    ProbeWorkspace& operator=(const ProbeWorkspace&) = delete;
    ~ProbeWorkspace() {
        if (!succeeded) return;
        lease.reset();
        try {
            NativeArtifactStore::PruneCache(path.parent_path(), 0, 0, true,
                [&](const fs::path& candidate) { return candidate.filename() == path.filename(); });
        } catch (...) { /* A later bounded pass retries optional scratch cleanup. */ }
    }
};

ProbeWorkspace PrepareProbeWorkspace(const fs::path& parent) {
    fs::create_directories(parent);
    const DWORD attributes = GetFileAttributesW(parent.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("Capability probe root must be an ordinary directory.");
    // Bounds apply to released participating entries. Active and legacy state
    // remain protected even if their bytes exceed this soft quota.
    NativeArtifactStore::PruneCache(parent, 512ull * 1024 * 1024, 7ull * 24 * 60 * 60, true, ProbeEntry);
    return ProbeWorkspace(parent / NewOperationId());
}

bool RecordProbeOutput(const fs::path& scratch, const ProcessResult& result) {
    return AtomicFile::Publish(scratch / "stderr.log", result.std_err) &&
        AtomicFile::Publish(scratch / "stdout.log", result.std_out);
}

std::wstring HostEnvironmentValue(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    if (written >= size) return {};
    value.resize(written);
    return value;
}

std::string ProbeVersion(const fs::path& executable, const std::vector<std::wstring>& suffix = {L"--version"}) {
    if (executable.empty() || !fs::exists(executable)) return {};
    std::vector<std::wstring> args;
    args.push_back(executable.wstring());
    args.insert(args.end(), suffix.begin(), suffix.end());
    const ProcessResult result = Win32Process::Run(executable.wstring(), args);
    const std::string text = result.std_out + "\n" + result.std_err;
    std::smatch match;
    if (std::regex_search(text, match, std::regex("([0-9]+(?:\\.[0-9]+){1,3})")) && match.size() > 1) {
        return match[1].str();
    }
    return {};
}

std::string PathSafeVersion(std::string value, const std::string& fallback) {
    if (value.empty()) return fallback;
    for (char& c : value) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_')) c = '_';
    }
    return value;
}

std::string DetectSdkVersion(const fs::path& sdk) {
    for (const auto& file : {sdk / "SDKSettings.json", sdk / "SDKSettings.plist"}) {
        std::ifstream input(file, std::ios::binary);
        if (!input) continue;
        const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        for (const auto& expression : {
                 std::regex("\\\"Version\\\"\\s*:\\s*\\\"([0-9]+(?:\\.[0-9]+)*)\\\""),
                 std::regex("<key>Version</key>\\s*<string>([0-9]+(?:\\.[0-9]+)*)</string>"),
                 std::regex("<key>CanonicalName</key>\\s*<string>[^0-9]*([0-9]+(?:\\.[0-9]+)*)</string>")}) {
            std::smatch match;
            if (std::regex_search(text, match, expression) && match.size() > 1) return match[1].str();
        }
    }
    return {};
}

std::string DetectXcodeVersion(const fs::path& xcode) {
    for (const auto& file : {
             xcode / "Contents" / "version.plist",
             xcode / "Contents" / "Info.plist"}) {
        std::ifstream input(file, std::ios::binary);
        if (!input) continue;
        const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        for (const auto& expression : {
                 std::regex("<key>CFBundleShortVersionString</key>\\s*<string>([0-9]+(?:\\.[0-9]+)*)</string>"),
                 std::regex("<key>ProductVersion</key>\\s*<string>([0-9]+(?:\\.[0-9]+)*)</string>"),
                 std::regex(R"(\"CFBundleShortVersionString\"\s*:\s*\"([0-9]+(?:\.[0-9]+)*)\")")}) {
            std::smatch match;
            if (std::regex_search(text, match, expression) && match.size() > 1) return match[1].str();
        }
    }
    return "current";
}

std::string MajorVersion(const std::string& value) {
    if (value.empty()) return "current";
    const std::size_t dot = value.find('.');
    return dot == std::string::npos ? value : value.substr(0, dot);
}


bool SwiftHostManifestSmokeTest(const fs::path& swift_bin) {
    if (swift_bin.empty() || !fs::exists(swift_bin / "swift.exe")) return false;

    const auto platform = EnvironmentManager::ResolveSwiftHostPlatform(swift_bin);
    if (platform.runtime_bin.empty() || platform.windows_sdk.empty()) return false;
    const std::wstring inherited_path = HostEnvironmentValue(L"PATH");
    std::wstring child_path = platform.runtime_bin.wstring();
    if (!inherited_path.empty()) child_path += L";" + inherited_path;

    const std::size_t key = std::hash<std::wstring>{}(fs::absolute(swift_bin).lexically_normal().wstring());
    const fs::path root = ToolPaths::UserStateRoot() / "state" / "swift-host-smoke" / std::to_string(key);
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) return false;

    ProcessRunOptions controls;
    controls.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    std::shared_ptr<ArtifactLease> lease;
    try { lease = ArtifactLease::Acquire(root, controls); }
    catch (...) { return false; }
    const fs::path manifest = root / "Package.swift";
    const std::string expected = "// swift-tools-version: 6.0\nimport PackageDescription\n"
                                 "let package = Package(name: \"OPENFRUITBootstrapSmoke\")\n";
    std::ifstream input(manifest, std::ios::binary);
    const std::string existing{std::istreambuf_iterator<char>(input), {}};
    input.close();
    if (existing != expected && !AtomicFile::Publish(manifest, expected)) return false;

    const fs::path swift = swift_bin / "swift.exe";
    const ProcessResult result = Win32Process::Run(
        swift.wstring(),
        {swift.wstring(), L"package", L"--package-path", root.wstring(), L"dump-package"},
        root.wstring(), {{L"SDKROOT", platform.windows_sdk.wstring()}, {L"PATH", child_path}},
        nullptr, nullptr, controls
    );
    { std::ofstream diagnostics(root / "stderr.log", std::ios::binary | std::ios::trunc);
      if (diagnostics) diagnostics << result.std_err; }
    return result.success;
}


bool IsSourceSwiftToolchainUsable(const fs::path& swift_bin) {
    if (swift_bin.empty()) return false;
    std::error_code ec;
    for (const auto& exe : {"swift.exe", "swiftc.exe", "clang.exe", "llvm-ar.exe", "llvm-readobj.exe"}) {
        ec.clear();
        if (!fs::is_regular_file(swift_bin / exe, ec) || ec) return false;
    }
    return true;
}

void MarkManagedSwiftRelocatable(const fs::path& managed_root, bool good) {
    const fs::path marker = managed_root / ".OPENFRUIT-relocatable-ok";
    std::error_code ec;
    if (!good) {
        fs::remove(marker, ec);
        return;
    }
    std::ofstream out(marker, std::ios::binary | std::ios::trunc);
    if (out) out << "OPENFRUIT-swift-relocatable-v1\n";
}

bool IsUnder(const fs::path& child, const fs::path& parent) {
    std::error_code ec1, ec2;
    const fs::path c = fs::weakly_canonical(child, ec1);
    const fs::path p = fs::weakly_canonical(parent, ec2);
    if (ec1 || ec2) return false;
    auto ci = c.begin();
    auto pi = p.begin();
    for (; pi != p.end(); ++pi, ++ci) {
        if (ci == c.end()) return false;
        std::wstring a = ci->wstring(), b = pi->wstring();
        std::transform(a.begin(), a.end(), a.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        std::transform(b.begin(), b.end(), b.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        if (a != b) return false;
    }
    return true;
}

bool RunWingetInstall(const std::string& id, const std::wstring& custom = {},
    const std::string& version = {}, bool force = false) {
    const fs::path winget = ToolPaths::FindOnPath(L"winget.exe");
    if (winget.empty()) return false;
    std::cout << "OPENFRUIT bootstrap: installing " << id << " using WinGet..." << std::endl;
    std::vector<std::wstring> arguments{winget.wstring(), L"install", L"--id", Win32Process::ToWide(id), L"-e",
        L"--source", L"winget", L"--accept-package-agreements", L"--accept-source-agreements", L"--silent"};
    if (!custom.empty()) { arguments.push_back(L"--custom"); arguments.push_back(custom); }
    if (!version.empty()) { arguments.push_back(L"--version"); arguments.push_back(Win32Process::ToWide(version)); }
    if (force) arguments.push_back(L"--force");
    const ProcessResult result = Win32Process::Run(winget.wstring(), arguments);
    return result.success;
}

fs::path FindSwiftBinCandidate(const fs::path& repo_root, const Config& config) {
    const fs::path managed_root = ToolPaths::LocalHome() / "toolchains" / "swift";

    if (!config.toolchain_path.empty() && !ToolPaths::IsImportScratchPath(config.toolchain_path) && fs::exists(config.toolchain_path)) {
        const fs::path configured(config.toolchain_path);
        if (IsUnder(configured, managed_root)) {
            // A managed/copy-relocated Swift installation is usable only if it
            // can actually compile and execute a host Package.swift manifest.
            if (ToolPaths::IsPublishedSwiftBin(configured) && SwiftHostManifestSmokeTest(configured)) return configured;
        } else if (IsSourceSwiftToolchainUsable(configured)) {
            // External/patched cross toolchains are valid sources even though
            // their host runtime is supplied separately by SwiftPMEnvironment.
            return configured;
        }
    }

    const fs::path discovered = ToolPaths::SwiftBin(repo_root);
    if (discovered.empty()) return {};
    if (IsUnder(discovered, managed_root)) {
        return ToolPaths::IsPublishedSwiftBin(discovered) && SwiftHostManifestSmokeTest(discovered) ? discovered : fs::path{};
    }
    return IsSourceSwiftToolchainUsable(discovered) ? discovered : fs::path{};
}

fs::path FindLlvmBinCandidate(const fs::path& repo_root, const Config& config) {
    if (!config.llvm_path.empty() && !ToolPaths::IsImportScratchPath(config.llvm_path) && fs::exists(config.llvm_path)) return fs::path(config.llvm_path);
    return ToolPaths::LlvmBin(repo_root);
}

void AddStatus(BootstrapResult& result, DependencyStatus status) {
    result.dependencies.push_back(std::move(status));
}

void SaveSdkOrigin(const std::string& slot, const fs::path& source) {
    if (slot.empty() || source.empty()) return;
    const fs::path file = ToolPaths::UserStateRoot() / "state" / "sdk-origin" / (slot + ".path");
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    if (ec) return;
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) return;
    out << Win32Process::ToNarrow(source.wstring()) << "\n";
}

void WriteInstalledManifest(const Config& config, const BootstrapResult& result) {
    const fs::path manifest = fs::path(config.OPENFRUIT_home) / "manifests" / "installed.json";
    std::error_code ec;
    fs::create_directories(manifest.parent_path(), ec);
    std::ofstream out(manifest, std::ios::binary | std::ios::trunc);
    if (!out) return;
    out << "{\n  \"schema\": 1,\n  \"dependencies\": [\n";
    for (std::size_t i = 0; i < result.dependencies.size(); ++i) {
        const auto& d = result.dependencies[i];
        auto esc = [](std::string value) {
            std::string out;
            for (char c : value) { if (c == '\\' || c == '"') out.push_back('\\'); out.push_back(c); }
            return out;
        };
        out << "    {\"name\":\"" << esc(d.name) << "\",\"scope\":\"" << esc(d.scope)
            << "\",\"available\":" << (d.available ? "true" : "false")
            << ",\"version\":\"" << esc(d.version) << "\",\"path\":\""
            << esc(Win32Process::ToNarrow(d.path.wstring())) << "\"}" << (i + 1 == result.dependencies.size() ? "" : ",") << "\n";
    }
    out << "  ]\n}\n";
}

} // namespace

SwiftHostPlatform EnvironmentManager::ResolveSwiftHostPlatform(const fs::path& swift_bin) {
    SwiftHostPlatform result;
    if (swift_bin.empty()) return result;
    std::error_code ec;
    const auto bin = fs::absolute(swift_bin, ec).lexically_normal();
    if (ec) return result;
    const fs::path compiler = bin / "swiftc.exe";
    if (!fs::is_regular_file(compiler, ec) || ec) return result;
    ProcessRunOptions controls;
    controls.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    const auto probe = Win32Process::Run(compiler.wstring(),
        {compiler.wstring(), L"--version"}, {}, {}, nullptr, nullptr, controls);
    if (!probe.success) return result;
    std::smatch match;
    if (!std::regex_search(probe.std_out, match,
            std::regex(R"(Swift version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?)"))) return result;
    const auto parse = [](const std::string& value, std::array<int, 3>& version) {
        std::smatch found;
        if (!std::regex_search(value, found, std::regex(R"(^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?)"))) return false;
        try {
            version = {std::stoi(found[1].str()), std::stoi(found[2].str()),
                       found[3].matched ? std::stoi(found[3].str()) : 0};
        } catch (...) { return false; }
        return true;
    };
    std::array<int, 3> required{};
    if (!parse(match[0].str().substr(std::string("Swift version ").size()), required)) return result;

    // The original installer uses sibling Toolchains/Runtimes/Platforms trees.
    // A managed toolchain mirror can still consume the registered source runtime.
    std::vector<fs::path> installations = {
        bin.parent_path().parent_path().parent_path().parent_path()};
    const auto local = HostEnvironmentValue(L"LOCALAPPDATA");
    if (!local.empty()) installations.push_back(fs::path(local) / "Programs" / "Swift");
    std::set<fs::path> seen;
    std::array<int, 3> best{-1, -1, -1};
    for (const auto& installation : installations) {
        if (!seen.insert(installation.lexically_normal()).second) continue;
        const fs::path runtimes = installation / "Runtimes";
        ec.clear();
        if (!fs::is_directory(runtimes, ec) || ec) continue;
        for (fs::directory_iterator it(runtimes, ec), end; !ec && it != end; it.increment(ec)) {
            std::array<int, 3> version{};
            if (!parse(Win32Process::ToNarrow(it->path().filename().wstring()), version) ||
                version[0] != required[0] || version[1] != required[1] || version <= best) continue;
            const auto runtime = it->path() / "usr" / "bin";
            const auto sdk = installation / "Platforms" / it->path().filename() /
                "Windows.platform" / "Developer" / "SDKs" / "Windows.sdk";
            std::error_code entry_ec;
            if (!fs::is_regular_file(runtime / "swiftCore.dll", entry_ec) || entry_ec ||
                !fs::is_directory(sdk, entry_ec) || entry_ec) continue;
            result = {runtime, sdk};
            best = version;
        }
    }
    return result;
}

bool EnvironmentManager::ValidateSwiftHostToolchain(const fs::path& swift_bin) {
    return SwiftHostManifestSmokeTest(swift_bin);
}

bool EnvironmentManager::EnsureCompatibleLlvm(Config& config, const fs::path& sdk,
    const std::wstring& deployment, const std::wstring& architecture,
    bool attempt_install, std::string& error) {
    error.clear();
    if (!SDKCatalog::HasUsableLayout(sdk) ||
        !std::regex_match(deployment, std::wregex(L"[0-9]+(\\.[0-9]+){0,2}")) ||
        (architecture != L"arm64" && architecture != L"arm64e")) {
        error = "Invalid SDK, deployment target or architecture for LLVM validation.";
        return false;
    }
    const std::string sdk_version = DetectSdkVersion(sdk);
    if (sdk_version.empty()) { error = "Original SDK version metadata is missing."; return false; }
    auto validate = [&](const fs::path& bin) {
        const fs::path linker = bin / "ld64.lld.exe";
        if (!fs::is_regular_file(linker)) { error = "LLVM ld64.lld is missing."; return false; }
        try {
            auto workspace = PrepareProbeWorkspace(ToolPaths::CacheRoot() / "llvm-sdk-probes");
            const fs::path scratch = workspace.path;
            const fs::path output = scratch / "probe.dylib";
            ProcessRunOptions controls;
            controls.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            const auto result = Win32Process::Run(linker.wstring(), {
                linker.wstring(), L"-dylib", L"-arch", architecture, L"-platform_version", L"ios",
                deployment, Win32Process::ToWide(sdk_version), L"-syslibroot", sdk.wstring(),
                L"-lSystem", L"-o", output.wstring()
            }, scratch.wstring(), {}, nullptr, nullptr, controls);
            if (!RecordProbeOutput(scratch, result)) { error = "Cannot retain LLVM probe diagnostics."; return false; }
            unsigned char header[4]{};
            std::ifstream binary(output, std::ios::binary);
            binary.read(reinterpret_cast<char*>(header), sizeof(header));
            if (!result.success || result.timed_out || binary.gcount() != 4 ||
                header[0] != 0xcf || header[1] != 0xfa || header[2] != 0xed || header[3] != 0xfe) {
                error = "Original SDK TAPI validation failed; diagnostics: " +
                    (scratch / "stderr.log").string() + "\n" + result.std_err;
                return false;
            }
            error.clear();
            workspace.succeeded = true;
            return true;
        } catch (const std::exception& failure) { error = failure.what(); return false; }
    };
    // Once a validated toolchain is published, the downloaded release archives
    // are only re-extraction sources and are discarded with their markers.
    const auto discard_archives = [] {
        for (const auto* archive : {L"7e69dc07a4536b79ff24a651a2611990bf8eaab17ea560f1092707c4f31ba01d.tar.zst",
                                    L"9ee6a2192fbb30c776415af529927f76ca6b5d1d55699bb1315f9878e610b5b8.tar.xz"}) {
            std::error_code ignored;
            const auto path = ToolPaths::CacheRoot() / "llvm-downloads" / archive;
            if (fs::remove(path, ignored) || !fs::exists(path, ignored))
                for (const auto* marker : {L".import-lock", L".transfer-lock"})
                    fs::remove(fs::path(path.wstring() + marker), ignored);
        }
    };
    const fs::path current = FindLlvmBinCandidate({}, config);
    if (validate(current)) { discard_archives(); return true; }
    const bool missing = !fs::is_regular_file(current / "ld64.lld.exe");
    if (!attempt_install || !config.bootstrap_auto_install ||
        (!missing && error.find("unknown architecture") == std::string::npos)) return false;
#if defined(_M_X64) || defined(__x86_64__)
    // Pinned upstream release containing the arm64e.x1 TextAPI fix. Hashes
    // come from the official llvm/llvm-project release asset digest.
    const fs::path managed = fs::path(config.OPENFRUIT_home) / "toolchains" / "llvm" / "23.1.3";
    const fs::path bin = managed / "bin";
    if (!validate(bin)) {
        try {
            const bool acquired = [&]() -> bool {
                // Archive identity is immutable content, while each extraction is private.
                // Keep the archive lease until publication and linker validation finish.
                auto workspace = PrepareProbeWorkspace(ToolPaths::CacheRoot() / "llvm-acquisition");
                const fs::path scratch = workspace.path;
                const fs::path archives = ToolPaths::CacheRoot() / "llvm-downloads";
                fs::create_directories(archives);
                const DWORD attributes = GetFileAttributesW(archives.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
                    (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    error = "LLVM archive cache must be an ordinary directory."; return false;
                }
                TransferRequest request;
                request.reuse_verified_destination = true;
                request.url = L"https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/clang%2Bllvm-23.1.3-x86_64-pc-windows-msvc.tar.zst";
                request.expected_sha256 = "7e69dc07a4536b79ff24a651a2611990bf8eaab17ea560f1092707c4f31ba01d";
                request.destination = archives / (request.expected_sha256 + ".tar.zst");
                request.max_bytes = 276320456;
                request.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
                ProcessRunOptions archive_controls;
                archive_controls.deadline = request.deadline;
                auto archive_lease = ArtifactLease::Acquire(request.destination, archive_controls);
                // Another owner may have completed publication while this caller waited.
                if (!validate(bin)) {
                    std::cout << "OPENFRUIT: acquiring verified LLVM23.1.3 for original SDK TAPI support..." << std::endl;
                    const auto transfer = HttpTransfer::Download(request);
                    if (!transfer.Succeeded()) { error = "Verified LLVM download failed (HTTP " + std::to_string(transfer.http_status) + ")."; return false; }
                    const fs::path extracted = scratch / "extracted";
                    if (!ArchiveShim::ExtractArchiveCompat(request.destination, extracted)) {
                        // Some Windows libarchive builds reject the release's zstd window
                        // even though zstd is supported. Use the identical upstream xz
                        // package, in a distinct extraction directory and with its own hash.
                        request.url = L"https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/clang%2Bllvm-23.1.3-x86_64-pc-windows-msvc.tar.xz";
                        request.expected_sha256 = "9ee6a2192fbb30c776415af529927f76ca6b5d1d55699bb1315f9878e610b5b8";
                        request.destination = archives / (request.expected_sha256 + ".tar.xz");
                        request.max_bytes = 901331280;
                        request.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
                        archive_controls.deadline = request.deadline;
                        archive_lease.reset();
                        archive_lease = ArtifactLease::Acquire(request.destination, archive_controls);
                        if (validate(bin)) { workspace.succeeded = true; return true; }
                        std::cout << "OPENFRUIT: using verified upstream LLVM xz archive after zstd extraction failure..." << std::endl;
                        if (!HttpTransfer::Download(request).Succeeded() ||
                            !ArchiveShim::ExtractArchiveCompat(request.destination, scratch / "extracted-xz")) {
                            error = "Verified LLVM xz acquisition or system archive extraction failed.";
                            return false;
                        }
                    }
                    const fs::path extraction_root = request.destination.extension() == ".xz"
                        ? scratch / "extracted-xz" : extracted;
                    fs::path source;
                    if (fs::is_regular_file(extraction_root / "bin" / "ld64.lld.exe")) source = extraction_root;
                    else for (const auto& entry : fs::directory_iterator(extraction_root)) {
                        if (entry.is_directory() && fs::is_regular_file(entry.path() / "bin" / "ld64.lld.exe")) {
                            if (!source.empty()) { error = "Ambiguous LLVM archive roots."; return false; }
                            source = entry.path();
                        }
                    }
                    if (source.empty() || !NativeArtifactStore::ImportTreeTransactional(source, managed,
                            [&](const fs::path& root) { return validate(root / "bin"); })) {
                        if (error.empty()) error = "Managed LLVM transactional publication failed.";
                        return false;
                    }
                }
                // Publication validated the real linker before discarding private scratch.
                workspace.succeeded = true;
                return true;
            }();
            if (!acquired) return false;
        } catch (const std::exception& failure) { error = failure.what(); return false; }
    }
    if (!validate(bin)) return false;
    discard_archives();
    config.llvm_path = bin.wstring();
    // Update both consumers: AppBuilder resolves ToolPaths from the process
    // environment, while later invocations reload the persisted configuration.
    SetEnvironmentVariableW(L"OPENFRUIT_LLVM_BIN", config.llvm_path.c_str());
    std::cout << "OPENFRUIT: validated native LLVM " << ProbeVersion(bin / "ld64.lld.exe")
              << " against original SDK " << sdk_version << "." << std::endl;
    return true;
#else
    error = "Automatic verified LLVM acquisition is currently available for Windows x64 hosts.";
    return false;
#endif
}

fs::path EnvironmentManager::SelectSwiftToolchain(
    const Config& config, const std::wstring& compiler_version,
    const std::wstring& sdk_compatibility_probe, const std::wstring& deployment_target) {
    const std::string required = Win32Process::ToNarrow(compiler_version);
    std::smatch requested;
    if (!std::regex_match(required, requested,
            std::regex(R"(([0-9]+)\.([0-9]+)(?:\.([0-9]+))?)"))) return {};
    const int major = std::stoi(requested[1].str());
    const int minor = std::stoi(requested[2].str());
    const bool exact_patch = requested[3].matched;
    const int patch = exact_patch ? std::stoi(requested[3].str()) : 0;

    std::vector<fs::path> candidates;
    const fs::path managed_root = ToolPaths::LocalHome() / "toolchains" / "swift";
    auto add_tree = [&](const fs::path& root) {
        std::error_code ec;
        if (!fs::is_directory(root, ec) || ec) return;
        for (fs::directory_iterator it(root, ec), end; !ec && it != end;
             it.increment(ec)) {
            if (it->is_directory(ec) && !ec)
                candidates.push_back(it->path() / "usr" / "bin");
            ec.clear();
        }
    };
    add_tree(managed_root);
    if (!config.toolchain_path.empty()) candidates.push_back(config.toolchain_path);
    wchar_t local_data[MAX_PATH] = {};
    const DWORD local_length = GetEnvironmentVariableW(L"LOCALAPPDATA", local_data, MAX_PATH);
    if (local_length > 0 && local_length < MAX_PATH)
        add_tree(fs::path(local_data) / "Programs" / "Swift" / "Toolchains");

    fs::path best;
    int best_patch = -1;
    bool best_development = false;
    bool best_no_asserts = false;
    std::set<fs::path> seen;
    for (const auto& candidate : candidates) {
        if (ToolPaths::IsImportScratchPath(candidate)) continue;
        if (!seen.insert(candidate.lexically_normal()).second ||
            !IsSourceSwiftToolchainUsable(candidate)) continue;
        if (IsUnder(candidate, managed_root) &&
            (!ToolPaths::IsPublishedSwiftBin(candidate) || !SwiftHostManifestSmokeTest(candidate))) continue;
        const auto compiler = candidate / "swiftc.exe";
        const ProcessResult probe = Win32Process::Run(
            compiler.wstring(), {compiler.wstring(), L"--version"});
        if (!probe.success) continue;
        const std::string text = probe.std_out + "\n" + probe.std_err;
        std::smatch found;
        if (!std::regex_search(text, found,
                std::regex(R"(Swift version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(-dev)?)")) ||
            std::stoi(found[1].str()) != major ||
            std::stoi(found[2].str()) != minor) continue;
        const bool development = found[4].matched;
        if (development && (sdk_compatibility_probe.empty() || deployment_target.empty())) continue;
        const int candidate_patch = found[3].matched ? std::stoi(found[3].str()) : 0;
        const bool no_asserts = ToolPaths::SwiftAssertions(candidate) == SwiftToolchainAssertions::Disabled;
        if (exact_patch && candidate_patch != patch) continue;
        if (!best.empty() && ((!best_development && development) ||
            (best_development == development && (candidate_patch < best_patch ||
                (candidate_patch == best_patch && (!no_asserts || best_no_asserts)))))) continue;
        if (development) {
            // An SDK's required version is not evidence that a particular
            // development snapshot can parse it. Exercise the actual compiler
            // and original SDK with a fresh, isolated cache before selection.
            try {
                auto workspace = PrepareProbeWorkspace(ToolPaths::CacheRoot() / "compiler-sdk-probes");
                const fs::path scratch = workspace.path;
                const fs::path source = scratch / "ImportSwift.swift";
                { std::ofstream input(source); input << "import Swift\n"; if (!input) continue; }
                ProcessRunOptions controls;
                controls.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
                const auto validation = Win32Process::Run(compiler.wstring(), {
                    compiler.wstring(), L"-target", L"arm64-apple-ios" + deployment_target, L"-sdk", sdk_compatibility_probe,
                    L"-module-cache-path", (scratch / "modules").wstring(), L"-typecheck", source.wstring()
                }, scratch.wstring(), {}, nullptr, nullptr, controls);
                if (!RecordProbeOutput(scratch, validation) || !validation.success || validation.timed_out) continue;
                workspace.succeeded = true;
            } catch (const std::exception&) { continue; }
        }
        best = candidate;
        best_patch = candidate_patch;
        best_development = development;
        best_no_asserts = no_asserts;
    }
    return best;
}

bool EnvironmentManager::EnsureManagedLayout() {
    const fs::path local = ToolPaths::LocalHome();
    const fs::path user = ToolPaths::UserStateRoot();

    // Check if managed layout was placed in a package-virtualized LocalCache
    // (e.g. when run inside a packaged container like Codex or an MSIX app).
    // If local/sdk is missing or empty, search LocalAppData/Packages/*/LocalCache/Local/OPENFRUIT.
    std::error_code ec;
    const fs::path packages = local.parent_path() / "Packages";
    if (fs::is_directory(packages, ec)) {
        for (fs::directory_iterator it(packages, ec), end; !ec && it != end; it.increment(ec)) {
            if (!it->is_directory(ec)) continue;
            const fs::path virtual_OPENFRUIT = it->path() / "LocalCache" / "Local" / "OPENFRUIT";
            if (!fs::is_directory(virtual_OPENFRUIT, ec)) continue;

            auto merge_tree = [](auto& self, const fs::path& s, const fs::path& d) -> void {
                std::error_code m_ec;
                fs::create_directories(d, m_ec);
                for (fs::directory_iterator s_it(s, m_ec), s_end; !m_ec && s_it != s_end; s_it.increment(m_ec)) {
                    const fs::path src_item = s_it->path();
                    const fs::path dst_item = d / src_item.filename();
                    if (s_it->is_directory(m_ec)) {
                        self(self, src_item, dst_item);
                    } else if (!fs::exists(dst_item, m_ec)) {
                        m_ec.clear();
                        fs::rename(src_item, dst_item, m_ec);
                        if (m_ec) {
                            m_ec.clear();
                            fs::copy_file(src_item, dst_item, fs::copy_options::overwrite_existing, m_ec);
                        }
                    }
                    m_ec.clear();
                }
            };
            merge_tree(merge_tree, virtual_OPENFRUIT, local);
            break;
        }
    }

    const std::vector<fs::path> dirs = {
        local / "bin", local / "bin" / "signing", local / "sdk" / "ios",
        local / "sdk" / "macos", local / "sdk" / "xcode", local / "toolchains" / "swift",
        local / "toolchains" / "llvm", local / "toolchains" / "git", local / "toolchains" / "device", local / "toolchains" / "darling",
        local / "toolchains" / "asset-compiler" / "bin",
        local / "downloads", local / "manifests", local / "logs",
        user / "cache", user / "cache" / "swiftpm", user / "cache" / "compiler-rt",
        user / "cache" / "modules", user / "cache" / "artifacts", user / "cache" / "build",
        user / "credentials", user / "certificates", user / "state"
    };
    ec.clear();
    for (const auto& dir : dirs) {
        fs::create_directories(dir, ec);
        if (ec) return false;
    }
    EnsureAssetCompiler();
    return true;
}

namespace {
// Builds the asset compiler package with the selected Windows Swift toolchain
// and returns a self-contained bundle (executable, package DLLs/resources and
// the matching Swift host runtime). The package's Patches/<Package>-<version>-
// *.patch files are applied to that dependency's checkout first, idempotently.
fs::path BuildAssetCompilerBundle(const fs::path& source,
                                  std::vector<std::pair<std::wstring, std::wstring>> environment) {
    const auto swift_bin = ToolPaths::SwiftBin({});
    const auto host = EnvironmentManager::ResolveSwiftHostPlatform(swift_bin);
    if (swift_bin.empty() || host.runtime_bin.empty()) return {};
    const auto root = ToolPaths::CacheRoot() / "asset-compiler-build";
    const auto scratch = root / "scratch", bundle = root / "bundle";
    std::error_code ec;
    fs::create_directories(scratch, ec);
    // The toolchain's own tools come first; the host environment supplies the
    // matching runtime and the Windows SDK projected for the installed UCRT.
    for (auto& [name, value] : environment)
        if (_wcsicmp(name.c_str(), L"PATH") == 0) value = swift_bin.wstring() + L";" + value;
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(30);
    const auto swift = (swift_bin / "swift.exe").wstring();
    const std::vector<std::wstring> common = {L"--package-path", source.wstring(), L"--scratch-path", scratch.wstring()};
    const auto run = [&](std::vector<std::wstring> arguments) {
        arguments.insert(arguments.begin(), swift);
        arguments.insert(arguments.end(), common.begin(), common.end());
        const auto result = Win32Process::Run(swift, arguments, source.wstring(), environment, nullptr, nullptr, options);
        if (!result.success) std::cerr << "OPENFRUIT: asset compiler build step failed:\n" << result.std_err << result.std_out << '\n';
        return result;
    };
    std::cout << "OPENFRUIT: building the native asset catalog compiler from source...\n" << std::flush;
    if (!run({L"package", L"resolve"}).success) return {};
    const auto git = ToolPaths::Git();
    for (fs::directory_iterator it(source / "Patches", ec), end; !ec && it != end; it.increment(ec)) {
        if (it->path().extension() != L".patch") continue;
        const auto name = it->path().stem().wstring();
        const auto checkout = scratch / "checkouts" / name.substr(0, name.find(L'-'));
        if (!fs::is_directory(checkout)) return {};
        const auto patch = it->path().wstring();
        const auto applied = Win32Process::Run(git.wstring(),
            {git.wstring(), L"-C", checkout.wstring(), L"apply", L"--reverse", L"--check", patch}, {}, {}, nullptr, nullptr, options);
        if (applied.success) continue;
        if (!Win32Process::Run(git.wstring(), {git.wstring(), L"-C", checkout.wstring(), L"apply", patch},
                {}, {}, nullptr, nullptr, options).success) {
            std::cerr << "OPENFRUIT: asset compiler dependency patch did not apply: " << Win32Process::ToNarrow(patch) << '\n';
            return {};
        }
    }
    // The managed toolchain is not an installation layout with Toolchains/ and
    // Platforms/, which the SwiftBuild backend requires; use SwiftPM's native
    // build system, as package builds do.
    if (!run({L"build", L"-c", L"release", L"--build-system", L"native", L"--product", L"OPENFRUIT-asset-compiler"}).success) return {};
    const auto bin = run({L"build", L"-c", L"release", L"--build-system", L"native", L"--show-bin-path"});
    std::string bin_text = bin.std_out;
    while (!bin_text.empty() && (bin_text.back() == '\n' || bin_text.back() == '\r')) bin_text.pop_back();
    const fs::path products(Win32Process::ToWide(bin_text));
    if (!bin.success || !fs::is_regular_file(products / "OPENFRUIT-asset-compiler.exe", ec)) return {};
    fs::remove_all(bundle, ec);
    fs::create_directories(bundle, ec);
    if (ec) return {};
    for (const auto& entry : fs::directory_iterator(products)) {
        const auto extension = entry.path().extension().wstring();
        if (entry.path().filename() == L"OPENFRUIT-asset-compiler.exe" || extension == L".dll")
            fs::copy_file(entry.path(), bundle / entry.path().filename(), fs::copy_options::overwrite_existing);
        else if (entry.is_directory() && extension == L".resources")
            fs::copy(entry.path(), bundle / entry.path().filename(), fs::copy_options::recursive);
    }
    for (const auto& entry : fs::directory_iterator(host.runtime_bin))
        if (entry.path().extension() == L".dll")
            fs::copy_file(entry.path(), bundle / entry.path().filename(), fs::copy_options::skip_existing);
    return bundle;
}
}

bool EnvironmentManager::EnsureAssetCompiler(const fs::path& repo_root,
    const std::vector<std::pair<std::wstring, std::wstring>>* build_environment) {
    const fs::path managed_bin = ToolPaths::LocalHome() / "toolchains" / "asset-compiler" / "bin";
    // Consume a complete host bundle. Never guess a runtime from another Swift
    // installation merely because it happens to contain swiftCore.dll.
    const auto validate = [&](const fs::path& directory) {
        const auto executable = directory / "OPENFRUIT-asset-compiler.exe";
        std::error_code ec;
        if (!fs::is_regular_file(executable, ec) || ec) return false;
        ProcessRunOptions options;
        options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        options.capture_limit_bytes = 64 * 1024;
        if (const auto context = CurrentOperationContext(); context && context->control) {
            options.deadline = std::min(options.deadline, context->control->deadline);
            options.cancellation = std::shared_ptr<std::atomic<bool>>(context->control,
                &context->control->cancellation_requested);
        }
        wchar_t system_directory[MAX_PATH]{};
        if (!GetSystemDirectoryW(system_directory, MAX_PATH)) return false;
        const std::vector<std::pair<std::wstring, std::wstring>> environment = {
            {L"PATH", directory.wstring() + L";" + system_directory}
        };
        const auto capabilities = Win32Process::Run(executable.wstring(),
            {executable.wstring(), L"--capabilities"}, L"", environment,
            nullptr, nullptr, options);
        const auto metadata = JsonValue::Parse(capabilities.std_out);
        if (!capabilities.success || capabilities.output_truncated || !metadata ||
            metadata->GetString("schema") != "openfruit.asset-compiler.v1" ||
            metadata->GetString("svg_backend") != "resvg" ||
            metadata->GetString("svg_warning_policy") != "error" ||
            metadata->GetString("other_platform_layered_images") != "skipped" ||
            metadata->GetString("photoshop_composites") != "decoded" ||
            metadata->GetString("alternate_app_icons") != "partial_info_plist" ||
            metadata->GetString("icon_composer_documents") != "flattened_static_layers" ||
            !metadata->Get("native_windows") || !metadata->Get("native_windows")->Bool()) return false;
        try {
            auto workspace = PrepareProbeWorkspace(ToolPaths::CacheRoot() / "asset-compiler-probes");
            const auto scratch = workspace.path;
            const auto catalog = scratch / "Probe.xcassets";
            const auto color = catalog / "Probe.colorset";
            const auto output = scratch / "output";
            fs::create_directories(color);
            fs::create_directories(output);
            std::ofstream(color / "Contents.json") << R"({"info":{"author":"xcode","version":1},"colors":[{"idiom":"universal","color":{"color-space":"srgb","components":{"red":"0.1","green":"0.2","blue":"0.3","alpha":"1.0"}}}]})";
            const auto compiled = Win32Process::Run(executable.wstring(),
                {executable.wstring(), L"--output-directory", output.wstring(),
                 L"--deployment-target", L"15.0", catalog.wstring()},
                scratch.wstring(), environment, nullptr, nullptr, options);
            if (!RecordProbeOutput(scratch, compiled)) return false;
            std::ifstream file(output / "Assets.car", std::ios::binary);
            char magic[8]{};
            file.read(magic, sizeof(magic));
            const bool valid = compiled.success && !compiled.output_truncated &&
                file.gcount() == sizeof(magic) && std::string(magic, sizeof(magic)) == "BOMStore";
            workspace.succeeded = valid;
            return valid;
        } catch (...) { return false; }
    };
    // The source build's SwiftPM scratch and bundle only feed one import.
    const auto discard_build = [] { std::error_code ignored; fs::remove_all(ToolPaths::CacheRoot() / "asset-compiler-build", ignored); };
    try {
        if (validate(managed_bin)) { discard_build(); return true; }
        std::vector<fs::path> candidates;
        std::error_code ec;
        for (const auto& root : {repo_root, fs::current_path(ec)}) {
            if (root.empty()) continue;
            candidates.push_back(root / "build" / "OPENFRUIT-core-v4" / "asset-compiler" /
                "out" / "Products" / "Release-windows-x86_64");
            candidates.push_back(root / "native" / "asset-compiler" / ".build" /
                "out" / "Products" / "Release-windows-x86_64");
        }
        for (const auto& directory : candidates) {
            if (validate(directory) && NativeArtifactStore::ImportTreeTransactional(
                    directory, managed_bin, validate)) return true;
        }
        // No prebuilt bundle: build the OPENFRUIT-owned source package with the
        // selected Windows Swift toolchain, then import it like any candidate.
        for (const auto& root : {repo_root, fs::current_path(ec)}) {
            if (!build_environment) break;
            if (root.empty() || !fs::is_regular_file(root / "native" / "asset-compiler" / "Package.swift", ec)) continue;
            const auto bundle = BuildAssetCompilerBundle(root / "native" / "asset-compiler", *build_environment);
            if (!bundle.empty() && validate(bundle) &&
                NativeArtifactStore::ImportTreeTransactional(bundle, managed_bin, validate)) { discard_build(); return true; }
            break;
        }
    } catch (const std::exception& error) {
        std::cerr << "OPENFRUIT: asset compiler installation failed: " << error.what() << '\n';
        return false;
    } catch (...) { return false; }
    return false;
}

BootstrapResult EnvironmentManager::CheckAndBootstrap(
    const fs::path& repo_root,
    Config& config,
    bool attempt_install,
    bool verbose
) {
    BootstrapResult result;

    if (config.OPENFRUIT_home.empty()) config.OPENFRUIT_home = ToolPaths::LocalHome().wstring();
    if (config.user_state_root.empty()) config.user_state_root = ToolPaths::UserStateRoot().wstring();
    if (config.cache_root.empty()) config.cache_root = (fs::path(config.user_state_root) / "cache").wstring();
    config.ApplyEnvironment();

    if (!EnsureManagedLayout()) {
        std::cerr << "OPENFRUIT bootstrap: unable to create the managed OPENFRUIT directory layout." << std::endl;
        return result;
    }
    if (config.credentials_dir.empty()) config.credentials_dir = (ToolPaths::UserStateRoot() / "credentials").wstring();
    if (config.certificates_dir.empty()) config.certificates_dir = (ToolPaths::UserStateRoot() / "certificates").wstring();
    if (config.secrets_path.empty()) config.secrets_path = (fs::path(config.credentials_dir) / "secrets.json").wstring();

    // Keep a managed copy of the currently running OPENFRUIT executable when
    // bootstrap/build is allowed to mutate the managed installation. `doctor`
    // remains a read-mostly diagnostic operation.
    if (attempt_install) {
        wchar_t module_path[32768] = {};
        const DWORD module_len = GetModuleFileNameW(nullptr, module_path, static_cast<DWORD>(std::size(module_path)));
        if (module_len > 0 && module_len < std::size(module_path)) {
            NativeArtifactStore::ImportFile(fs::path(module_path), fs::path(config.OPENFRUIT_home) / "bin" / "OPENFRUIT.exe");
        }
    }

    // Git.
    fs::path git = !config.git_path.empty() && fs::exists(config.git_path)
        ? fs::path(config.git_path) : ToolPaths::Git();
    if (git.empty() && attempt_install && config.bootstrap_auto_install && RunWingetInstall("Git.Git")) {
        git = ToolPaths::Git();
    }
    if (attempt_install && !git.empty() && !IsUnder(git, fs::path(config.OPENFRUIT_home))) {
        const fs::path source_root = git.parent_path().parent_path();
        if (fs::is_directory(source_root)) {
            const std::string version = PathSafeVersion(ProbeVersion(git), "git");
            const fs::path managed_root = fs::path(config.OPENFRUIT_home) / "toolchains" / "git" / version;
            const fs::path relative_git = git.lexically_relative(source_root);
            const fs::path managed_git = managed_root / relative_git;
            if (!fs::exists(managed_git)) {
                std::size_t imported = 0;
                if (verbose) std::cout << "OPENFRUIT bootstrap: importing Git " << version << " into " << managed_root.string() << "..." << std::endl;
                if (NativeArtifactStore::ImportTree(source_root, managed_root, &imported) && verbose) {
                    std::cout << "OPENFRUIT bootstrap: Git imported (" << imported << " file aliases/copies)." << std::endl;
                }
            }
            if (fs::exists(managed_git)) git = managed_git;
        }
    }
    if (!git.empty()) config.git_path = git.wstring();
    AddStatus(result, {"Git", "build", !git.empty(), true, true, git, ProbeVersion(git), git.empty() ? "missing" : "ready"});

    // Swift cross toolchain. Import a discovered external toolchain into the
    // versioned OPENFRUIT home so subsequent builds do not depend on repo-local
    // `.tools` paths or on installer PATH propagation.
    fs::path swift_bin = FindSwiftBinCandidate(repo_root, config);
    if (!swift_bin.empty() && !config.toolchain_path.empty() &&
        fs::path(config.toolchain_path).lexically_normal() != swift_bin.lexically_normal() && verbose) {
        std::cout << "OPENFRUIT bootstrap: stale/non-relocatable Swift path ignored; using validated source cross toolchain: "
                  << swift_bin.string() << std::endl;
    }
    if (swift_bin.empty() && attempt_install && config.bootstrap_auto_install) {
        // Swift.org publishes the Windows toolchain through WinGet. OPENFRUIT
        // still validates the concrete executables below before declaring the
        // build environment ready.
        if (RunWingetInstall("Swift.Toolchain",
                L"OptionsInstallNoAssertsToolchain=1 OptionsIncludeNoAsserts=1"))
            swift_bin = ToolPaths::SwiftBin(repo_root);
    }
    // A stock Windows installer defaults to +Asserts, independently of the
    // application's Debug/Release setting. Prefer the original release variant
    // of the same compiler version, and acquire its optional installer feature
    // when bootstrap installation is permitted. Never alter compiler binaries.
    if (!swift_bin.empty() && ToolPaths::SwiftAssertions(swift_bin) == SwiftToolchainAssertions::Enabled) {
        const auto version = ProbeVersion(swift_bin / "swiftc.exe");
        if (!version.empty()) {
            auto release = SelectSwiftToolchain(config, Win32Process::ToWide(version));
            if (ToolPaths::SwiftAssertions(release) != SwiftToolchainAssertions::Disabled &&
                attempt_install && config.bootstrap_auto_install &&
                RunWingetInstall("Swift.Toolchain",
                    L"OptionsInstallNoAssertsToolchain=1 OptionsIncludeNoAsserts=1", version, true))
                release = SelectSwiftToolchain(config, Win32Process::ToWide(version));
            if (ToolPaths::SwiftAssertions(release) == SwiftToolchainAssertions::Disabled)
                swift_bin = release;
        }
    }
    if (!swift_bin.empty() && attempt_install && !IsUnder(swift_bin, fs::path(config.OPENFRUIT_home))) {
        const fs::path source_bin = swift_bin;
        const fs::path source_root = source_bin.parent_path().parent_path();
        if (fs::is_directory(source_root)) {
            const std::string version = PathSafeVersion(ProbeVersion(source_bin / "swiftc.exe"), "OPENFRUIT") +
                (ToolPaths::SwiftAssertions(source_bin) == SwiftToolchainAssertions::Disabled ? "+NoAsserts" : "");
            const fs::path managed_root = fs::path(config.OPENFRUIT_home) / "toolchains" / "swift" / version;
            const fs::path managed_bin = managed_root / "usr" / "bin";
            if (!SwiftHostManifestSmokeTest(managed_bin)) {
                NativeArtifactStore::ImportTreeTransactional(source_root, managed_root, [](const fs::path& root) {
                    return SwiftHostManifestSmokeTest(root / "usr" / "bin");
                });
            }
            const bool managed_ok = SwiftHostManifestSmokeTest(managed_bin);
            MarkManagedSwiftRelocatable(managed_root, managed_ok);
            if (managed_ok) swift_bin = managed_bin;
            else swift_bin = source_bin;
        }
    }
    if (!swift_bin.empty()) config.toolchain_path = swift_bin.wstring();
    const fs::path swiftc = swift_bin.empty() ? fs::path{} : swift_bin / "swiftc.exe";
    AddStatus(result, {"Swift toolchain", "build", fs::exists(swiftc), true, true, swift_bin, ProbeVersion(swiftc), fs::exists(swiftc) ? "ready" : "missing swiftc.exe"});

    const fs::path swift_clang = swift_bin.empty() ? fs::path{} : swift_bin / "clang.exe";
    const fs::path swift_ar = swift_bin.empty() ? fs::path{} : swift_bin / "llvm-ar.exe";
    const fs::path swift_readobj = swift_bin.empty() ? fs::path{} : swift_bin / "llvm-readobj.exe";
    AddStatus(result, {"Clang C/ObjC frontend", "build", fs::exists(swift_clang), true, false, swift_clang, ProbeVersion(swift_clang), fs::exists(swift_clang) ? "ready" : "missing clang.exe in Swift/OPENFRUIT toolchain"});
    AddStatus(result, {"LLVM librarian", "build", fs::exists(swift_ar), true, false, swift_ar, ProbeVersion(swift_ar), fs::exists(swift_ar) ? "ready" : "missing llvm-ar.exe"});
    AddStatus(result, {"LLVM readobj", "sign", fs::exists(swift_readobj), false, false, swift_readobj, ProbeVersion(swift_readobj), fs::exists(swift_readobj) ? "ready" : "missing llvm-readobj.exe"});

    // Upstream LLVM/LLD.
    fs::path llvm_bin = FindLlvmBinCandidate(repo_root, config);
    fs::path ld64 = llvm_bin.empty() ? fs::path{} : llvm_bin / "ld64.lld.exe";
    if ((!fs::exists(ld64)) && attempt_install && config.bootstrap_auto_install && RunWingetInstall("LLVM.LLVM")) {
        llvm_bin = ToolPaths::LlvmBin(repo_root);
        ld64 = llvm_bin / "ld64.lld.exe";
    }
    if (!llvm_bin.empty() && fs::exists(ld64) && attempt_install && !IsUnder(llvm_bin, fs::path(config.OPENFRUIT_home))) {
        const fs::path source_root = llvm_bin.parent_path();
        const std::string version = PathSafeVersion(ProbeVersion(ld64), "llvm");
        const fs::path managed_root = fs::path(config.OPENFRUIT_home) / "toolchains" / "llvm" / version;
        const fs::path managed_bin = managed_root / "bin";
        if (!fs::exists(managed_bin / "ld64.lld.exe")) {
            std::size_t imported = 0;
            if (verbose) std::cout << "OPENFRUIT bootstrap: importing LLVM " << version << " into " << managed_root.string() << "..." << std::endl;
            if (NativeArtifactStore::ImportTree(source_root, managed_root, &imported) && verbose) {
                std::cout << "OPENFRUIT bootstrap: LLVM imported (" << imported << " file aliases/copies)." << std::endl;
            }
        }
        if (fs::exists(managed_bin / "ld64.lld.exe")) {
            llvm_bin = managed_bin;
            ld64 = managed_bin / "ld64.lld.exe";
        }
    }
    if (!llvm_bin.empty()) config.llvm_path = llvm_bin.wstring();
    AddStatus(result, {"LLVM/ld64.lld", "build", fs::exists(ld64), true, true, ld64, ProbeVersion(ld64), fs::exists(ld64) ? "ready" : "missing upstream Apple-capable LLD"});

    // Apple SDK source and managed SDK import.
    fs::path sdk = !config.sdk_path.empty() && SDKCatalog::HasUsableLayout(fs::path(config.sdk_path)) ? fs::path(config.sdk_path) : ToolPaths::IosSdk(repo_root);
    if (sdk.empty() && attempt_install && config.bootstrap_auto_install) {
        const std::string requested = config.ios_sdk_version.empty() ? "18.0" : Win32Process::ToNarrow(config.ios_sdk_version);
        std::cout << "OPENFRUIT bootstrap: Apple iOS SDK is missing; asking the configured authenticated SDK provider for iOS " << requested << "..." << std::endl;
        const auto acquisition = SDKAcquisition::Download(requested, fs::path(config.OPENFRUIT_home));
        if (!acquisition.Succeeded()) std::cerr << "OPENFRUIT bootstrap: " << acquisition.message << "\n";
        const fs::path candidate = acquisition.destination;
        if (acquisition.Succeeded() && SDKCatalog::HasUsableLayout(candidate)) sdk = candidate;
    }
    if (!sdk.empty()) {
        std::string sdk_version = DetectSdkVersion(sdk);
        if (sdk_version.empty()) sdk_version = config.ios_sdk_version.empty() ? "current" : Win32Process::ToNarrow(config.ios_sdk_version);
        const std::string slot = MajorVersion(sdk_version);
        const auto selected = config.ios_sdk_paths.find(config.ios_sdk_version);
        std::error_code selected_error;
        const bool registered_selection = selected != config.ios_sdk_paths.end() &&
            !selected->second.empty() && fs::equivalent(sdk, fs::path(selected->second), selected_error) &&
            !selected_error;
        const fs::path managed_sdk = fs::path(config.OPENFRUIT_home) / "sdk" / "ios" / slot / "iPhoneOS.sdk";
        if (!IsUnder(sdk, fs::path(config.OPENFRUIT_home))) {
            if (!SDKCatalog::HasUsableLayout(managed_sdk)) {
                if (NativeArtifactStore::CreateDirectoryJunction(managed_sdk, sdk) && SDKCatalog::HasUsableLayout(managed_sdk)) {
                    SaveSdkOrigin(slot, sdk);
                    if (verbose) std::cout << "OPENFRUIT bootstrap: linked iOS SDK via NTFS junction into " << managed_sdk.string() << std::endl;
                    sdk = managed_sdk;
                } else if (attempt_install) {
                    std::size_t imported = 0;
                    if (verbose) std::cout << "OPENFRUIT bootstrap: importing iOS SDK " << sdk_version << " into " << managed_sdk.string() << "..." << std::endl;
                    const fs::path source_sdk = sdk;
                    if (NativeArtifactStore::ImportTreeTransactional(source_sdk, managed_sdk, SDKCatalog::HasUsableLayout, &imported)) {
                        SaveSdkOrigin(slot, source_sdk);
                        if (verbose) std::cout << "OPENFRUIT bootstrap: iOS SDK imported and validated (" << imported << " file aliases/copies)." << std::endl;
                        sdk = managed_sdk;
                    } else if (verbose) {
                        std::cout << "OPENFRUIT bootstrap: managed SDK import did not validate; using the original SDK path for this build." << std::endl;
                    }
                }
            } else {
                sdk = managed_sdk;
            }
        } else if (!registered_selection && SDKCatalog::HasUsableLayout(managed_sdk)) {
            sdk = managed_sdk;
        }
        config.sdk_path = sdk.wstring();
        const std::wstring registration_version = registered_selection
            ? config.ios_sdk_version : Win32Process::ToWide(sdk_version);
        config.ios_sdk_version = registration_version;
        config.ios_sdk_paths[registration_version] = sdk.wstring();
    }
    AddStatus(result, {"Apple iOS SDK", "build", SDKCatalog::HasUsableLayout(sdk), true, false, sdk, config.ios_sdk_version.empty() ? "" : Win32Process::ToNarrow(config.ios_sdk_version), SDKCatalog::HasUsableLayout(sdk) ? "ready" : "USER-PROVIDED / authenticated Apple provider required or managed import incomplete"});
    AddStatus(result, {"iOS compiler-rt availability builtins", "build", true, true, false, {}, "LLVM embedded fallback", "Apple libclang_rt.ios.a preferred; OPENFRUIT LLVM fallback available"});

    // Register Xcode source and import macOS SDK when present, without duplicating the full Xcode bundle.
    fs::path xcode = !config.xcode_path.empty() && fs::exists(config.xcode_path) ? fs::path(config.xcode_path) : ToolPaths::XcodeRoot(repo_root);
    if (!xcode.empty()) {
        config.xcode_path = xcode.wstring();
        if (attempt_install) {
            const std::string xcode_version = DetectXcodeVersion(xcode);
            const fs::path xcode_root = fs::path(config.OPENFRUIT_home) / "sdk" / "xcode";
            const fs::path version_slot = xcode_root / PathSafeVersion(xcode_version, "current");
            const fs::path current_slot = xcode_root / "current";
            std::error_code ec;
            for (const auto& slot : {version_slot, current_slot}) {
                fs::create_directories(slot, ec);
                ec.clear();
                std::ofstream pointer(slot / "source.path", std::ios::binary | std::ios::trunc);
                if (pointer) pointer << xcode.string() << "\n";
            }
            if (verbose) {
                std::cout << "OPENFRUIT bootstrap: registered Xcode " << xcode_version
                          << " in " << version_slot.string() << std::endl;
            }
        }

        const fs::path mac_sdk = xcode / "Contents" / "Developer" / "Platforms" / "MacOSX.platform" / "Developer" / "SDKs" / "MacOSX.sdk";
        if (fs::exists(mac_sdk)) {
            const std::string mac_version = DetectSdkVersion(mac_sdk);
            const fs::path managed_mac = fs::path(config.OPENFRUIT_home) / "sdk" / "macos" / MajorVersion(mac_version) / "MacOSX.sdk";
            if (!fs::exists(managed_mac / "usr" / "lib")) {
                if (!NativeArtifactStore::CreateDirectoryJunction(managed_mac, mac_sdk) || !fs::exists(managed_mac / "usr" / "lib")) {
                    if (attempt_install) NativeArtifactStore::ImportTree(mac_sdk, managed_mac);
                }
            }
            if (fs::exists(managed_mac)) {
                config.macos_sdk_path = managed_mac.wstring();
                config.macos_sdk_paths[Win32Process::ToWide(MajorVersion(mac_version))] = managed_mac.wstring();
            }
        }
    }
    AddStatus(result, {"Xcode components", "apple-macro", !xcode.empty(), false, false, xcode, {}, xcode.empty() ? "USER-PROVIDED" : "registered"});

    // zsign: import a repo-owned binary into managed bin.
    fs::path zsign = !config.zsign_path.empty() && fs::exists(config.zsign_path) ? fs::path(config.zsign_path) : ToolPaths::Zsign(repo_root);
    if (attempt_install && !zsign.empty() && !IsUnder(zsign, fs::path(config.OPENFRUIT_home))) {
        const fs::path managed = fs::path(config.OPENFRUIT_home) / "bin" / "signing" / "zsign.exe";
        if (NativeArtifactStore::ImportFile(zsign, managed)) zsign = managed;
    }
    if (!zsign.empty()) config.zsign_path = zsign.wstring();
    AddStatus(result, {"zsign", "sign", !zsign.empty() && fs::exists(zsign), false, false, zsign, ProbeVersion(zsign), zsign.empty() ? "missing; configure tools.zsign" : "ready"});

    // ipsw: external diagnostic and firmware/dyld inspection tool.
    fs::path ipsw = !config.ipsw_path.empty() && fs::exists(config.ipsw_path) ? fs::path(config.ipsw_path) : ToolPaths::Ipsw();
    if (attempt_install && !ipsw.empty() && !IsUnder(ipsw, fs::path(config.OPENFRUIT_home))) {
        const fs::path managed = fs::path(config.OPENFRUIT_home) / "bin" / "ipsw.exe";
        if (NativeArtifactStore::ImportFile(ipsw, managed)) ipsw = managed;
    }
    if (!ipsw.empty()) config.ipsw_path = ipsw.wstring();
    AddStatus(result, {"ipsw", "diagnostic", !ipsw.empty() && fs::exists(ipsw), false, false, ipsw, ProbeVersion(ipsw), ipsw.empty() ? "missing; configure tools.ipsw" : "ready"});

    const fs::path signing_p12(config.signing_p12_path);
    const fs::path signing_profile(config.signing_profile_path);
    const fs::path signing_dpapi(config.signing_password_dpapi_path);
    AddStatus(result, {"Apple signing certificate", "sign", !signing_p12.empty() && fs::exists(signing_p12), false, false, signing_p12, {}, signing_p12.empty() ? "configure signing.p12" : "missing file"});
    AddStatus(result, {"Provisioning profile", "sign", !signing_profile.empty() && fs::exists(signing_profile), false, false, signing_profile, {}, signing_profile.empty() ? "configure signing.provisioning_profile" : "missing file"});
    AddStatus(result, {"Signing password DPAPI blob", "sign", !signing_dpapi.empty() && fs::exists(signing_dpapi), false, false, signing_dpapi, {}, signing_dpapi.empty() ? "configure signing.password_dpapi" : "missing file"});

    // Native builds must not discover, start or import legacy WSL/Darling.
    // Report the selected compiler's actual native provider; availability
    // does not assert that every macro library is supported.
    std::wstring native_server, native_plugins;
    const bool native_provider = MacroEngine::EnsureMacroBridge(
        repo_root.wstring(), native_server, native_plugins, config.toolchain_path);
    AddStatus(result, {"Swift native plugin server", "macro", native_provider,
        false, false, fs::path(native_server), {},
        native_provider ? "native provider available; library support is separate"
                        : "missing native provider for the selected Swift toolchain"});

    // Device tooling is optional for normal builds.
    fs::path pymobile = !config.pymobiledevice3_path.empty() && fs::exists(config.pymobiledevice3_path)
        ? fs::path(config.pymobiledevice3_path) : ToolPaths::Pymobiledevice3(repo_root);
    if (!pymobile.empty()) config.pymobiledevice3_path = pymobile.wstring();
    AddStatus(result, {"pymobiledevice3", "deploy", !pymobile.empty() && fs::exists(pymobile), false, true, pymobile, ProbeVersion(pymobile), pymobile.empty() ? "optional; required only for --deploy" : "ready"});

    config.Save();
    config.ApplyEnvironment();

    result.build_ready = true;
    result.signing_ready = true;
    result.deploy_ready = true;
    for (const auto& dep : result.dependencies) {
        if (dep.required_for_build && !dep.available) result.build_ready = false;
        if (dep.scope == "sign" && !dep.available) result.signing_ready = false;
        if (dep.scope == "deploy" && !dep.available) result.deploy_ready = false;
    }

    WriteInstalledManifest(config, result);
    if (verbose) PrintReport(result);
    return result;
}

void EnvironmentManager::PrintReport(const BootstrapResult& result) {
    std::cout << "OPENFRUIT environment check\n";
    for (const auto& dep : result.dependencies) {
        std::cout << "  [" << (dep.available ? "OK" : (dep.required_for_build ? "MISSING" : "OPTIONAL")) << "] "
                  << dep.name;
        if (!dep.version.empty()) std::cout << " " << dep.version;
        if (!dep.path.empty()) std::cout << " -> " << dep.path.string();
        if (!dep.detail.empty() && !dep.available) std::cout << " (" << dep.detail << ")";
        std::cout << "\n";
    }
    std::cout << "  Build environment: " << (result.build_ready ? "READY" : "NOT READY") << "\n"
              << "  Signing tools:      " << (result.signing_ready ? "READY" : "INCOMPLETE") << "\n"
              << "  Deployment tools:   " << (result.deploy_ready ? "READY" : "OPTIONAL/MISSING") << "\n";
}

} // namespace OpenFruit
