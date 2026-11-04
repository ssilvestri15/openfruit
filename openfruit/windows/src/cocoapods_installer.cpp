#include "cocoapods_installer.hpp"

#include "archive_shim.hpp"
#include "content_hash.hpp"
#include "git_source_view.hpp"
#include "artifact_store.hpp"
#include "http_transfer.hpp"
#include "tool_paths.hpp"

#include <windows.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <regex>
#include <stdexcept>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

// Pinned RubyInstaller archive: the original upstream Ruby for Windows. The
// digest is the published release asset's SHA-256.
constexpr const char* kRubyVersion = "3.3.5";
constexpr const wchar_t* kRubyRelease = L"3.3.5-1";
constexpr const wchar_t* kRubyUrl =
    L"https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-3.3.5-1/rubyinstaller-3.3.5-1-x64.7z";
constexpr const char* kRubySha256 = "7b1715e464ce750c171d53b5191d549a599d07befb0f54fb56aa785e3f25ba8d";
constexpr std::uint64_t kRubyBytes = 15469018;

std::optional<std::string> ReadText(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    std::string text((std::istreambuf_iterator<char>(input)), {});
    if (input.bad()) return std::nullopt;
    return text;
}

std::string Trimmed(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) text.pop_back();
    return text;
}

// A private, uniquely named directory below an owned cache area.
fs::path PrivateScratch(const fs::path& area) {
    fs::create_directories(area);
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        const auto candidate = area / (std::to_wstring(GetCurrentProcessId()) + L"-" +
                                       std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(attempt));
        if (fs::create_directory(candidate)) return candidate;
    }
    throw std::runtime_error("OPENFRUIT CocoaPods: cannot reserve a private scratch directory.");
}

struct ScratchGuard {
    fs::path path;
    ~ScratchGuard() { std::error_code ignored; if (!path.empty()) fs::remove_all(path, ignored); }
};

// Managed Git for Windows ships libcurl and the Unix tools CocoaPods invokes.
fs::path GitRoot() {
    auto git = ToolPaths::Git();
    for (auto current = git.parent_path(); !current.empty() && current != current.parent_path();
         current = current.parent_path())
        if (fs::is_directory(current / "mingw64" / "bin") && fs::is_directory(current / "usr" / "bin"))
            return current;
    throw std::runtime_error("OPENFRUIT CocoaPods: a Git for Windows installation (mingw64, usr) is required.");
}

bool RubyReady(const fs::path& root) {
    const auto ruby = root / "bin" / "ruby.exe";
    if (!fs::is_regular_file(ruby)) return false;
    ProcessRunOptions controls;
    controls.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const auto result = Win32Process::Run(ruby.wstring(), {ruby.wstring(), L"-e", L"print RUBY_VERSION"},
                                          root.wstring(), {}, nullptr, nullptr, controls);
    return result.success && result.std_out == kRubyVersion;
}

fs::path EnsureRuby(const ProcessRunOptions& control) {
    const auto managed = ToolPaths::LocalHome() / "toolchains" / "ruby" / kRubyRelease;
    if (RubyReady(managed)) return managed;
    const auto archives = ToolPaths::CacheRoot() / "ruby-downloads";
    fs::create_directories(archives);
    TransferRequest request;
    request.url = kRubyUrl;
    request.expected_sha256 = kRubySha256;
    request.destination = archives / (std::string(kRubySha256) + ".7z");
    request.max_bytes = kRubyBytes;
    request.reuse_verified_destination = true;
    request.deadline = std::min(control.deadline, std::chrono::steady_clock::now() + std::chrono::minutes(10));
    std::cout << "OPENFRUIT CocoaPods: acquiring verified Ruby " << kRubyVersion << "..." << std::endl;
    if (!HttpTransfer::Download(request).Succeeded())
        throw std::runtime_error("OPENFRUIT CocoaPods: verified Ruby download failed.");
    ScratchGuard scratch{PrivateScratch(ToolPaths::CacheRoot() / "ruby-acquisition")};
    if (!ArchiveShim::ExtractArchiveCompat(request.destination, scratch.path / "extracted"))
        throw std::runtime_error("OPENFRUIT CocoaPods: Ruby archive extraction failed.");
    fs::path source;
    for (const auto& entry : fs::directory_iterator(scratch.path / "extracted"))
        if (entry.is_directory() && fs::is_regular_file(entry.path() / "bin" / "ruby.exe")) {
            if (!source.empty()) throw std::runtime_error("OPENFRUIT CocoaPods: ambiguous Ruby archive roots.");
            source = entry.path();
        }
    if (source.empty() || !NativeArtifactStore::ImportTreeTransactional(source, managed, RubyReady))
        throw std::runtime_error("OPENFRUIT CocoaPods: managed Ruby publication failed.");
    std::error_code ignored;
    fs::remove(request.destination, ignored); // Re-extraction source only.
    return managed;
}

// The environment CocoaPods needs on Windows, expressed only through its own
// and its libraries' documented settings:
//  - COCOAPODS_SKIP_CACHE: the download cache unlinks lock files while they
//    are open, which Windows refuses; downloads go straight to the sandbox.
//  - ETHON_CURL_LIBS / RUBY_DLL_PATH: the CDN client requires an HTTP/2
//    capable libcurl, loaded through FFI from Git for Windows.
std::vector<std::pair<std::wstring, std::wstring>> PodEnvironment(const fs::path& ruby, const fs::path& gems) {
    const auto git = GitRoot();
    std::wstring path = (ruby / "bin").wstring() + L";" + (git / "mingw64" / "bin").wstring() + L";" +
                        (git / "cmd").wstring() + L";" + (git / "usr" / "bin").wstring();
    wchar_t inherited[32767] = {};
    if (const auto length = GetEnvironmentVariableW(L"PATH", inherited, 32767); length > 0 && length < 32767)
        path += L";" + std::wstring(inherited, length);
    const auto home = ToolPaths::CacheRoot() / "cocoapods";
    fs::create_directories(home);
    return {
        {L"PATH", path},
        {L"GEM_HOME", gems.wstring()},
        {L"GEM_PATH", gems.wstring()},
        {L"RUBY_DLL_PATH", (git / "mingw64" / "bin").wstring()},
        {L"ETHON_CURL_LIBS", L"libcurl-openssl-4"},
        {L"CP_HOME_DIR", home.wstring()},
        {L"COCOAPODS_SKIP_CACHE", L"1"},
        {L"COCOAPODS_DISABLE_STATS", L"1"},
        {L"LANG", L"en_US.UTF-8"},
        // Pod sources follow the same long-path rules as the checkout itself.
        {L"GIT_CONFIG_COUNT", L"1"},
        {L"GIT_CONFIG_KEY_0", L"core.longpaths"},
        {L"GIT_CONFIG_VALUE_0", L"true"},
    };
}

bool CocoaPodsReady(const fs::path& ruby, const fs::path& gems, const std::string& version) {
    const auto pod = gems / "bin" / "pod";
    if (!fs::is_regular_file(pod)) return false;
    ProcessRunOptions controls;
    controls.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(2);
    const auto exe = (ruby / "bin" / "ruby.exe").wstring();
    const auto result = Win32Process::Run(exe, {exe, pod.wstring(), L"--version"}, gems.wstring(),
                                          PodEnvironment(ruby, gems), nullptr, nullptr, controls);
    return result.success && Trimmed(result.std_out) == version;
}

fs::path EnsureCocoaPods(const fs::path& ruby, const std::string& version, const ProcessRunOptions& control) {
    const auto managed = ToolPaths::LocalHome() / "toolchains" / "cocoapods" / version;
    if (CocoaPodsReady(ruby, managed, version)) return managed;
    std::cout << "OPENFRUIT CocoaPods: installing CocoaPods " << version << "..." << std::endl;
    ScratchGuard scratch{PrivateScratch(ToolPaths::CacheRoot() / "cocoapods-acquisition")};
    const auto staged = scratch.path / "gems";
    const auto exe = (ruby / "bin" / "ruby.exe").wstring();
    const auto gem = (ruby / "bin" / "gem").wstring();
    ProcessRunOptions controls = control;
    controls.deadline = std::min(control.deadline, std::chrono::steady_clock::now() + std::chrono::minutes(20));
    const auto result = Win32Process::Run(exe, {exe, gem, L"install", L"cocoapods", L"-v",
        // GEM_HOME selects the destination; --install-dir would also hide
        // Ruby's default gems from resolution and force native rebuilds.
        Win32Process::ToWide(version), L"--no-document", L"--bindir", (staged / "bin").wstring()},
        scratch.path.wstring(),
        PodEnvironment(ruby, staged), nullptr, nullptr, controls);
    if (!result.success)
        throw std::runtime_error("OPENFRUIT CocoaPods: gem install cocoapods " + version + " failed:\n" + result.std_err);
    if (!NativeArtifactStore::ImportTreeTransactional(staged, managed,
            [&](const fs::path& root) { return CocoaPodsReady(ruby, root, version); }))
        throw std::runtime_error("OPENFRUIT CocoaPods: managed CocoaPods publication failed.");
    return managed;
}

} // namespace

bool CocoaPodsSandboxCurrent(const fs::path& installation_root) {
    const auto lock = ReadText(installation_root / "Podfile.lock");
    const auto manifest = ReadText(installation_root / "Pods" / "Manifest.lock");
    return lock && manifest && *lock == *manifest;
}

std::optional<std::string> CocoaPodsLockedVersion(const fs::path& podfile_lock) {
    const auto text = ReadText(podfile_lock);
    if (!text) return std::nullopt;
    std::smatch match;
    static const std::regex pattern(R"((?:^|\n)COCOAPODS: ([0-9]+\.[0-9]+\.[0-9]+(?:\.[A-Za-z0-9]+)?)\r?(?:\n|$))");
    if (!std::regex_search(*text, match, pattern)) return std::nullopt;
    return match[1].str();
}

bool EnsureCocoaPodsSandbox(const fs::path& installation_root, const ProcessRunOptions& control) {
    if (!fs::is_regular_file(installation_root / "Podfile") ||
        !fs::is_regular_file(installation_root / "Podfile.lock")) return false;
    if (CocoaPodsSandboxCurrent(installation_root)) return false;
    const auto version = CocoaPodsLockedVersion(installation_root / "Podfile.lock");
    if (!version) throw std::runtime_error("OPENFRUIT CocoaPods: Podfile.lock does not record a CocoaPods version.");
    const auto ruby = EnsureRuby(control);
    const auto gems = EnsureCocoaPods(ruby, *version, control);
    std::cout << "OPENFRUIT CocoaPods: pod install --deployment (CocoaPods " << *version << ") in "
              << installation_root.string() << std::endl;
    const auto exe = (ruby / "bin" / "ruby.exe").wstring();
    const auto pod = (gems / "bin" / "pod").wstring();
    const auto print = [](const std::string& chunk) { std::cout << chunk << std::flush; };
    const auto result = Win32Process::Run(exe, {exe, pod, L"install", L"--deployment"},
        installation_root.wstring(), PodEnvironment(ruby, gems), print, print, control);
    if (!result.success) throw std::runtime_error("OPENFRUIT CocoaPods: pod install --deployment failed.");
    if (!CocoaPodsSandboxCurrent(installation_root))
        throw std::runtime_error("OPENFRUIT CocoaPods: Pods/Manifest.lock does not match Podfile.lock after install.");
    return true;
}

std::optional<CocoaPodsView> PrepareCocoaPodsView(const fs::path& target, const fs::path& source_root,
    const fs::path& views_parent, const ProcessRunOptions& control) {
    const auto absolute = fs::absolute(target).lexically_normal();
    const auto installation = absolute.extension() == L".xcodeproj" || absolute.extension() == L".xcworkspace" ||
        fs::is_regular_file(absolute) ? absolute.parent_path() : absolute;
    if (!fs::is_regular_file(installation / "Podfile") || !fs::is_regular_file(installation / "Podfile.lock") ||
        CocoaPodsSandboxCurrent(installation)) return std::nullopt;
    const auto root = fs::canonical(source_root);
    const auto relative = fs::canonical(installation).lexically_relative(root);
    if (relative.empty() || relative.is_absolute() || *relative.begin() == L"..")
        throw std::runtime_error("OPENFRUIT CocoaPods: Podfile is outside the checkout.");
    const auto identity = Sha256("openfruit.cocoapods-view.v1:" + Win32Process::ToNarrow(root.wstring()));
    if (!identity) throw std::runtime_error("OPENFRUIT CocoaPods: cannot hash the view identity.");
    const auto slot = fs::absolute(views_parent).lexically_normal() / ("pods-" + identity->substr(0, 16));
    CocoaPodsView view;
    view.lease = ArtifactLease::Acquire(slot, control);
    const auto sources = slot / "sources" / root.filename();
    SynchronizeGitSourceView(root, sources, slot / "source-view-receipt.json", control);
    EnsureCocoaPodsSandbox((sources / relative).lexically_normal(), control);
    view.target = (sources / absolute.lexically_relative(root)).lexically_normal();
    return view;
}

} // namespace OpenFruit
