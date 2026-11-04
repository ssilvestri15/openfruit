#include "svg_runtime_provider.hpp"
#include "http_transfer.hpp"
#include "archive_shim.hpp"
#include "artifact_store.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <fstream>
#include <thread>
namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
constexpr char Version[] = "0.45.1";
constexpr char Url[] = "https://github.com/linebender/resvg/releases/download/v0.45.1/resvg-win64.zip";
// OPENFRUIT pins observed original release bytes. GitHub's asset API does not
// supply a publisher digest for this release; this is not a signed checksum.
constexpr char ArchiveSha[] = "a15172d72d72e219b896ef5942a48c1a57b7280d63ef8380d95dee8005549922";
constexpr char ExeSha[] = "402af74641e3c63f843153ca85bca836850d232658a4d1ee9de98a94d6ce4e5a";
constexpr std::uint64_t ArchiveBytes = 1378552;
std::string Bytes(const fs::path& p) { std::ifstream f(p, std::ios::binary); return {std::istreambuf_iterator<char>(f), {}}; }
bool Within(const fs::path& root, const fs::path& path) {
    const auto a = fs::weakly_canonical(root), b = fs::weakly_canonical(path);
    auto i = a.begin(), j = b.begin();
    for (; i != a.end(); ++i, ++j) {
        if (j == b.end()) return false;
        auto x = i->wstring(), y = j->wstring();
        std::transform(x.begin(), x.end(), x.begin(), towlower);
        std::transform(y.begin(), y.end(), y.begin(), towlower);
        if (x != y) return false;
    }
    return true;
}
bool Regular(const fs::path& p) { return fs::symlink_status(p).type() == fs::file_type::regular; }
struct Controls {
    CancellationSource source;
    ProcessRunOptions process;
    std::jthread watcher;
    Controls() {
        const auto context = CurrentOperationContext();
        process.cancellation = std::make_shared<std::atomic<bool>>(false);
        process.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
        if (context && context->control) process.deadline = std::min(process.deadline, context->control->deadline);
        if (context && context->CancellationRequested()) { source.Cancel(); process.cancellation->store(true); }
        watcher = std::jthread([this, context](std::stop_token stop) {
            while (!stop.stop_requested()) {
                if (context && (context->CancellationRequested() || context->DeadlineExceeded())) {
                    source.Cancel(); process.cancellation->store(true); return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
        });
    }
    bool Active() const { return !source.Token().Requested() && std::chrono::steady_clock::now() < process.deadline; }
};
struct Lease {
    HANDLE mutex = nullptr;
    bool held = false;
    Lease(const fs::path& path, const Controls& controls) {
        auto canonical = fs::weakly_canonical(path).wstring();
        std::transform(canonical.begin(), canonical.end(), canonical.begin(), towlower);
        const auto key = Sha256(Win32Process::ToNarrow(canonical));
        if (!key) return;
        mutex = CreateMutexW(nullptr, FALSE, (L"Local\\OPENFRUIT-svg-" + Win32Process::ToWide(*key)).c_str());
        while (mutex && controls.Active()) {
            const auto status = WaitForSingleObject(mutex, 100);
            if (status == WAIT_OBJECT_0 || status == WAIT_ABANDONED) { held = true; return; }
            if (status != WAIT_TIMEOUT) return;
        }
    }
    ~Lease() { if (held) ReleaseMutex(mutex); if (mutex) CloseHandle(mutex); }
};
bool PeAmd64(const fs::path& executable) {
    if (!Regular(executable) || fs::file_size(executable) != 3229184) return false;
    const auto data = Bytes(executable);
    auto u16 = [&](std::size_t n) { return static_cast<unsigned char>(data[n]) | (static_cast<unsigned char>(data[n+1]) << 8); };
    auto u32 = [&](std::size_t n) { return static_cast<std::uint32_t>(u16(n)) | (static_cast<std::uint32_t>(u16(n+2)) << 16); };
    if (data.size() < 64 || data.substr(0,2) != "MZ") return false;
    const auto offset = u32(60);
    return offset <= data.size()-26 && data.substr(offset,4) == std::string("PE\0\0",4) && u16(offset+4)==0x8664 &&
        (u16(offset+22)&2) && !(u16(offset+22)&0x2000) && u16(offset+24)==0x20b;
}
bool Probe(const fs::path& executable, const fs::path& scratch_parent, Controls& controls, JsonValue& evidence) {
    struct InputLease {
        HANDLE handle = INVALID_HANDLE_VALUE;
        ~InputLease() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    } input;
    input.handle = CreateFileW(executable.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input.handle == INVALID_HANDLE_VALUE) return false;
    if (!controls.Active() || !PeAmd64(executable) || Sha256File(executable, controls.source.Token(), controls.process.deadline) != std::optional<std::string>(ExeSha)) return false;
    const auto version = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--version"}, L"", {}, nullptr, nullptr, controls.process);
    auto actual = version.std_out;
    actual.erase(std::remove_if(actual.begin(), actual.end(), [](unsigned char c){return c=='\r'||c=='\n';}),actual.end());
    if (!version.success || version.output_truncated || version.callback_failed || actual != Version) return false;
    const auto scratch = scratch_parent / NewOperationId();
    fs::create_directories(scratch);
    const auto svg = scratch / "input.svg", png = scratch / "output.png";
    if (!AtomicFile::Publish(svg, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"13\" height=\"7\"><rect width=\"13\" height=\"7\" fill=\"#123456\"/></svg>")) return false;
    const auto rendered = Win32Process::Run(executable.wstring(), {executable.wstring(), svg.wstring(), png.wstring()}, scratch.wstring(), {}, nullptr, nullptr, controls.process);
    if (!rendered.success || rendered.output_truncated || rendered.callback_failed || !Regular(png)) return false;
    const auto data = Bytes(png);
    const auto big = [&](std::size_t p) { return (std::uint32_t(static_cast<unsigned char>(data[p]))<<24) | (std::uint32_t(static_cast<unsigned char>(data[p+1]))<<16) | (std::uint32_t(static_cast<unsigned char>(data[p+2]))<<8) | static_cast<unsigned char>(data[p+3]); };
    if (data.size() < 33 || data.substr(0,8) != std::string("\x89PNG\r\n\x1a\n",8) || big(8)!=13 || data.substr(12,4)!="IHDR" || big(16)!=13 || big(20)!=7) return false;
    evidence.Set("version", JsonValue::String(actual)); evidence.Set("png_width", JsonValue::Number("13")); evidence.Set("png_height", JsonValue::Number("7"));
    const auto digest = Sha256File(png, controls.source.Token(), controls.process.deadline);
    if (!digest || !controls.Active()) return false;
    evidence.Set("png_sha256", JsonValue::String(*digest)); evidence.Set("probe_schema", JsonValue::String("resvg-native-png-dimensions-v1"));
    std::error_code ignored;
    if (Within(scratch_parent, scratch) && scratch.parent_path() == scratch_parent) fs::remove_all(scratch, ignored);
    return true;
}
}
SvgRuntimeProviderResult EnsureNativeSvgProvider(const fs::path& managed_home) {
    SvgRuntimeProviderResult result;
    OperationSpan span("resource.svg.provider");
    auto fail = [&](std::string error) { result.error = std::move(error); result.evidence.Set("error", JsonValue::String(result.error)); span.Complete(result.evidence, false); return result; };
    try {
        Controls controls;
        if (!controls.Active()) return fail("Native SVG provider acquisition cancelled or timed out.");
        if (!managed_home.is_absolute()) return fail("Native SVG provider requires an absolute managed installation root.");
        const auto destination = managed_home / "toolchains" / "svg" / "resvg" / Version;
        const auto staging_parent = managed_home / "cache" / "svg-provider";
        if (!Within(managed_home, destination) || !Within(managed_home, staging_parent)) return fail("SVG provider path escaped managed installation.");
        Lease lease(destination, controls);
        if (!lease.held) return fail("Native SVG provider acquisition lease cancelled or failed.");
        fs::create_directories(staging_parent);
        auto validate = [&](const fs::path& root) {
            if (!Within(managed_home, root)) return false;
            const auto parsed = JsonValue::Parse(Bytes(root / "receipt.json"));
            if (!parsed || parsed->GetString("schema") != "openfruit.svg-provider.v1" || parsed->GetString("source_url") != Url ||
                parsed->GetString("archive_sha256") != ArchiveSha || parsed->GetString("executable_sha256") != ExeSha) return false;
            std::size_t count = 0;
            for (const auto& entry : fs::directory_iterator(root)) { if (!Regular(entry.path()) || (entry.path().filename()!="resvg.exe" && entry.path().filename()!="receipt.json")) return false; ++count; }
            if (count!=2) return false;
            result.evidence = *parsed;
            return Probe(root / "resvg.exe", staging_parent, controls, result.evidence);
        };
        if (fs::is_directory(destination) && validate(destination)) { result.available=true; result.executable=destination/"resvg.exe"; span.Complete(result.evidence,true); return result; }
        const auto archive = staging_parent / "resvg-0.45.1-win64.zip";
        if (!Regular(archive) || fs::file_size(archive)!=ArchiveBytes || Sha256File(archive,controls.source.Token(),controls.process.deadline)!=std::optional<std::string>(ArchiveSha)) {
            TransferRequest request; request.url=Win32Process::ToWide(Url); request.destination=archive; request.expected_sha256=ArchiveSha; request.max_bytes=ArchiveBytes;
            request.cancellation=controls.source.Token(); request.deadline=controls.process.deadline;
            const auto downloaded=HttpTransfer::Download(request);
            if (!downloaded.Succeeded() || downloaded.bytes!=ArchiveBytes) return fail("Pinned official Windows SVG archive could not be acquired.");
        }
        struct ArchiveLease {
            HANDLE handle = INVALID_HANDLE_VALUE;
            ~ArchiveLease() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
        } original;
        original.handle=CreateFileW(archive.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if (original.handle==INVALID_HANDLE_VALUE || Sha256FileHandle(original.handle,controls.source.Token(),controls.process.deadline)!=std::optional<std::string>(ArchiveSha))
            return fail("Original Windows SVG archive changed before extraction.");
        const auto staging=staging_parent/NewOperationId();
        if (!controls.Active() || !ArchiveShim::ExtractZipCompat(archive,staging)) return fail("Windows SVG archive extraction failed or acquisition cancelled.");
        if (!Probe(staging/"resvg.exe",staging_parent,controls,result.evidence)) return fail("Original Windows SVG executable failed PE/version/render verification.");
        JsonValue receipt=result.evidence;
        receipt.Set("schema",JsonValue::String("openfruit.svg-provider.v1")); receipt.Set("source_url",JsonValue::String(Url));
        receipt.Set("archive_sha256",JsonValue::String(ArchiveSha)); receipt.Set("executable_sha256",JsonValue::String(ExeSha));
        receipt.Set("publisher_digest_available",JsonValue::Boolean(false)); receipt.Set("digest_origin",JsonValue::String("OPENFRUIT observed original HTTPS release asset pin"));
        if (!AtomicFile::Publish(staging/"receipt.json",receipt.Serialize(true)) || !controls.Active() ||
            !NativeArtifactStore::ImportTreeTransactional(staging,destination,validate)) return fail("Verified SVG provider could not be published transactionally.");
        result.available=true; result.executable=destination/"resvg.exe"; result.evidence=receipt; span.Complete(result.evidence,true); return result;
    } catch (const std::exception& error) { return fail("Native SVG provider failed: "+std::string(error.what())); }
}
}
