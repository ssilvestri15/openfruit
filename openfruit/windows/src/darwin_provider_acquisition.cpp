#include "darwin_provider_acquisition.hpp"
#include "aea_input.hpp"
#include "apfs_metadata.hpp"
#include "archive_tree_extraction.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "darwin_macro_provider.hpp"
#include "darwin_macro_provider_import.hpp"
#include "dyld_cache.hpp"
#include "http_transfer.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "restore_manifest.hpp"
#include "win32_process.hpp"
#include "xip_archive.hpp"
#include <plist/plist.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <functional>
#include <optional>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {

// Apple's public catalog of macOS restore images.
constexpr wchar_t kRestoreCatalog[] = L"https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml";
constexpr char kSharedCache[] = "/System/Library/dyld/dyld_shared_cache_arm64e";
constexpr char kDiskDyld[] = "/usr/lib/dyld";
constexpr char kToolchain[] = "Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/";
constexpr char kPlatform[] = "Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/";
constexpr char kPlatformPlugins[] = "Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/lib/swift/host/plugins/";

void Need(bool condition, const std::string& message) { if (!condition) throw std::runtime_error(message); }

std::string Text(const fs::path& path) { return Win32Process::ToNarrow(path.wstring()); }
std::string Rel(const fs::path& root, const fs::path& path) {
    return Win32Process::ToNarrow(path.lexically_relative(root).generic_wstring());
}

std::optional<JsonValue> ReadJsonFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    std::string text((std::istreambuf_iterator<char>(input)), {});
    return JsonValue::Parse(text);
}
void WriteJsonFile(const fs::path& path, const JsonValue& value) {
    Need(AtomicFile::Publish(path, value.Serialize(true)), "Cannot write acquisition record " + Text(path));
}
bool Complete(const JsonValue& value) { const auto* flag = value.Get("complete"); return flag && flag->IsBoolean() && flag->Bool(); }

// Runs a stage once: a complete earlier record is reused; a missing or failed
// one is produced again after its partial output directory is removed.
JsonValue Stage(const fs::path& record, const fs::path& output, std::ostream& log, const std::string& label,
                const std::function<JsonValue()>& produce) {
    if (const auto existing = ReadJsonFile(record); existing && Complete(*existing)) {
        log << "  " << label << ": reused\n" << std::flush;
        return *existing;
    }
    std::error_code ignored;
    if (!output.empty()) fs::remove_all(output, ignored);
    log << "  " << label << "...\n" << std::flush;
    const auto started = std::chrono::steady_clock::now();
    auto value = produce();
    WriteJsonFile(record, value);
    Need(Complete(value), label + " failed: " + value.GetString("error"));
    log << "  " << label << ": done in " << std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - started).count() << " s\n" << std::flush;
    return value;
}

struct Plist {
    plist_t root = nullptr;
    ~Plist() { if (root) plist_free(root); }
};
std::string PlistString(plist_t dict, const char* key) {
    const auto node = dict ? plist_dict_get_item(dict, key) : nullptr;
    if (!node || plist_get_node_type(node) != PLIST_STRING) return {};
    char* value = nullptr; plist_get_string_val(node, &value);
    std::string text = value ? value : ""; if (value) plist_mem_free(value); return text;
}
std::string PlistFileString(const fs::path& path, const char* key) {
    std::ifstream input(path, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(input)), {});
    Plist plist; plist_format_t format{};
    if (bytes.empty() || plist_from_memory(bytes.data(), static_cast<uint32_t>(bytes.size()), &plist.root, &format) != PLIST_ERR_SUCCESS) return {};
    return PlistString(plist.root, key);
}

std::vector<unsigned> VersionParts(const std::string& version) {
    std::vector<unsigned> parts; unsigned value = 0; bool digits = false;
    for (const char c : version) {
        if (c >= '0' && c <= '9') { value = value * 10 + static_cast<unsigned>(c - '0'); digits = true; }
        else if (c == '.' && digits) { parts.push_back(value); value = 0; digits = false; }
        else return {};
    }
    if (digits) parts.push_back(value);
    return parts;
}

// Newest restore image in Apple's catalog; every listed Mac shares it.
JsonValue SelectRestoreImage() {
    JsonPostRequest request; request.url = kRestoreCatalog; request.max_bytes = 16 * 1024 * 1024;
    request.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(2);
    const auto response = HttpTransfer::GetBytes(request);
    Need(response.Succeeded() && !response.body.empty(), "Apple's macOS restore catalog is unavailable.");
    Plist plist; plist_format_t format{};
    Need(plist_from_memory(response.body.data(), static_cast<uint32_t>(response.body.size()), &plist.root, &format) == PLIST_ERR_SUCCESS,
         "Apple's macOS restore catalog is not a property list.");
    std::string url, version, build; std::vector<unsigned> best;
    const auto by_version = plist_dict_get_item(plist.root, "MobileDeviceSoftwareVersionsByVersion");
    Need(by_version && plist_get_node_type(by_version) == PLIST_DICT, "Restore catalog has no software versions.");
    plist_dict_iter outer = nullptr; plist_dict_new_iter(by_version, &outer);
    for (;;) {
        char* key = nullptr; plist_t group = nullptr; plist_dict_next_item(by_version, outer, &key, &group);
        if (key) plist_mem_free(key);
        if (!group) break;
        const auto devices = plist_dict_get_item(group, "MobileDeviceSoftwareVersions");
        if (!devices || plist_get_node_type(devices) != PLIST_DICT) continue;
        plist_dict_iter device_iter = nullptr; plist_dict_new_iter(devices, &device_iter);
        for (;;) {
            char* device = nullptr; plist_t builds = nullptr; plist_dict_next_item(devices, device_iter, &device, &builds);
            if (device) plist_mem_free(device);
            if (!builds) break;
            if (plist_get_node_type(builds) != PLIST_DICT) continue;
            plist_dict_iter build_iter = nullptr; plist_dict_new_iter(builds, &build_iter);
            for (;;) {
                char* name = nullptr; plist_t entry = nullptr; plist_dict_next_item(builds, build_iter, &name, &entry);
                if (name) plist_mem_free(name);
                if (!entry) break;
                const auto restore = plist_get_node_type(entry) == PLIST_DICT ? plist_dict_get_item(entry, "Restore") : nullptr;
                const auto candidate_url = PlistString(restore, "FirmwareURL");
                const auto candidate_version = PlistString(restore, "ProductVersion");
                const auto parts = VersionParts(candidate_version);
                if (!candidate_url.starts_with("https://") || parts.empty() || (!best.empty() && !(best < parts))) continue;
                best = parts; url = candidate_url; version = candidate_version; build = PlistString(restore, "BuildVersion");
            }
            plist_mem_free(build_iter);
        }
        plist_mem_free(device_iter);
    }
    plist_mem_free(outer);
    Need(!url.empty(), "Apple's restore catalog lists no macOS restore image.");
    auto out = JsonValue::ObjectValue();
    out.Set("complete", JsonValue::Boolean(true));
    out.Set("catalog", JsonValue::String(Win32Process::ToNarrow(kRestoreCatalog)));
    out.Set("catalog_sha256", JsonValue::String(Sha256(response.body).value_or("")));
    out.Set("url", JsonValue::String(url));
    out.Set("product_version", JsonValue::String(version));
    out.Set("product_build", JsonValue::String(build));
    return out;
}

// A restore component whose variants are staged and decoded only when needed,
// most widely used first; each decoded image is dropped once it is consumed.
struct ComponentVariants {
    fs::path work; std::string url, component, tag; std::ostream& log;
    std::optional<std::size_t> count;
    // The decoded-image record of a variant, or nothing past the last one.
    std::optional<fs::path> Decoded(std::size_t index) {
        if (count && index >= *count) return std::nullopt;
        const auto suffix = tag + "-" + std::to_string(index);
        RangeTransferRequest request; request.url = Win32Process::ToWide(url);
        const auto staged = Stage(work / ("stage-" + suffix + ".json"), work / ("stage-" + suffix), log,
            "Downloading macOS " + component + (index ? " (variant " + std::to_string(index + 1) + ")" : ""), [&] {
                request.deadline = std::chrono::steady_clock::now() + std::chrono::hours(6);
                return StageRestoreComponents(request, component, work / ("stage-" + suffix), index);
            });
        if (const auto* total = staged.Get("selected_variant_count")) count = static_cast<std::size_t>(total->Int(1));
        const auto record = work / ("decoded-" + suffix + ".json");
        Stage(record, work / ("decoded-" + suffix), log, "Decrypting " + component, [&] {
            return DecodeAeaStage(work / ("stage-" + suffix + ".json"), work / ("decoded-" + suffix));
        });
        // The encrypted input is no longer needed once decoded and verified.
        std::error_code ignored; fs::remove_all(work / ("stage-" + suffix), ignored);
        return record;
    }
};

// Extracts one original file from the first variant that holds it and returns
// that variant's decoded-image record with the extraction report.
struct Extracted { fs::path record; JsonValue report; fs::path decoded; };
Extracted ExtractFirst(ComponentVariants& variants, const std::string& virtual_path,
                       const fs::path& output_parent, const fs::path& record, std::ostream& log) {
    if (const auto existing = ReadJsonFile(record); existing && Complete(*existing))
        return {record, *existing, fs::path(Win32Process::ToWide(existing->GetString("decoded_record")))};
    std::string errors;
    fs::create_directories(output_parent);
    for (std::size_t index = 0;; ++index) {
        const auto decoded = variants.Decoded(index);
        if (!decoded) break;
        const auto output = output_parent / NewOperationId();
        log << "  Extracting " << virtual_path << "...\n" << std::flush;
        auto value = ExtractApfsStage(*decoded, virtual_path, output, {},
                                      std::chrono::steady_clock::now() + std::chrono::hours(1));
        if (Complete(value)) {
            value.Set("decoded_record", JsonValue::String(Text(*decoded)));
            WriteJsonFile(record, value);
            return {record, value, *decoded};
        }
        errors += " [" + std::to_string(index + 1) + "] " + value.GetString("error");
        std::error_code ignored; fs::remove_all(output, ignored);
    }
    throw std::runtime_error("Original " + virtual_path + " was not extracted:" + errors);
}
// Extracts a file that must come from the same decoded image as another.
std::pair<fs::path, JsonValue> ExtractFrom(const fs::path& decoded, const std::string& virtual_path,
                                           const fs::path& output_parent, const fs::path& record, std::ostream& log) {
    if (const auto existing = ReadJsonFile(record); existing && Complete(*existing)) return {record, *existing};
    log << "  Extracting " << virtual_path << "...\n" << std::flush;
    auto value = ExtractApfsStage(decoded, virtual_path, output_parent / NewOperationId(), {},
                                  std::chrono::steady_clock::now() + std::chrono::hours(1));
    WriteJsonFile(record, value);
    Need(Complete(value), "Original " + virtual_path + " was not extracted: " + value.GetString("error"));
    return {record, value};
}

bool Under(const std::string& path, const char* prefix) { return path.starts_with(prefix); }
bool ProviderMember(std::string path) {
    if (path.starts_with("./")) path.erase(0, 2);
    // As Xcode registers them: the platform's plugins with the platform's own
    // plugin server and host libraries, and the toolchain's server, host
    // libraries and plugins for modules only the toolchain provides.
    const std::string toolchain = kToolchain, platform = kPlatform;
    return path == "Xcode.app/Contents/version.plist" ||
           path == toolchain + "ToolchainInfo.plist" ||
           path == toolchain + "usr/bin/swift-plugin-server" ||
           Under(path, (toolchain + "usr/lib/swift/host/").c_str()) ||
           path == platform + "usr/bin/swift-plugin-server" ||
           Under(path, (platform + "usr/lib/swift/host/").c_str());
}

// The original plugin server, its host libraries and the plugin libraries.
JsonValue ExtractXcodeTree(const fs::path& archive, const fs::path& destination) {
    const ArchiveTreeSelector select = [](const fs::path& source, const XipReadOptions& options) {
        struct Collect final : XipVisitor {
            std::vector<std::string> members;
            void Begin(const XipEntry& entry) override { if (ProviderMember(entry.path)) members.push_back(entry.path); }
            void Data(std::span<const std::uint8_t>) override {}
            XipVisit End() override { return XipVisit::Continue; }
        } collect;
        ArchiveTreeSelection selection;
        const auto walked = XipArchive::Walk(source, collect, options);
        if (walked.status != XipStatus::Completed) {
            selection.status = ArchiveExtractionStatus::ArchiveFailure;
            selection.diagnostic_code = std::string("xip.walk.") + XipStatusName(walked.status);
            return selection;
        }
        if (collect.members.empty()) { selection.status = ArchiveExtractionStatus::MissingSelection; return selection; }
        // With the platform's own server, the toolchain contributes only its
        // plugins: its server and host libraries would go unused.
        const auto normal = [](std::string path) { if (path.starts_with("./")) path.erase(0, 2); return path; };
        const std::string toolchain = kToolchain;
        const auto platform_server = std::string(kPlatform) + "usr/bin/swift-plugin-server";
        if (std::any_of(collect.members.begin(), collect.members.end(), [&](const std::string& m) { return normal(m) == platform_server; }))
            std::erase_if(collect.members, [&](const std::string& m) {
                const auto path = normal(m);
                return path == toolchain + "usr/bin/swift-plugin-server" ||
                       (Under(path, (toolchain + "usr/lib/swift/host/").c_str()) &&
                        !Under(path, (toolchain + "usr/lib/swift/host/plugins/").c_str()));
            });
        selection.member_paths = std::move(collect.members);
        return selection;
    };
    const auto result = ArchiveTreeExtraction::Extract(archive, destination, select);
    auto out = result.ToJson();
    out.Set("complete", JsonValue::Boolean(result.Succeeded() && result.toc_checksum_verified &&
        result.content_checksum_verified && result.xar_signature_valid && result.apple_signing_chain_valid));
    if (!result.Succeeded()) out.Set("error", JsonValue::String("Xcode archive extraction failed: " + result.diagnostic_code));
    return out;
}

JsonValue CacheDescriptor(const fs::path& managed, const fs::path& report_source, const fs::path& report_destination,
                          const JsonValue& report) {
    auto out = JsonValue::ObjectValue();
    out.Set("report", JsonValue::String(Rel(managed, report_destination)));
    out.Set("report_sha256", JsonValue::String(Sha256File(report_source).value_or("")));
    out.Set("payload", JsonValue::String(Rel(managed, fs::path(Win32Process::ToWide(report.GetString("path"))))));
    out.Set("sha256", JsonValue::String(report.GetString("sha256")));
    out.Set("bytes", *report.Get("decoded_bytes"));
    out.Set("source_sha256", JsonValue::String(report.GetString("source_sha256")));
    out.Set("virtual_path", JsonValue::String(report.GetString("virtual_path")));
    return out;
}

void AddFiles(const fs::path& managed, const fs::path& source, const fs::path& destination, JsonValue& files) {
    for (fs::recursive_directory_iterator it(source), end; it != end; ++it) {
        if (it->is_directory()) continue;
        Need(it->is_regular_file(), "Unsupported original provider entry: " + Text(it->path()));
        const auto target = destination / it->path().lexically_relative(source);
        auto file = JsonValue::ObjectValue();
        file.Set("path", JsonValue::String(Rel(managed, target)));
        const auto digest = Sha256File(it->path());
        Need(digest.has_value(), "Cannot hash original provider file " + Text(it->path()));
        file.Set("sha256", JsonValue::String(*digest));
        file.Set("bytes", JsonValue::Number(std::to_string(fs::file_size(it->path()))));
        files.ArrayItems().push_back(std::move(file));
    }
}

struct WorkLock {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~WorkLock() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};

// The macOS part of every provider: the original dyld shared cache set (with
// its extraction reports) and disk dyld of one restore image build, kept once
// under sdk/macos-restore/<build> and shared by all SDKs' providers.
struct MacosRuntime {
    fs::path parent_record; JsonValue parent;
    std::vector<std::pair<fs::path, JsonValue>> children;
    fs::path dyld;
};
fs::path MacosRuntimeRoot(const fs::path& managed, const std::string& build) {
    Need(!build.empty() && std::all_of(build.begin(), build.end(), [](unsigned char c) { return std::isalnum(c); }),
         "Invalid macOS restore image build.");
    return managed / "sdk" / "macos-restore" / build;
}
std::optional<MacosRuntime> LoadMacosRuntime(const fs::path& shared) {
    const auto index = ReadJsonFile(shared / "runtime.json");
    if (!index || !Complete(*index)) return std::nullopt;
    const auto load = [&](const std::string& name) -> std::optional<std::pair<fs::path, JsonValue>> {
        const auto record = shared / "reports" / name;
        const auto report = ReadJsonFile(record);
        std::error_code ec;
        if (!report || !Complete(*report) || !fs::is_regular_file(fs::path(Win32Process::ToWide(report->GetString("path"))), ec))
            return std::nullopt;
        return std::pair{record, *report};
    };
    MacosRuntime runtime;
    const auto parent = load("parent.json");
    if (!parent) return std::nullopt;
    runtime.parent_record = parent->first; runtime.parent = parent->second;
    const auto* count = index->Get("children");
    for (int child = 0; count && child < count->Int(-1); ++child) {
        auto loaded = load("child-" + std::to_string(child) + ".json");
        if (!loaded) return std::nullopt;
        runtime.children.push_back(std::move(*loaded));
    }
    runtime.dyld = shared / "system" / "usr" / "lib" / "dyld";
    std::error_code ec;
    if (!count || !fs::is_regular_file(runtime.dyld, ec)) return std::nullopt;
    return runtime;
}
void PublishMacosRuntime(const fs::path& shared, std::size_t children, const std::string& build) {
    auto index = JsonValue::ObjectValue();
    index.Set("complete", JsonValue::Boolean(true));
    index.Set("product_build", JsonValue::String(build));
    index.Set("children", JsonValue::Number(std::to_string(children)));
    WriteJsonFile(shared / "runtime.json", index);
}
// Registers the macOS runtime of a provider published before the shared store
// existed: its payloads and disk dyld are hard-linked (no copy) and its
// extraction reports are rebound to the linked payloads.
bool AdoptMacosRuntime(const fs::path& managed, const std::string& build, const fs::path& shared) {
    std::error_code ec;
    for (fs::directory_iterator slot(managed / "sdk" / "xcode", ec), end; !ec && slot != end; slot.increment(ec)) {
        const auto receipt = ReadJsonFile(slot->path() / "darwin-provider" / kDarwinMacroProviderReceipt);
        const auto* provenance = receipt ? receipt->Get("provenance") : nullptr;
        const auto* image = provenance ? provenance->Get("restore_image") : nullptr;
        if (!image || image->GetString("product_build") != build) continue;
        try {
            std::vector<const JsonValue*> descriptors{receipt->Get("cache")->Get("parent")};
            for (const auto& child : receipt->Get("cache")->Get("children")->ArrayItems()) descriptors.push_back(&child);
            fs::create_directories(shared / "reports");
            for (std::size_t index = 0; index < descriptors.size(); ++index) {
                const auto& descriptor = *descriptors[index];
                auto report = ReadJsonFile(managed / fs::path(Win32Process::ToWide(descriptor.GetString("report"))));
                Need(report && Complete(*report), "Provider cache report unavailable.");
                const auto payload = managed / fs::path(Win32Process::ToWide(descriptor.GetString("payload")));
                const auto directory = shared / "cache" / NewOperationId();
                fs::create_directories(directory);
                const auto linked = directory / payload.filename();
                fs::create_hard_link(payload, linked);
                report->Set("path", JsonValue::String(Text(linked)));
                WriteJsonFile(shared / "reports" / (index ? "child-" + std::to_string(index - 1) + ".json" : std::string("parent.json")), *report);
            }
            fs::path dyld;
            for (const auto& tree : receipt->Get("original_trees")->ArrayItems()) {
                const auto candidate = managed / fs::path(Win32Process::ToWide(tree.StringValue())) / "usr" / "lib" / "dyld";
                if (fs::is_regular_file(candidate)) dyld = candidate;
            }
            Need(!dyld.empty(), "Provider disk dyld unavailable.");
            fs::create_directories(shared / "system" / "usr" / "lib");
            fs::create_hard_link(dyld, shared / "system" / "usr" / "lib" / "dyld");
            PublishMacosRuntime(shared, descriptors.size() - 1, build);
            return true;
        } catch (const std::exception&) {
            fs::remove_all(shared / "cache", ec); fs::remove_all(shared / "reports", ec); fs::remove_all(shared / "system", ec);
            ec.clear();
        }
    }
    return false;
}
// Downloads, decodes and extracts the macOS runtime of one restore image.
MacosRuntime AcquireMacosRuntime(const fs::path& shared, const std::string& url, std::ostream& log) {
    const auto work = shared / "work";
    fs::create_directories(work);
    fs::create_directories(shared / "reports");
    // A consumed decoded image (its directory beside its record) is dropped.
    const auto drop_decoded = [](const fs::path& record) {
        std::error_code ignored; fs::remove_all(fs::path(record).replace_extension(), ignored);
    };
    ComponentVariants system_os{work, url, "Cryptex1,SystemOS", "systemos", log};
    const auto cache_root = shared / "cache";
    fs::create_directories(cache_root);
    const auto parent_found = ExtractFirst(system_os, kSharedCache, cache_root, shared / "reports" / "parent.json", log);
    const auto inspected = Stage(work / "cache-inspect.json", {}, log, "Reading dyld shared cache layout", [&] {
        return InspectDyldCacheStage(parent_found.record, {}, std::chrono::steady_clock::now() + std::chrono::minutes(30));
    });
    const auto* subcaches = inspected.Get("subcaches");
    Need(subcaches && subcaches->IsArray(), "The dyld shared cache declares no subcache list.");
    for (std::size_t index = 0; index < subcaches->ArrayItems().size(); ++index) {
        const auto virtual_path = subcaches->ArrayItems()[index].GetString("virtual_path");
        Need(virtual_path.starts_with(kSharedCache), "Unexpected dyld subcache path " + virtual_path);
        // Subcaches belong to the image that holds their main cache.
        ExtractFrom(parent_found.decoded, virtual_path, cache_root,
                    shared / "reports" / ("child-" + std::to_string(index) + ".json"), log);
    }
    drop_decoded(parent_found.decoded);
    ComponentVariants os{work, url, "OS", "os", log};
    const auto dyld_found = ExtractFirst(os, kDiskDyld, work / "dyld-extract", work / "disk-dyld.json", log);
    fs::create_directories(shared / "system" / "usr" / "lib");
    fs::copy_file(fs::path(Win32Process::ToWide(dyld_found.report.GetString("path"))), shared / "system" / "usr" / "lib" / "dyld",
                  fs::copy_options::overwrite_existing);
    drop_decoded(dyld_found.decoded);
    PublishMacosRuntime(shared, subcaches->ArrayItems().size(), std::string(shared.filename().string()));
    std::error_code ignored; fs::remove_all(work, ignored);
    auto runtime = LoadMacosRuntime(shared);
    Need(runtime.has_value(), "The acquired macOS runtime is incomplete.");
    return *runtime;
}
// Ensures an already published provider's macOS runtime is also in the shared
// store, so later SDKs reuse it even if this SDK is removed.
void ShareProviderRuntime(const fs::path& managed, const fs::path& receipt_path) {
    try {
        const auto receipt = ReadJsonFile(receipt_path);
        const auto* provenance = receipt ? receipt->Get("provenance") : nullptr;
        const auto* image = provenance ? provenance->Get("restore_image") : nullptr;
        if (!image) return;
        const auto build = image->GetString("product_build");
        const auto shared = MacosRuntimeRoot(managed, build);
        if (LoadMacosRuntime(shared)) return;
        fs::create_directories(shared);
        WorkLock lock;
        lock.handle = CreateFileW((shared / ".lock").c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (lock.handle == INVALID_HANDLE_VALUE || LoadMacosRuntime(shared)) return;
        AdoptMacosRuntime(managed, build, shared);
    } catch (...) {}
}

} // namespace

DarwinProviderAcquisitionResult EnsureDarwinMacroProvider(const fs::path& selected_sdk, const fs::path& managed_home,
                                                          std::ostream& log) {
    DarwinProviderAcquisitionResult result;
    OperationSpan span("darwin.provider.acquire");
    try {
        const auto managed = fs::weakly_canonical(managed_home);
        const auto sdk = fs::weakly_canonical(selected_sdk);
        if (const auto existing = FindDarwinMacroProviderReceipt(managed, sdk); !existing.empty()) {
            ShareProviderRuntime(managed, existing);
            result.succeeded = result.already_present = true; span.Succeed(); return result;
        }
        // Managed SDKs live in sdk/xcode/<archive identity>/; that identity also
        // names the retained Apple archive the SDK was extracted from.
        fs::path slot;
        for (auto path = sdk; path.has_parent_path() && path.parent_path() != path; path = path.parent_path())
            if (path.parent_path() == managed / "sdk" / "xcode") { slot = path; break; }
        Need(!slot.empty(), "The selected SDK is not a managed Xcode SDK.");
        const auto archive = managed / "cache" / "sdk-downloads" / (slot.filename().wstring() + L".download");
        Need(fs::is_regular_file(archive), "The Xcode archive of the selected SDK is not retained.");
        const auto provider = slot / "darwin-provider";
        const auto work = slot / "darwin-provider-work";
        fs::create_directories(work);
        WorkLock lock;
        lock.handle = CreateFileW((work / ".lock").c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        Need(lock.handle != INVALID_HANDLE_VALUE, "Another OPENFRUIT process is acquiring this macro provider.");
        if (const auto existing = FindDarwinMacroProviderReceipt(managed, sdk); !existing.empty()) {
            ShareProviderRuntime(managed, existing);
            result.succeeded = result.already_present = true; span.Succeed(); return result;
        }

        log << "OPENFRUIT: acquiring the original Darwin macro provider for this SDK (first use)...\n" << std::flush;
        const auto image = Stage(work / "restore-image.json", {}, log, "Selecting macOS restore image", SelectRestoreImage);
        const auto build = image.GetString("product_build");
        log << "  macOS " << image.GetString("product_version") << " (" << build << ")\n" << std::flush;

        // The macOS part is SDK-independent: shared by every SDK's provider and
        // downloaded once per restore image build.
        const auto shared = MacosRuntimeRoot(managed, build);
        fs::create_directories(shared);
        WorkLock shared_lock;
        shared_lock.handle = CreateFileW((shared / ".lock").c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        Need(shared_lock.handle != INVALID_HANDLE_VALUE, "Another OPENFRUIT process is acquiring this macOS runtime.");
        auto runtime = LoadMacosRuntime(shared);
        if (runtime) log << "  macOS runtime " << build << ": reused\n" << std::flush;
        else if (AdoptMacosRuntime(managed, build, shared) && (runtime = LoadMacosRuntime(shared)))
            log << "  macOS runtime " << build << ": adopted from an existing provider\n" << std::flush;
        else { log << "  macOS runtime " << build << ": downloading once (large)\n" << std::flush;
               runtime = AcquireMacosRuntime(shared, image.GetString("url"), log); }
        const auto& parent_record = runtime->parent_record; const auto& parent = runtime->parent;
        const auto& children = runtime->children;
        const auto system_tree = work / "system-tree";
        if (!fs::exists(system_tree / "usr" / "lib" / "dyld")) {
            std::error_code ignored; fs::remove_all(system_tree, ignored);
            fs::create_directories(system_tree / "usr" / "lib");
            fs::copy_file(runtime->dyld, system_tree / "usr" / "lib" / "dyld");
        }

        Stage(work / "xcode-tree.json", work / "xcode-tree", log, "Extracting the original plugin server from the Xcode archive", [&] {
            return ExtractXcodeTree(archive, work / "xcode-tree");
        });

        log << "  Publishing the provider...\n" << std::flush;
        const auto original = provider / "original", system = provider / "system", reports = provider / "cache-reports";
        auto files = JsonValue::ArrayValue();
        AddFiles(managed, work / "xcode-tree", original, files);
        AddFiles(managed, system_tree, system, files);
        const std::string toolchain = kToolchain;
        // The selected platform's plugin server serves its plugins in Xcode;
        // the toolchain's server is used only when the platform has none.
        std::string server_member = std::string(kPlatform) + "usr/bin/swift-plugin-server";
        if (!fs::is_regular_file(work / "xcode-tree" / fs::path(Win32Process::ToWide(server_member))))
            server_member = toolchain + "usr/bin/swift-plugin-server";
        const auto server = work / "xcode-tree" / fs::path(Win32Process::ToWide(server_member));
        Need(fs::is_regular_file(server), "The Xcode archive has no swift-plugin-server.");
        const auto xcode_build = PlistFileString(work / "xcode-tree" / "Xcode.app" / "Contents" / "version.plist", "ProductBuildVersion");
        const auto toolchain_id = PlistFileString(work / "xcode-tree" / fs::path(Win32Process::ToWide(toolchain + "ToolchainInfo.plist")), "Identifier");

        auto selection = JsonValue::ObjectValue();
        selection.Set("sdk", JsonValue::String(Rel(managed, sdk)));
        selection.Set("sdk_settings_sha256", JsonValue::String(Sha256File(sdk / "SDKSettings.json").value_or("")));
        selection.Set("archive_sha256", JsonValue::String(Sha256File(archive).value_or("")));
        selection.Set("xcode_build", JsonValue::String(xcode_build));
        selection.Set("toolchain_identifier", JsonValue::String(toolchain_id));
        auto executable = JsonValue::ObjectValue();
        executable.Set("virtual_path", JsonValue::String("/" + server_member));
        executable.Set("member", JsonValue::String(Rel(managed, original / fs::path(Win32Process::ToWide(server_member)))));
        executable.Set("sha256", JsonValue::String(Sha256File(server).value_or("")));
        auto trees = JsonValue::ArrayValue();
        trees.ArrayItems().push_back(JsonValue::String(Rel(managed, original)));
        trees.ArrayItems().push_back(JsonValue::String(Rel(managed, system)));
        auto plugin_directories = JsonValue::ArrayValue();
        // Search precedence: the selected platform's plugins before the toolchain's.
        for (const auto& directory : {std::string(kPlatformPlugins).substr(0, std::string(kPlatformPlugins).size() - 1), toolchain + "usr/lib/swift/host/plugins"})
            if (fs::is_directory(work / "xcode-tree" / fs::path(Win32Process::ToWide(directory))))
                plugin_directories.ArrayItems().push_back(JsonValue::String("/" + directory));
        auto cache = JsonValue::ObjectValue();
        auto report_imports = JsonValue::ArrayValue();
        const auto add_report = [&](const fs::path& source, const std::string& name) {
            auto mapping = JsonValue::ObjectValue();
            mapping.Set("source", JsonValue::String(Text(source)));
            mapping.Set("destination", JsonValue::String(Rel(managed, reports / name)));
            report_imports.ArrayItems().push_back(std::move(mapping));
            return reports / name;
        };
        cache.Set("parent", CacheDescriptor(managed, parent_record, add_report(parent_record, "parent.json"), parent));
        auto child_descriptors = JsonValue::ArrayValue();
        for (std::size_t index = 0; index < children.size(); ++index)
            child_descriptors.ArrayItems().push_back(CacheDescriptor(managed, children[index].first,
                add_report(children[index].first, "child-" + std::to_string(index) + ".json"), children[index].second));
        cache.Set("children", std::move(child_descriptors));
        auto provenance = JsonValue::ObjectValue();
        provenance.Set("restore_image", image);
        provenance.Set("acquisition", JsonValue::String("openfruit.darwin-provider-acquisition.v1"));

        auto receipt = JsonValue::ObjectValue();
        receipt.Set("schema", JsonValue::String("openfruit.darwin-provider.v1"));
        receipt.Set("path_anchor", JsonValue::String("managed-home"));
        receipt.Set("selection", std::move(selection));
        receipt.Set("executable", std::move(executable));
        receipt.Set("original_trees", std::move(trees));
        receipt.Set("original_files", std::move(files));
        receipt.Set("plugin_directories", std::move(plugin_directories));
        receipt.Set("cache", std::move(cache));
        receipt.Set("provenance", std::move(provenance));
        auto tree_imports = JsonValue::ArrayValue();
        for (const auto& [source, destination] : {std::pair{work / "xcode-tree", original}, std::pair{system_tree, system}}) {
            auto mapping = JsonValue::ObjectValue();
            mapping.Set("source", JsonValue::String(Text(source)));
            mapping.Set("destination", JsonValue::String(Rel(managed, destination)));
            tree_imports.ArrayItems().push_back(std::move(mapping));
        }
        auto specification = JsonValue::ObjectValue();
        specification.Set("schema", JsonValue::String("openfruit.darwin-provider-import.v1"));
        specification.Set("receipt", std::move(receipt));
        specification.Set("original_trees", std::move(tree_imports));
        specification.Set("cache_reports", std::move(report_imports));
        const auto specification_path = work / "import-specification.json";
        WriteJsonFile(specification_path, specification);
        std::string error;
        Need(ImportDarwinMacroProvider(specification_path, managed, sdk, error), "Provider import failed: " + error);

        // The provider owns its trees, reports and cache payloads now; the
        // encrypted/decoded restore images and staging trees are disposable.
        for (const auto& entry : fs::directory_iterator(work)) {
            if (entry.path().filename() == ".lock") continue;
            std::error_code ignored; fs::remove_all(entry.path(), ignored);
        }
        log << "OPENFRUIT: original Darwin macro provider published.\n" << std::flush;
        result.succeeded = true;
        span.Succeed();
    } catch (const std::exception& failure) {
        result.message = failure.what();
    }
    return result;
}

} // namespace OpenFruit
