#include "sdk_target_runtime.hpp"
#include "tool_paths.hpp"
#include "sdk_runtime_abi.hpp"
#include "archive_tree_extraction.hpp"
#include "atomic_file.hpp"
#include "artifact_store.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cwctype>
#include <fstream>
#include <set>
#include <thread>
namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
std::string Bytes(const fs::path& p) { std::ifstream f(p, std::ios::binary); return {std::istreambuf_iterator<char>(f), {}}; }
std::string Fold(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}
fs::path RelativeTail(const fs::path& root, const fs::path& path) {
    auto item = path.begin();
    for (auto ignored = root.begin(); ignored != root.end(); ++ignored) ++item;
    fs::path tail;
    for (; item != path.end(); ++item) tail /= *item;
    return tail;
}
bool Within(const fs::path& root, const fs::path& path) {
    auto a = fs::weakly_canonical(root), b = fs::weakly_canonical(path);
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
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~Handle() { if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h); }
};
struct Controls {
    CancellationSource source;
    ProcessRunOptions process;
    std::jthread watcher;
    Controls() {
        process.cancellation = std::make_shared<std::atomic<bool>>(false);
        const auto context = CurrentOperationContext();
        process.deadline = context && context->control ? context->control->deadline :
            std::chrono::steady_clock::now() + std::chrono::hours(4);
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
    Handle mutex;
    bool held = false;
    Lease(const std::string& key, const Controls& controls) {
        const auto name = L"Local\\OPENFRUIT-ios-runtime-" + Win32Process::ToWide(key);
        mutex.h = CreateMutexW(nullptr, FALSE, name.c_str());
        while (mutex.h && controls.Active()) {
            const auto status = WaitForSingleObject(mutex.h, 100);
            if (status == WAIT_OBJECT_0 || status == WAIT_ABANDONED) { held = true; return; }
            if (status != WAIT_TIMEOUT) return;
        }
    }
    ~Lease() { if (held) ReleaseMutex(mutex.h); }
};
bool Authenticated(const XipReadResult& r) {
    return r.status == XipStatus::Completed && r.toc_checksum_verified && r.content_checksum_verified &&
        r.xar_signature_valid && r.apple_signing_chain_valid && r.apple_revocation_valid;
}
bool Regular(const fs::path& p) { return fs::symlink_status(p).type() == fs::file_type::regular; }
bool Digest(const std::string& value) {
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}
std::optional<std::string> RuntimeKey(const std::string& archive_sha, const std::string& sdk_sha,
    const std::string& tool_sha, const std::string& readobj_sha, const std::string& deployment) {
    return Sha256("apple-ios-runtime-v1\nopenfruit.ios-runtime-archive-abi.v1\n" + archive_sha +
        "\n" + sdk_sha + "\n" + tool_sha + "\n" + readobj_sha + "\n" + deployment);
}
bool ValidReceipt(const fs::path& destination, const std::string& key, Controls& controls, JsonValue& receipt) {
    if (!fs::is_directory(destination / "lib") || !fs::is_regular_file(destination / "receipt.json")) return false;
    const auto parsed = JsonValue::Parse(Bytes(destination / "receipt.json"));
    if (!parsed || parsed->GetString("key") != key || parsed->GetString("schema") != "apple-ios-runtime-v1") return false;
    const auto* extraction = parsed->Get("extraction");
    if (!extraction || !extraction->Get("toc_checksum_verified") || !extraction->Get("toc_checksum_verified")->Bool() ||
        !extraction->Get("content_checksum_verified") || !extraction->Get("content_checksum_verified")->Bool() ||
        !extraction->Get("xar_signature_valid") || !extraction->Get("xar_signature_valid")->Bool() ||
        !extraction->Get("apple_signing_chain_valid") || !extraction->Get("apple_signing_chain_valid")->Bool() ||
        !extraction->Get("apple_revocation_valid") || !extraction->Get("apple_revocation_valid")->Bool()) return false;
    const auto* libraries = parsed->Get("libraries");
    if (!libraries || !libraries->IsArray() || libraries->ArrayItems().empty()) return false;
    std::set<std::string> names;
    for (const auto& item : libraries->ArrayItems()) {
        const auto name = item.GetString("name");
        if (name.empty() || fs::path(name).filename().string() != name || !names.insert(name).second) return false;
        const auto path = destination / "lib" / name;
        if (!Within(destination, path) || !Regular(path)) return false;
        const auto digest = Sha256FileStatCached(path, ToolPaths::FileDigestCache(), controls.process.deadline);
        if (!digest || *digest != item.GetString("sha256")) return false;
    }
    std::size_t actual = 0;
    for (const auto& entry : fs::directory_iterator(destination / "lib")) {
        if (!Regular(entry.path()) || !names.contains(entry.path().filename().string())) return false;
        ++actual;
    }
    if (actual != names.size()) return false;
    receipt = *parsed;
    return controls.Active();
}
}
IosTargetRuntimeResult EnsureIosTargetRuntime(const fs::path& sdk_path, const fs::path& llvm_bin,
    const std::string& deployment_target, const fs::path& managed_home) {
    IosTargetRuntimeResult result;
    OperationSpan span("sdk.target_runtime.acquire");
    auto fail = [&](std::string message) {
        result.available = false;
        result.library_directories.clear();
        result.artifact_lease.reset();
        result.error = std::move(message);
        result.evidence.Set("error", JsonValue::String(result.error));
        span.Complete(result.evidence, false);
        return result;
    };
    try {
        Controls controls;
        if (!controls.Active()) return fail("iOS target runtime acquisition cancelled or timed out.");
        const auto parent = fs::weakly_canonical(managed_home / "sdk" / "xcode");
        const auto sdk = fs::weakly_canonical(sdk_path);
        if (!Within(parent, sdk)) return fail("Selected SDK has no paired managed Apple XIP archive.");
        const auto relative = RelativeTail(parent, sdk);
        auto part = relative.begin();
        if (part == relative.end()) return fail("Selected SDK has no archive identity.");
        const auto identity = Fold(part->string());
        if (identity.size() != 64 || identity.find_first_not_of("0123456789abcdef") != std::string::npos)
            return fail("Managed SDK archive identity is invalid.");
        const auto xcode_root = parent / identity;
        auto sdk_member = RelativeTail(xcode_root, sdk).generic_string() + "/SDKSettings.json";
        const auto archive = managed_home / "cache" / "sdk-downloads" / (identity + ".download");
        // Keep every input that determines the receipt locked through tool
        // execution and publication, not merely while calculating its hash.
        std::vector<std::unique_ptr<Handle>> input_leases;
        for (const auto& input : {sdk / "SDKSettings.json", llvm_bin / "llvm-objdump.exe", llvm_bin / "llvm-readobj.exe"}) {
            if (!Regular(input)) return fail("Runtime acquisition/reuse requires a regular SDK/tool input: " +
                input.generic_string() + (Regular(archive) ? "." : "; paired Apple XIP unavailable."));
            auto input_lease = std::make_unique<Handle>();
            input_lease->h = CreateFileW(input.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (input_lease->h == INVALID_HANDLE_VALUE) return fail("Runtime acquisition input cannot be leased against mutation.");
            input_leases.push_back(std::move(input_lease));
        }
        const auto sdk_sha = Sha256FileStatCached(sdk / "SDKSettings.json", ToolPaths::FileDigestCache(), controls.process.deadline);
        const auto tool_sha = Sha256FileStatCached(llvm_bin / "llvm-objdump.exe", ToolPaths::FileDigestCache(), controls.process.deadline);
        const auto readobj_sha = Sha256FileStatCached(llvm_bin / "llvm-readobj.exe", ToolPaths::FileDigestCache(), controls.process.deadline);
        if (!sdk_sha || !tool_sha || !readobj_sha) return fail("Runtime acquisition input identity could not be verified.");
        const auto root = managed_home / "toolchains" / "apple-ios";
        // A bound receipt records a prior authenticated archive/SDK pairing.
        // Revalidate all current inputs, its content key and every published
        // library before reuse. Legacy receipts require the archive once to bind.
        auto matches = [&](const JsonValue& receipt, const fs::path& destination) {
            const auto archive_digest = receipt.GetString("archive_sha256");
            if (!Digest(archive_digest) || receipt.GetString("sdk_archive_identity") != identity ||
                Fold(receipt.GetString("sdk_settings_member")) != Fold(sdk_member) ||
                receipt.GetString("sdk_settings_sha256") != *sdk_sha ||
                receipt.GetString("llvm_objdump_sha256") != *tool_sha ||
                receipt.GetString("llvm_readobj_sha256") != *readobj_sha ||
                receipt.GetString("deployment_target") != deployment_target) return false;
            const auto expected = RuntimeKey(archive_digest, *sdk_sha, *tool_sha, *readobj_sha, deployment_target);
            return expected && receipt.GetString("key") == *expected && destination.filename().string() == *expected;
        };
        const auto pin_bound = [&](const fs::path& destination, bool archive_free) {
            if (!Within(managed_home, destination) ||
                fs::symlink_status(destination).type() != fs::file_type::directory) return false;
            const auto marker = fs::path(destination.wstring() + L".import-lock");
            if (!fs::exists(marker)) {
                // Migrate only a fully verified publication to the existing
                // consumer protocol; never infer ownership from its path.
                JsonValue prior;
                if (!ValidReceipt(destination, destination.filename().string(), controls, prior) ||
                    !matches(prior, destination)) return false;
                auto initial = ArtifactLease::Acquire(destination, controls.process);
                JsonValue verified;
                if (!ValidReceipt(destination, destination.filename().string(), controls, verified) ||
                    !matches(verified, destination)) return false;
            }
            auto reader = ArtifactLease::AcquireSharedRead(destination, controls.process);
            JsonValue verified;
            // Writer -> reader is intentionally not an atomic upgrade. Check
            // every output again while the reader excludes replacement/prune.
            if (!ValidReceipt(destination, destination.filename().string(), controls, verified) ||
                !matches(verified, destination)) return false;
            result.evidence = std::move(verified);
            if (archive_free) result.evidence.Set("reused_without_archive", JsonValue::Boolean(true));
            result.artifact_lease = std::move(reader);
            result.library_directories = {destination / "lib"};
            result.available = true;
            span.Complete(result.evidence, true);
            return true;
        };
        std::vector<fs::path> candidates;
        if (fs::is_directory(root) && fs::symlink_status(root).type() == fs::file_type::directory && Within(managed_home, root)) {
            for (const auto& entry : fs::directory_iterator(root)) {
                if (!controls.Active()) return fail("Runtime reuse cancelled or timed out.");
                if (entry.symlink_status().type() != fs::file_type::directory ||
                    !Digest(entry.path().filename().string()) || !Within(root, entry.path()) ||
                    !Regular(entry.path() / "receipt.json")) continue;
                const auto parsed = JsonValue::Parse(Bytes(entry.path() / "receipt.json"));
                if (parsed && matches(*parsed, entry.path())) candidates.push_back(entry.path());
            }
        }
        // Multiple source-container identities for the same SDK are ambiguous;
        // use the actual paired archive to select, rather than choosing by age.
        if (candidates.size() == 1) {
            const auto& destination = candidates.front();
            const auto lease_key = Sha256(Fold(fs::weakly_canonical(destination).generic_string()));
            if (!lease_key) return fail("Runtime reuse lease identity unavailable.");
            Lease lease(*lease_key, controls);
            if (!lease.held) return fail("Runtime reuse lease cancelled or timed out.");
            if (pin_bound(destination, true)) return result;
        }
        if (!Within(managed_home, archive) || !Regular(archive)) return fail("Original paired Apple XIP is unavailable; no unique verified bound runtime is reusable.");
        Handle original;
        original.h = CreateFileW(archive.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (original.h == INVALID_HANDLE_VALUE) return fail("Original Apple XIP cannot be leased against mutation.");
        const auto archive_sha = Sha256FileHandleStatCached(original.h, ToolPaths::FileDigestCache(), controls.source.Token(), controls.process.deadline);
        if (!archive_sha) return fail("Runtime archive identity could not be verified.");
        const auto key = RuntimeKey(*archive_sha, *sdk_sha, *tool_sha, *readobj_sha, deployment_target);
        if (!key) return fail("Runtime acquisition key could not be generated.");
        const auto destination = root / *key;
        if (!Within(managed_home, destination)) return fail("Runtime publication escaped managed storage.");
        const auto lease_key = Sha256(Fold(fs::weakly_canonical(destination).generic_string()));
        if (!lease_key) return fail("Runtime publication lease identity unavailable.");
        Lease lease(*lease_key, controls);
        if (!lease.held) return fail("Runtime publication lease cancelled or timed out.");
        // Exact archive selection can disambiguate an already bound output.
        // Keep using readers in that case; existing consumers may still own it.
        if (pin_bound(destination, false)) return result;
        if (ValidReceipt(destination, *key, controls, result.evidence) &&
            result.evidence.GetString("archive_sha256") == *archive_sha &&
            result.evidence.GetString("sdk_settings_sha256") == *sdk_sha &&
            result.evidence.GetString("llvm_objdump_sha256") == *tool_sha &&
            result.evidence.GetString("llvm_readobj_sha256") == *readobj_sha &&
            result.evidence.GetString("deployment_target") == deployment_target) {
            auto publisher = ArtifactLease::Acquire(destination, controls.process);
            if (!ValidReceipt(destination, *key, controls, result.evidence) ||
                result.evidence.GetString("archive_sha256") != *archive_sha ||
                result.evidence.GetString("sdk_settings_sha256") != *sdk_sha ||
                result.evidence.GetString("llvm_objdump_sha256") != *tool_sha ||
                result.evidence.GetString("llvm_readobj_sha256") != *readobj_sha ||
                result.evidence.GetString("deployment_target") != deployment_target)
                return fail("Runtime changed before source binding publication.");
            result.evidence.Set("sdk_archive_identity", JsonValue::String(identity));
            result.evidence.Set("sdk_settings_member", JsonValue::String(sdk_member));
            if (!AtomicFile::Publish(destination / "receipt.json", result.evidence.Serialize(true)))
                return fail("Verified runtime source binding could not be published.");
            publisher.reset();
            if (!pin_bound(destination, false)) return fail("Runtime changed before consumer lease validation.");
            return result;
        }
        const auto staging = root / "_staging" / NewOperationId();
        fs::create_directories(staging.parent_path());
        if (!Within(managed_home, staging)) return fail("Runtime staging escaped managed storage.");
        std::vector<std::string> selected;
        // Every original target archive an authenticated walk of this XIP
        // selects is kept once per archive and SDK pairing, whatever the
        // deployment target; eligibility is decided below for each target.
        const auto sources_key = Sha256("apple-ios-runtime-sources-v1\n" + *archive_sha + "\n" + Fold(sdk_member));
        if (!sources_key) return fail("Runtime source identity unavailable.");
        const auto sources = root / "_sources" / *sources_key;
        if (!Within(managed_home, sources)) return fail("Runtime sources escaped managed storage.");
        const auto sources_lease_key = Sha256(Fold(fs::weakly_canonical(sources).generic_string()));
        if (!sources_lease_key) return fail("Runtime source lease identity unavailable.");
        Lease sources_lease(*sources_lease_key, controls);
        if (!sources_lease.held) return fail("Runtime source lease cancelled or timed out.");
        fs::path member_root = staging;
        JsonValue extraction_evidence;
        bool reused_sources = false;
        if (fs::symlink_status(sources).type() == fs::file_type::directory && Regular(sources / "sources.json")) {
            const auto recorded = JsonValue::Parse(Bytes(sources / "sources.json"));
            const auto* recorded_extraction = recorded ? recorded->Get("extraction") : nullptr;
            const auto* members = recorded ? recorded->Get("members") : nullptr;
            const auto flag = [&](const char* name) {
                const auto* value = recorded_extraction ? recorded_extraction->Get(name) : nullptr;
                return value && value->Bool();
            };
            bool valid = recorded && recorded->GetString("schema") == "apple-ios-runtime-sources-v1" &&
                recorded->GetString("key") == *sources_key && recorded->GetString("archive_sha256") == *archive_sha &&
                recorded->GetString("sdk_settings_sha256") == *sdk_sha &&
                Fold(recorded->GetString("sdk_settings_member")) == Fold(sdk_member) &&
                flag("toc_checksum_verified") && flag("content_checksum_verified") && flag("xar_signature_valid") &&
                flag("apple_signing_chain_valid") && flag("apple_revocation_valid") &&
                members && members->IsArray() && !members->ArrayItems().empty();
            std::vector<std::string> recorded_members;
            if (valid) {
                for (const auto& item : members->ArrayItems()) {
                    const auto member = item.GetString("member");
                    const auto path = sources / fs::path(member);
                    const auto digest = member.empty() || !Within(sources, path) || !Regular(path)
                        ? std::nullopt : Sha256FileStatCached(path, ToolPaths::FileDigestCache(), controls.process.deadline);
                    if (!digest || *digest != item.GetString("sha256")) { valid = false; break; }
                    recorded_members.push_back(member);
                }
            }
            if (valid && controls.Active()) {
                selected = std::move(recorded_members);
                sdk_member = recorded->GetString("sdk_settings_member");
                extraction_evidence = *recorded_extraction;
                member_root = sources;
                reused_sources = true;
            }
        }
        if (!reused_sources) {
        XipInventory inventory;
        ArchiveExtractionOptions options;
        options.read.cancellation = controls.source.Token(); options.read.deadline = controls.process.deadline;
        options.max_written_bytes = 128ull * 1024 * 1024;
        const auto extracted = ArchiveTreeExtraction::Extract(archive, staging,
            [&](const fs::path& source, const XipReadOptions& read) {
                XipInventoryOptions inventory_options; inventory_options.read = read;
                // One full authenticated walk. Retain SDKSettings metadata too,
                // resolving Windows path aliases to the archive's exact case.
                inventory = XipInventory::Inspect(source, "", inventory_options);
                ArchiveTreeSelection selection;
                if (!Authenticated(inventory.read)) { selection.status = ArchiveExtractionStatus::ArchiveFailure; selection.diagnostic_code = "ios.runtime.archive_not_authenticated"; return selection; }
                const auto slash = Fold(sdk_member).find("/contents/");
                if (slash == std::string::npos) { selection.status = ArchiveExtractionStatus::MissingSelection; return selection; }
                const auto toolchain_prefix = Fold(sdk_member.substr(0, slash) + "/Contents/Developer/Toolchains/");
                std::string paired_member;
                for (const auto& member : inventory.members) {
                    const auto path = fs::path(member.entry.path).lexically_normal().generic_string();
                    if (Fold(path) == Fold(sdk_member)) {
                        if (!paired_member.empty()) { selection.status = ArchiveExtractionStatus::UnsafePath; return selection; }
                        paired_member = path;
                    }
                    if (Fold(path).starts_with(toolchain_prefix) && path.find("/usr/lib/swift/iphoneos/") != std::string::npos &&
                        fs::path(path).extension() == ".a") selected.push_back(path);
                }
                if (paired_member.empty()) { selection.status = ArchiveExtractionStatus::MissingSelection; selection.diagnostic_code = "ios.runtime.sdk_pair_missing"; return selection; }
                sdk_member = paired_member;
                if (selected.empty()) { selection.status = ArchiveExtractionStatus::MissingSelection; selection.diagnostic_code = "ios.runtime.no_target_archives"; return selection; }
                selection.member_paths = selected; selection.member_paths.push_back(sdk_member); return selection;
            }, options);
        if (!extracted.Succeeded() || !extracted.toc_checksum_verified || !extracted.content_checksum_verified ||
            !extracted.xar_signature_valid || !extracted.apple_signing_chain_valid || !extracted.apple_revocation_valid)
            return fail("Original runtime extraction failed authentication: " + extracted.diagnostic_code);
        const auto paired_sha = Sha256File(staging / fs::path(sdk_member), controls.source.Token(), controls.process.deadline);
        if (!paired_sha || *paired_sha != *sdk_sha) return fail("Selected SDKSettings bytes do not match the original XIP SDK.");
        extraction_evidence = extracted.ToJson();
        // Keep the authenticated originals for other deployment targets. A
        // failure here only costs a later target this extraction again.
        try {
            const auto pending = root / "_staging" / ("sources-" + NewOperationId());
            JsonValue members = JsonValue::ArrayValue();
            bool copied_all = true;
            for (const auto& member : selected) {
                const auto from = staging / fs::path(member), to = pending / fs::path(member);
                const auto digest = Sha256File(from, controls.source.Token(), controls.process.deadline);
                if (!digest) { copied_all = false; break; }
                fs::create_directories(to.parent_path());
                fs::copy_file(from, to);
                if (Sha256File(to, controls.source.Token(), controls.process.deadline) != digest) { copied_all = false; break; }
                JsonValue item = JsonValue::ObjectValue();
                item.Set("member", JsonValue::String(member)); item.Set("sha256", JsonValue::String(*digest));
                members.ArrayItems().push_back(std::move(item));
            }
            JsonValue recorded = JsonValue::ObjectValue();
            recorded.Set("schema", JsonValue::String("apple-ios-runtime-sources-v1"));
            recorded.Set("key", JsonValue::String(*sources_key));
            recorded.Set("archive_sha256", JsonValue::String(*archive_sha));
            recorded.Set("sdk_settings_member", JsonValue::String(sdk_member));
            recorded.Set("sdk_settings_sha256", JsonValue::String(*sdk_sha));
            recorded.Set("extraction", extraction_evidence);
            recorded.Set("members", std::move(members));
            std::error_code ignored;
            if (copied_all && AtomicFile::Publish(pending / "sources.json", recorded.Serialize(true))) {
                if (fs::exists(sources)) fs::rename(sources, root / "_staging" / ("invalid-" + NewOperationId()), ignored);
                fs::create_directories(sources.parent_path(), ignored);
                fs::rename(pending, sources, ignored);
            }
            if (fs::exists(pending)) fs::remove_all(pending, ignored);
        } catch (const std::exception&) {}
        }
        JsonValue libraries = JsonValue::ArrayValue(), rejected = JsonValue::ArrayValue();
        const auto publication = staging / "publication";
        fs::create_directories(publication / "lib");
        std::set<std::string> names;
        for (const auto& member : selected) {
            if (!controls.Active()) return fail("Runtime inspection cancelled or timed out.");
            const auto path = member_root / fs::path(member);
            if (!Within(member_root, path) || !Regular(path)) return fail("Extracted runtime is not a regular original file.");
            auto inspection = InspectIosRuntimeArchive(path, llvm_bin, deployment_target, controls.process);
            JsonValue record = JsonValue::ObjectValue();
            record.Set("member", JsonValue::String(member)); record.Set("inspection", inspection.evidence);
            if (!inspection.eligible) { record.Set("error", JsonValue::String(inspection.error)); rejected.ArrayItems().push_back(record); continue; }
            const auto name = path.filename().string();
            if (!names.insert(name).second) return fail("Multiple toolchains expose ambiguous target runtime archive names.");
            const auto digest = Sha256File(path, controls.source.Token(), controls.process.deadline);
            if (!digest) return fail("Original target archive digest unavailable.");
            fs::copy_file(path, publication / "lib" / name);
            const auto copied = Sha256File(publication / "lib" / name, controls.source.Token(), controls.process.deadline);
            if (!copied || *copied != *digest) return fail("Target runtime publication copy failed digest verification.");
            record.Set("name", JsonValue::String(name)); record.Set("sha256", JsonValue::String(*digest));
            libraries.ArrayItems().push_back(record);
        }
        if (libraries.ArrayItems().empty()) return fail("Original archive contains no eligible iOS ARM64 target runtime libraries.");
        JsonValue receipt = JsonValue::ObjectValue();
        receipt.Set("schema", JsonValue::String("apple-ios-runtime-v1")); receipt.Set("key", JsonValue::String(*key));
        receipt.Set("sdk_archive_identity", JsonValue::String(identity));
        receipt.Set("sdk_settings_member", JsonValue::String(sdk_member));
        receipt.Set("archive_sha256", JsonValue::String(*archive_sha)); receipt.Set("sdk_settings_sha256", JsonValue::String(*sdk_sha));
        receipt.Set("llvm_objdump_sha256", JsonValue::String(*tool_sha));
        receipt.Set("llvm_readobj_sha256", JsonValue::String(*readobj_sha));
        receipt.Set("deployment_target", JsonValue::String(deployment_target)); receipt.Set("libraries", libraries); receipt.Set("rejected", rejected);
        receipt.Set("extraction", extraction_evidence);
        if (reused_sources) receipt.Set("reused_authenticated_sources", JsonValue::String(*sources_key));
        if (!controls.Active() || Sha256File(sdk / "SDKSettings.json", controls.source.Token(), controls.process.deadline) != sdk_sha)
            return fail("SDK changed or acquisition cancelled before publication.");
        auto publisher = ArtifactLease::Acquire(destination, controls.process);
        if (fs::exists(destination)) fs::rename(destination, root / "_staging" / ("invalid-" + NewOperationId()));
        fs::rename(publication, destination);
        if (!AtomicFile::Publish(destination / "receipt.json", receipt.Serialize(true))) return fail("Runtime receipt publication failed.");
        publisher.reset();
        if (!pin_bound(destination, false)) return fail("Published runtime failed consumer lease validation.");
        return result;
    } catch (const std::exception& exception) { return fail("iOS target runtime acquisition failed: " + std::string(exception.what())); }
}
}
