#include "git_source_view.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out << bytes;
    Require(static_cast<bool>(out), "fixture write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    Require(static_cast<bool>(in), "fixture read failed");
    return {(std::istreambuf_iterator<char>(in)), {}};
}
std::string Git(const fs::path& root, std::vector<std::wstring> args) {
    args.insert(args.begin(), {L"git.exe", L"-C", root.wstring()});
    const auto result = Win32Process::Run(L"git.exe", args);
    Require(result.success && !result.output_truncated, "fixture Git command failed");
    return result.std_out;
}
void Link(const fs::path& root, const fs::path& name, const std::string& target) {
    Write(root / name, target);
    auto oid = Git(root, {L"hash-object", L"-w", (root / name).wstring()});
    while (!oid.empty() && (oid.back() == '\n' || oid.back() == '\r')) oid.pop_back();
    Git(root, {L"update-index", L"--add", L"--cacheinfo", L"120000",
               Win32Process::ToWide(oid), name.wstring()});
}
std::uint64_t AliasWriteTime(const fs::path& path, bool set_old = false) {
    const HANDLE handle = CreateFileW(path.c_str(), set_old ? FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES : FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    Require(handle != INVALID_HANDLE_VALUE, "cannot inspect native alias timestamp");
    bool updated = true;
    if (set_old) {
        const std::uint64_t value = 132537600000000000ULL;
        const FILETIME old{static_cast<DWORD>(value), static_cast<DWORD>(value >> 32)};
        updated = SetFileTime(handle, nullptr, nullptr, &old) != FALSE;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    const bool read = GetFileInformationByHandle(handle, &info) != FALSE;
    CloseHandle(handle);
    Require(updated && read, "cannot read or set native alias timestamp");
    return (static_cast<std::uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
}

bool NativeLink(const fs::path& link, const fs::path& target, bool directory) {
    const DWORD flags = directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
    if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags | 0x2)) return true;
    DWORD error = GetLastError();
    if (error == ERROR_INVALID_PARAMETER) {
        if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags)) return true;
        error = GetLastError();
    }
    if (error == ERROR_PRIVILEGE_NOT_HELD) {
        std::cerr << "SKIP native symlink subcase: Windows symlink privilege unavailable\n";
        return false;
    }
    throw std::runtime_error("native symlink fixture creation failed: " + std::to_string(error));
}
void Rejected(const fs::path& root, const fs::path& destination, const char* reason,
              const ProcessRunOptions& control = {}) {
    bool rejected = false;
    try { CreateGitSourceView(root, destination, control); }
    catch (const std::exception& error) {
        rejected = std::string(error.what()).find(reason) != std::string::npos;
    }
    Require(rejected, "wrong or missing rejection");
    Require(!fs::exists(destination), "failed view was published");
    for (const auto& item : fs::directory_iterator(destination.parent_path()))
        Require(item.path().filename().wstring().find(destination.filename().wstring() + L".pending-") != 0,
                "staging directory leaked");
}
void TestOptionalMetadataResolution(const fs::path& root) {
    const auto source = root / "optional-metadata";
    Write(source / "Config/Real.xcconfig", "VALUE = original\n");
    Write(source / "ordinary.xcconfig", "Config/Real.xcconfig");
    Git(source, {L"init", L"--quiet"});
    Git(source, {L"config", L"core.symlinks", L"false"});
    Git(source, {L"add", L"."});
    Link(source, "alias", "Config");
    Link(source, "broken", "absent-directory");
    Link(source, "missing-placeholder", "Config/Real.xcconfig");
    fs::remove(source / "missing-placeholder");
    Link(source, "cycle", "cycle");
    Link(source, "escape", "../outside");
    const bool native_broken = NativeLink(source / "native-broken", "native-target-absent", false);
    const auto original_status = Git(source, {L"status", L"--porcelain", L"-z"});
    Require(!TryResolveGitSourcePath(source, source / "optional-absent.xcconfig"),
        "Ordinary optional absence was not represented as nullopt");
    Require(!TryResolveGitSourcePath(source, source / "alias/optional-absent.xcconfig"),
        "Missing child below a valid directory alias was mistaken for a broken link target");
    Require(TryResolveGitSourcePath(source, fs::path("Config/Real.xcconfig")) == source / "Config/Real.xcconfig",
        "Relative optional metadata resolved through process CWD instead of its source root");
    Require(TryResolveGitSourcePath(source, source / "ordinary.xcconfig") == source / "ordinary.xcconfig" &&
        Read(source / "ordinary.xcconfig") == "Config/Real.xcconfig",
        "A short ordinary metadata file was interpreted as a link");
    const auto error = [&](const fs::path& path, const ProcessRunOptions& control = {}) {
        try { (void)TryResolveGitSourcePath(source, path, control); }
        catch (const std::exception&) { return true; }
        return false;
    };
    Require(error(source / "broken/optional-absent.xcconfig"),
        "Broken indexed directory target was hidden as optional absence");
    Require(error(source / "missing-placeholder"), "Missing indexed placeholder was hidden as optional absence");
    Require(error(source / "cycle"), "Optional metadata accepted a link cycle");
    Require(error(source / "escape"), "Optional metadata accepted source escape");
    ProcessRunOptions cancelled;
    cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
    Require(error(source / "optional-absent.xcconfig", cancelled), "Cancellation was hidden as optional absence");
    ProcessRunOptions expired;
    expired.deadline = std::chrono::steady_clock::now();
    Require(error(source / "optional-absent.xcconfig", expired), "Deadline was hidden as optional absence");
    if (native_broken)
        Require(error(source / "native-broken"), "Broken native link was hidden as optional absence");
    Require(Read(source / "alias") == "Config" && Read(source / "broken") == "absent-directory" &&
        Read(source / "Config/Real.xcconfig") == "VALUE = original\n" &&
        !fs::exists(source / "optional-absent.xcconfig"), "Optional metadata lookup mutated original inputs");
    (void)TryResolveGitSourcePath(source, source / "alias/optional-absent.xcconfig");
    Require(original_status == Git(source, {L"status", L"--porcelain", L"-z"}), "Optional lookup changed Git state");
}

void TestPhysicalRootSpelling(const fs::path& root) {
    const auto source = root / "case-root";
    const auto alias = root / "CASE-ROOT";
    Write(source / "folder/value.txt", "inside\n");
    const auto canonical_source = fs::canonical(source);
    const auto expected = canonical_source / "folder/value.txt";
    // These paths refer to the same directory on the ordinary Windows temp
    // volume. If the host uses inherited case sensitivity this positive case
    // is unavailable, rather than evidence of a failed identity comparison.
    std::error_code error;
    if (fs::canonical(alias, error) == canonical_source && !error) {
        Require(ResolveGitSourcePath(source, alias / "folder/value.txt") == expected,
            "A physically identical uppercase root spelling was rejected");
        Require(TryResolveGitSourcePath(alias, alias / "folder/value.txt") == expected,
            "Optional lookup did not rebase a physically identical root spelling");
        Require(!TryResolveGitSourcePath(source, alias / "folder/absent.txt"),
            "Optional absence below a root spelling alias was rejected");
        // Retain raw suffix order through a true directory link: expanding the
        // target before '..' selects source/other/value.txt, not source/value.txt.
        Write(source / "other/nested/owned.txt", "nested\n");
        Write(source / "other/value.txt", "after expansion\n");
        Write(source / "value.txt", "wrong normalized lookup\n");
        if (NativeLink(source / "dir-alias", "other/nested", true)) {
            Require(ResolveGitSourcePath(source, alias / "dir-alias/../value.txt") ==
                canonical_source / "other/value.txt", "Root rebasing normalized '..' before directory-link expansion");
        }
    } else std::cerr << "SKIP uppercase-root positive case: temp root is case-sensitive\n";
    const auto other = root / "different-root";
    Write(other / "value.txt", "outside\n");
    if (NativeLink(root / "wrong-root", "different-root", true)) {
        bool refused = false;
        try { (void)TryResolveGitSourcePath(source, root / "wrong-root/value.txt"); }
        catch (const std::exception&) { refused = true; }
        Require(refused, "A native root alias resolving to another sibling escaped source containment");
    }
    // fsutil changes only this fresh empty owned fixture directory. The host
    // may require privileges or filesystem support; report an unavailable
    // negative control explicitly and never infer success from that skip.
    const auto parent = root / "case-sensitive-parent";
    fs::create_directory(parent);
    const auto enabled = Win32Process::Run(L"fsutil.exe", {L"fsutil.exe", L"file",
        L"setCaseSensitiveInfo", parent.wstring(), L"enable"});
    if (enabled.success) {
        const auto lower = parent / "owned";
        const auto upper = parent / "OWNED";
        Write(lower / "value.txt", "inside\n");
        Write(upper / "value.txt", "outside\n");
        Require(fs::canonical(lower) != fs::canonical(upper) && !fs::equivalent(lower, upper),
            "Case-sensitive fixture did not create distinct case siblings");
        bool refused = false;
        try { (void)TryResolveGitSourcePath(lower, upper / "value.txt"); }
        catch (const std::exception&) { refused = true; }
        Require(refused && Read(lower / "value.txt") == "inside\n" && Read(upper / "value.txt") == "outside\n",
            "Case-sensitive sibling was admitted by case-insensitive root spelling fallback");
    } else std::cerr << "SKIP case-sensitive sibling negative control: fsutil unavailable/unsupported, exit="
        << enabled.exit_code << '\n';
}

struct CancelDuringSync final : EventSink {
    std::weak_ptr<OperationContext> context;
    bool observed = false;
    void Emit(OperationEvent event) noexcept override {
        if (event.kind == "source.view.sync" && event.data.GetString("state") == "updating") {
            observed = true;
            if (const auto value = context.lock()) value->RequestCancellation();
        }
    }
};
void TestSynchronization(const fs::path& root) {
    const auto source = root / "sync-original";
    const auto output = root / "sync-view";
    const auto receipt = root / "sync-receipt.json";
    Write(source / "first.txt", "first-v1");
    Write(source / "sibling.txt", "sibling-v1");
    Write(source / "folder/value.txt", "nested-v1");
    Git(source, {L"init", L"--quiet"});
    Git(source, {L"config", L"core.symlinks", L"false"});
    Git(source, {L"add", L"."});
    Link(source, "alias.txt", "first.txt");
    Link(source, "folder/back", "..");
    const auto first = SynchronizeGitSourceView(source, output, receipt);
    Require(first.stats.files_copied == 3 && first.stats.files_reused == 0,
        "first synchronization did not copy the exact input files");
    const auto sibling_time = fs::last_write_time(output / "sibling.txt");
    const auto nested_time = fs::last_write_time(output / "folder/value.txt");
    const auto first_time = fs::last_write_time(output / "first.txt");
    const auto warm = SynchronizeGitSourceView(source, output, receipt);
    Require(warm.stats.files_copied == 0 && warm.stats.bytes_copied == 0 && warm.stats.files_reused == 4,
        "unchanged synchronization rewrote source files");
    Require(fs::last_write_time(output / "first.txt") == first_time &&
            fs::last_write_time(output / "sibling.txt") == sibling_time &&
            fs::last_write_time(output / "folder/value.txt") == nested_time,
        "unchanged synchronization modified timestamps");
    Require(fs::equivalent(output, output / "folder/back"), "synchronized ancestor alias escaped owned view");
    Write(source / "folder/value.txt", "nested-v2");
    const auto delta = SynchronizeGitSourceView(source, output, receipt);
    Require(delta.stats.files_copied == 1 && delta.stats.files_reused == 3 &&
            fs::last_write_time(output / "sibling.txt") == sibling_time,
        "single input delta invalidated a sibling");
    const auto original_stamp = fs::last_write_time(output / "sibling.txt");
    Write(output / "sibling.txt", "corrupt-v1"); // Same size, timestamp restored.
    fs::last_write_time(output / "sibling.txt", original_stamp);
    const auto repaired = SynchronizeGitSourceView(source, output, receipt);
    Require(repaired.stats.files_copied == 1 && Read(output / "sibling.txt") == "sibling-v1",
        "same-size same-time output corruption was reused");
    Write(source / "added.txt", "new input");
    fs::remove(source / "folder/value.txt");
    const auto changed_set = SynchronizeGitSourceView(source, output, receipt);
    Require(changed_set.stats.files_copied == 1 && !fs::exists(output / "folder/value.txt") &&
            Read(output / "added.txt") == "new input", "input add/remove did not synchronize");
    Link(source, "alias.txt", "sibling.txt");
    const auto retargeted = SynchronizeGitSourceView(source, output, receipt);
    Require(Read(output / "alias.txt") == "sibling-v1" && retargeted.stats.files_copied == 0,
        "changed Git link was not synchronized");
    fs::remove(source / "added.txt");
    Write(source / "added.txt/inside.txt", "directory instead");
    SynchronizeGitSourceView(source, output, receipt);
    Require(Read(output / "added.txt/inside.txt") == "directory instead", "file-to-directory input change failed");
    fs::remove(source / "added.txt/inside.txt"); fs::remove(source / "added.txt");
    Write(source / "added.txt", "file again");
    SynchronizeGitSourceView(source, output, receipt);
    Require(Read(output / "added.txt") == "file again", "directory-to-file input change failed");

    // Interrupted updates are repairable: only the durable ownership list is
    // admitted. Complete-state is not required, and output bytes are rechecked.
    auto updating = JsonValue::Parse(Read(receipt));
    Require(updating.has_value(), "sync receipt is not JSON");
    updating->Set("state", JsonValue::String("updating"));
    Write(receipt, updating->Serialize(true));
    fs::remove(output / "first.txt");
    const auto recovered = SynchronizeGitSourceView(source, output, receipt);
    Require(recovered.stats.files_copied == 1 && Read(output / "first.txt") == "first-v1" &&
            JsonValue::Parse(Read(receipt))->GetString("state") == "complete",
        "interrupted synchronization was not repaired");
    ProcessRunOptions cancelled;
    cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
    const auto receipt_before = Read(receipt);
    bool stopped = false;
    try { SynchronizeGitSourceView(source, output, receipt, cancelled); }
    catch (const std::exception& error) { stopped = std::string(error.what()).find("cancelled") != std::string::npos; }
    Require(stopped && Read(receipt) == receipt_before, "cancelled inventory changed published state");

    Write(source / "interrupted.txt", "new durable ownership");
    const auto observer = std::make_shared<CancelDuringSync>();
    const auto context = std::make_shared<OperationContext>();
    context->sink = observer; observer->context = context;
    bool interrupted = false;
    {
        OperationBinding binding(context);
        try { SynchronizeGitSourceView(source, output, receipt); }
        catch (const std::exception& error) {
            interrupted = std::string(error.what()).find("cancelled") != std::string::npos;
        }
    }
    Require(interrupted && observer->observed && !fs::exists(output / "interrupted.txt") &&
            JsonValue::Parse(Read(receipt))->GetString("state") == "updating",
        "cancellation after ownership publication was not retained as incomplete");
    const auto resumed = SynchronizeGitSourceView(source, output, receipt);
    Require(resumed.stats.files_copied == 1 && Read(output / "interrupted.txt") == "new durable ownership",
        "real interrupted update could not resume its new entry");
    const auto complete_before_collision = Read(receipt);
    // An unrelated output is never erased or silently adopted.
    Write(output / "foreign.txt", "unowned");
    Write(source / "foreign.txt", "source collides");
    bool collision = false;
    try { SynchronizeGitSourceView(source, output, receipt); }
    catch (const std::exception& error) { collision = std::string(error.what()).find("unowned") != std::string::npos; }
    Require(collision && Read(output / "foreign.txt") == "unowned", "unowned output was overwritten");
    fs::remove(source / "foreign.txt");
    Link(source, "escape", "../outside");
    bool escape = false;
    try { SynchronizeGitSourceView(source, output, receipt); }
    catch (const std::exception& error) { escape = std::string(error.what()).find("escapes") != std::string::npos; }
    Require(escape && Read(receipt) == complete_before_collision, "unsafe input changed owned projection");
    fs::remove(source / "escape");
    Git(source, {L"update-index", L"--force-remove", L"escape"});
    fs::remove(receipt);
    bool unowned = false;
    try { SynchronizeGitSourceView(source, output, receipt); }
    catch (const std::exception& error) { unowned = std::string(error.what()).find("ownership receipt") != std::string::npos; }
    Require(unowned && Read(output / "foreign.txt") == "unowned", "markerless existing directory was adopted");
}

void TestSynchronizationOptions(const fs::path& root) {
    auto source = root / "tool-state-original";
    const auto output = root / "tool-state-view";
    const auto receipt = root / "tool-state-receipt.json";
    Write(source / "payload.bin", "original payload");
    Write(source / "scratch/omitted.bin", "not admitted");
    Write(source / "nested/scratch/kept.bin", "nested input");
    Git(source, {L"init", L"--quiet"});
    Git(source, {L"config", L"core.symlinks", L"false"});
    Git(source, {L"add", L"."});
    Link(source, "placeholder.bin", "payload.bin");
    GitSourceViewSyncOptions options;
    options.resolve_git_placeholders = false;
    options.include_git_metadata = true;
    options.excluded_root_entries = {"scratch"};
    options.source_identity = "owned-tool-state-slot-v1";
    SynchronizeGitSourceView(source, output, receipt, {}, options);
    Require(Read(output / "placeholder.bin") == "payload.bin", "tool state unexpectedly resolved Git placeholder");
    Require(fs::is_regular_file(output / ".git/index"), "requested Git metadata was omitted");
    Require(!fs::exists(output / "scratch") && Read(output / "nested/scratch/kept.bin") == "nested input",
        "root-only exclusion also removed nested input");
    const auto payload_stamp = fs::last_write_time(output / "payload.bin");
    const auto metadata_stamp = fs::last_write_time(output / ".git/index");
    const auto moved = root / "tool-state-relocated";
    fs::rename(source, moved); source = moved; // The registered old root no longer exists.
    const auto relocated = SynchronizeGitSourceView(source, output, receipt, {}, options);
    Require(relocated.stats.files_copied == 0 && fs::last_write_time(output / "payload.bin") == payload_stamp &&
            fs::last_write_time(output / ".git/index") == metadata_stamp,
        "logical source relocation rewrote unchanged input bytes");
    Require(JsonValue::Parse(Read(receipt))->GetString("source") == Win32Process::ToNarrow(source.wstring()),
        "source relocation did not publish new physical provenance");
    const auto complete = Read(receipt);
    auto wrong = options; wrong.source_identity = "another-owner";
    bool mismatch = false;
    try { SynchronizeGitSourceView(source, output, receipt, {}, wrong); }
    catch (const std::exception& error) { mismatch = std::string(error.what()).find("ownership mismatch") != std::string::npos; }
    Require(mismatch && Read(receipt) == complete, "different logical owner adopted existing projection");
    auto invalid_exclusion = options; invalid_exclusion.excluded_root_entries = {"nested/scratch"};
    bool invalid = false;
    try { SynchronizeGitSourceView(source, output, receipt, {}, invalid_exclusion); }
    catch (const std::exception& error) { invalid = std::string(error.what()).find("single root name") != std::string::npos; }
    Require(invalid && Read(receipt) == complete, "nested exclusion was accepted or modified output");

    const auto exact_source = root / "exact-owner-source";
    const auto exact_view = root / "exact-owner-view";
    const auto exact_receipt = root / "exact-owner-receipt.json";
    Write(exact_source / "input", "owned exact input");
    SynchronizeGitSourceView(exact_source, exact_view, exact_receipt);
    GitSourceViewSyncOptions claimed; claimed.source_identity = "new-owner";
    bool missing_identity = false;
    try { SynchronizeGitSourceView(exact_source, exact_view, exact_receipt, {}, claimed); }
    catch (const std::exception& error) { missing_identity = std::string(error.what()).find("ownership mismatch") != std::string::npos; }
    Require(missing_identity, "identity-less receipt accepted a newly claimed logical owner");
    const auto exact_moved = root / "exact-owner-relocated";
    fs::rename(exact_source, exact_moved);
    bool exact_mismatch = false;
    try { SynchronizeGitSourceView(exact_moved, exact_view, exact_receipt); }
    catch (const std::exception& error) { exact_mismatch = std::string(error.what()).find("ownership mismatch") != std::string::npos; }
    Require(exact_mismatch, "default synchronization admitted a different physical source root");
}

// CocoaPods publishes header aliases as hard links on Windows: the view must
// keep one identity for them, as #import deduplication observes.
void TestHardLinkIdentity(const fs::path& root) {
    const auto source = root / "hardlink-original";
    Write(source / "Sources/Shared.h", "@interface OPENFRUITHardLinked\n@end\n");
    Write(source / "consumer.m", "#import \"Headers/Shared.h\"\n#import \"Sources/Shared.h\"\n");
    fs::create_directories(source / "Headers");
    fs::create_hard_link(source / "Sources/Shared.h", source / "Headers/Shared.h");
    Git(source, {L"init", L"--quiet"});
    const auto created = CreateGitSourceView(source, root / "hardlink-created");
    Require(fs::equivalent(created.root / "Headers/Shared.h", created.root / "Sources/Shared.h"),
        "hard-linked sources were published as independent files");
    const auto compiled = Win32Process::Run(L"clang.exe", {L"clang.exe", L"-fsyntax-only",
        L"-x", L"objective-c", (created.root / "consumer.m").wstring()});
    Require(compiled.success, "#import through hard links produced duplicate interface");
    const auto synced = SynchronizeGitSourceView(source, root / "hardlink-synced", root / "hardlink-receipt.json");
    Require(fs::equivalent(synced.view.root / "Headers/Shared.h", synced.view.root / "Sources/Shared.h"),
        "synchronized hard links were copied independently");
}

void TestFileAliasIdentity(const fs::path& root) {
    const auto source = root / "import-original";
    const auto output = root / "import-synchronized";
    const auto receipt = root / "import-receipt.json";
    Write(source / "Canonical.h", "@interface OPENFRUITShared\n@end\n");
    Write(source / "Other.h", "@interface OPENFRUITOther\n@end\n");
    Write(source / "consumer.m", "#import \"Canonical.h\"\n#import \"Alias.h\"\n#import \"Chain.h\"\n");
    Git(source, {L"init", L"--quiet"});
    Git(source, {L"config", L"core.symlinks", L"false"});
    Git(source, {L"add", L"."});
    Link(source, "Alias.h", "Canonical.h");
    Link(source, "Chain.h", "Alias.h");
    const auto before = Git(source, {L"status", L"--porcelain", L"-z"});
    const auto baseline = root / "import-copy-baseline";
    Write(baseline / "Canonical.h", Read(source / "Canonical.h"));
    Write(baseline / "Alias.h", Read(source / "Canonical.h"));
    Write(baseline / "Chain.h", Read(source / "Canonical.h"));
    Write(baseline / "consumer.m", Read(source / "consumer.m"));
    const auto duplicate = Win32Process::Run(L"clang.exe", {L"clang.exe", L"-fsyntax-only",
        L"-x", L"objective-c", (baseline / "consumer.m").wstring()});
    Require(!duplicate.success && duplicate.std_err.find("duplicate interface") != std::string::npos,
        "independent-header negative control did not reproduce #import identity failure");
    const auto created = CreateGitSourceView(source, root / "import-created");
    Require(fs::is_symlink(fs::symlink_status(created.root / "Alias.h")) &&
            !fs::read_symlink(created.root / "Alias.h").is_absolute() &&
            fs::equivalent(created.root / "Alias.h", created.root / "Canonical.h") &&
            fs::equivalent(created.root / "Chain.h", created.root / "Canonical.h"),
        "file alias chain did not preserve canonical owned identity");
    const auto compiled = Win32Process::Run(L"clang.exe", {L"clang.exe", L"-fsyntax-only",
        L"-x", L"objective-c", (created.root / "consumer.m").wstring()});
    Require(compiled.success, "#import through canonical and symlink alias produced duplicate interface");
    const auto first = SynchronizeGitSourceView(source, output, receipt);
    Require(first.stats.files_copied == 3 && fs::equivalent(output / "Alias.h", output / "Canonical.h"),
        "synchronized file aliases were copied independently");
    const auto canonical_stamp = fs::last_write_time(output / "Canonical.h");
    const auto alias_stamp = AliasWriteTime(output / "Alias.h", true);
    const auto chain_stamp = AliasWriteTime(output / "Chain.h", true);
    const auto warm = SynchronizeGitSourceView(source, output, receipt);
    Require(warm.stats.files_copied == 0 && warm.stats.files_reused == 5 &&
            fs::last_write_time(output / "Alias.h") == canonical_stamp &&
            AliasWriteTime(output / "Alias.h") == alias_stamp && AliasWriteTime(output / "Chain.h") == chain_stamp,
        "warm file alias synchronization changed canonical content or link timestamp");
    Require(before == Git(source, {L"status", L"--porcelain", L"-z"}) &&
            Read(source / "Alias.h") == "Canonical.h" && Read(source / "Chain.h") == "Alias.h",
        "file identity projection modified original inputs");
    Write(source / "Canonical.h", "@interface OPENFRUITSharedChanged\n@end\n");
    const auto delta = SynchronizeGitSourceView(source, output, receipt);
    Require(delta.stats.files_copied == 1 && fs::equivalent(output / "Chain.h", output / "Canonical.h") &&
            Read(output / "Alias.h") == Read(source / "Canonical.h") &&
            AliasWriteTime(output / "Alias.h") > alias_stamp && AliasWriteTime(output / "Chain.h") > chain_stamp,
        "canonical delta did not refresh alias timestamps and preserve file identity");
    // Receipt input bytes did not change, but the owned canonical output did.
    // Repair must also invalidate consumers watching the alias's own timestamp.
    const auto repair_alias_stamp = AliasWriteTime(output / "Alias.h", true);
    const auto repair_chain_stamp = AliasWriteTime(output / "Chain.h", true);
    Write(output / "Canonical.h", "corrupted owned canonical output");
    const auto repaired_canonical = SynchronizeGitSourceView(source, output, receipt);
    Require(repaired_canonical.stats.files_copied == 1 &&
            Read(output / "Canonical.h") == Read(source / "Canonical.h") &&
            AliasWriteTime(output / "Alias.h") > repair_alias_stamp &&
            AliasWriteTime(output / "Chain.h") > repair_chain_stamp,
        "canonical output corruption repair retained stale alias timestamps");
    // Repair a hostile link without ever following it for mutation.
    const auto outside = root / "outside-header.h";
    Write(outside, "outside remains unchanged");
    fs::remove(output / "Alias.h");
    Require(NativeLink(output / "Alias.h", outside, false), "file alias test needs native link support");
    const auto repaired = SynchronizeGitSourceView(source, output, receipt);
    Require(repaired.stats.files_copied == 0 && fs::equivalent(output / "Alias.h", output / "Canonical.h") &&
            Read(outside) == "outside remains unchanged", "corrupt file alias was followed or not repaired");
    Link(source, "Alias.h", "Other.h");
    const auto retarget_input = Git(source, {L"status", L"--porcelain", L"-z"});
    const auto retarget = SynchronizeGitSourceView(source, output, receipt);
    Require(retarget.stats.files_copied == 0 && fs::equivalent(output / "Alias.h", output / "Other.h") &&
            fs::equivalent(output / "Chain.h", output / "Other.h"), "file alias retarget did not update its chain");
    Require(retarget_input == Git(source, {L"status", L"--porcelain", L"-z"}) &&
            Read(source / "Alias.h") == "Other.h" && Read(source / "Chain.h") == "Alias.h",
        "file alias retarget synchronization changed upstream");
    Link(source, "Alias.h", "Canonical.h");
    const auto observer = std::make_shared<CancelDuringSync>();
    const auto context = std::make_shared<OperationContext>();
    context->sink = observer; observer->context = context;
    bool cancelled = false;
    {
        OperationBinding binding(context);
        try { SynchronizeGitSourceView(source, output, receipt); }
        catch (const std::exception& error) { cancelled = std::string(error.what()).find("cancelled") != std::string::npos; }
    }
    Require(cancelled && observer->observed && fs::equivalent(output / "Alias.h", output / "Other.h"),
        "cancelled file alias retarget mutated the published alias");
    const auto resumed = SynchronizeGitSourceView(source, output, receipt);
    Require(resumed.stats.files_copied == 0 && fs::equivalent(output / "Chain.h", output / "Canonical.h"),
        "cancelled file alias retarget could not resume");

    // A canonical node omitted by source policy cannot become a dangling link.
    Link(source, "Private.h", ".git/HEAD");
    Rejected(source, root / "private-target-view", "canonical target is not published");
    bool sync_rejected = false;
    try { SynchronizeGitSourceView(source, output, receipt); }
    catch (const std::exception& error) {
        sync_rejected = std::string(error.what()).find("canonical target is not published") != std::string::npos;
    }
    Require(sync_rejected && !fs::exists(output / "Private.h"), "unpublished canonical target was admitted");
    fs::remove(source / "Private.h");
    Git(source, {L"update-index", L"--force-remove", L"Private.h"});
    GitSourceViewSyncOptions excluded; excluded.excluded_root_entries = {"Canonical.h"};
    bool excluded_rejected = false;
    try { SynchronizeGitSourceView(source, output, receipt, {}, excluded); }
    catch (const std::exception& error) {
        excluded_rejected = std::string(error.what()).find("canonical target is not published") != std::string::npos;
    }
    Require(excluded_rejected, "excluded canonical file target was silently admitted");
}

}

int main() {
    // The physical temporary directory: the resolver returns physical paths.
    auto root = fs::canonical(fs::temp_directory_path()) /
        (L"OPENFRUIT-source-view-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
         std::to_wstring(GetTickCount64()));
    try {
        Require(fs::create_directory(root), "cannot reserve fixture");
        const auto source = root / L"upstream", views = root / L"views";
        fs::create_directories(source); fs::create_directory(views);
        Git(source, {L"init", L"--quiet"});
        Git(source, {L"config", L"core.symlinks", L"false"});
        Write(source / "inc dir" / "real.h", "#include \"relative.h\"\n#define VALUE RELATIVE_VALUE\n");
        Write(source / "inc dir" / "relative.h", "#define RELATIVE_VALUE 17\n");
        Write(source / "ordinary.h", "inc dir/real.h");
        Write(source / "main.c", "#include \"alias dir/alias.h\"\n_Static_assert(VALUE == 17, \"relative include\");\n");
        Write(source / L"dati è.bin", std::string("a\0b", 3));
        Git(source, {L"add", L"."});
        Link(source, "alias dir", "inc dir");
        Link(source, "inc dir/alias.h", "real.h");
        Link(source, "main-alias.c", "main.c");
        Link(source, "resource.bin", "dati è.bin");
        Link(source, "chain.bin", "resource.bin");
        Link(source, "through-directory.h", "alias dir/alias.h");
        Link(source, "case-reference.h", "inc dir/ALIAS.h");
        Link(source, "Tests/Alternate/Library", "../..");
        Write(source / "deeper" / "nested" / "file.txt", "nested\n");
        Write(source / "deeper" / "file.txt", "after directory expansion\n");
        Link(source, "jump", "deeper/nested");
        Link(source, "dotdot.txt", "jump/../file.txt");
        Link(source, "revisit.txt", "jump/../nested/../../jump/file.txt");
        Git(source, {L"add", L"deeper"});
        Link(source, "deeper/nested/back", "..");
        Git(source, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
                     L"commit", L"--quiet", L"-m", L"owned fixture"});
        const auto before = Git(source, {L"status", L"--porcelain", L"-z"});
        Require(before.empty(), "fixture must begin pristine");
        const auto view = CreateGitSourceView(source, views / "success");
        Require(fs::is_directory(view.root / "alias dir"), "directory alias not projected");
        Require(fs::is_symlink(fs::symlink_status(view.root / "Tests/Alternate/Library")),
                "ancestor directory reference was unfolded instead of preserved");
        Require(fs::equivalent(view.root, view.root / "Tests/Alternate/Library"),
                "published ancestor reference does not point to the owned view");
        Require(Read(view.root / "Tests/Alternate/Library/resource.bin") == std::string("a\0b", 3),
                "finite ancestor reference cannot read original resource bytes");
        Require(fs::equivalent(view.root / "deeper", view.root / "deeper/nested/back"),
                "non-root ancestor reference points to the wrong owned directory");
        Require(Read(view.root / "deeper/nested/back/file.txt") == "after directory expansion\n",
                "non-root ancestor reference cannot read its own directory contents");
        Require(fs::is_regular_file(fs::symlink_status(view.root / "alias dir/real.h")) &&
                !fs::is_symlink(fs::symlink_status(view.root / "alias dir/real.h")) &&
                !fs::is_symlink(fs::symlink_status(view.root / "alias dir/relative.h")),
                "normal children of an expanded directory alias became external file aliases");
        Require(fs::is_symlink(fs::symlink_status(view.root / "alias dir/alias.h")) &&
                fs::equivalent(view.root / "alias dir/alias.h", view.root / "inc dir/real.h"),
                "explicit file alias nested in an expanded directory lost canonical identity");
        const auto exported_alias = views / "exported-directory-alias";
        fs::create_directory(exported_alias);
        // Preserve symlinks during directory export as resource bundlers do.
        // Normal children must remain readable without the private canonical
        // subtree. The explicit nested file link retains its distinct contract.
        fs::copy(view.root / "alias dir", exported_alias,
            fs::copy_options::recursive | fs::copy_options::copy_symlinks);
        Require(Read(exported_alias / "real.h") == Read(source / "inc dir/real.h") &&
                Read(exported_alias / "relative.h") == Read(source / "inc dir/relative.h"),
                "independent copy of expanded directory children lost resource bytes");
        Require(Read(view.root / "ordinary.h") == "inc dir/real.h", "ordinary short file was interpreted");
        Require(Read(view.root / "chain.bin") == std::string("a\0b", 3), "resource chain changed bytes");
        Require(Read(view.root / "through-directory.h") == Read(source / "inc dir" / "real.h"),
                "target through a directory placeholder was not resolved");
        Require(Read(view.root / "case-reference.h") == Read(source / "inc dir" / "real.h"),
                "Windows case variant bypassed Git placeholder identity");
        Require(Read(view.root / "dotdot.txt") == "after directory expansion\n",
                "dotdot evaluated before directory symlink expansion");
        Require(Read(view.root / "revisit.txt") == "nested\n",
                "valid repeated directory alias was rejected as a cycle");
        Require(ResolveGitSourcePath(source, source / "jump" / ".." / "file.txt") ==
                    source / "deeper" / "file.txt",
                "public resolver normalized dotdot before directory alias expansion");
        Require(Read(view.root / "main-alias.c") == Read(source / "main.c"), "source alias not projected");
        Require(!fs::exists(view.root / ".git"), "Git metadata copied into view");
        bool has_alias_provenance = false;
        for (const auto& mapping : view.mappings)
            if (mapping.original == source / "alias dir" / "alias.h") {
                has_alias_provenance = mapping.resolved == source / "inc dir" / "real.h" &&
                    mapping.projected == view.root / "alias dir" / "alias.h";
            }
        Require(has_alias_provenance, "directory alias provenance lost logical source identity");
        const auto compiled = Win32Process::Run(L"clang.exe", {L"clang.exe", L"-fsyntax-only",
            (view.root / "main-alias.c").wstring()});
        Require(compiled.success, "real compiler cannot consume projected relative includes");
        Write(view.root / "alias dir" / "relative.h", "changed view\n");
        Require(Read(source / "inc dir" / "relative.h") == "#define RELATIVE_VALUE 17\n",
                "view write changed upstream through a hard link");
        Require(Read(source / "alias dir") == "inc dir", "directory placeholder changed");
        Require(Read(source / "inc dir/alias.h") == "real.h", "header placeholder changed");
        Require(before == Git(source, {L"status", L"--porcelain", L"-z"}), "success changed checkout");
        // A Unix directory link may have been created with Windows file-link
        // flags by an extractor. Resolve its target, not the reparse type bit.
        const auto native = root / "native-links";
        Write(native / "Versions/A/Headers/API.h", "original header\n");
        Write(native / "Versions/A/marker.txt", "after native directory expansion\n");
        Write(native / "marker.txt", "wrong lexical parent\n");
        if (NativeLink(native / "Versions/Current", "A", true) &&
            NativeLink(native / "Headers", "Versions/Current/Headers", false) &&
            NativeLink(native / "Jump", "Versions/A/Headers", true) &&
            NativeLink(native / "dotdot.txt", "Jump/../marker.txt", false)) {
            const auto native_view = CreateGitSourceView(native, views / "native-success");
            Require(Read(native_view.root / "Headers/API.h") == "original header\n",
                    "file-typed directory link was not projected");
            Require(Read(native_view.root / "dotdot.txt") == "after native directory expansion\n",
                    "native symlink dotdot was normalized before expansion");
            Require(ResolveGitSourcePath(native, native / "Jump/../marker.txt") ==
                        native / "Versions/A/marker.txt", "native directory resolver lost dotdot semantics");
            Require(fs::is_symlink(fs::symlink_status(native / "Headers")),
                    "source projection modified original native link");
            Require(NativeLink(native / "bad", "../outside", false), "native link prerequisite changed");
            Rejected(native, views / "native-escape", "link escapes source root");
            fs::remove(native / "bad");
            Require(NativeLink(native / "bad", "bad", false), "native link prerequisite changed");
            Rejected(native, views / "native-cycle", "symlink cycle");
        }
        ProcessRunOptions cancelled;
        cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
        Rejected(source, views / "cancelled", "cancelled", cancelled);
        ProcessRunOptions deadline;
        deadline.deadline = std::chrono::steady_clock::now();
        Rejected(source, views / "deadline", "deadline exceeded", deadline);
        Rejected(source, source / "forbidden", "destination is inside source root");
        Rejected(source / "inc dir", source / "forbidden", "destination is inside source checkout");
        Link(source, "bad", "not-present");
        Link(source, "inc dir/dangling", "../absent/fixture");
        // Links to content absent from the checkout stay dangling links, as
        // in a POSIX checkout, while the remaining view is still published.
        const auto dangling = CreateGitSourceView(source, views / "dangling");
        Require(fs::is_symlink(fs::symlink_status(dangling.root / "bad")) &&
                    fs::read_symlink(dangling.root / "bad") == fs::path("not-present") &&
                    fs::read_symlink(dangling.root / "inc dir/dangling") == fs::path("../absent/fixture").make_preferred() &&
                    !fs::exists(dangling.root / "inc dir/dangling") &&
                    fs::exists(dangling.root / "inc dir/real.h"),
                "dangling links were not preserved in the view");
        Link(source, "inc dir/dangling", "../../outside");
        Rejected(source, views / "dangling-escape", "link escapes source root");
        fs::remove(source / "inc dir/dangling");
        Git(source, {L"update-index", L"--force-remove", L"inc dir/dangling"});
        Link(source, "bad", "../outside");
        Rejected(source, views / "escape", "link escapes source root");
        Link(source, "bad", "bad");
        Rejected(source, views / "cycle", "symlink cycle");
        Link(source, "bad", "BAD");
        Rejected(source, views / "case-cycle", "symlink cycle");
        Link(source, "bad", ".");
        const auto back_reference = CreateGitSourceView(source, views / "directory-back-reference");
        Require(fs::equivalent(back_reference.root, back_reference.root / "bad/bad"),
                "finite repeated ancestor reference was rejected or escaped the view");
        Write(back_reference.root / "bad/inc dir/relative.h", "owned back-reference write\n");
        Require(Read(back_reference.root / "inc dir/relative.h") == "owned back-reference write\n" &&
                Read(source / "inc dir/relative.h") == "#define RELATIVE_VALUE 17\n",
                "ancestor alias write did not stay in the independent view");
        Link(source, "bad", "C:/outside");
        Rejected(source, views / "absolute", "absolute symlink target");
        const auto dirty = Git(source, {L"status", L"--porcelain", L"-z"});
        Require(Read(source / "bad") == "C:/outside", "failure changed placeholder");
        Rejected(source, views / "repeat", "absolute symlink target");
        Require(dirty == Git(source, {L"status", L"--porcelain", L"-z"}), "failure changed checkout");
        TestSynchronization(root);
        TestSynchronizationOptions(root);
        TestFileAliasIdentity(root);
        TestHardLinkIdentity(root);
        TestOptionalMetadataResolution(root);
        TestPhysicalRootSpelling(root);
        // Cleanup only this freshly reserved owned test directory.
        fs::remove_all(root);
        std::cout << "PASS: external Git source view preserves bytes and relative includes; unsafe links/cancel fail atomically\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nEvidence: " << root.string() << '\n';
        return 1;
    }
}
