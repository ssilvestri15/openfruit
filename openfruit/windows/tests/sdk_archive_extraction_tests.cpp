#include "sdk_archive_extraction.hpp"
#include "archive_tree_extraction.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "xip_archive_fixture.hpp"
#include <windows.h>
#include <iostream>
namespace fs = std::filesystem;
using namespace OpenFruitOwnedFixture;
const std::string settings = R"({"Version":"28.7.1","CanonicalName":"iphoneos28.7.1","DefaultProperties":{"PLATFORM_NAME":"iphoneos"},"SupportedTargets":{"iphoneos":{}}})";
const std::string canonical = "owned canonical payload";
Bytes Fixture(const std::string& extra_name = {}, const std::string& link_target = {}, bool source_missing = false,
    bool checksummed = false) {
    Bytes bytes;
    Entry(bytes, "Package/Device.sdk", "", 0040755, 20);
    Entry(bytes, "Package/Device.sdk/SDKSettings.json", settings, 0100644, 1);
    if (!source_missing) Entry(bytes, "Payload/Shared/source.h", canonical, 0100644, 7, 3);
    const auto clone = "NULLcanary" + std::string(canonical.size() - 10, '\0');
    Entry(bytes, "Package/Device.sdk/include/first.h", clone, 0100644, 7, 3);
    Entry(bytes, "Package/Device.sdk/include/second.h", clone, 0100644, 7, 3);
    Entry(bytes, "Package/Device.sdk/include/empty-link.h", "", 0100644, 8, 2);
    Entry(bytes, "Package/Device.sdk/include/late-source.h", "late canonical bytes", 0100644, 8, 2);
    if (!extra_name.empty()) Entry(bytes, extra_name, "owned extra", 0100644, 19);
    if (!link_target.empty()) Entry(bytes, "Package/Device.sdk/alias", link_target, 0120777, 25);
    Entry(bytes, "TRAILER!!!", "");
    auto payload = Payload(bytes, true);
    return checksummed ? ArchiveWithChecksums(payload) : Archive(payload);
}
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary); return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
bool SameFile(const fs::path& first, const fs::path& second) {
    auto a = CreateFileW(first.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    auto b = CreateFileW(second.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    BY_HANDLE_FILE_INFORMATION x{}, y{};
    const bool same = a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE && GetFileInformationByHandle(a, &x)
        && GetFileInformationByHandle(b, &y) && x.dwVolumeSerialNumber == y.dwVolumeSerialNumber
        && x.nFileIndexHigh == y.nFileIndexHigh && x.nFileIndexLow == y.nFileIndexLow;
    if (a != INVALID_HANDLE_VALUE) CloseHandle(a); if (b != INVALID_HANDLE_VALUE) CloseHandle(b); return same;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-extraction-" + OpenFruit::NewOperationId()); fs::create_directories(root);
    const auto archive = root / "unrelated-999.xip";
    Write(archive, Fixture());
    bool passed = true;
    const auto expect = [&](bool okay, const char* label) { if (!okay) { std::cerr << label << '\n'; passed = false; } };
    const auto output = root / "staging";
    const auto extracted = OpenFruit::SDKArchiveExtraction::ExtractIos(archive, output);
    expect(extracted.Succeeded() && extracted.version == "28.7.1" && extracted.staging_present && extracted.files == 5
        && extracted.hardlinks == 3 && extracted.sdk_path == output / "Package/Device.sdk", "derived SDK staging and original-path hardlinks");
    if (extracted.Succeeded()) {
        const auto sdk = extracted.sdk_path;
        expect(Read(sdk / "SDKSettings.json") == settings && Read(sdk / "include/first.h") == canonical
            && Read(sdk / "include/second.h") == canonical && SameFile(sdk / "include/first.h", sdk / "include/second.h")
            && Read(sdk / "include/empty-link.h") == "late canonical bytes"
            && SameFile(sdk / "include/empty-link.h", sdk / "include/late-source.h")
            && !fs::exists(output / "Payload/Shared/source.h"), "canonical bytes, identity and selective scope");
        for (const auto& item : fs::directory_iterator(output)) expect(!item.path().filename().wstring().starts_with(L".OPENFRUIT-"), "no generated clone cache in staging");
    } else std::cerr << extracted.ToJson().Serialize(true) << '\n';
    expect(OpenFruit::SDKArchiveExtraction::ExtractIos(archive, output).status == OpenFruit::SDKExtractionStatus::DestinationExists
        && Read(output / "Package/Device.sdk/SDKSettings.json") == settings, "existing destination preservation");
    Write(archive, Fixture({}, {}, false, true));
    const auto checked = OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "checksummed");
    expect(checked.Succeeded() && checked.toc_checksum_verified && checked.content_checksum_verified &&
        Read(checked.sdk_path / "SDKSettings.json") == settings, "full archive integrity reaches SDK staging result");
    Write(archive, Fixture());
    OpenFruit::SDKExtractionOptions options; options.max_written_bytes = 1;
    const auto limited = OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "limited", options);
    expect(limited.status == OpenFruit::SDKExtractionStatus::ResourceLimit && !limited.staging_present && !fs::exists(root / "limited"), "output budget and partial rollback");
    options = {}; options.max_plan_entries = 1;
    expect(OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "plan-limited", options).status == OpenFruit::SDKExtractionStatus::ResourceLimit
        && !fs::exists(root / "plan-limited"), "inventory budget before publication");
    for (const auto& bad : {std::string("Package/Device.sdk/include/../escape"), std::string("Package/Device.sdk/AUX.h"),
            std::string("Package/Device.sdk/include/FIRST.h"), std::string("Package/Device.sdk/include/first.h")}) {
        Write(archive, Fixture(bad));
        const auto rejected = OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "invalid-path");
        expect(rejected.status == OpenFruit::SDKExtractionStatus::UnsafePath && !fs::exists(root / "invalid-path"), "unsafe/duplicate/case-collision rejection");
    }
    Write(archive, Fixture({}, {}, true));
    expect(OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "missing-source").diagnostic_code == "sdk.extraction.missing_clone_source"
        && !fs::exists(root / "missing-source"), "missing canonical clone failure");
    Write(archive, Fixture()); OpenFruit::CancellationSource cancellation; cancellation.Cancel(); options = {}; options.read.cancellation = cancellation.Token();
    expect(OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "cancelled", options).status == OpenFruit::SDKExtractionStatus::Cancelled
        && !fs::exists(root / "cancelled"), "cancel before staging");
    options = {}; options.read.deadline = std::chrono::steady_clock::now();
    expect(OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "timeout", options).status == OpenFruit::SDKExtractionStatus::TimedOut, "deadline");
    for (const auto& target : {std::string("../../../../outside"), std::string("/System/owned"), std::string("does-not-exist"), std::string("alias")}) {
        Write(archive, Fixture({}, target));
        const auto bad = OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "invalid-link");
        expect((bad.status == OpenFruit::SDKExtractionStatus::UnsafePath || bad.status == OpenFruit::SDKExtractionStatus::UnresolvedLink)
            && !fs::exists(root / "invalid-link"), "link escape, absolute, missing or cyclic target");
    }
    Write(archive, Fixture({}, "../../Payload/Shared"));
    const auto linked = OpenFruit::SDKArchiveExtraction::ExtractIos(archive, root / "linked");
    if (linked.Succeeded()) {
        expect(linked.symlinks == 1 && fs::read_symlink(linked.sdk_path / "alias").generic_string() == "../../Payload/Shared"
            && Read(linked.sdk_path / "alias/source.h") == canonical, "external link closure and unchanged target");
    } else expect(linked.status == OpenFruit::SDKExtractionStatus::SymbolicLinksUnavailable && !linked.staging_present
        && !fs::exists(root / "linked"), "explicit Windows symlink capability and rollback");
    Write(archive, Fixture());
    const auto executable = fs::absolute(argv[1]).wstring();
    const auto cli = OpenFruit::Win32Process::Run(executable,
        {executable, L"sdk", L"extract-archive", archive.wstring(), (root / "cli").wstring()}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    const auto data = OpenFruit::JsonValue::Parse(cli.std_out);
    expect(cli.success && data && data->GetString("version") == "28.7.1" && data->Get("publisher_verified")
        && !data->Get("publisher_verified")->Bool(true) && data->Get("published") && !data->Get("published")->Bool(true)
        && data->Get("apple_signing_chain_valid") && !data->Get("apple_signing_chain_valid")->Bool(true)
        && data->Get("apple_revocation_valid") && !data->Get("apple_revocation_valid")->Bool(true)
        && !fs::exists(root / "config.toml") && !fs::exists(root / "credentials"), "CLI uses same staging service without authentication/registration");
    // Generic original-tree contract: no SDK metadata and no guessed product path.
    Bytes members;
    Entry(members, "Runtime/provider", canonical, 0100644, 42, 2);
    Entry(members, "Tools/server", "", 0100644, 42, 2);
    Entry(members, "Tools/other", "second owned payload", 0100644, 43);
    Entry(members, "TRAILER!!!", "");
    Write(archive, ArchiveWithChecksums(Payload(members, true)));
    bool source_locked = false;
    const auto generic = OpenFruit::ArchiveTreeExtraction::Extract(archive, root / "generic",
        [&](const fs::path& original, const OpenFruit::XipReadOptions& read) {
            auto mutation = CreateFileW(original.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
            source_locked = mutation == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
            if (mutation != INVALID_HANDLE_VALUE) CloseHandle(mutation);
            OpenFruit::XipInventoryOptions inventory_options; inventory_options.read = read;
            const auto inventory = OpenFruit::XipInventory::Inspect(original, "Tools/", inventory_options);
            OpenFruit::ArchiveTreeSelection selection;
            if (!inventory.Complete()) selection.status = OpenFruit::ArchiveExtractionStatus::ArchiveFailure;
            else for (const auto& member : inventory.members) if (member.selected_by_filter)
                selection.member_paths.push_back(member.entry.path);
            return selection;
        });
    expect(generic.Succeeded() && source_locked && generic.files == 2 && generic.hardlinks == 1
        && generic.toc_checksum_verified && generic.content_checksum_verified && generic.member_paths.size() == 2
        && Read(root / "generic/Tools/server") == canonical && Read(root / "generic/Tools/other") == "second owned payload"
        && !fs::exists(root / "generic/Runtime"), "inventory selection, source lease and non-SDK clone closure");
    const auto missing = OpenFruit::ArchiveTreeExtraction::ExtractMembers(archive, root / "absent-member", {"Tools/missing"});
    expect(missing.status == OpenFruit::ArchiveExtractionStatus::MissingSelection && !missing.staging_present,
        "missing selection cannot publish an empty success");
    expect(OpenFruit::ArchiveTreeExtraction::ExtractMembers(archive, root / "empty-member", {}).status
        == OpenFruit::ArchiveExtractionStatus::MissingSelection && !fs::exists(root / "empty-member"), "empty selection rejected");
    expect(OpenFruit::ArchiveTreeExtraction::ExtractMembers(archive, root / "escape-member", {"../Tools/server"}).status
        == OpenFruit::ArchiveExtractionStatus::UnsafePath && !fs::exists(root / "escape-member"), "generic selection escape rejected");
    OpenFruit::ArchiveExtractionOptions bounded; bounded.max_written_bytes = 1;
    const auto generic_limited = OpenFruit::ArchiveTreeExtraction::ExtractMembers(archive, root / "generic-limit", {"Tools"}, bounded);
    expect(generic_limited.status == OpenFruit::ArchiveExtractionStatus::ResourceLimit && !generic_limited.staging_present,
        "generic output budget rollback");
    const auto generic_cli = OpenFruit::Win32Process::Run(executable,
        {executable, L"sdk", L"extract-members", archive.wstring(), (root / "generic-cli").wstring(), L"Tools"},
        L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    const auto generic_data = OpenFruit::JsonValue::Parse(generic_cli.std_out);
    expect(generic_cli.success && generic_data && generic_data->GetString("status") == "succeeded"
        && generic_data->Get("member_paths") && !generic_data->Get("publisher_verified")->Bool(true)
        && !generic_data->Get("published")->Bool(true) && Read(root / "generic-cli/Tools/server") == canonical
        && !fs::exists(root / "config.toml") && !fs::exists(root / "credentials"), "generic native CLI staging propagation");
    fs::remove_all(root); // Unique, explicitly owned fixture only; no user state.
    return passed ? 0 : 1;
}
