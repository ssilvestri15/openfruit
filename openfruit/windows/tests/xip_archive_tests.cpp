#include "xip_archive.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <zlib.h>
#include <lzma.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
namespace fs = std::filesystem;
#include "xip_archive_fixture.hpp"
using namespace OpenFruitOwnedFixture;
class Visitor : public OpenFruit::XipVisitor {
public:
    std::vector<OpenFruit::XipEntry> entries;
    std::vector<std::string> contents;
    bool stop = false, fail = false;
    void Begin(const OpenFruit::XipEntry& entry) override { if (fail) throw std::runtime_error("owned-sensitive-consumer-message"); entries.push_back(entry); contents.emplace_back(); }
    void Data(std::span<const std::uint8_t> bytes) override { contents.back().append(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
    OpenFruit::XipVisit End() override { return stop ? OpenFruit::XipVisit::Stop : OpenFruit::XipVisit::Continue; }
};
int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--walk") {
        class Discard final : public OpenFruit::XipVisitor {
            void Begin(const OpenFruit::XipEntry&) override {}
            void Data(std::span<const std::uint8_t>) override {}
            OpenFruit::XipVisit End() override { return OpenFruit::XipVisit::Continue; }
        } visitor;
        const auto read = OpenFruit::XipArchive::Walk(fs::path(argv[2]), visitor);
        auto data = OpenFruit::JsonValue::ObjectValue();
        data.Set("status", OpenFruit::JsonValue::String(OpenFruit::XipStatusName(read.status)));
        data.Set("entries", OpenFruit::JsonValue::Number(std::to_string(read.entries)));
        data.Set("encoded_bytes", OpenFruit::JsonValue::Number(std::to_string(read.encoded_bytes)));
        data.Set("encoded_total", OpenFruit::JsonValue::Number(std::to_string(read.encoded_total)));
        data.Set("decoded_bytes", OpenFruit::JsonValue::Number(std::to_string(read.decoded_bytes)));
        data.Set("diagnostic_code", OpenFruit::JsonValue::String(read.error));
        data.Set("toc_checksum_verified", OpenFruit::JsonValue::Boolean(read.toc_checksum_verified));
        data.Set("content_checksum_verified", OpenFruit::JsonValue::Boolean(read.content_checksum_verified));
        data.Set("xar_signature_valid", OpenFruit::JsonValue::Boolean(read.xar_signature_valid));
        data.Set("apple_signing_chain_valid", OpenFruit::JsonValue::Boolean(read.apple_signing_chain_valid));
        data.Set("apple_revocation_valid", OpenFruit::JsonValue::Boolean(read.apple_revocation_valid));
        data.Set("publisher_verified", OpenFruit::JsonValue::Boolean(false));
        std::cout << data.Serialize(true) << '\n';
        return read.status == OpenFruit::XipStatus::Completed ? 0 : 1;
    }
    if (argc == 3 && std::string(argv[1]) == "--inspect") {
        const auto info = OpenFruit::SDKArchiveMetadata::DiscoverIos(fs::path(argv[2]));
        std::cout << info.ToJson().Serialize(true) << '\n'; return info.Found() ? 0 : 1;
    }
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-xip-" + OpenFruit::NewOperationId());
    fs::create_directories(root); const auto path = root / "unrelated-version-999.xip";
    Bytes cpio;
    const std::string settings = R"({"Version":"28.7.1","CanonicalName":"iphoneos28.7.1","DefaultProperties":{"PLATFORM_NAME":"iphoneos"},"SupportedTargets":{"iphoneos":{}}})";
    Entry(cpio, "Tool.app/SDKs/Unrelated.sdk/SDKSettings.json", settings);
    Entry(cpio, "Tool.app/SDKs/Unrelated.sdk/Library", std::string(100000, 'x'), 0100644, 7, 2);
    Entry(cpio, "Tool.app/SDKs/Unrelated.sdk/Clone", "NULLcanary", 0100644, 7, 2);
    Entry(cpio, "Tool.app/SDKs/Alias.sdk", "Unrelated.sdk", 0120777);
    Entry(cpio, "TRAILER!!!", ""); cpio.insert(cpio.end(), 32, 0);
    bool passed = true;
    const auto expect = [&](bool okay, const char* label) { if (!okay) { std::cerr << label << '\n'; passed = false; } };
    for (const bool compressed : {false, true}) {
        Write(path, Archive(Payload(cpio, compressed))); Visitor visitor;
        const auto read = OpenFruit::XipArchive::Walk(path, visitor);
        expect(read.status == OpenFruit::XipStatus::Completed && read.entries == 4 && visitor.contents.size() == 4
            && visitor.contents[0] == settings && visitor.contents[1] == std::string(100000, 'x')
            && visitor.entries[1].inode == visitor.entries[2].inode && visitor.entries[1].links == 2
            && visitor.contents[2] == "NULLcanary" && visitor.contents[3] == "Unrelated.sdk", "raw/compressed stream or original link metadata");
        const auto metadata = OpenFruit::SDKArchiveMetadata::DiscoverIos(path);
        expect(metadata.Found() && metadata.version == "28.7.1" && metadata.sdk_root == "Tool.app/SDKs/Unrelated.sdk", "metadata derivation");
        const auto inventory = OpenFruit::XipInventory::Inspect(path, "/Clone");
        expect(inventory.Complete() && inventory.members.size() == 2 &&
            inventory.members[0].entry.path.ends_with("/Library") && !inventory.members[0].selected_by_filter &&
            inventory.members[1].entry.path.ends_with("/Clone") && inventory.members[1].selected_by_filter &&
            inventory.members[1].content_kind == "xip-clone-marker" && inventory.members[0].entry.inode == inventory.members[1].entry.inode,
            "original member selection includes structured clone partners");
        expect(OpenFruit::XipInventory::Inspect(path, "absent").Complete() &&
            OpenFruit::XipInventory::Inspect(path, "absent").members.empty(), "missing member is complete empty inventory");
        Visitor stopped; stopped.stop = true;
        expect(OpenFruit::XipArchive::Walk(path, stopped).status == OpenFruit::XipStatus::Stopped && stopped.entries.size() == 1, "explicit incomplete stop");
    }
    const auto native_payload = Payload(cpio, true);
    {
        // Only a prefix-hint fixture, never a valid executable/loader proof.
        Bytes hinted;
        std::string header(32, '\0');
        header[0] = static_cast<char>(0xcf); header[1] = static_cast<char>(0xfa);
        header[2] = static_cast<char>(0xed); header[3] = static_cast<char>(0xfe);
        header[4] = 7; header[7] = 1;
        Entry(hinted, "Tool.app/Toolchains/Owned/usr/bin/tool", header);
        Entry(hinted, "TRAILER!!!", "");
        Write(path, Archive(Payload(hinted, true)));
        const auto hint = OpenFruit::XipInventory::Inspect(path, "/usr/bin/");
        expect(hint.Complete() && hint.members.size() == 1 && hint.members[0].content_kind == "mach-o-64" &&
            hint.members[0].cpu_type_hint == 0x01000007, "CPU hint derived from original prefix without executable validity claim");
    }
    Write(path, Archive(native_payload, "<xar><toc><extension><foreign:KeyInfo xmlns:foreign='urn:owned:extension'>"
        "<foreign:name>Content</foreign:name></foreign:KeyInfo></extension><file><name>Content</name><data><offset>0</offset><length>" +
        std::to_string(native_payload.size()) + "</length></data></file></toc></xar>"));
    expect(OpenFruit::SDKArchiveMetadata::DiscoverIos(path).Found(), "foreign XML extensions do not hide XAR metadata");
    if (argc == 2) {
        const auto executable = fs::absolute(argv[1]).wstring();
        const auto cli = OpenFruit::Win32Process::Run(executable,
            {executable, L"sdk", L"inspect-archive", path.wstring()}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
        const auto data = OpenFruit::JsonValue::Parse(cli.std_out);
        expect(cli.success && data && data->GetString("version") == "28.7.1" && data->GetString("status") == "stopped"
            && data->Get("publisher_verified") && !data->Get("publisher_verified")->Bool(true)
            && data->Get("apple_signing_chain_valid") && !data->Get("apple_signing_chain_valid")->Bool(true)
            && data->Get("apple_revocation_valid") && !data->Get("apple_revocation_valid")->Bool(true)
            && !fs::exists(root / "config.toml") && !fs::exists(root / "credentials") && !fs::exists(root / "sdk"), "CLI reads metadata without installation/credential bootstrap");
        const auto listed = OpenFruit::Win32Process::Run(executable,
            {executable, L"sdk", L"archive-members", path.wstring(), L"/Clone"}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
        const auto listing = OpenFruit::JsonValue::Parse(listed.std_out);
        expect(listed.success && listing && listing->Get("inventory_complete")->Bool() &&
            listing->Get("members")->ArrayItems().size() == 2 && !listing->Get("published")->Bool(true) &&
            !fs::exists(root / "config.toml") && !fs::exists(root / "credentials") && !fs::exists(root / "sdk"),
            "CLI same native inventory service, no credential/bootstrap/publication");
    }
    Visitor visitor;
    OpenFruit::XipReadOptions limit; limit.max_decoded_bytes = 512;
    expect(OpenFruit::XipArchive::Walk(path, visitor, limit).status == OpenFruit::XipStatus::ResourceLimit, "decoded limit");
    limit = {}; limit.max_entries = 1;
    expect(OpenFruit::XipArchive::Walk(path, visitor, limit).status == OpenFruit::XipStatus::ResourceLimit, "entry limit");
    OpenFruit::CancellationSource cancellation; cancellation.Cancel(); limit = {}; limit.cancellation = cancellation.Token();
    expect(OpenFruit::XipArchive::Walk(path, visitor, limit).status == OpenFruit::XipStatus::Cancelled, "cancellation");
    OpenFruit::XipInventoryOptions inventory_limit; inventory_limit.read = limit;
    const auto cancelled_inventory = OpenFruit::XipInventory::Inspect(path, "", inventory_limit);
    expect(cancelled_inventory.read.status == OpenFruit::XipStatus::Cancelled && cancelled_inventory.members.empty(), "inventory cancellation is not complete/partial metadata");
    inventory_limit = {}; inventory_limit.max_metadata_entries = 1;
    const auto limited_inventory = OpenFruit::XipInventory::Inspect(path, "", inventory_limit);
    expect(limited_inventory.read.status == OpenFruit::XipStatus::ResourceLimit && limited_inventory.members.empty(), "inventory bounded metadata before publication");
    inventory_limit = {}; inventory_limit.max_path_bytes = 1;
    expect(OpenFruit::XipInventory::Inspect(path, "", inventory_limit).read.status == OpenFruit::XipStatus::ResourceLimit, "inventory string budget");
    OpenFruit::CancellationSource during_read;
    class Cancelling final : public Visitor {
    public:
        explicit Cancelling(OpenFruit::CancellationSource& source) : source_(source) {}
        void Data(std::span<const std::uint8_t>) override { source_.Cancel(); }
    private:
        OpenFruit::CancellationSource& source_;
    } cancelling(during_read);
    limit = {}; limit.cancellation = during_read.Token();
    expect(OpenFruit::XipArchive::Walk(path, cancelling, limit).status == OpenFruit::XipStatus::Cancelled, "cancellation during streamed member");
    limit = {}; limit.deadline = std::chrono::steady_clock::now();
    expect(OpenFruit::XipArchive::Walk(path, visitor, limit).status == OpenFruit::XipStatus::TimedOut, "deadline");
    Visitor failed; failed.fail = true;
    const auto failure = OpenFruit::XipArchive::Walk(path, failed);
    expect(failure.status == OpenFruit::XipStatus::ConsumerFailure && failure.error.find("sensitive") == std::string::npos, "consumer failure redaction");
    const auto checked = ArchiveWithChecksums(Payload(cpio, false));
    Write(path, checked);
    const auto verified = OpenFruit::XipArchive::Walk(path, visitor);
    const auto complete_inventory = OpenFruit::XipInventory::Inspect(path, "/Clone");
    expect(complete_inventory.Complete() && complete_inventory.read.toc_checksum_verified &&
        complete_inventory.read.content_checksum_verified && !complete_inventory.read.apple_signing_chain_valid &&
        !complete_inventory.read.apple_revocation_valid, "full inventory integrity is separate from Apple signing trust");
    expect(verified.status == OpenFruit::XipStatus::Completed && verified.toc_checksum_verified &&
        verified.content_checksum_verified && !verified.apple_signing_chain_valid && !verified.apple_revocation_valid,
        "XAR TOC and archived Content digests do not establish an Apple signing chain");
    const auto inspected = OpenFruit::SDKArchiveMetadata::DiscoverIos(path);
    expect(inspected.Found() && inspected.read.toc_checksum_verified && !inspected.read.content_checksum_verified,
        "early metadata stop does not claim full payload integrity");
    auto corrupted = checked;
    std::size_t toc_bytes = 0;
    for (std::size_t index = 8; index < 16; ++index) toc_bytes = (toc_bytes << 8) | checked[index];
    corrupted[28 + toc_bytes] ^= 1;
    Write(path, corrupted);
    expect(OpenFruit::XipArchive::Walk(path, visitor).error == "archive.toc_checksum_mismatch", "TOC digest mismatch");
    corrupted = checked;
    corrupted[27] = 0;
    Write(path, corrupted);
    expect(OpenFruit::XipArchive::Walk(path, visitor).error == "archive.invalid_toc_checksum", "XAR header cannot disable TOC checksum");
    Write(path, ArchiveWithChecksums(Payload(cpio, false),
        "<signature style=\"RSA\"><offset>20</offset><size>256</size></signature>"));
    expect(OpenFruit::XipArchive::Walk(path, visitor).error == "archive.invalid_signature_metadata",
        "signature without a certificate is rejected");
    corrupted = checked;
    const auto first = std::search(cpio.begin(), cpio.end(), settings.begin(), settings.end());
    expect(first != cpio.end(), "fixture payload located");
    if (first != cpio.end()) {
        const auto offset = static_cast<std::size_t>(first - cpio.begin());
        const auto encoded_offset = 12 + (offset / 256) * (16 + 256) + 16 + offset % 256;
        corrupted[28 + toc_bytes + 20 + encoded_offset] ^= 1;
    }
    Write(path, corrupted);
    expect(OpenFruit::XipArchive::Walk(path, visitor).error == "archive.content_checksum_mismatch", "archived Content digest mismatch");
    const auto invalid_inventory = OpenFruit::XipInventory::Inspect(path, "");
    expect(!invalid_inventory.Complete() && invalid_inventory.members.empty() &&
        invalid_inventory.read.error == "archive.content_checksum_mismatch", "invalid archive cannot publish partial inventory");
    auto damaged = Payload(cpio, true); damaged.back() ^= 1; Write(path, Archive(damaged));
    expect(OpenFruit::XipArchive::Walk(path, visitor).status == OpenFruit::XipStatus::InvalidArchive, "XZ checksum");
    damaged = Archive(Payload(cpio, false)); damaged.resize(damaged.size() - 1); Write(path, damaged);
    expect(OpenFruit::XipArchive::Walk(path, visitor).status == OpenFruit::XipStatus::InvalidArchive, "truncated range");
    const auto file = std::string("<file><name>Content</name><data><offset>0</offset><length>12</length></data></file>");
    for (const auto& toc : {"<xar><toc>" + file + file + "</toc></xar>",
            std::string("<!DOCTYPE xar [<!ENTITY input SYSTEM 'file:///unavailable'>]><xar><toc>&input;</toc></xar>"),
            std::string("<xar><toc><file xmlns='urn:owned:foreign'><name>Content</name><data><offset>0</offset><length>12</length></data></file></toc></xar>"),
            std::string("<xar><toc><file><name>Content</name><data><offset>18446744073709551615</offset><length>12</length></data></file></toc></xar>")}) {
        Write(path, Archive(Payload(cpio, false), toc));
        expect(OpenFruit::XipArchive::Walk(path, visitor).status == OpenFruit::XipStatus::InvalidArchive, "XML/range rejection");
    }
    fs::remove_all(root); // Unique owned fixture only.
    return passed ? 0 : 1;
}
