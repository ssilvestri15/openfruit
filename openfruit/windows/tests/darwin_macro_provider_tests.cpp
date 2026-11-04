#include "darwin_macro_provider.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
void Require(bool value, const std::string& message) { if (!value) throw std::runtime_error(message); }
void File(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path()); std::ofstream out(path, std::ios::binary); out << bytes;
    Require(bool(out), "owned fixture write failed");
}
std::string Hash(const fs::path& path) {
    const auto hash = Sha256File(path); Require(hash.has_value(), "fixture hashing failed"); return *hash;
}
void Little(std::string& bytes, std::size_t offset, std::uint64_t value, unsigned count = 4) {
    for (unsigned n = 0; n < count; ++n) bytes[offset + n] = static_cast<char>(value >> (n * 8));
}
std::string MachO() {
    // Owned metadata fixture only: these bytes are never executed as a plugin.
    std::string bytes(4096, '\0'); Little(bytes, 0, 0xfeedfacf); Little(bytes, 4, 0x0100000c);
    Little(bytes, 12, 2); Little(bytes, 16, 1); Little(bytes, 20, 72);
    Little(bytes, 32, 0x19); Little(bytes, 36, 72); bytes.replace(40, 6, "__TEXT");
    Little(bytes, 56, 0x100000000ULL, 8); Little(bytes, 64, 4096, 8); Little(bytes, 80, 4096, 8);
    Little(bytes, 88, 5); Little(bytes, 92, 5); return bytes;
}
JsonValue Strings(std::initializer_list<std::string> values) {
    auto result = JsonValue::ArrayValue(); for (const auto& value : values) result.ArrayItems().push_back(JsonValue::String(value)); return result;
}
struct Fixture {
    fs::path root, managed, sdk, receipt, tree, executable, plugin;
    JsonValue document;
    explicit Fixture(const fs::path& directory) : root(directory), managed(root / "managed"),
        sdk(managed / "sdk" / "slot" / "Xcode.app" / "SDK.sdk"),
        receipt(managed / "sdk" / "slot" / "darwin-provider" / "provider.json"),
        tree(managed / "sdk" / "slot" / "darwin-provider" / "original"),
        executable(tree / "toolchain" / "swift-plugin-server"), plugin(tree / "plugins" / "nested" / "libOwnedMacro.dylib") {
        File(sdk / "SDKSettings.json", "{\"Version\":\"27.0\",\"CanonicalName\":\"iphoneos27.0\"}");
        File(executable, MachO()); File(plugin, "owned library metadata fixture");
        document = JsonValue::ObjectValue(); document.Set("schema", JsonValue::String("openfruit.darwin-provider.v1"));
        document.Set("path_anchor", JsonValue::String("managed-home"));
        auto selection = JsonValue::ObjectValue(); selection.Set("sdk", JsonValue::String(Relative(sdk)));
        selection.Set("sdk_settings_sha256", JsonValue::String(Hash(sdk / "SDKSettings.json")));
        selection.Set("archive_sha256", JsonValue::String(std::string(64, 'a')));
        selection.Set("xcode_build", JsonValue::String("owned-build")); selection.Set("toolchain_identifier", JsonValue::String("owned-toolchain"));
        document.Set("selection", std::move(selection));
        auto server = JsonValue::ObjectValue(); server.Set("virtual_path", JsonValue::String("/toolchain/swift-plugin-server"));
        server.Set("member", JsonValue::String(Relative(executable))); server.Set("sha256", JsonValue::String(Hash(executable)));
        document.Set("executable", std::move(server)); document.Set("original_trees", Strings({Relative(tree)}));
        document.Set("original_files", JsonValue::ArrayValue({Original(executable), Original(plugin)}));
        document.Set("plugin_directories", Strings({"/plugins"}));
        auto cache = JsonValue::ObjectValue(); cache.Set("parent", Cache("main"));
        cache.Set("children", JsonValue::ArrayValue({Cache("first"), Cache("second")})); document.Set("cache", std::move(cache));
        auto provenance = JsonValue::ObjectValue(); provenance.Set("source", JsonValue::String("owned-test-input"));
        provenance.Set("publisher_verified", JsonValue::Boolean(false)); provenance.Set("published", JsonValue::Boolean(false));
        document.Set("provenance", std::move(provenance)); Save(document);
    }
    std::string Relative(const fs::path& path) const { return Win32Process::ToNarrow(path.lexically_relative(managed).generic_wstring()); }
    JsonValue Original(const fs::path& path) const {
        auto value = JsonValue::ObjectValue(); value.Set("path", JsonValue::String(Relative(path)));
        value.Set("sha256", JsonValue::String(Hash(path))); value.Set("bytes", JsonValue::Number(std::to_string(fs::file_size(path)))); return value;
    }
    JsonValue Cache(const std::string& name) const {
        const auto payload = managed / "cache" / (name + ".bin"), report = managed / "cache" / (name + ".json");
        File(payload, std::string(512, name.front())); auto descriptor = JsonValue::ObjectValue();
        for (const auto* key : {"complete", "file_contents_verified", "metadata_verified", "volume_trees_verified", "quarantined"}) descriptor.Set(key, JsonValue::Boolean(true));
        descriptor.Set("scope", JsonValue::String("selected-original-apfs-file-decoded-data-hashes"));
        descriptor.Set("path", JsonValue::String(Win32Process::ToNarrow(payload.generic_wstring())));
        descriptor.Set("source_sha256", JsonValue::String(std::string(64, 'b')));
        descriptor.Set("sha256", JsonValue::String(Hash(payload))); descriptor.Set("decoded_bytes", JsonValue::Number("512"));
        descriptor.Set("virtual_path", JsonValue::String("/System/cache/" + name)); File(report, descriptor.Serialize());
        auto value = JsonValue::ObjectValue(); value.Set("report", JsonValue::String(Relative(report)));
        value.Set("report_sha256", JsonValue::String(Hash(report))); value.Set("payload", JsonValue::String(Relative(payload)));
        for (const auto* key : {"sha256", "source_sha256", "virtual_path"}) value.Set(key, *descriptor.Get(key));
        value.Set("bytes", JsonValue::Number("512")); return value;
    }
    void Save(const JsonValue& value) const { File(receipt, value.Serialize(true)); }
    void Reject(JsonValue value, const std::string& expected, const DarwinClosureOptions& options = {}) const {
        Save(value); DarwinMacroProvider output; output.executable = "stale"; output.plugins.push_back({"stale", {}, {}, {}}); std::string error;
        Require(!ReadDarwinMacroProvider(receipt, managed, output, error, sdk, options), "bad provider admitted: " + expected);
        Require(!error.empty() && error.find(expected) != std::string::npos, "unexpected provider error: " + error + "; expected " + expected);
        Require(output.executable.empty() && output.plugins.empty() && output.retained_inputs.empty() && output.receipt.empty(), "failed admission retained output/leases");
    }
};
}
int main() {
    // The physical temporary directory: receipt discovery reports physical paths.
    const auto root = fs::canonical(fs::temp_directory_path()) / ("openfruit-darwin-provider-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    try {
        Fixture fixture(root); DarwinMacroProvider output; std::string error;
        Require(ReadDarwinMacroProvider(fixture.receipt, fixture.managed, output, error, fixture.sdk), error);
        Require(output.plugins.size() == 1 && output.plugins[0].module == "OwnedMacro" && output.child_cache_reports.size() == 2, "recursive plugin/dynamic cache inventory missing");
        Require(!output.provenance.Get("publisher_verified")->Bool() && !output.provenance.Get("published")->Bool(), "receipt admission promoted trust");
        Require(FindDarwinMacroProviderReceipt(fixture.managed, fixture.sdk) == fixture.receipt, "SDK ancestor receipt discovery failed");
        Require(FindDarwinMacroProviderReceipt(fixture.managed, root).empty(), "receipt discovery escaped managed root");
        std::string translated;
        Require(output.TranslateLibraryPath(Win32Process::ToNarrow(fixture.plugin.wstring()), translated) && translated == "/plugins/nested/libOwnedMacro.dylib", "physical plugin path was not translated");
        Require(output.TranslateLibraryPath("/plugins/nested/libOwnedMacro.dylib", translated), "admitted virtual plugin not translated");
        Require(!output.TranslateLibraryPath("libOwnedMacro.dylib", translated) && translated.empty(), "basename plugin fallback accepted");
        Require(!output.TranslateLibraryPath("/plugins/libUnknown.dylib", translated) && translated.empty(), "unknown plugin fallback accepted");
        Require(!output.TranslateLibraryPath(Win32Process::ToNarrow(fixture.executable.wstring()), translated), "non-plugin original admitted for translation");
        auto spelling = Win32Process::ToNarrow(fixture.plugin.wstring());
        std::transform(spelling.begin(), spelling.end(), spelling.begin(), [](unsigned char c) { return c >= 'a' && c <= 'z' ? char(c - 32) : char(c); });
        Require(output.TranslateLibraryPath(spelling, translated), "Windows case-insensitive canonical spelling rejected");
        HANDLE writer = CreateFileW(fixture.plugin.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION, "admitted original lease permitted mutation");
        output = {};

        auto bad = fixture.document; bad.Set("schema", JsonValue::String("unknown")); fixture.Reject(bad, "schema");
        bad = fixture.document; bad.Get("selection")->Set("sdk_settings_sha256", JsonValue::String(std::string(64, '0'))); fixture.Reject(bad, "SHA256 mismatch");
        fs::create_directories(fixture.managed / "other-sdk"); fixture.Save(fixture.document);
        Require(!ReadDarwinMacroProvider(fixture.receipt, fixture.managed, output, error, fixture.managed / "other-sdk") && error.find("selected SDK") != std::string::npos, "different selected SDK admitted");
        bad = fixture.document; bad.Get("original_files")->ArrayItems()[0].Set("path", JsonValue::String("../outside")); fixture.Reject(bad, "traversal");
        bad = fixture.document; bad.Get("original_files")->ArrayItems()[0].Set("path", JsonValue::String("C:drive-relative")); fixture.Reject(bad, "relative");
        bad = fixture.document; bad.Get("original_files")->ArrayItems()[0].Set("sha256", JsonValue::String(std::string(64, '0'))); fixture.Reject(bad, "SHA256 mismatch");
        bad = fixture.document; bad.Get("original_files")->ArrayItems()[0].Set("bytes", JsonValue::Number("1")); fixture.Reject(bad, "size mismatch");
        bad = fixture.document; bad.Get("original_files")->ArrayItems()[0].Set("bytes", JsonValue::Number("-1")); fixture.Reject(bad, "unsigned integer");
        bad = fixture.document; bad.Get("original_files")->ArrayItems().push_back(bad.Get("original_files")->ArrayItems()[0]); fixture.Reject(bad, "Ambiguous");
        File(fixture.tree / "unlisted", "unlisted original"); fixture.Reject(fixture.document, "Unlisted"); fs::remove(fixture.tree / "unlisted");
        const auto second_tree = fixture.tree.parent_path() / "second-original";
        File(second_tree / "plugins", "file at a virtual directory");
        bad = fixture.document; bad.Get("original_trees")->ArrayItems().push_back(JsonValue::String(fixture.Relative(second_tree)));
        bad.Get("original_files")->ArrayItems().push_back(fixture.Original(second_tree / "plugins"));
        fixture.Reject(bad, "file/directory namespace collision"); fs::remove_all(second_tree);
        const auto duplicate = fixture.tree / "plugins" / "other" / "libOwnedMacro.dylib";
        File(duplicate, "another library"); bad = fixture.document; bad.Get("original_files")->ArrayItems().push_back(fixture.Original(duplicate)); fixture.Reject(bad, "Ambiguous original plugin module"); fs::remove_all(duplicate.parent_path());
        {
            // The same module in two listed directories: the earlier directory wins.
            const auto shadowed = fixture.tree / "later-plugins" / "libOwnedMacro.dylib";
            File(shadowed, "shadowed library"); auto layered = fixture.document;
            layered.Get("original_files")->ArrayItems().push_back(fixture.Original(shadowed));
            layered.Get("plugin_directories")->ArrayItems().push_back(JsonValue::String("/later-plugins"));
            fixture.Save(layered); DarwinMacroProvider precedence; std::string precedence_error;
            Require(ReadDarwinMacroProvider(fixture.receipt, fixture.managed, precedence, precedence_error, fixture.sdk), precedence_error);
            Require(precedence.plugins.size() == 1 && precedence.plugins[0].virtual_path == "/plugins/nested/libOwnedMacro.dylib",
                    "earlier plugin directory did not take precedence");
            precedence = {}; fs::remove_all(shadowed.parent_path());
        }
        bad = fixture.document; bad.Get("original_trees")->ArrayItems().push_back(JsonValue::String(fixture.Relative(fixture.tree / "plugins"))); fixture.Reject(bad, "Overlapping");
        bad = fixture.document; bad.Get("cache")->Get("parent")->Set("report_sha256", JsonValue::String(std::string(64, '0'))); fixture.Reject(bad, "SHA256 mismatch");
        bad = fixture.document; bad.Get("cache")->Get("parent")->Set("sha256", JsonValue::String(std::string(64, '0'))); fixture.Reject(bad, "digest/virtual");
        bad = fixture.document; bad.Get("cache")->Get("parent")->Set("payload", JsonValue::String("cache/first.bin")); fixture.Reject(bad, "embedded payload");
        bad = fixture.document; bad.Get("cache")->Get("children")->ArrayItems()[0].Set("source_sha256", JsonValue::String(std::string(64, 'c'))); fixture.Reject(bad, "digest/virtual");
        bad = fixture.document; bad.Get("cache")->Get("children")->ArrayItems().push_back(bad.Get("cache")->Get("children")->ArrayItems()[0]); fixture.Reject(bad, "Duplicate provider cache report");
        File(fixture.plugin, "tampered library"); fixture.Reject(fixture.document, "size mismatch"); File(fixture.plugin, "owned library metadata fixture");
        auto same_size_tamper = std::string("owned library metadata fixture"); same_size_tamper[0] = 'X';
        File(fixture.plugin, same_size_tamper); fixture.Reject(fixture.document, "SHA256 mismatch"); File(fixture.plugin, "owned library metadata fixture");
        auto wrong_cpu = MachO(); Little(wrong_cpu, 4, 0x01000007); File(fixture.executable, wrong_cpu);
        bad = fixture.document; bad.Get("original_files")->ArrayItems()[0] = fixture.Original(fixture.executable);
        bad.Get("executable")->Set("sha256", JsonValue::String(Hash(fixture.executable))); fixture.Reject(bad, "ARM64"); File(fixture.executable, MachO());

        DarwinClosureOptions limit; limit.max_files = 1; fixture.Reject(fixture.document, "file budget", limit);
        limit = {}; limit.max_depth = 1; fixture.Reject(fixture.document, "depth budget", limit);
        limit = {}; limit.deadline = std::chrono::steady_clock::now(); fixture.Reject(fixture.document, "deadline", limit);
        CancellationSource cancelled; cancelled.Cancel(); limit = {}; limit.cancellation = cancelled.Token(); fixture.Reject(fixture.document, "cancelled", limit);

        const auto outside = root / "outside", alias = fixture.tree / "escape"; File(outside / "owned", "outside managed root");
        if (CreateSymbolicLinkW(alias.c_str(), outside.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2)) {
            bad = fixture.document; auto escaped = fixture.Original(alias / "owned"); bad.Get("original_files")->ArrayItems().push_back(escaped);
            fixture.Reject(bad, "escapes managed root"); fs::remove(alias);
        } else std::cout << "directory reparse negative skipped: symbolic link capability unavailable\n";
        fixture.Save(fixture.document); Require(ReadDarwinMacroProvider(fixture.receipt, fixture.managed, output, error, fixture.sdk), error);
        output = {}; fs::remove_all(root); std::cout << "Darwin provider receipt/lease/path/plugin/cache admission tests passed (metadata only).\n"; return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n'; std::error_code ignored; fs::remove_all(root, ignored); return 1;
    }
}
