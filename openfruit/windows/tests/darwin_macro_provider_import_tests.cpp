#include "darwin_macro_provider.hpp"
#include "darwin_macro_provider_import.hpp"
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

namespace {
struct ImportFixture {
    Fixture fixture;
    fs::path source, specification;
    JsonValue specification_json;
    explicit ImportFixture(const fs::path& root) : fixture(root), source(root / "original-source"), specification(root / "import.json") {
        fs::rename(fixture.tree, source);
        fs::remove(fixture.receipt);
        specification_json = JsonValue::ObjectValue();
        specification_json.Set("schema", JsonValue::String("openfruit.darwin-provider-import.v1"));
        auto trees = JsonValue::ArrayValue(); auto tree = JsonValue::ObjectValue();
        tree.Set("source", JsonValue::String(Win32Process::ToNarrow(source.generic_wstring())));
        tree.Set("destination", JsonValue::String(fixture.Relative(fixture.tree))); trees.ArrayItems().push_back(std::move(tree));
        specification_json.Set("original_trees", std::move(trees));
        auto reports = JsonValue::ArrayValue();
        auto remap_report = [&](JsonValue& value) {
            const fs::path original = fixture.managed / fs::path(Win32Process::ToWide(value.GetString("report")));
            const auto destination = fixture.receipt.parent_path() / "cache-reports" / original.filename();
            auto mapping = JsonValue::ObjectValue(); mapping.Set("source", JsonValue::String(Win32Process::ToNarrow(original.generic_wstring())));
            mapping.Set("destination", JsonValue::String(fixture.Relative(destination))); reports.ArrayItems().push_back(std::move(mapping));
            value.Set("report", JsonValue::String(fixture.Relative(destination)));
        };
        remap_report(*fixture.document.Get("cache")->Get("parent"));
        for (auto& value : fixture.document.Get("cache")->Get("children")->ArrayItems()) remap_report(value);
        specification_json.Set("cache_reports", std::move(reports));
        specification_json.Set("receipt", fixture.document); Save();
    }
    void Save() const { File(specification, specification_json.Serialize(true)); }
    bool Import(std::string& error) const { return ImportDarwinMacroProvider(specification, fixture.managed, fixture.sdk, error); }
};
}
int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-darwin-provider-import-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    try {
        std::string error;
        {
            ImportFixture input(root / "positive");
            const auto payload_hash = Hash(input.fixture.managed / "cache" / "main.bin");
            Require(input.Import(error), "valid owned import failed: " + error);
            Require(fs::exists(input.fixture.receipt), "successful import did not publish receipt");
            DarwinMacroProvider provider;
            Require(ReadDarwinMacroProvider(input.fixture.receipt, input.fixture.managed, provider, error, input.fixture.sdk), error);
            Require(provider.plugins.size() == 1 && provider.child_cache_reports.size() == 2, "published metadata inventory differs");
            Require(!provider.provenance.Get("publisher_verified")->Bool() && !provider.provenance.Get("published")->Bool(), "import promoted publisher provenance");
            const auto before_receipt = Hash(input.fixture.receipt), before_plugin = Hash(input.fixture.plugin);
            provider = {};
            // Idempotence depends on admitted managed state, not source survival.
            fs::remove_all(input.source);
            Require(input.Import(error), "idempotent import required vanished original source: " + error);
            Require(Hash(input.fixture.receipt) == before_receipt && Hash(input.fixture.plugin) == before_plugin, "idempotent import rewrote originals/receipt");
            Require(Hash(input.fixture.managed / "cache" / "main.bin") == payload_hash, "import mutated cache payload");
            File(input.fixture.plugin, "modified original");
            Require(!input.Import(error) && !error.empty(), "idempotent import accepted modified managed originals");
            Require(Hash(input.fixture.receipt) == before_receipt, "invalid present provider receipt was replaced");
        }
        {
            ImportFixture input(root / "bad-original");
            input.specification_json.Get("receipt")->Get("original_files")->ArrayItems()[0].Set("sha256", JsonValue::String(std::string(64, '0'))); input.Save();
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt) && !fs::exists(input.fixture.tree), "bad original digest published provider/tree");
        }
        {
            ImportFixture input(root / "existing-invalid-tree");
            File(input.fixture.tree / "retained", "existing unrelated data"); const auto before = Hash(input.fixture.tree / "retained");
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "invalid existing tree accepted");
            Require(Hash(input.fixture.tree / "retained") == before, "invalid existing original tree was overwritten");
        }
        {
            ImportFixture input(root / "bad-cache-source");
            const auto* mapping = input.specification_json.Get("cache_reports");
            const fs::path report(Win32Process::ToWide(mapping->ArrayItems()[0].GetString("source"))); File(report, "tampered report");
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "tampered cache report published provider");
            Require(fs::is_directory(input.fixture.tree), "verified original tree unexpectedly removed after later import failure");
        }
        {
            ImportFixture input(root / "existing-invalid-report");
            const auto relative = input.specification_json.Get("cache_reports")->ArrayItems()[0].GetString("destination");
            const fs::path report = input.fixture.managed / fs::path(Win32Process::ToWide(relative)); File(report, "retained invalid report");
            const auto before = Hash(report); Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "invalid existing report accepted");
            Require(Hash(report) == before, "invalid existing report was overwritten");
        }
        {
            ImportFixture input(root / "bad-final-receipt");
            input.specification_json.Get("receipt")->Get("executable")->Set("virtual_path", JsonValue::String("/unlisted-server")); input.Save();
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "failed complete receipt admission published provider");
            for (const auto& file : fs::directory_iterator(input.fixture.receipt.parent_path()))
                Require(!file.path().filename().wstring().starts_with(L".provider-candidate-"), "failed candidate receipt leaked");
        }
        {
            ImportFixture input(root / "bad-sdk");
            input.specification_json.Get("receipt")->Get("selection")->Set("sdk_settings_sha256", JsonValue::String(std::string(64, '0'))); input.Save();
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt) && !fs::exists(input.fixture.tree), "SDK mismatch wrote provider inputs");
        }
        {
            ImportFixture input(root / "unlisted-destination");
            input.specification_json.Get("original_trees")->ArrayItems()[0].Set("destination", JsonValue::String("sdk/slot/unlisted")); input.Save();
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "unlisted import destination accepted");
        }
        {
            ImportFixture input(root / "traversal");
            input.specification_json.Get("original_trees")->ArrayItems()[0].Set("destination", JsonValue::String("../outside")); input.Save();
            Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "traversal import destination accepted");
        }
        {
            ImportFixture input(root / "reparse"); const auto outside = root / "outside"; fs::create_directories(outside);
            if (CreateSymbolicLinkW(input.fixture.tree.c_str(), outside.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2)) {
                Require(!input.Import(error) && !fs::exists(input.fixture.receipt), "reparse import destination accepted");
                Require(fs::is_empty(outside), "import wrote outside managed root through reparse point"); fs::remove(input.fixture.tree);
            } else std::cout << "import reparse negative skipped: symbolic link capability unavailable\n";
        }
        fs::remove_all(root); std::cout << "Darwin provider local import/publication tests passed (owned metadata; no guest execution).\n"; return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n'; std::error_code ignored; fs::remove_all(root, ignored); return 1;
    }
}
