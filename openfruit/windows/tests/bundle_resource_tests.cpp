#include "bundle_resources.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <plist/plist.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
void File(const fs::path& path, std::string_view bytes) {
    fs::create_directories(path.parent_path()); std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), bytes.size()); Require(bool(output), "owned resource fixture write failed");
}
struct Scratch {
    const fs::path parent = fs::absolute(fs::temp_directory_path()).lexically_normal();
    const fs::path root = parent / ("OPENFRUIT-bundle-resources-" + NewOperationId());
    ~Scratch() { if (root.is_absolute() && root.parent_path() == parent && root.filename().wstring().starts_with(L"OPENFRUIT-bundle-resources-")) {
        std::error_code ignored; fs::remove_all(root, ignored);
    } }
};
struct Parsed {
    plist_t value = nullptr;
    explicit Parsed(std::string_view xml) { Require(plist_from_memory(xml.data(), static_cast<uint32_t>(xml.size()), &value, nullptr) == PLIST_ERR_SUCCESS, "cannot inspect CodeResources fixture"); }
    ~Parsed() { if (value) plist_free(value); }
    std::string Xml() {
        char* bytes = nullptr; uint32_t size = 0;
        Require(plist_to_xml(value, &bytes, &size) == PLIST_ERR_SUCCESS && bytes, "cannot serialize resource negative control");
        std::string result(bytes, size); plist_mem_free(bytes); return result;
    }
};
bool Hash(plist_t node, std::string_view bytes, const wchar_t* algorithm, DWORD expected_size) {
    BYTE digest[32]{}; DWORD size = sizeof(digest);
    Require(CryptHashCertificate2(algorithm, 0, nullptr, reinterpret_cast<const BYTE*>(bytes.data()), static_cast<DWORD>(bytes.size()), digest, &size), "independent resource digest failed");
    uint64_t length = 0; const auto value = node && plist_get_node_type(node) == PLIST_DATA ? plist_get_data_ptr(node, &length) : nullptr;
    return value && size == expected_size && length == expected_size && std::string_view(value, length) == std::string_view(reinterpret_cast<char*>(digest), size);
}
}
int main() {
    try {
        Scratch scratch; const auto bundle = scratch.root / "Owned.app";
        const std::string info = "<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>ActualMain</string></dict></plist>";
        File(bundle / "Info.plist", info); File(bundle / "ActualMain", "owned main stage bytes");
        File(bundle / "Assets" / "data.bin", std::string(2 * 1024 * 1024 + 7, 'x'));
        File(bundle / "Empty", ""); File(bundle / "embedded.mobileprovision", "owned retained profile stage bytes");
        File(bundle / "Base.lproj" / "Localizable.strings", "required base");
        File(bundle / "it.lproj" / "Localizable.strings", "optional localization");
        File(bundle / "it.lproj" / "locversion.plist", "omitted localization bookkeeping");
        File(bundle / ".DS_Store", "omitted from modern envelope"); File(bundle / "PkgInfo", "omitted modern metadata");
        File(bundle / "_CodeSignature" / "CodeResources", "old root seal must not seal itself");
        File(bundle / "PlugIns" / "Child.appex" / "_CodeSignature" / "CodeResources", "nested signature bytes must be sealed");
        File(bundle / "PlugIns" / "Child.appex" / "ActualChild", "nested executable bytes must be sealed");
        File(bundle / L"Assets" / L"nome-è.txt", "Unicode path");
        BundleResourceSeal seal; std::string error;
        Require(BuildFlatBundleResourceSeal(bundle, seal, error), error.c_str());
        Require(seal.executable_path == bundle / "ActualMain" && seal.info_plist == info &&
            VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), error.c_str());
        Parsed parsed(seal.code_resources);
        const auto files = plist_dict_get_item(parsed.value, "files"), files2 = plist_dict_get_item(parsed.value, "files2");
        Require(plist_dict_get_item(files, "Info.plist") && !plist_dict_get_item(files2, "Info.plist") &&
            !plist_dict_get_item(files, "ActualMain") && !plist_dict_get_item(files2, "ActualMain"), "flat Info/executable exclusion policy is wrong");
        Require(!plist_dict_get_item(files2, "_CodeSignature/CodeResources") &&
            plist_dict_get_item(files2, "PlugIns/Child.appex/_CodeSignature/CodeResources") &&
            plist_dict_get_item(files2, "PlugIns/Child.appex/ActualChild"), "root exclusions accidentally hid nested code signatures");
        Require(!plist_dict_get_item(files2, ".DS_Store") && !plist_dict_get_item(files2, "PkgInfo") &&
            !plist_dict_get_item(files, "it.lproj/locversion.plist") && !plist_dict_get_item(files2, "it.lproj/locversion.plist"), "flat omission rules incorrect");
        Require(Hash(plist_dict_get_item(files, "Empty"), "", L"SHA1", 20) &&
            Hash(plist_dict_get_item(plist_dict_get_item(files2, "Empty"), "hash2"), "", L"SHA256", 32), "empty file digests differ from CryptoAPI");
        const auto large = std::string(2 * 1024 * 1024 + 7, 'x');
        Require(Hash(plist_dict_get_item(plist_dict_get_item(files2, "Assets/data.bin"), "hash2"), large, L"SHA256", 32), "streamed resource SHA256 differs from CryptoAPI");
        File(bundle / "ActualMain", "new main byte-stage output");
        Require(VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "resource verifier hashes separately sealed main executable");
        File(bundle / "Assets" / "data.bin", "altered");
        Require(!VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "altered regular resource accepted"); File(bundle / "Assets" / "data.bin", large);
        File(bundle / "new-resource", "new"); Require(!VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "unsealed additional resource accepted");
        fs::remove(bundle / "new-resource");
        fs::remove(bundle / "it.lproj" / "Localizable.strings");
        Require(VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "permitted optional localization removal rejected");
        fs::remove(bundle / "Base.lproj" / "Localizable.strings");
        Require(!VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "missing required Base localization accepted"); File(bundle / "Base.lproj" / "Localizable.strings", "required base");
        File(bundle / "PlugIns" / "Child.appex" / "_CodeSignature" / "CodeResources", "changed child seal");
        Require(!VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "changed nested signature file accepted");
        File(bundle / "PlugIns" / "Child.appex" / "_CodeSignature" / "CodeResources", "nested signature bytes must be sealed");
        for (int mutation = 0; mutation < 5; ++mutation) {
            Parsed changed(seal.code_resources);
            const auto current = plist_dict_get_item(changed.value, "files2");
            if (mutation == 0) plist_dict_remove_item(current, "Assets/data.bin");
            if (mutation == 1) plist_dict_set_item(plist_dict_get_item(current, "Assets/data.bin"), "hash2", plist_new_data("wrong", 5));
            if (mutation == 2) plist_dict_set_item(plist_dict_get_item(changed.value, "rules2"), "^.*", plist_new_bool(0));
            if (mutation == 3) plist_dict_set_item(current, "../escape", plist_copy(plist_dict_get_item(current, "Empty")));
            if (mutation == 4) plist_dict_set_item(plist_dict_get_item(current, "it.lproj/Localizable.strings"), "hash2", plist_new_string("malformed missing optional seal"));
            Require(!VerifyFlatBundleResourceSeal(bundle, changed.Xml(), error), "malformed seal/schema/rules/path accepted");
        }
        const auto link = bundle / "asset-link";
        Require(CreateSymbolicLinkW(link.c_str(), L"Empty", SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE), "owned Windows symlink fixture unavailable");
        BundleResourceSeal linked;
        Require(BuildFlatBundleResourceSeal(bundle, linked, error) && VerifyFlatBundleResourceSeal(bundle, linked.code_resources, error), error.c_str());
        Parsed linked_xml(linked.code_resources);
        Require(!plist_dict_get_item(plist_dict_get_item(linked_xml.value, "files"), "asset-link") &&
            plist_get_node_type(plist_dict_get_item(plist_dict_get_item(plist_dict_get_item(linked_xml.value, "files2"), "asset-link"), "symlink")) == PLIST_STRING,
            "symlink sealed as target bytes instead of portable target metadata");
        fs::remove(link); Require(CreateSymbolicLinkW(link.c_str(), L"MissingTarget", SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE), "broken link fixture unavailable");
        Require(!VerifyFlatBundleResourceSeal(bundle, linked.code_resources, error), "retargeted/broken resource link accepted under old seal");
        Require(BuildFlatBundleResourceSeal(bundle, linked, error), "link target existence wrongly required to seal link text");
        fs::remove(link);
        File(bundle / "Info.plist", "<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>../escape</string></dict></plist>");
        linked = seal; Require(!BuildFlatBundleResourceSeal(bundle, linked, error) && linked.code_resources.empty() && linked.info_plist.empty() && linked.executable_path.empty(), "invalid executable path retained stale seal");
        File(bundle / "Info.plist", info);
        for (const bool deadline : {false, true}) {
            auto context = std::make_shared<OperationContext>();
            if (deadline) context->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() - std::chrono::seconds(1));
            else context->RequestCancellation(); OperationBinding binding(context); linked = seal;
            Require(!BuildFlatBundleResourceSeal(bundle, linked, error) && linked.code_resources.empty() && error.find("cancelled or deadline") != std::string::npos,
                "cancelled resource producer published stale output");
            Require(!VerifyFlatBundleResourceSeal(bundle, seal.code_resources, error), "cancelled resource verifier continued");
        }
        std::cout << "Flat iOS CodeResources generation, streaming digests and independent inventory/schema verification: PASS\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
