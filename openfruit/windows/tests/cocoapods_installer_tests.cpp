#include "cocoapods_installer.hpp"

#include <windows.h>

#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    Require(static_cast<bool>(out), "cannot write fixture");
}
} // namespace

int main() {
    const auto root = fs::temp_directory_path() /
        ("OPENFRUIT-cocoapods-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    try {
        const std::string lock = "PODS:\n  - Base32 (1.1.2)\n\nPODFILE CHECKSUM: 50cc\n\nCOCOAPODS: 1.16.2\n";
        Write(root / "Podfile", "target 'App' do\n  pod 'Base32'\nend\n");
        Write(root / "Podfile.lock", lock);
        Require(CocoaPodsLockedVersion(root / "Podfile.lock") == std::optional<std::string>("1.16.2"),
                "locked CocoaPods version was not read");
        Write(root / "crlf.lock", "PODS:\r\n\r\nCOCOAPODS: 1.15.2\r\n");
        Require(CocoaPodsLockedVersion(root / "crlf.lock") == std::optional<std::string>("1.15.2"),
                "CRLF Podfile.lock version was not read");
        Write(root / "none.lock", "PODS:\n  - Base32 (1.1.2)\n");
        Require(!CocoaPodsLockedVersion(root / "none.lock"), "missing version was invented");

        // [CP] Check Pods Manifest.lock: absent or different manifest is stale.
        Require(!CocoaPodsSandboxCurrent(root), "missing sandbox reported current");
        Write(root / "Pods" / "Manifest.lock", lock + "\n");
        Require(!CocoaPodsSandboxCurrent(root), "different manifest reported current");
        Write(root / "Pods" / "Manifest.lock", lock);
        Require(CocoaPodsSandboxCurrent(root), "identical manifest reported stale");
        // A current sandbox needs no installer and no toolchain acquisition.
        Require(!EnsureCocoaPodsSandbox(root), "current sandbox was reinstalled");
        // Without a lockfile there is nothing to install deterministically.
        fs::remove(root / "Podfile.lock");
        Require(!EnsureCocoaPodsSandbox(root), "unlocked Podfile was installed");
        fs::remove_all(root);
        std::cout << "PASS: CocoaPods manifest contract and locked version\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nEvidence: " << root.string() << '\n';
        return 1;
    }
}
