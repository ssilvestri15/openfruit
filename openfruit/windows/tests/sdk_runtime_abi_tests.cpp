#include "sdk_runtime_abi.hpp"
#include "tool_paths.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <cstdint>
#include <cstring>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void Write(const fs::path& path, const std::string& bytes) { std::ofstream(path, std::ios::binary) << bytes; }
void WriteUnversionedObject(const fs::path& path, bool payload) {
    // Owned minimal Mach-O object fixture: no Apple input is patched. LLVM, not
    // this writer, parses the generated archive in the production inspector.
    std::string bytes(184 + (payload ? 4 : 0), '\0');
    auto put = [&](std::size_t offset, std::uint32_t value) { std::memcpy(bytes.data() + offset, &value, 4); };
    put(0, 0xfeedfacf); put(4, 0x0100000c); put(12, 1); put(16, 1); put(20, 152);
    put(32, 0x19); put(36, 152); put(72, 184); put(80, payload ? 4 : 0);
    put(88, 7); put(92, 7); put(96, 1);
    std::memcpy(bytes.data() + 104, "__text", 6); std::memcpy(bytes.data() + 120, "__TEXT", 6);
    put(144, payload ? 4 : 0); put(152, 184); put(168, 0x800004);
    Write(path, bytes);
}
ProcessResult Run(const fs::path& executable, std::vector<std::wstring> args) {
    args.insert(args.begin(), executable.wstring());
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    return Win32Process::Run(executable.wstring(), args, L"", {}, nullptr, nullptr, options);
}
}
int main() {
    const auto llvm = ToolPaths::LlvmBin({});
    if (!fs::is_regular_file(llvm / "clang.exe") || !fs::is_regular_file(llvm / "llvm-ar.exe") ||
        !fs::is_regular_file(llvm / "llvm-objdump.exe") || !fs::is_regular_file(llvm / "llvm-readobj.exe")) {
        std::cout << "SKIP: managed LLVM clang/ar/objdump unavailable\n"; return 77;
    }
    const auto root = fs::temp_directory_path() / ("openfruit-ios-archive-abi-" + std::to_string(GetCurrentProcessId()));
    fs::create_directories(root);
    try {
        Write(root / "value.c", "int runtime_abi_fixture(void) { return 7; }\n");
        Write(root / "empty.c", "\n");
        auto compile = [&](const std::string& stem, const std::string& target, bool empty = false) {
            const auto output = Run(llvm / "clang.exe", {L"-target", Win32Process::ToWide(target), L"-c",
                (root / (empty ? "empty.c" : "value.c")).wstring(), L"-o", (root / (stem + ".o")).wstring()});
            if (!output.success) throw std::runtime_error("Actual LLVM fixture compile failed: " + output.std_err);
        };
        auto archive = [&](const std::string& name, std::initializer_list<std::string> objects) {
            std::vector<std::wstring> args{L"rcs", (root / (name + ".a")).wstring()};
            for (const auto& object : objects) args.push_back((root / (object + ".o")).wstring());
            const auto output = Run(llvm / "llvm-ar.exe", std::move(args));
            if (!output.success) throw std::runtime_error("Actual LLVM archive fixture failed: " + output.std_err);
            return root / (name + ".a");
        };
        compile("ios", "arm64-apple-ios17.0");
        compile("new-ios", "arm64-apple-ios18.0");
        compile("macos", "arm64-apple-macos14.0");
        compile("simulator", "arm64-apple-ios17.0-simulator");
        compile("x86", "x86_64-apple-ios17.0-simulator");
        compile("elf", "aarch64-none-elf");
        // An Apple-target object with no load-version command is permitted only
        // when all sections are empty. This is not a runtime implementation.
        WriteUnversionedObject(root / "empty.o", false);
        WriteUnversionedObject(root / "unversioned-code.o", true);
        auto valid = archive("valid", {"ios"});
        auto inspection = InspectIosRuntimeArchive(valid, llvm, "17.0");
        if (!inspection.eligible) throw std::runtime_error("Actual iOS archive rejected: " + inspection.error);
        Require(inspection.architectures == std::vector<std::string>{"arm64"}, "Selected architecture evidence wrong");
        Require(inspection.minimum_versions == std::vector<std::string>{"17.0"}, "Minimum iOS evidence wrong");
        Require(!InspectIosRuntimeArchive(valid, llvm, "16.9").eligible, "Higher deployment member accepted");
        Require(!InspectIosRuntimeArchive(valid, llvm, "17garbage").eligible, "Invalid deployment accepted");
        Require(!InspectIosRuntimeArchive(archive("too-new", {"new-ios"}), llvm, "17.0").eligible, "New iOS deployment accepted");
        Require(!InspectIosRuntimeArchive(archive("macos", {"macos"}), llvm, "17.0").eligible, "macOS runtime accepted");
        Require(!InspectIosRuntimeArchive(archive("mixed", {"ios", "macos"}), llvm, "17.0").eligible, "Mixed platform accepted");
        Require(!InspectIosRuntimeArchive(archive("simulator", {"simulator"}), llvm, "17.0").eligible, "Simulator accepted for device");
        Require(!InspectIosRuntimeArchive(archive("mixed-cpu", {"ios", "x86"}), llvm, "17.0").eligible, "Mixed CPU archive accepted");
        Require(!InspectIosRuntimeArchive(archive("mixed-elf", {"ios", "elf"}), llvm, "17.0").eligible, "Silently skipped ELF member accepted");
        Require(InspectIosRuntimeArchive(archive("empty-plus-ios", {"empty", "ios"}), llvm, "17.0").eligible, "Empty unversioned object rejected");
        Require(!InspectIosRuntimeArchive(archive("unversioned-code", {"unversioned-code"}), llvm, "17.0").eligible, "Unversioned code accepted");
        Require(!InspectIosRuntimeArchive(root / "ios.o", llvm, "17.0").eligible, "Raw object accepted as archive");
        Write(root / "bad.a", "!<arch>\ncorrupt");
        Require(!InspectIosRuntimeArchive(root / "bad.a", llvm, "17.0").eligible, "Malformed archive accepted");
        ProcessRunOptions cancelled;
        cancelled.cancellation = std::make_shared<std::atomic<bool>>(true);
        Require(!InspectIosRuntimeArchive(valid, llvm, "17.0", cancelled).eligible, "Cancelled inspection accepted");
        ProcessRunOptions bounded;
        bounded.capture_limit_bytes = 16;
        Require(!InspectIosRuntimeArchive(valid, llvm, "17.0", bounded).eligible, "Truncated tool output accepted");
        fs::remove_all(root);
        std::cout << "Actual LLVM iOS archive ABI fixtures PASS (static eligibility only)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\nOwned fixtures retained: " << root << '\n'; return 1;
    }
}
