#include "package_engine.hpp"
#include "artifact_store.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "tool_paths.hpp"
#include "operation_events.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const std::string& message) { if (!value) throw std::runtime_error(message); }
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
}
int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    const auto root = fs::temp_directory_path() / ("openfruit-proxy-identity-" + NewOperationId());
    try {
        Require(argc == 2, "Pass the actual native OPENFRUIT candidate path");
        const auto original = fs::absolute(fs::path(argv[1]));
        const auto original_hash = Sha256File(original);
        Require(original_hash.has_value(), "Actual native CLI could not be verified");
        fs::create_directories(root / "input");
        const auto source = root / "input" / "OPENFRUIT.exe";
        fs::copy_file(original, source);
        Require(Sha256File(source) == original_hash, "Owned independent CLI copy differs from actual candidate");
        const auto container = root / "execution";
        auto lease = ArtifactLease::Acquire(container);
        fs::create_directories(container / "s");
        const auto directory = container / "s" / "OPENFRUIT-ios-target-toolchain";
        const auto receipt = container / "i" / "compiler-proxy.json";
        // Production generates this value from CMake inputs. These tests cover
        // the storage contract; the two-CLI production warm gate verifies the
        // derivation independently, without caller-injected build dimensions.
        const auto implementation = PackageEngine::CompilerProxyIdentity();
        Require(implementation.size() == 64, "Automatic implementation identity is unavailable");
        const auto semantic = Sha256("owned-proxy-contract\n" + implementation).value();
        std::string error;
        bool reused = true;
        auto prepare = [&](const std::string& identity = {}) {
            return PackageEngine::PrepareCompilerProxyToolchain(source, directory, receipt,
                identity.empty() ? semantic : identity, error, &reused);
        };
        Require(prepare() && !reused, "First native proxy publication failed");
        const auto executable = directory / "swiftc.exe";
        const auto written = fs::last_write_time(executable);
        const auto receipt_time = fs::last_write_time(receipt);
        Require(Sha256File(executable) == original_hash, "Published proxy is not the real CLI");
        Require(prepare() && reused && fs::last_write_time(executable) == written &&
            fs::last_write_time(receipt) == receipt_time, "Warm verification rewrote proxy or ownership metadata");
        const auto changed = Sha256(semantic + "semantic-change").value();
        Require(prepare(changed) && !reused, "Different semantic identity was admitted as a warm hit");
        Require(prepare(changed) && reused, "Verified changed identity did not stabilize");
        {
            std::fstream corrupt(executable, std::ios::binary | std::ios::in | std::ios::out);
            char byte = 0; corrupt.read(&byte, 1); byte ^= 1; corrupt.seekp(0); corrupt.write(&byte, 1);
        }
        Require(prepare(changed) && !reused && Sha256File(executable) == original_hash,
            "Corrupt owned proxy was reused or not repaired from the actual candidate");
        auto ownership = JsonValue::Parse(Read(receipt));
        Require(ownership.has_value(), "Published proxy receipt cannot be parsed");
        ownership->Set("phase", JsonValue::String("prepared"));
        Require(AtomicFile::Publish(receipt, ownership->Serialize(true)), "Owned interruption setup failed");
        fs::remove(directory / "clang++.exe");
        Require(prepare(changed) && !reused && Sha256File(directory / "clang++.exe") == original_hash,
            "Owned interrupted publication was not repaired");
        const auto legacy = root / "legacy";
        auto legacy_lease = ArtifactLease::Acquire(legacy);
        const auto legacy_directory = legacy / "s" / "OPENFRUIT-ios-target-toolchain";
        fs::create_directories(legacy_directory);
        std::ofstream(legacy_directory / "unowned.txt") << "owned negative-control legacy bytes";
        Require(!PackageEngine::PrepareCompilerProxyToolchain(source, legacy_directory,
            legacy / "i" / "compiler-proxy.json", semantic, error) &&
            !fs::exists(legacy / "i" / "compiler-proxy.json") && fs::exists(legacy_directory / "unowned.txt"),
            "Unreceipted legacy files were adopted or deleted");
        {
            const auto context = std::make_shared<OperationContext>();
            context->RequestCancellation();
            OperationBinding binding(context);
            Require(!prepare(changed) && !error.empty(), "Cancelled identity verification reported success");
        }
        const auto before_corrupt_receipt = Sha256File(executable);
        Require(AtomicFile::Publish(receipt, "corrupt-owned-negative-control"), "Corrupt receipt setup failed");
        Require(!prepare(changed) && Sha256File(executable) == before_corrupt_receipt,
            "Corrupt ownership metadata authorized proxy replacement");
        Require(Sha256File(original) == original_hash && Sha256File(source) == original_hash,
            "Proxy preparation mutated original inputs");
        // Use a real host compilation followed by the same driver mode used
        // by SwiftPM's debug AST wrapping. The published production proxy must
        // preserve both command contracts without caller-supplied SIL options.
        const auto swift = ToolPaths::SwiftBin({}) / "swiftc.exe";
        if (fs::is_regular_file(swift)) {
            auto environment = PackageEngine::HostEnvironment(swift.parent_path());
            // The isolated executable retains the candidate's native DLL
            // dependencies. Discover their directory from the actual candidate,
            // rather than relying on the interactive shell's PATH.
            for (auto& [name, value] : environment)
                if (_wcsicmp(name.c_str(), L"PATH") == 0)
                    value = original.parent_path().wstring() + L";" + value;
            environment.emplace_back(L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", swift.wstring());
            const auto input = root / "input/CommandMode.swift";
            const auto module = root / "CommandMode.swiftmodule";
            const auto wrapped = root / "CommandMode.o";
            std::ofstream(input) << "public let commandModeValue = 17\n";
            const auto compile = Win32Process::Run(executable.wstring(), {executable.wstring(),
                L"-emit-module", L"-module-name", L"CommandMode", input.wstring(),
                L"-o", module.wstring()}, root.wstring(), environment);
            Require(compile.success && fs::is_regular_file(module),
                "Real Swift module compilation through the production proxy failed (" +
                std::to_string(compile.exit_code) + "): " + compile.std_out + compile.std_err);
            const auto wrap = Win32Process::Run(executable.wstring(), {executable.wstring(),
                L"-modulewrap", module.wstring(), L"-o", wrapped.wstring()}, root.wstring(), environment);
            Require(wrap.success && fs::is_regular_file(wrapped) && fs::file_size(wrapped) > 0,
                "Production proxy corrupted Swift AST-wrapper mode: " + wrap.std_err);
        }
        lease.reset(); legacy_lease.reset();
        fs::remove_all(root); // Unique owned fixture only, after consumers release.
        std::cout << "Verified native compiler proxy identity and ownership: PASS\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << "; owned fixture retained: " << root << '\n';
        return 1;
    }
}
