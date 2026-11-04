#include "sdk_target_runtime.hpp"
#include "operation_events.hpp"
#include "content_hash.hpp"
#include "artifact_store.hpp"
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <utility>
using namespace OpenFruit;
namespace fs = std::filesystem;
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void ContendedReuseTests(const fs::path& sdk, const fs::path& llvm, const fs::path& home,
    const fs::path& destination) {
    auto writer = ArtifactLease::Acquire(destination);
    Require(!ArtifactLease::TryAcquireSharedRead(destination), "Reader entered an active writer scope");
    for (const bool cancel : {false, true}) {
        auto context = std::make_shared<OperationContext>();
        const auto started = std::chrono::steady_clock::now();
        context->control = std::make_shared<OperationControl>(started +
            (cancel ? std::chrono::seconds(2) : std::chrono::milliseconds(100)));
        std::jthread requester;
        if (cancel) requester = std::jthread([context] {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            context->RequestCancellation();
        });
        IosTargetRuntimeResult blocked;
        { OperationBinding binding(context); blocked = EnsureIosTargetRuntime(sdk, llvm, "17.0", home); }
        Require(!blocked.available && !blocked.artifact_lease && blocked.library_directories.empty(),
            "A contended writer exposed an unleased runtime result");
        Require(blocked.error.find(cancel ? "cancel" : "tim") != std::string::npos ||
            (!cancel && blocked.error.find("deadline") != std::string::npos),
            "Runtime reader contention did not preserve cancellation/deadline diagnostics");
        Require(std::chrono::steady_clock::now() - started < std::chrono::seconds(3),
            "Contended runtime reuse exceeded its bounded operation control");
    }
}
void ConsumerLifetimeTests(const fs::path& sdk, const fs::path& llvm, const fs::path& home,
    const fs::path& destination) {
    // Admission applies only to this owned fixture. Production managed categories
    // remain protected by the CLI's separate eligibility policy.
    const auto prune = [&] {
        return NativeArtifactStore::PruneCache(destination.parent_path(), 0, 0, true,
            [&](const fs::path& candidate) { return candidate == destination; });
    };
    auto first = EnsureIosTargetRuntime(sdk, llvm, "17.0", home);
    Require(first.available && first.artifact_lease, "Available runtime must carry its consumer lease");
    const auto receipt_time = fs::last_write_time(destination / "receipt.json");
    auto context = std::make_shared<OperationContext>();
    context->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() + std::chrono::seconds(2));
    IosTargetRuntimeResult second;
    { OperationBinding binding(context); second = EnsureIosTargetRuntime(sdk, llvm, "17.0", home); }
    Require(second.available && second.artifact_lease && fs::last_write_time(destination / "receipt.json") == receipt_time,
        "Repeated Ensure with a live reader must share access without rewriting the receipt");
    auto copied = first;
    auto moved = std::move(copied);
    first = {}; second = {};
    Require(moved.available && moved.artifact_lease && !ArtifactLease::TryAcquire(destination),
        "Copy/move of a runtime result lost its consumer lease");
    auto retained = prune();
    Require(retained.success && retained.entries_removed == 0 && retained.entries_skipped_in_use == 1 && fs::exists(destination),
        "Retention removed an output still owned by a result copy");
    bool thread_retained = false, thread_released = false;
    std::exception_ptr worker_error;
    std::thread consumer([owned = std::move(moved), &destination, &prune, &thread_retained,
                          &thread_released, &worker_error]() mutable {
        try {
            const auto report = prune();
            thread_retained = owned.artifact_lease && !ArtifactLease::TryAcquire(destination) &&
                report.success && report.entries_removed == 0 && report.entries_skipped_in_use == 1;
            owned = {};
            thread_released = static_cast<bool>(ArtifactLease::TryAcquire(destination));
        } catch (...) { worker_error = std::current_exception(); }
    });
    consumer.join();
    if (worker_error) std::rethrow_exception(worker_error);
    Require(thread_retained && thread_released, "Final result ownership/release did not survive transfer to another thread");
    const auto removed = prune();
    Require(removed.success && removed.entries_removed == 1 && !fs::exists(destination),
        "Owned fixture was not prunable after every runtime result released its lease");
}
// Owned receipt-admission fixtures, not Apple authentication/ABI evidence.
void ReuseTests(const fs::path& root) {
    const auto home = root / "reuse-managed", llvm = root / "reuse-llvm";
    const auto identity = std::string(64, 'b');
    const auto member = fs::path("Xcode.app/Contents/Developer/SDKs/iPhoneOS.sdk/SDKSettings.json");
    const auto sdk = home / "sdk/xcode" / identity / member.parent_path();
    fs::create_directories(sdk); fs::create_directories(llvm);
    std::ofstream(sdk / "SDKSettings.json") << "owned-sdk-input";
    std::ofstream(llvm / "llvm-objdump.exe") << "owned-tool-never-executed";
    std::ofstream(llvm / "llvm-readobj.exe") << "owned-readobj-never-executed";
    const auto archive_sha = *Sha256("owned-archive"), sdk_sha = *Sha256File(sdk / "SDKSettings.json");
    const auto tool_sha = *Sha256File(llvm / "llvm-objdump.exe"), readobj_sha = *Sha256File(llvm / "llvm-readobj.exe");
    const auto key = *Sha256("apple-ios-runtime-v1\nopenfruit.ios-runtime-archive-abi.v1\n" + archive_sha +
        "\n" + sdk_sha + "\n" + tool_sha + "\n" + readobj_sha + "\n17.0");
    const auto destination = home / "toolchains/apple-ios" / key;
    fs::create_directories(destination / "lib");
    std::ofstream(destination / "lib/libOwned.a") << "owned-cache-output";
    auto receipt = JsonValue::ObjectValue();
    for (const auto& [name, value] : std::vector<std::pair<std::string, std::string>>{
        {"schema", "apple-ios-runtime-v1"}, {"key", key}, {"archive_sha256", archive_sha},
        {"sdk_archive_identity", identity}, {"sdk_settings_member", member.generic_string()},
        {"sdk_settings_sha256", sdk_sha}, {"llvm_objdump_sha256", tool_sha},
        {"llvm_readobj_sha256", readobj_sha}, {"deployment_target", "17.0"}})
        receipt.Set(name, JsonValue::String(value));
    auto authentication = JsonValue::ObjectValue();
    for (const auto* name : {"toc_checksum_verified", "content_checksum_verified", "xar_signature_valid",
            "apple_signing_chain_valid", "apple_revocation_valid"})
        authentication.Set(name, JsonValue::Boolean(true));
    receipt.Set("extraction", authentication);
    auto library = JsonValue::ObjectValue();
    library.Set("name", JsonValue::String("libOwned.a"));
    library.Set("sha256", JsonValue::String(*Sha256File(destination / "lib/libOwned.a")));
    auto libraries = JsonValue::ArrayValue(); libraries.ArrayItems().push_back(library);
    receipt.Set("libraries", libraries);
    auto publish = [&](const JsonValue& value) { std::ofstream(destination / "receipt.json") << value.Serialize(true); };
    publish(receipt);
    auto reused = EnsureIosTargetRuntime(sdk, llvm, "17.0", home);
    Require(reused.available && reused.library_directories == std::vector<fs::path>{destination / "lib"} &&
        reused.evidence.Get("reused_without_archive") && reused.evidence.Get("reused_without_archive")->Bool() &&
        !fs::exists(home / "cache"), "Bound output must revalidate and reuse without an archive or tool execution");
    Require(static_cast<bool>(reused.artifact_lease), "Warm reuse returned no lifetime consumer lease");
    // The corruption cases deliberately mutate owned fixture state outside the
    // cooperating protocol; release every valid consumer before doing so.
    reused = {};
    auto reject = [&] { Require(!EnsureIosTargetRuntime(sdk, llvm, "17.0", home).available,
        "Mismatched/corrupt/unbound output was admitted without its source archive"); };
    for (const auto* field : {"sdk_archive_identity", "sdk_settings_member", "archive_sha256",
            "sdk_settings_sha256", "llvm_objdump_sha256", "llvm_readobj_sha256", "deployment_target", "key", "schema"}) {
        auto changed = receipt; changed.Set(field, JsonValue::String("mismatch")); publish(changed); reject();
    }
    auto unbound = receipt; unbound.ObjectItems().erase("sdk_archive_identity"); publish(unbound); reject();
    auto unauthenticated = receipt;
    authentication.Set("apple_signing_chain_valid", JsonValue::Boolean(false));
    unauthenticated.Set("extraction", authentication); publish(unauthenticated); reject();
    publish(receipt);
    std::ofstream(destination / "lib/libOwned.a") << "corrupt"; reject();
    std::ofstream(destination / "lib/libOwned.a") << "owned-cache-output";
    std::ofstream(destination / "lib/extra.a") << "unexpected"; reject();
    fs::remove(destination / "lib/extra.a");
    Require(!EnsureIosTargetRuntime(sdk, llvm, "18.0", home).available, "Deployment target mismatch reused runtime");
    std::ofstream(llvm / "llvm-objdump.exe") << "changed-tool"; reject();
    std::ofstream(llvm / "llvm-objdump.exe") << "owned-tool-never-executed";
    std::ofstream(sdk / "SDKSettings.json") << "changed-sdk"; reject();
    std::ofstream(sdk / "SDKSettings.json") << "owned-sdk-input";
    Require(EnsureIosTargetRuntime(sdk, llvm, "17.0", home).available, "Restored verified inputs did not reuse output");
    const auto other_archive = *Sha256("another-owned-archive");
    const auto other_key = *Sha256("apple-ios-runtime-v1\nopenfruit.ios-runtime-archive-abi.v1\n" + other_archive +
        "\n" + sdk_sha + "\n" + tool_sha + "\n" + readobj_sha + "\n17.0");
    const auto other = home / "toolchains/apple-ios" / other_key;
    fs::create_directories(other / "lib");
    fs::copy_file(destination / "lib/libOwned.a", other / "lib/libOwned.a");
    auto ambiguous = receipt;
    ambiguous.Set("key", JsonValue::String(other_key));
    ambiguous.Set("archive_sha256", JsonValue::String(other_archive));
    std::ofstream(other / "receipt.json") << ambiguous.Serialize(true);
    reject();
    // A paired archive can disambiguate two bound fixtures without rewriting
    // either receipt or upgrading an already held reader to a writer.
    const auto paired_archive = home / "cache" / "sdk-downloads" / (identity + ".download");
    fs::create_directories(paired_archive.parent_path());
    std::ofstream(paired_archive) << "owned-archive";
    {
        auto selected = EnsureIosTargetRuntime(sdk, llvm, "17.0", home);
        Require(selected.available && selected.artifact_lease, "Exact archive did not select the bound runtime");
        const auto before = fs::last_write_time(destination / "receipt.json");
        auto bounded = std::make_shared<OperationContext>();
        bounded->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() + std::chrono::seconds(2));
        OperationBinding binding(bounded);
        auto repeated = EnsureIosTargetRuntime(sdk, llvm, "17.0", home);
        Require(repeated.available && repeated.artifact_lease &&
            fs::last_write_time(destination / "receipt.json") == before,
            "Disambiguated bound reuse attempted a writer while an existing reader was alive");
    }
    fs::remove(paired_archive);
    fs::remove_all(other);
    auto context = std::make_shared<OperationContext>(); context->RequestCancellation();
    { OperationBinding binding(context);
      Require(!EnsureIosTargetRuntime(sdk, llvm, "17.0", home).available,
          "Warm cache reuse ignored operation cancellation"); }
    ContendedReuseTests(sdk, llvm, home, destination);
    ConsumerLifetimeTests(sdk, llvm, home, destination);
}
int main(int argc, char** argv) {
    // Diagnostic invocation of the actual native service on admitted inputs;
    // no stand-in extraction, tool selection or fabricated success path.
    if (argc == 6 && std::string(argv[1]) == "--probe-managed") {
        auto result = EnsureIosTargetRuntime(fs::u8path(argv[2]), fs::u8path(argv[3]), argv[4], fs::u8path(argv[5]));
        auto report = result.evidence;
        report.Set("available", JsonValue::Boolean(result.available));
        report.Set("error", JsonValue::String(result.error));
        std::cout << report.Serialize(true) << '\n';
        return result.available ? 0 : 1;
    }
    if (argc != 1) return 2;
    const auto root = fs::temp_directory_path() / ("o-" + NewOperationId().substr(0, 16));
    try {
        fs::create_directories(root / "custom.sdk");
        std::ofstream(root / "custom.sdk" / "SDKSettings.json") << "{\"Version\":\"27.0\"}";
        const auto custom = EnsureIosTargetRuntime(root / "custom.sdk", root / "llvm", "17.0", root / "managed");
        Require(!custom.available && custom.library_directories.empty() && !custom.error.empty(), "Custom SDK must not borrow unrelated original libraries");
        Require(!fs::exists(root / "managed" / "toolchains"), "Unavailable SDK must not publish runtime state");
        const auto managed_sdk = root / "managed" / "sdk" / "xcode" / std::string(64, 'a') / "Xcode.app" / "Contents" / "Developer" / "Platforms" / "iPhoneOS.platform" / "Developer" / "SDKs" / "iPhoneOS.sdk";
        fs::create_directories(managed_sdk);
        std::ofstream(managed_sdk / "SDKSettings.json") << "{}";
        const auto absent = EnsureIosTargetRuntime(managed_sdk, root / "llvm", "17.0", root / "managed");
        Require(!absent.available && absent.error.find("unavailable") != std::string::npos, "Managed path alone must not establish archive authenticity");
        auto context = std::make_shared<OperationContext>();
        context->RequestCancellation();
        { OperationBinding binding(context);
          const auto cancelled = EnsureIosTargetRuntime(managed_sdk, root / "llvm", "17.0", root / "managed");
          Require(!cancelled.available && cancelled.error.find("cancelled") != std::string::npos, "Operation cancellation must stop acquisition before publication"); }
        Require(!fs::exists(root / "managed" / "toolchains"), "Negative gates must not publish state");
        // These inputs never execute: an invalid original container must be
        // rejected before a tool can inspect or publish target libraries.
        fs::create_directories(root / "managed" / "cache" / "sdk-downloads");
        fs::create_directories(root / "llvm");
        std::ofstream(root / "managed" / "cache" / "sdk-downloads" / (std::string(64, 'a') + ".download")) << "not-an-Apple-XIP";
        std::ofstream(root / "llvm" / "llvm-objdump.exe") << "must-never-execute";
        std::ofstream(root / "llvm" / "llvm-readobj.exe") << "must-never-execute";
        const auto invalid = EnsureIosTargetRuntime(managed_sdk, root / "llvm", "17.0", root / "managed");
        Require(!invalid.available && invalid.library_directories.empty() &&
            invalid.error.find("authentication") != std::string::npos,
            "An archive digest or managed pathname must not substitute Apple authentication");
        const auto runtime_root = root / "managed" / "toolchains" / "apple-ios";
        if (fs::exists(runtime_root)) for (const auto& entry : fs::directory_iterator(runtime_root))
            Require(entry.path().filename() == "_staging", "Failed authentication must not publish a content-key directory");
        ReuseTests(root);
        fs::remove_all(root);
        std::cout << "sdk_target_runtime_tests PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        if (fs::exists(root) && root.parent_path() == fs::temp_directory_path()) fs::remove_all(root);
        return 1;
    }
}
