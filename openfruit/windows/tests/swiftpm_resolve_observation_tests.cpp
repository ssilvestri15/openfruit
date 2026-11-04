#include "swiftpm_resolve_observation.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
const JsonValue& Field(const JsonValue& value, const char* name) {
    const auto* field = value.Get(name);
    Require(field != nullptr, name);
    return *field;
}
std::string Digest(std::string_view value) {
    const auto digest = Sha256(value);
    Require(digest.has_value(), "Test SHA256 failed");
    return *digest;
}
void Write(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Require(static_cast<bool>(stream), "Cannot write owned test input");
}
struct EnvironmentValue {
    bool present = false;
    std::wstring value;
};
EnvironmentValue ReadEnvironment(const wchar_t* key) {
    SetLastError(ERROR_SUCCESS);
    const DWORD required = GetEnvironmentVariableW(key, nullptr, 0);
    if (required == 0) return {GetLastError() != ERROR_ENVVAR_NOT_FOUND, {}};
    std::wstring value(required, L'\0');
    const DWORD count = GetEnvironmentVariableW(key, value.data(), required);
    Require(count < required, "Environment changed during test read");
    value.resize(count);
    return {true, std::move(value)};
}
class EnvironmentGuard {
public:
    EnvironmentGuard(const wchar_t* key, const wchar_t* value) : key_(key), saved_(ReadEnvironment(key)) {
        Require(SetEnvironmentVariableW(key, value) != FALSE, "Cannot prepare owned test environment");
    }
    ~EnvironmentGuard() { SetEnvironmentVariableW(key_.c_str(), saved_.present ? saved_.value.c_str() : nullptr); }
private:
    std::wstring key_;
    EnvironmentValue saved_;
};
class EventSinkCollector final : public EventSink {
public:
    void Emit(OperationEvent event) noexcept override {
        try { std::lock_guard lock(mutex_); events.push_back(std::move(event)); }
        catch (...) { failed = true; }
    }
    std::vector<OperationEvent> events;
    bool failed = false;
private:
    std::mutex mutex_;
};
struct Fixture {
    fs::path root = fs::temp_directory_path() / ("OPENFRUIT-resolve-observation-" + NewOperationId());
    fs::path package = root / "Package";
    fs::path scratch = root / "Scratch";
    std::shared_ptr<EventSinkCollector> sink = std::make_shared<EventSinkCollector>();
    std::shared_ptr<OperationContext> context = std::make_shared<OperationContext>(
        OperationContext{sink, NewOperationId(), NewOperationId(), {}});
    Fixture() { fs::create_directories(package); fs::create_directories(scratch); }
    ~Fixture() { std::error_code error; fs::remove_all(root, error); }
    const OperationEvent& Observe(const std::vector<std::pair<std::wstring, std::wstring>>& env = {},
                                  const ProcessResult* result = nullptr) {
        OperationBinding binding(context);
        const auto before = sink->events.size();
        EmitSwiftPMResolveObservation("owned-resolve-id", package, scratch, env, result);
        Require(!sink->failed && sink->events.size() == before + 1, "Observation missing or emitted extra events/spans");
        const auto& event = sink->events.back();
        Require(event.kind == "dependencies.resolve.observation", "Wrong resolve event kind");
        Require(event.build_id == context->build_id && event.span_id == context->span_id,
                "Observation replaced the owning operation/span identity");
        Require(event.data.GetString("schema") == "openfruit.swiftpm.resolve-observation.v1", "Wrong observation schema");
        Require(event.data.GetString("resolve_id") == "owned-resolve-id", "Resolve pair identity lost");
        Require(event.data.GetString("phase") == (result ? "after" : "before"), "Resolve phase is wrong");
        return event;
    }
};
const JsonValue& FileRow(const OperationEvent& event, const char* key) {
    return Field(Field(event.data, "files"), key);
}
void CheckHashed(const JsonValue& row, const std::string& bytes) {
    Require(row.GetString("status") == "hashed", "Regular input did not hash");
    Require(row.GetString("sha256") == Digest(bytes), "File digest does not match original bytes");
    const auto& size = Field(row, "bytes");
    Require(size.IsNumber() && size.Int(-1) == static_cast<int>(bytes.size()), "File byte count is incorrect");
}
void TestFilesAndResult() {
    Fixture fixture;
    const std::string manifest = "// owned manifest\nlet evidence = \"caf\xc3\xa9\"\n";
    const std::string lock = "{\"pins\":[],\"owned\":\"lock\"}\r\n";
    const std::string state("owned\0workspace-state", 21);
    Write(fixture.package / "Package.swift", manifest);
    Write(fixture.package / "Package.resolved", lock);
    Write(fixture.scratch / "workspace-state.json", state);
    const auto before = fixture.Observe();
    CheckHashed(FileRow(before, "manifest"), manifest);
    CheckHashed(FileRow(before, "lock"), lock);
    CheckHashed(FileRow(before, "workspace_state"), state);
    Require(!before.data.Get("result"), "Before observation fabricated a process result");

    ProcessResult result;
    result.exit_code = -1073741795;
    result.launched = true;
    result.cancelled = true;
    result.timed_out = true;
    result.output_truncated = true;
    result.callback_failed = true;
    result.process_id = 1234;
    result.win32_error = ERROR_ACCESS_DENIED;
    result.tool_stack_frame_count = 7;
    result.std_out = "owned-secret-process-stdout";
    result.std_err = "owned-secret-process-stderr";
    const auto after = fixture.Observe({}, &result);
    const auto& outcome = Field(after.data, "result");
    Require(Field(outcome, "exit_code").Int() == result.exit_code, "Native failure code changed");
    for (const char* key : {"launched", "cancelled", "timed_out", "output_truncated", "callback_failed"})
        Require(Field(outcome, key).IsBoolean() && Field(outcome, key).Bool(), "Process failure flag missing");
    Require(!Field(outcome, "success").Bool(true), "Failed process fabricated success");
    Require(Field(outcome, "win32_error").Int() == ERROR_ACCESS_DENIED &&
            Field(outcome, "tool_stack_frame_count").Int() == 7, "Process failure evidence missing");
    Require(Field(outcome, "process_id").Int() == 1234 &&
            Field(outcome, "captured_stdout_bytes").Int() == static_cast<int>(result.std_out.size()) &&
            Field(outcome, "captured_stderr_bytes").Int() == static_cast<int>(result.std_err.size()),
            "Process identity or captured byte counts missing");
    Require(after.data.Serialize().find("owned-secret-process") == std::string::npos, "Observation copied process output");
    Require(after.data.Serialize().find("owned manifest") == std::string::npos &&
            after.data.Serialize().find("owned\\\":\\\"lock") == std::string::npos,
            "Observation copied resolver file contents");
    CheckHashed(FileRow(after, "manifest"), manifest);
    Require(Sha256File(fixture.package / "Package.swift") == Sha256(manifest) &&
            Sha256File(fixture.package / "Package.resolved") == Sha256(lock) &&
            Sha256File(fixture.scratch / "workspace-state.json") == Sha256(state), "Observation modified resolver inputs");
}
void TestFileAvailabilityAndBound() {
    Fixture fixture;
    const auto missing = fixture.Observe();
    for (const char* key : {"manifest", "lock", "workspace_state"}) {
        const auto& row = FileRow(missing, key);
        Require(row.GetString("status") == "missing" && !row.Get("sha256"), "Missing file fabricated a hash");
    }
    fs::create_directory(fixture.package / "Package.resolved");
    const std::string boundary(1024 * 1024, 'B');
    Write(fixture.package / "Package.swift", boundary);
    Write(fixture.scratch / "workspace-state.json", boundary + "X");
    const auto bounded = fixture.Observe();
    CheckHashed(FileRow(bounded, "manifest"), boundary);
    Require(FileRow(bounded, "lock").GetString("status") == "non_regular", "Directory classified as missing/file");
    const auto& large = FileRow(bounded, "workspace_state");
    Require(large.GetString("status") == "too_large" && !large.Get("sha256"), "Oversized file bypassed observation bound");
    Require(Field(large, "bytes").Int() == 1024 * 1024 + 1, "Oversized file length lost");
    const HANDLE locked = CreateFileW((fixture.package / "Package.swift").c_str(), GENERIC_READ, 0, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(locked != INVALID_HANDLE_VALUE, "Could not exclusively open owned input");
    const auto unavailable = fixture.Observe();
    CloseHandle(locked);
    Require(FileRow(unavailable, "manifest").GetString("status") == "unavailable" &&
            !FileRow(unavailable, "manifest").Get("sha256"), "Unreadable input fabricated a digest");
}
void CheckEnvironmentRow(const JsonValue& env, const char* key, bool present, const char* source,
                         const std::string& value = {}) {
    const auto& row = Field(env, key);
    Require(Field(row, "present").IsBoolean() && Field(row, "present").Bool() == present, "Environment presence incorrect");
    Require(row.GetString("source") == source, "Environment provenance incorrect");
    if (present) Require(row.GetString("sha256") == Digest(value), "Environment UTF8 digest incorrect");
    else Require(!row.Get("sha256"), "Absent environment value acquired a digest");
    Require(!row.Get("value"), "Raw environment value was recorded");
}
void TestEnvironmentPrivacyAndChildPropagation(const fs::path& executable) {
    EnvironmentGuard sdk(L"SDKROOT", L"owned-inherited-sdk");
    EnvironmentGuard count(L"GIT_CONFIG_COUNT", L"owned-inherited-count");
    EnvironmentGuard absent(L"GIT_CONFIG_KEY_0", nullptr);
    EnvironmentGuard compiler(L"SWIFT_EXEC", L"owned-compiler-selection");
    Fixture fixture;
    const std::wstring chosen = L"owned-final-sdk-\u00e8-\u96ea";
    const std::vector<std::pair<std::wstring, std::wstring>> overrides = {
        {L"SdkRoot", L"owned-overridden-first-sdk"}, {L"sDkRoOt", chosen},
        {L"git_config_value_0", L""}, {L"OWNED_SECRET_NOT_ALLOWLISTED", L"owned-unlisted-secret"}
    };
    const auto observation = fixture.Observe(overrides);
    const auto& env = Field(observation.data, "environment");
    CheckEnvironmentRow(env, "SDKROOT", true, "override", Win32Process::ToNarrow(chosen));
    CheckEnvironmentRow(env, "GIT_CONFIG_COUNT", true, "inherited", "owned-inherited-count");
    CheckEnvironmentRow(env, "GIT_CONFIG_KEY_0", false, "absent");
    CheckEnvironmentRow(env, "GIT_CONFIG_VALUE_0", true, "override", "");
    CheckEnvironmentRow(env, "SWIFT_EXEC", true, "inherited", "owned-compiler-selection");
    Require(!env.Get("SdkRoot") && !env.Get("sDkRoOt") && !env.Get("OWNED_SECRET_NOT_ALLOWLISTED"),
            "Environment keys escaped uppercase allowlist");
    const auto serialized = observation.data.Serialize();
    Require(serialized.find(Win32Process::ToNarrow(fixture.package.wstring())) == std::string::npos &&
            serialized.find(Win32Process::ToNarrow(fixture.scratch.wstring())) == std::string::npos &&
            serialized.find(fixture.root.filename().string()) == std::string::npos,
            "Observation exposed a raw workspace path");
    for (const char* secret : {"owned-final-sdk", "owned-inherited-sdk", "owned-inherited-count",
                               "owned-overridden-first-sdk", "owned-unlisted-secret", "owned-compiler-selection"})
        Require(serialized.find(secret) == std::string::npos, "Raw environment secret leaked");

    // Feed the exact same override vector to the real production process runner.
    // The child hashes its received SDKROOT, so an observer-only hand-built value
    // cannot satisfy propagation if last-override/UTF8 handling differs.
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    const auto child = Win32Process::Run(executable.wstring(), {executable.wstring(), L"--child-env"},
                                         fixture.root.wstring(), overrides, nullptr, nullptr, options);
    Require(child.launched && child.success, "Production process runner did not execute environment child");
    Require(child.std_out == Field(env, "SDKROOT").GetString("sha256"), "Observed override differs from actual child environment");

    EnvironmentGuard empty(L"SDKROOT", L"");
    const auto inherited_empty = fixture.Observe();
    CheckEnvironmentRow(Field(inherited_empty.data, "environment"), "SDKROOT", true, "inherited", "");
    EnvironmentGuard removed(L"SDKROOT", nullptr);
    const auto inherited_absent = fixture.Observe();
    CheckEnvironmentRow(Field(inherited_absent.data, "environment"), "SDKROOT", false, "absent");
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--child-env") {
            const auto value = ReadEnvironment(L"SDKROOT");
            Require(value.present, "Child SDKROOT absent");
            std::cout << Digest(Win32Process::ToNarrow(value.value));
            return 0;
        }
        // The telemetry API must remain harmless when no operation is bound.
        EmitSwiftPMResolveObservation("no-context", {}, {}, {});
        TestFilesAndResult();
        TestFileAvailabilityAndBound();
        TestEnvironmentPrivacyAndChildPropagation(fs::absolute(argv[0]));
        std::cout << "SwiftPM resolve observations: file integrity, privacy and actual child propagation PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
