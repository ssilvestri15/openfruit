#include "swiftpm_resolve_observation.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <cwchar>
#include <optional>

namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
constexpr LONGLONG kMaximumFileBytes = 1024 * 1024;

struct FileHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~FileHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

JsonValue ObserveFile(const fs::path& path) {
    auto row = JsonValue::ObjectValue();
    std::error_code error;
    auto absolute = fs::absolute(path, error).lexically_normal().wstring();
    if (error) {
        row.Set("status", JsonValue::String("unavailable"));
        return row;
    }
    if (absolute.rfind(L"\\\\?\\", 0) != 0)
        absolute = absolute.rfind(L"\\\\", 0) == 0
            ? L"\\\\?\\UNC\\" + absolute.substr(2) : L"\\\\?\\" + absolute;
    const auto attributes = GetFileAttributesW(absolute.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        row.Set("status", JsonValue::String("non_regular"));
        return row;
    }
    FileHandle file;
    file.value = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file.value == INVALID_HANDLE_VALUE) {
        const auto code = GetLastError();
        row.Set("status", JsonValue::String(code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND
            ? "missing" : "unavailable"));
        row.Set("win32_error", JsonValue::Number(std::to_string(code)));
        return row;
    }
    LARGE_INTEGER size{};
    if (GetFileType(file.value) != FILE_TYPE_DISK || !GetFileSizeEx(file.value, &size) || size.QuadPart < 0) {
        row.Set("status", JsonValue::String("unavailable"));
        return row;
    }
    row.Set("bytes", JsonValue::Number(std::to_string(size.QuadPart)));
    if (size.QuadPart > kMaximumFileBytes) {
        row.Set("status", JsonValue::String("too_large"));
        return row;
    }
    const auto digest = Sha256FileHandle(file.value, {},
        std::chrono::steady_clock::now() + std::chrono::milliseconds(500));
    row.Set("status", JsonValue::String(digest ? "hashed" : "unavailable"));
    if (digest) row.Set("sha256", JsonValue::String(*digest));
    return row; // Release the stable handle before SwiftPM can mutate its state.
}

struct EnvironmentObservation {
    std::optional<std::wstring> value;
    bool unavailable = false;
};

EnvironmentObservation InheritedValue(const wchar_t* key) {
    SetLastError(ERROR_SUCCESS);
    const auto size = GetEnvironmentVariableW(key, nullptr, 0);
    if (!size) {
        const auto code = GetLastError();
        if (code == ERROR_ENVVAR_NOT_FOUND) return {};
        if (code == ERROR_SUCCESS) return {std::wstring{}, false};
        return {std::nullopt, true};
    }
    std::wstring value(size, L'\0');
    SetLastError(ERROR_SUCCESS);
    const auto written = GetEnvironmentVariableW(key, value.data(), size);
    if (written >= size || (!written && GetLastError() != ERROR_SUCCESS))
        return {std::nullopt, true}; // Concurrent mutation/error; do not report absence.
    value.resize(written);
    return {std::move(value), false};
}

JsonValue ObserveEnvironment(const std::vector<std::pair<std::wstring, std::wstring>>& overrides) {
    constexpr const wchar_t* keys[] = {
        L"SDKROOT", L"PATH", L"TEMP", L"TMP", L"AR", L"LIBTOOL", L"SWIFT_EXEC", L"SWIFT_EXEC_MANIFEST",
        L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL", L"OPENFRUIT_SWIFT_MANIFEST_SDK",
        L"OPENFRUIT_COMPILER_PROXY_REAL", L"OPENFRUIT_COMPILER_SYMLINK_MAP",
        L"OPENFRUIT_COMPILER_STRING_MACROS", L"OPENFRUIT_COMPILER_OBJC_STRING_MACROS",
        L"OPENFRUIT_USE_APPLE_PLUGIN_SERVER", L"GIT_CONFIG_COUNT", L"GIT_CONFIG_KEY_0",
        L"GIT_CONFIG_VALUE_0", L"GIT_CONFIG_KEY_1", L"GIT_CONFIG_VALUE_1"
    };
    auto rows = JsonValue::ObjectValue();
    for (const auto key : keys) {
        auto inherited = InheritedValue(key);
        auto value = std::move(inherited.value);
        const char* source = inherited.unavailable ? "unavailable" : value ? "inherited" : "absent";
        for (auto it = overrides.rbegin(); it != overrides.rend(); ++it) {
            if (_wcsicmp(it->first.c_str(), key) == 0) {
                value = it->second;
                source = "override";
                inherited.unavailable = false;
                break;
            }
        }
        auto row = JsonValue::ObjectValue();
        row.Set("present", inherited.unavailable ? JsonValue::Null() : JsonValue::Boolean(value.has_value()));
        row.Set("source", JsonValue::String(source));
        if (value) {
            const auto digest = Sha256(Win32Process::ToNarrow(*value));
            if (digest) row.Set("sha256", JsonValue::String(*digest));
            else row.Set("hash_status", JsonValue::String("unavailable"));
        }
        rows.Set(Win32Process::ToNarrow(key), std::move(row));
    }
    return rows;
}

void ObservePath(JsonValue& data, const char* key, const fs::path& path) {
    const auto value = Win32Process::ToNarrow(path.wstring());
    auto row = JsonValue::ObjectValue();
    row.Set("utf16_length", JsonValue::Number(std::to_string(path.wstring().size())));
    const auto digest = Sha256(value);
    if (digest) row.Set("sha256_utf8", JsonValue::String(*digest));
    data.Set(key, std::move(row));
}
}

void EmitSwiftPMResolveObservation(std::string_view resolve_id,
    const fs::path& package, const fs::path& scratch,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment,
    const ProcessResult* result) noexcept {
    const auto context = CurrentOperationContext();
    if (!context) return;
    try {
        auto data = JsonValue::ObjectValue();
        data.Set("schema", JsonValue::String("openfruit.swiftpm.resolve-observation.v1"));
        data.Set("resolve_id", JsonValue::String(std::string(resolve_id)));
        data.Set("phase", JsonValue::String(result ? "after" : "before"));
        data.Set("consistency", JsonValue::String("per-file-observation"));
        data.Set("environment_scope", JsonValue::String("allowlisted caller overrides and inherited variables, before journal injection"));
        ObservePath(data, "package_path", package);
        ObservePath(data, "scratch_path", scratch);
        ObservePath(data, "shared_cache_path", scratch / "shared-cache");
        auto files = JsonValue::ObjectValue();
        files.Set("manifest", ObserveFile(package / "Package.swift"));
        files.Set("lock", ObserveFile(package / "Package.resolved"));
        files.Set("workspace_state", ObserveFile(scratch / "workspace-state.json"));
        data.Set("files", std::move(files));
        data.Set("environment", ObserveEnvironment(environment));
        if (result) {
            auto outcome = JsonValue::ObjectValue();
            outcome.Set("exit_code", JsonValue::Number(std::to_string(result->exit_code)));
            outcome.Set("process_id", JsonValue::Number(std::to_string(result->process_id)));
            outcome.Set("win32_error", JsonValue::Number(std::to_string(result->win32_error)));
            outcome.Set("tool_stack_frame_count", JsonValue::Number(std::to_string(result->tool_stack_frame_count)));
            outcome.Set("captured_stdout_bytes", JsonValue::Number(std::to_string(result->std_out.size())));
            outcome.Set("captured_stderr_bytes", JsonValue::Number(std::to_string(result->std_err.size())));
            outcome.Set("launched", JsonValue::Boolean(result->launched));
            outcome.Set("success", JsonValue::Boolean(result->success));
            outcome.Set("cancelled", JsonValue::Boolean(result->cancelled));
            outcome.Set("timed_out", JsonValue::Boolean(result->timed_out));
            outcome.Set("output_truncated", JsonValue::Boolean(result->output_truncated));
            outcome.Set("callback_failed", JsonValue::Boolean(result->callback_failed));
            data.Set("result", std::move(outcome));
        }
        context->Emit("dependencies.resolve.observation", std::move(data));
    } catch (...) {
        // Observation failure must not replace a resolver result or change its inputs.
        context->Emit("dependencies.resolve.observation.unavailable");
    }
}
}
