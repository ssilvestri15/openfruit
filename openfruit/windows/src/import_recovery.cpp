#include "import_recovery.hpp"
#include "operation_events.hpp"
#include "text_util.hpp"
#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <chrono>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <regex>
#include <set>
#include <sstream>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
struct RecoveryMetrics {
    OperationContextPtr context = CurrentOperationContext();
    std::map<std::string, std::uint64_t> counters = {
        {"recovery_attempts", 0}, {"sdk_walks", 0}, {"sdk_entries", 0},
        {"artifact_open_attempts", 0}, {"artifact_files_read", 0},
        {"artifact_bytes_read", 0}, {"candidates_evaluated", 0},
        {"symbol_cache_hits", 0}, {"symbol_cache_misses", 0},
        {"extractor_launch_attempts", 0}, {"extractor_processes", 0},
        {"extractor_failures", 0}, {"compiler_retries", 0},
        {"ambiguity_rejections", 0}};
    std::map<std::string, double> durations;
    bool recovered = false;
    ~RecoveryMetrics() try {
        if (!context) return;
        JsonValue data = JsonValue::ObjectValue();
        for (const auto& [name, value] : counters)
            data.Set(name, JsonValue::Number(std::to_string(value)));
        for (const auto& [name, value] : durations)
            data.Set(name + "_ms", JsonValue::Number(std::to_string(value)));
        data.Set("recovered", JsonValue::Boolean(recovered));
        context->Emit("recovery.metrics", std::move(data));
    } catch (...) {} // Observability must preserve the compiler result.
};
thread_local RecoveryMetrics* active_metrics = nullptr;
class RecoveryMeasurement {
public:
    explicit RecoveryMeasurement(RecoveryMetrics& metrics)
        : previous_(active_metrics) { active_metrics = &metrics; }
    ~RecoveryMeasurement() { active_metrics = previous_; }
private:
    RecoveryMetrics* previous_;
};
class RecoveryPhase {
public:
    explicit RecoveryPhase(const char* name)
        : metrics_(active_metrics), name_(name), started_(std::chrono::steady_clock::now()) {}
    ~RecoveryPhase() {
        if (metrics_) metrics_->durations[name_] +=
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started_).count();
    }
private:
    RecoveryMetrics* metrics_;
    const char* name_;
    std::chrono::steady_clock::time_point started_;
};
void CountRecovery(const char* name, std::uint64_t value = 1) {
    if (active_metrics) active_metrics->counters[name] += value;
}
fs::path ExtendedWin32FilesystemPath(const fs::path& value) {
    std::error_code ec;
    fs::path absolute = fs::absolute(value, ec).lexically_normal();
    if (ec) {
        absolute = value.lexically_normal();
    }
    const std::wstring path = absolute.wstring();
    if (path.rfind(L"\\\\?\\", 0) == 0) {
        return absolute;
    }
    if (path.rfind(L"\\\\", 0) == 0) {
        return fs::path(L"\\\\?\\UNC\\" + path.substr(2));
    }
    if (path.size() >= 3 && std::iswalpha(path[0]) &&
        path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        return fs::path(L"\\\\?\\" + path);
    }
    return absolute;
}

struct ImportRecoveryCandidate {
    std::string module;
    std::string origin;
    std::vector<fs::path> artifacts;
    bool ambiguous_origin = false;
};

std::vector<std::string> ParseJsonStrings(const std::string& text) {
    std::vector<std::string> values;
    for (std::size_t index = 0; index < text.size();) {
        if (text[index] != '"') {
            ++index;
            continue;
        }

        ++index;
        std::string value;
        bool complete = false;
        while (index < text.size()) {
            const char current = text[index++];
            if (current == '"') {
                complete = true;
                break;
            }
            if (current != '\\' || index == text.size()) {
                value += current;
                continue;
            }

            const char escaped = text[index++];
            switch (escaped) {
            case '"': value += '"'; break;
            case '\\': value += '\\'; break;
            case '/': value += '/'; break;
            case 'b': value += '\b'; break;
            case 'f': value += '\f'; break;
            case 'n': value += '\n'; break;
            case 'r': value += '\r'; break;
            case 't': value += '\t'; break;
            default:
                // SwiftPM paths and module identifiers are ASCII. Preserve
                // unsupported escapes so they cannot be misinterpreted.
                value += '\\';
                value += escaped;
                break;
            }
        }
        if (complete) {
            values.push_back(std::move(value));
        }
    }
    return values;
}

std::optional<std::wstring> SwiftArgumentValue(
    const std::vector<std::wstring>& arguments,
    const std::wstring& name
) {
    for (std::size_t index = 1; index + 1 < arguments.size(); ++index) {
        if (arguments[index] == name) {
            return arguments[index + 1];
        }
    }
    return std::nullopt;
}

bool JsonArgumentsMatch(
    const std::vector<std::string>& arguments,
    const std::string& module,
    const std::string& target
) {
    bool module_matches = false;
    bool target_matches = false;
    bool emits_module = false;
    for (std::size_t index = 0; index + 1 < arguments.size(); ++index) {
        if (arguments[index] == "-module-name" &&
            arguments[index + 1] == module) {
            module_matches = true;
        }
        if (arguments[index] == "-target" &&
            arguments[index + 1] == target) {
            target_matches = true;
        }
        if (arguments[index] == "-emit-module") {
            emits_module = true;
        }
    }
    return module_matches && target_matches && emits_module;
}

std::string SwiftModuleName(const fs::path& artifact) {
    if (artifact.extension() != ".swiftmodule") {
        return {};
    }
    if (artifact.parent_path().extension() == ".swiftmodule") {
        return artifact.parent_path().stem().string();
    }
    return artifact.stem().string();
}

void AddRecoveryCandidate(
    std::map<std::string, ImportRecoveryCandidate>& candidates,
    const std::string& module,
    const std::string& origin,
    const fs::path& artifact
) {
    if (module.empty()) {
        return;
    }
    const fs::path normalized = fs::absolute(artifact).lexically_normal();
    auto [it, inserted] = candidates.emplace(
        module,
        ImportRecoveryCandidate{module, origin, {normalized}, false});
    if (!inserted) {
        if (it->second.origin != origin) {
            it->second.ambiguous_origin = true;
        } else if (std::find(
                       it->second.artifacts.begin(),
                       it->second.artifacts.end(),
                       normalized) == it->second.artifacts.end()) {
            it->second.artifacts.push_back(normalized);
        }
    }
}

void AddSwiftPMGraphCandidates(
    std::map<std::string, ImportRecoveryCandidate>& candidates,
    const fs::path& build_description,
    const std::string& module,
    const std::string& target
) {
    RecoveryPhase phase("graph_lookup");
    std::ifstream input(build_description, std::ios::binary);
    if (!input) {
        return;
    }

    std::vector<std::string> current_inputs;
    std::string line;
    while (std::getline(input, line)) {
        const std::string trimmed = TrimWhitespace(line);
        if (trimmed.rfind("inputs:", 0) == 0) {
            current_inputs = ParseJsonStrings(trimmed.substr(7));
            continue;
        }
        if (trimmed.rfind("args:", 0) != 0) {
            continue;
        }

        const std::vector<std::string> command =
            ParseJsonStrings(trimmed.substr(5));
        if (!JsonArgumentsMatch(command, module, target)) {
            continue;
        }

        std::cerr
            << "OPENFRUIT Swift import recovery: matched SwiftPM command with "
            << current_inputs.size() << " graph input(s).\n";

        for (const std::string& value : current_inputs) {
            const fs::path artifact(Win32Process::ToWide(value));
            const std::string dependency = SwiftModuleName(artifact);
            std::error_code ec;
            if (!dependency.empty() &&
                fs::exists(ExtendedWin32FilesystemPath(artifact), ec) &&
                !ec) {
                AddRecoveryCandidate(
                    candidates,
                    dependency,
                    "SwiftPM dependency closure",
                    artifact);
            }
        }
        return;
    }
}

void AddModuleMapCandidates(
    std::map<std::string, ImportRecoveryCandidate>& candidates,
    const fs::path& module_map
) {
    std::ifstream input(module_map, std::ios::binary);
    if (!input) {
        return;
    }
    const std::regex declaration(
        R"((?:^|\s)(?:framework\s+)?module\s+([A-Za-z_][A-Za-z0-9_]*))");
    std::string line;
    while (std::getline(input, line)) {
        std::smatch match;
        if (std::regex_search(line, match, declaration)) {
            AddRecoveryCandidate(
                candidates,
                match[1].str(),
                "active SDK/toolchain",
                module_map.parent_path());
        }
    }
}

void AddSdkCandidates(
    std::map<std::string, ImportRecoveryCandidate>& candidates,
    const fs::path& sdk
) {
    RecoveryPhase phase("sdk_discovery");
    std::error_code ec;
    if (!fs::is_directory(sdk, ec) || ec) {
        return;
    }

    CountRecovery("sdk_walks");
    fs::recursive_directory_iterator iterator(
        ExtendedWin32FilesystemPath(sdk),
        fs::directory_options::skip_permission_denied,
        ec);
    const fs::recursive_directory_iterator end;
    while (!ec && iterator != end) {
        CountRecovery("sdk_entries");
        const fs::path path = iterator->path();
        if (iterator->is_directory(ec) && path.extension() == ".swiftmodule") {
            AddRecoveryCandidate(
                candidates,
                path.stem().string(),
                "active SDK/toolchain",
                path);
            iterator.disable_recursion_pending();
        } else if (iterator->is_regular_file(ec) &&
                   path.filename() == "module.modulemap") {
            AddModuleMapCandidates(candidates, path);
        }
        iterator.increment(ec);
    }
}

std::set<std::string> MissingSwiftIdentifiers(
    const ProcessResult& result
) {
    const std::string diagnostics = result.std_out + "\n" + result.std_err;
    if (diagnostics.find("error:") == std::string::npos) {
        return {};
    }

    static const std::vector<std::regex> patterns = {
        std::regex(R"(has no member '([A-Za-z_][A-Za-z0-9_]*)')"),
        std::regex(R"(reference to member '([A-Za-z_][A-Za-z0-9_]*)')"),
        std::regex(R"(cannot find (?:type )?'([A-Za-z_][A-Za-z0-9_]*)' in scope)"),
        std::regex(R"(unresolved identifier '([A-Za-z_][A-Za-z0-9_]*)')")
    };

    std::set<std::string> identifiers;
    for (const std::regex& pattern : patterns) {
        for (std::sregex_iterator it(
                 diagnostics.begin(), diagnostics.end(), pattern), end;
             it != end;
             ++it) {
            identifiers.insert((*it)[1].str());
        }
    }
    identifiers.erase("module");
    return identifiers;
}

bool ReadArtifactContains(
    const fs::path& path,
    const std::set<std::string>& identifiers
) {
    CountRecovery("artifact_open_attempts");
    std::ifstream input(
        ExtendedWin32FilesystemPath(path),
        std::ios::binary);
    if (!input) {
        return false;
    }
    const std::string content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    CountRecovery("artifact_files_read");
    CountRecovery("artifact_bytes_read", content.size());
    for (const std::string& identifier : identifiers) {
        if (content.find(identifier) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool ArtifactMayOwn(
    const fs::path& artifact,
    const std::set<std::string>& identifiers
) {
    RecoveryPhase phase("artifact_filter");
    std::error_code ec;
    if (fs::is_regular_file(artifact, ec) && !ec) {
        return ReadArtifactContains(artifact, identifiers);
    }
    if (!fs::is_directory(artifact, ec) || ec) {
        return false;
    }

    fs::recursive_directory_iterator iterator(
        artifact,
        fs::directory_options::skip_permission_denied,
        ec);
    const fs::recursive_directory_iterator end;
    while (!ec && iterator != end) {
        const fs::path path = iterator->path();
        if (fs::is_regular_file(ExtendedWin32FilesystemPath(path), ec)) {
            const std::string extension = path.extension().string();
            if ((extension == ".swiftmodule" ||
                 extension == ".swiftinterface" ||
                 extension == ".h" ||
                 extension == ".hpp" ||
                 extension == ".apinotes") &&
                ReadArtifactContains(path, identifiers)) {
                return true;
            }
        }
        iterator.increment(ec);
    }
    return false;
}

std::string StableRecoveryKey(const std::vector<std::wstring>& values) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const std::wstring& value : values) {
        const std::string narrow = Win32Process::ToNarrow(value);
        for (const unsigned char byte : narrow) {
            hash ^= byte;
            hash *= 1099511628211ULL;
        }
        hash ^= 0xff;
        hash *= 1099511628211ULL;
    }

    static constexpr char digits[] = "0123456789abcdef";
    std::string result(16, '0');
    for (int index = 15; index >= 0; --index) {
        result[static_cast<std::size_t>(index)] = digits[hash & 0xf];
        hash >>= 4;
    }
    return result;
}

void ApplyRecoveryModuleCacheKey(
    std::vector<std::wstring>& arguments,
    const std::string& recovery_key
) {
    for (std::size_t index = 1; index + 1 < arguments.size(); ++index) {
        if (arguments[index] != L"-module-cache-path") {
            continue;
        }
        arguments[index + 1] = (
            fs::path(arguments[index + 1]) /
            (L"OPENFRUIT-import-recovery-" +
             Win32Process::ToWide(recovery_key))
        ).wstring();
        return;
    }
}

std::set<std::string> ReadSymbolGraphTitles(const fs::path& directory) {
    std::set<std::string> titles;
    std::error_code ec;
    for (fs::directory_iterator iterator(directory, ec), end;
         !ec && iterator != end;
         iterator.increment(ec)) {
        if (!iterator->is_regular_file(ec) ||
            iterator->path().extension() != ".json") {
            continue;
        }
        std::ifstream input(iterator->path(), std::ios::binary);
        if (!input) {
            continue;
        }
        const std::string content(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        const std::string marker = "\"title\":\"";
        std::size_t offset = 0;
        while ((offset = content.find(marker, offset)) != std::string::npos) {
            offset += marker.size();
            std::size_t end_offset = offset;
            while (end_offset < content.size() &&
                   content[end_offset] != '"') {
                if (content[end_offset] == '\\' &&
                    end_offset + 1 < content.size()) {
                    end_offset += 2;
                } else {
                    ++end_offset;
                }
            }
            if (end_offset == content.size()) {
                break;
            }
            std::string title = content.substr(offset, end_offset - offset);
            const std::size_t parameters = title.find('(');
            if (parameters != std::string::npos) {
                title.resize(parameters);
            }
            if (!title.empty()) {
                titles.insert(std::move(title));
            }
            offset = end_offset + 1;
        }
    }
    return titles;
}

std::set<std::string> ExtractModuleTitles(
    const std::wstring& swiftc,
    const ImportRecoveryCandidate& candidate,
    const std::vector<std::wstring>& compile_arguments,
    const fs::path& recovery_root
) {
    RecoveryPhase phase("symbol_lookup");
    const fs::path extractor =
        fs::path(swiftc).parent_path() / "swift-symbolgraph-extract.exe";
    if (!fs::is_regular_file(extractor)) {
        return {};
    }

    const auto target = SwiftArgumentValue(compile_arguments, L"-target");
    const auto sdk = SwiftArgumentValue(compile_arguments, L"-sdk");
    if (!target || !sdk) {
        return {};
    }

    std::vector<std::wstring> identity = {
        swiftc,
        Win32Process::ToWide(candidate.module),
        *target,
        *sdk
    };
    for (const fs::path& artifact : candidate.artifacts) {
        identity.push_back(artifact.wstring());
    }
    for (std::size_t index = 1; index + 1 < compile_arguments.size(); ++index) {
        if (compile_arguments[index] == L"-I" ||
            compile_arguments[index] == L"-F" ||
            compile_arguments[index] == L"-Fsystem" ||
            compile_arguments[index] == L"-Isystem" ||
            compile_arguments[index] == L"-resource-dir" ||
            compile_arguments[index] == L"-module-cache-path" ||
            compile_arguments[index] == L"-libc") {
            identity.push_back(compile_arguments[index]);
            identity.push_back(compile_arguments[index + 1]);
            ++index;
        }
    }

    const fs::path output = recovery_root / "symbolgraphs" /
        StableRecoveryKey(identity);
    std::set<std::string> cached = ReadSymbolGraphTitles(output);
    if (!cached.empty()) {
        CountRecovery("symbol_cache_hits");
        return cached;
    }
    CountRecovery("symbol_cache_misses");

    std::error_code ec;
    fs::remove_all(output, ec);
    ec.clear();
    fs::create_directories(output, ec);
    if (ec) {
        return {};
    }

    std::vector<std::wstring> arguments = {
        extractor.wstring(),
        L"-module-name", Win32Process::ToWide(candidate.module),
        L"-target", *target,
        L"-sdk", *sdk,
        L"-output-dir", output.wstring(),
        L"-minimum-access-level", L"public"
    };
    for (std::size_t index = 1; index + 1 < compile_arguments.size(); ++index) {
        if (compile_arguments[index] == L"-I" ||
            compile_arguments[index] == L"-F" ||
            compile_arguments[index] == L"-Fsystem" ||
            compile_arguments[index] == L"-Isystem" ||
            compile_arguments[index] == L"-resource-dir" ||
            compile_arguments[index] == L"-module-cache-path" ||
            compile_arguments[index] == L"-libc") {
            arguments.push_back(compile_arguments[index]);
            arguments.push_back(compile_arguments[index + 1]);
            ++index;
        }
    }

    CountRecovery("extractor_launch_attempts");
    RecoveryPhase extraction_phase("symbol_extraction");
    const ProcessResult result = Win32Process::Run(extractor.wstring(), arguments);
    if (result.launched) CountRecovery("extractor_processes");
    if (!result.success) {
        CountRecovery("extractor_failures");
        fs::remove_all(output, ec);
        return {};
    }
    return ReadSymbolGraphTitles(output);
}

std::optional<ImportRecoveryCandidate> SelectImportRecoveryCandidate(
    const std::wstring& swiftc,
    const std::vector<std::wstring>& arguments,
    const std::set<std::string>& missing,
    const std::set<std::string>& recovered,
    const fs::path& build_description,
    const fs::path& recovery_root
) {
    const auto module = SwiftArgumentValue(arguments, L"-module-name");
    const auto target = SwiftArgumentValue(arguments, L"-target");
    const auto sdk = SwiftArgumentValue(arguments, L"-sdk");
    if (!module || !target || !sdk) {
        return std::nullopt;
    }

    std::map<std::string, ImportRecoveryCandidate> candidates;
    AddSwiftPMGraphCandidates(
        candidates,
        build_description,
        Win32Process::ToNarrow(*module),
        Win32Process::ToNarrow(*target));

    std::map<std::string, std::set<std::string>> owners;
    std::set<std::string> indexed;
    const auto index_new_candidates = [&]() {
        for (const auto& [name, candidate] : candidates) {
            if (!indexed.insert(name).second) {
                continue;
            }
            CountRecovery("candidates_evaluated");
            if (candidate.ambiguous_origin) {
                std::cerr
                    << "OPENFRUIT Swift import recovery: rejecting ambiguous module origins="
                    << name << "\n";
                continue;
            }
            if (recovered.contains(name)) {
                continue;
            }
            bool may_own = false;
            for (const fs::path& artifact : candidate.artifacts) {
                if (ArtifactMayOwn(artifact, missing)) {
                    may_own = true;
                    break;
                }
            }
            if (!may_own) {
                continue;
            }
            std::cerr
                << "OPENFRUIT Swift import recovery: indexing candidate="
                << name << " origin=" << candidate.origin << "\n";
            const std::set<std::string> titles = ExtractModuleTitles(
                swiftc, candidate, arguments, recovery_root);
            for (const std::string& identifier : missing) {
                if (titles.contains(identifier)) {
                    owners[identifier].insert(name);
                    std::cerr
                        << "OPENFRUIT Swift import recovery: owner="
                        << name << " symbol=" << identifier << "\n";
                }
            }
        }
    };

    const auto ownership_is_ambiguous = [&]() {
        std::set<std::string> unique_modules;
        for (const auto& [identifier, modules] : owners) {
            if (modules.size() > 1) {
                return true;
            }
            if (modules.size() == 1) {
                unique_modules.insert(*modules.begin());
            }
        }
        return unique_modules.size() > 1;
    };

    std::cerr
        << "OPENFRUIT Swift import recovery: evaluating "
        << candidates.size()
        << " SwiftPM dependency candidate(s) for "
        << Win32Process::ToNarrow(*module) << ".\n";
    index_new_candidates();
    if (ownership_is_ambiguous()) {
        CountRecovery("ambiguity_rejections");
        std::cerr
            << "OPENFRUIT Swift import recovery: ownership is ambiguous; "
               "SDK search is unnecessary and no module was imported.\n";
        return std::nullopt;
    }

    AddSdkCandidates(candidates, fs::path(*sdk));
    for (const auto& [name, candidate] : candidates) {
        if (!candidate.ambiguous_origin) {
            continue;
        }
        for (auto& [identifier, modules] : owners) {
            modules.erase(name);
        }
    }
    std::cerr
        << "OPENFRUIT Swift import recovery: evaluating "
        << candidates.size()
        << " total allowed candidate(s) after active SDK/toolchain discovery.\n";
    index_new_candidates();
    if (ownership_is_ambiguous()) {
        CountRecovery("ambiguity_rejections");
        std::cerr
            << "OPENFRUIT Swift import recovery: ownership is ambiguous; "
               "no module was imported.\n";
        return std::nullopt;
    }

    std::set<std::string> uniquely_required;
    for (const auto& [identifier, modules] : owners) {
        if (modules.size() == 1) {
            uniquely_required.insert(*modules.begin());
        }
    }
    if (uniquely_required.size() != 1) {
        if (!owners.empty()) {
            std::cerr
                << "OPENFRUIT Swift import recovery: ownership is ambiguous; "
                   "no module was imported.\n";
        }
        return std::nullopt;
    }

    const auto selected = candidates.find(*uniquely_required.begin());
    return selected == candidates.end()
        ? std::nullopt
        : std::optional<ImportRecoveryCandidate>(selected->second);
}

} // namespace
std::optional<ImportRecoveryOutcome> RecoverImplicitSwiftImports(
    const std::wstring& swiftc,
    const std::vector<std::wstring>& baseline_arguments,
    const ProcessResult& baseline,
    const fs::path& build_description,
    const fs::path& recovery_root
) {
    if (build_description.empty() || recovery_root.empty()) return std::nullopt;
    RecoveryMetrics metrics;
    RecoveryMeasurement measurement(metrics);
    RecoveryPhase total_phase("total");
    std::vector<std::wstring> arguments = baseline_arguments;
    ProcessResult current = baseline;
    std::set<std::string> recovered;
    constexpr std::size_t kMaximumRecoveries = 4;

    for (std::size_t attempt = 0; attempt < kMaximumRecoveries; ++attempt) {
        const std::set<std::string> missing = MissingSwiftIdentifiers(current);
        if (missing.empty()) {
            break;
        }
        CountRecovery("recovery_attempts");

        std::cerr << "OPENFRUIT Swift import recovery: visibility fingerprint=";
        bool first = true;
        for (const std::string& identifier : missing) {
            if (!first) {
                std::cerr << ',';
            }
            std::cerr << identifier;
            first = false;
        }
        std::cerr << "\n";

        const auto candidate = SelectImportRecoveryCandidate(
            swiftc,
            arguments,
            missing,
            recovered,
            build_description,
            recovery_root);
        if (!candidate) {
            break;
        }

        std::set<std::string> owned_missing;
        const std::set<std::string> titles = ExtractModuleTitles(
            swiftc, *candidate, arguments, recovery_root);
        for (const std::string& identifier : missing) {
            if (titles.contains(identifier)) {
                owned_missing.insert(identifier);
            }
        }
        if (owned_missing.empty()) {
            break;
        }

        std::vector<std::wstring> retry = arguments;
        retry.push_back(L"-Xfrontend");
        retry.push_back(L"-import-module");
        retry.push_back(L"-Xfrontend");
        retry.push_back(Win32Process::ToWide(candidate->module));
        const std::string cache_key = StableRecoveryKey(retry);
        ApplyRecoveryModuleCacheKey(retry, cache_key);

        std::cerr
            << "OPENFRUIT Swift import recovery: module="
            << candidate->module
            << " origin=" << candidate->origin
            << " cache-key=" << cache_key
            << " attempt=" << (attempt + 1)
            << "/" << kMaximumRecoveries << "\n";

        CountRecovery("compiler_retries");
        ProcessResult retried;
        {
            RecoveryPhase retry_phase("compiler_retry");
            retried = Win32Process::Run(swiftc, retry);
        }
        const std::set<std::string> remaining = MissingSwiftIdentifiers(retried);
        bool fingerprint_removed = true;
        for (const std::string& identifier : owned_missing) {
            if (remaining.contains(identifier)) {
                fingerprint_removed = false;
                break;
            }
        }
        if (!fingerprint_removed) {
            std::cerr
                << "OPENFRUIT Swift import recovery: candidate did not remove "
                   "the owned visibility fingerprint; discarding it.\n";
            break;
        }

        recovered.insert(candidate->module);
        arguments = std::move(retry);
        current = std::move(retried);
        if (current.success) {
            break;
        }
    }

    if (recovered.empty()) {
        return std::nullopt;
    }
    metrics.recovered = true;
    return ImportRecoveryOutcome{std::move(current), std::move(arguments)};
}

} // namespace OpenFruit
