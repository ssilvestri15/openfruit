#include "utf8_path.hpp"
#include "compiler_proxy.hpp"
#include "macro_engine.hpp"
#include "darwin_macro_provider.hpp"
#include "tool_paths.hpp"
#include "import_recovery.hpp"

#include "json_value.hpp"
#include "operation_events.hpp"
#include "string_catalog_compiler.hpp"
#include "system_info.hpp"
#include "win32_process.hpp"
#include "wsl_bridge.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

// Observe SwiftPM-owned paths without opening, creating or retaining them.
// Missing paths are evidence, never a reason to change compiler behavior.
void ObserveManifestFiles(const std::vector<std::wstring>& arguments,
                          const std::string& invocation, const char* phase) noexcept {
    try {
        const auto context = CurrentOperationContext();
        if (!context || !context->sink) return;
        auto files = JsonValue::ArrayValue();
        const auto append = [&](const char* role, const fs::path& path) {
            auto row = JsonValue::ObjectValue();
            const DWORD attributes = GetFileAttributesW(path.c_str());
            const DWORD error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
            row.Set("role", JsonValue::String(role));
            row.Set("path", JsonValue::String(Win32Process::ToNarrow(path.wstring())));
            row.Set("state", JsonValue::String(attributes != INVALID_FILE_ATTRIBUTES
                ? ((attributes & FILE_ATTRIBUTE_DIRECTORY) ? "directory" : "file")
                : ((error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) ? "missing" : "unavailable")));
            row.Set("win32_error", JsonValue::Number(std::to_string(error)));
            files.ArrayItems().push_back(std::move(row));
        };
        for (std::size_t index = 1; index + 1 < arguments.size(); ++index) {
            if (arguments[index] == L"-o" || arguments[index] == L"-vfsoverlay") {
                const bool output = arguments[index] == L"-o";
                const fs::path path(arguments[++index]);
                append(output ? "output" : "vfs_overlay", path);
                if (!path.parent_path().empty())
                    append(output ? "output_parent" : "vfs_parent", path.parent_path());
            }
        }
        auto data = JsonValue::ObjectValue();
        data.Set("invocation_id", JsonValue::String(invocation));
        data.Set("phase", JsonValue::String(phase));
        data.Set("files", std::move(files));
        context->Emit("compiler.manifest.files", std::move(data));
    } catch (...) {
        // Diagnostic allocation/conversion failures must not affect compilation.
    }
}

std::wstring ReadEnv(const wchar_t* name) {
    const DWORD required =
        GetEnvironmentVariableW(
            name,
            nullptr,
            0
        );

    if (required == 0) {
        return {};
    }

    std::wstring value(
        required,
        L'\0'
    );

    const DWORD written =
        GetEnvironmentVariableW(
            name,
            value.data(),
            required
        );

    if (written == 0 ||
        written >= required) {
        return {};
    }

    value.resize(written);
    return value;
}

std::unordered_set<std::string>
ParseSemicolonSet(
    const std::wstring& value
) {
    std::unordered_set<std::string> result;

    std::wstringstream stream(value);
    std::wstring item;

    while (std::getline(
               stream,
               item,
               L';')) {
        if (!item.empty()) {
            result.insert(
                Win32Process::ToNarrow(item)
            );
        }
    }

    return result;
}

bool EndsWithCaseInsensitive(
    const std::string& value,
    const std::string& suffix
) {
    if (value.size() < suffix.size()) {
        return false;
    }

    const std::size_t offset =
        value.size() - suffix.size();

    for (std::size_t i = 0;
         i < suffix.size();
         ++i) {
        const unsigned char lhs =
            static_cast<unsigned char>(
                value[offset + i]
            );

        const unsigned char rhs =
            static_cast<unsigned char>(
                suffix[i]
            );

        if (std::tolower(lhs) !=
            std::tolower(rhs)) {
            return false;
        }
    }

    return true;
}



bool IsClangModuleModeArgument(
    const std::string& argument
) {
    return argument == "-fmodules" ||
           argument == "-fcxx-modules" ||
           argument.rfind("-fmodule-map-file=", 0) == 0 ||
           argument.rfind("-fmodule-name=", 0) == 0 ||
           argument.rfind("-fmodule-file=", 0) == 0 ||
           argument.rfind("-fmodules-cache-path=", 0) == 0;
}

bool IsImplicitModuleDisableArgument(
    const std::string& argument
) {
    return argument == "-fno-implicit-modules" ||
           argument == "-fno-implicit-module-maps";
}

bool PatchGeneratedResourceAccessor(
    const fs::path& source
) {
    if (!EndsWithCaseInsensitive(
            source.filename().string(),
            "resource_bundle_accessor.m")) {
        return true;
    }

    const std::string normalized =
        source.generic_string();

    if (normalized.find(
            "/DerivedSources/") ==
        std::string::npos) {
        return true;
    }

    std::ifstream input(
        source,
        std::ios::binary
    );

    if (!input) {
        return true;
    }

    std::string content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );

    input.close();

    const std::string marker =
        "bundleWithPath:@\"";

    bool changed = false;
    std::size_t search_from = 0;

    while (true) {
        const std::size_t begin =
            content.find(
                marker,
                search_from
            );

        if (begin == std::string::npos) {
            break;
        }

        const std::size_t value_begin =
            begin + marker.size();

        const std::size_t value_end =
            content.find(
                '\"',
                value_begin
            );

        if (value_end ==
            std::string::npos) {
            break;
        }

        for (std::size_t i = value_begin;
             i < value_end;
             ++i) {
            if (content[i] == '\\') {
                content[i] = '/';
                changed = true;
            }
        }

        search_from = value_end + 1;
    }

    if (!changed) {
        return true;
    }

    const fs::path temporary =
        source.string() +
        ".OPENFRUIT.tmp";

    {
        std::ofstream output(
            temporary,
            std::ios::binary |
                std::ios::trunc
        );

        if (!output) {
            std::cerr
                << "OPENFRUIT compiler proxy: unable to patch generated "
                   "resource accessor: "
                << source.string()
                << std::endl;
            return false;
        }

        output.write(
            content.data(),
            static_cast<std::streamsize>(
                content.size()
            )
        );

        if (!output) {
            return false;
        }
    }

    std::error_code ec;
    fs::rename(
        temporary,
        source,
        ec
    );

    if (ec) {
        ec.clear();
        fs::remove(
            source,
            ec
        );
        ec.clear();

        fs::rename(
            temporary,
            source,
            ec
        );
    }

    if (ec) {
        std::cerr
            << "OPENFRUIT compiler proxy: unable to replace generated "
               "resource accessor: "
            << source.string()
            << " ("
            << ec.message()
            << ")"
            << std::endl;
        return false;
    }

    std::cout
        << "OPENFRUIT compiler proxy: normalized generated resource bundle path: "
        << source.string()
        << std::endl;

    return true;
}

struct IncludeRootMapping {
    fs::path alias_root;
    fs::path target_root;
};

std::wstring NormalizePathForComparison(
    const fs::path& input
) {
    std::error_code ec;
    fs::path absolute =
        input.is_absolute()
            ? input
            : fs::absolute(input, ec);

    if (ec) {
        absolute = input;
    }

    std::wstring value =
        absolute.lexically_normal().wstring();

    while (value.size() > 3 &&
           (value.back() == L'\\' ||
            value.back() == L'/')) {
        value.pop_back();
    }

    for (wchar_t& c : value) {
        if (c == L'/') {
            c = L'\\';
        } else {
            c = static_cast<wchar_t>(
                std::towlower(c)
            );
        }
    }

    return value;
}

std::vector<IncludeRootMapping>
ReadIncludeRootMappings() {
    std::vector<IncludeRootMapping>
        mappings;

    const std::wstring map_value =
        ReadEnv(
            L"OPENFRUIT_COMPILER_SYMLINK_MAP"
        );

    if (map_value.empty()) {
        return mappings;
    }

    const fs::path map_path =
        fs::path(map_value);

    std::ifstream input(
        map_path,
        std::ios::binary
    );

    if (!input) {
        return mappings;
    }

    std::string line;

    while (std::getline(input, line)) {
        if (!line.empty() &&
            line.back() == '\r') {
            line.pop_back();
        }

        const std::size_t tab =
            line.find('\t');

        if (tab == std::string::npos ||
            tab == 0 ||
            tab + 1 >= line.size()) {
            continue;
        }

        IncludeRootMapping mapping;
        mapping.alias_root =
            fs::path(
                Win32Process::ToWide(
                    line.substr(0, tab)
                )
            );

        mapping.target_root =
            fs::path(
                Win32Process::ToWide(
                    line.substr(tab + 1)
                )
            );

        if (mapping.alias_root.empty() ||
            mapping.target_root.empty()) {
            continue;
        }

        mappings.push_back(
            std::move(mapping)
        );
    }

    return mappings;
}

std::optional<fs::path>
CanonicalizeAliasedIncludeRoot(
    const fs::path& include_path,
    const std::vector<IncludeRootMapping>& mappings
) {
    std::error_code absolute_ec;
    fs::path include_absolute =
        include_path.is_absolute()
            ? include_path
            : fs::absolute(
                  include_path,
                  absolute_ec
              );

    if (absolute_ec) {
        include_absolute =
            include_path;
    }

    include_absolute =
        include_absolute.lexically_normal();

    const std::wstring include_key =
        NormalizePathForComparison(
            include_absolute
        );

    if (include_key.empty()) {
        return std::nullopt;
    }

    for (const auto& mapping : mappings) {
        const std::wstring alias_key =
            NormalizePathForComparison(
                mapping.alias_root
            );

        if (alias_key.empty() ||
            include_key.size() <
                alias_key.size()) {
            continue;
        }

        if (include_key.compare(
                0,
                alias_key.size(),
                alias_key) != 0) {
            continue;
        }

        if (include_key.size() >
                alias_key.size()) {
            const wchar_t boundary =
                include_key[
                    alias_key.size()
                ];

            if (boundary != L'\\') {
                continue;
            }
        }

        std::error_code ec;
        fs::path relative =
            fs::relative(
                include_absolute,
                mapping.alias_root,
                ec
            );

        if (ec) {
            ec.clear();
            relative =
                include_absolute.lexically_relative(
                    mapping.alias_root
                );
        }

        if (relative.empty() ||
            relative == ".") {
            relative.clear();
        }

        fs::path canonical =
            mapping.target_root;

        if (!relative.empty()) {
            canonical /= relative;
        }

        canonical =
            canonical.lexically_normal();

        if (fs::exists(
                canonical,
                ec) &&
            !ec &&
            fs::is_directory(
                canonical,
                ec) &&
            !ec) {
            return canonical;
        }
    }

    return std::nullopt;
}

bool IsJoinedIncludePathArgument(
    const std::string& argument
) {
    return argument.size() > 2 &&
           argument.rfind("-I", 0) == 0;
}

struct StringDefineOverride {
    std::string name;
    std::string value;
    bool objc = false;
};


bool IsCXXInvocation(
    int argc,
    char* argv[]
) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument =
            argv[i] ? argv[i] : "";

        if (EndsWithCaseInsensitive(argument, ".cc") ||
            EndsWithCaseInsensitive(argument, ".cpp") ||
            EndsWithCaseInsensitive(argument, ".cxx") ||
            EndsWithCaseInsensitive(argument, ".c++") ||
            EndsWithCaseInsensitive(argument, ".mm")) {
            return true;
        }

        if (argument == "-x" &&
            i + 1 < argc) {
            const std::string language =
                argv[i + 1] ? argv[i + 1] : "";

            if (language == "c++" ||
                language == "objective-c++") {
                return true;
            }
        }
    }

    return false;
}

bool IsDependencyModuleMapArgument(
    const std::string& argument
) {
    return argument.rfind(
               "-fmodule-map-file=",
               0
           ) == 0 ||
           argument == "-fmodule-map-file";
}

bool IsCompileOnlyInvocation(
    int argc,
    char* argv[]
) {
    for (int i = 1;
         i < argc;
         ++i) {
        const std::string argument =
            argv[i] ? argv[i] : "";

        if (argument == "-c" ||
            argument == "-S" ||
            argument == "-E" ||
            argument == "-fsyntax-only") {
            return true;
        }
    }

    return false;
}

bool IsObjectiveCInvocation(
    int argc,
    char* argv[]
) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument =
            argv[i] ? argv[i] : "";

        if (EndsWithCaseInsensitive(argument, ".m") ||
            EndsWithCaseInsensitive(argument, ".mm")) {
            return true;
        }

        if (argument == "-x" &&
            i + 1 < argc) {
            const std::string language =
                argv[i + 1] ? argv[i + 1] : "";

            if (language == "objective-c" ||
                language == "objective-c++") {
                return true;
            }
        }
    }

    return false;
}

bool ExtractStringDefineOverride(
    const std::string& argument,
    const std::unordered_set<std::string>& string_macros,
    const std::unordered_set<std::string>& objc_string_macros,
    bool objective_c_invocation,
    StringDefineOverride* output
) {
    if (!output ||
        argument.rfind("-D", 0) != 0) {
        return false;
    }

    const std::size_t equals =
        argument.find('=');

    if (equals == std::string::npos ||
        equals <= 2) {
        return false;
    }

    const std::string name =
        argument.substr(2, equals - 2);

    const bool plain =
        string_macros.find(name) !=
        string_macros.end();

    const bool objc =
        objc_string_macros.find(name) !=
        objc_string_macros.end();

    if (!plain && !objc) {
        return false;
    }

    /*
     * Objective-C string tokens (for example @"1.2.3") are only valid in
     * Objective-C / Objective-C++ translation units. Leave the original
     * argument untouched for plain C/C++ invocations rather than injecting an
     * Objective-C preprocessing token into an incompatible language mode.
     */
    if (objc && !objective_c_invocation) {
        return false;
    }

    std::string value =
        argument.substr(equals + 1);

    /*
     * Objective-C string tokens carry an @ prefix outside the quoted string:
     *
     *     @"1.2.3"
     *
     * Strip that language prefix before inspecting the quote wrapper. In
     * v4.0.20 the order was reversed, so a value received as @"20.0.5" was
     * reduced to "20.0.5" only after quote normalization had already run;
     * the forced-header writer then produced @""20.0.5"".
     */
    if (objc &&
        !value.empty() &&
        value.front() == '@') {
        value.erase(value.begin());
    }

    /*
     * By the time the proxy receives argv, Windows command-line parsing may
     * already have consumed the quotes which PackageDescription intended to
     * be part of the macro replacement token. Remove exactly one remaining
     * pair of outer syntactic quotes. The value inside is deliberately kept
     * as raw C token text so escapes retain their source semantics.
     */
    if (value.size() >= 4 &&
        value.rfind("\\\"", 0) == 0 &&
        value.compare(
            value.size() - 2,
            2,
            "\\\"") == 0) {
        value = value.substr(2, value.size() - 4);
    } else if (value.size() >= 2 &&
               value.front() == '"' &&
               value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }

    output->name = name;
    output->value = value;
    output->objc = objc;
    return true;
}

fs::path WriteForcedStringDefineHeader(
    const std::vector<StringDefineOverride>& overrides,
    bool objc_cxx_compat = false
) {
    if (overrides.empty() && !objc_cxx_compat) {
        return {};
    }

    std::error_code ec;
    const fs::path temp_root =
        fs::temp_directory_path(ec);

    if (ec || temp_root.empty()) {
        return {};
    }

    const fs::path header =
        temp_root /
        ("OPENFRUIT-string-defines-" +
         std::to_string(GetCurrentProcessId()) +
         "-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
         ".h");

    std::ofstream output(
        header,
        std::ios::binary |
            std::ios::trunc
    );

    if (!output) {
        return {};
    }

    output <<
        "/* Generated by OPENFRUIT compiler proxy. */\n";

    if (objc_cxx_compat) {
        /*
         * In Apple libc++ (<__functional/function.h>), when _LIBCPP_HAS_BLOCKS_RUNTIME
         * is enabled, an explicit specialization
         * template<...> class __func<_Rp1 (^)(_ArgTypes1...), _Rp(_ArgTypes...)>
         * is declared with only a copy constructor and no rvalue-reference constructor.
         * In Clang assertions builds, moving or constructing an Objective-C block into
         * std::function / __value_func attempts to bind an rvalue reference to a const
         * reference to an ARC-qualified type, triggering an AST assertion in
         * Qualifiers::addQualifiers (Type.h:697) and crashing Clang with STATUS_BREAKPOINT.
         * Disabling _LIBCPP_HAS_BLOCKS_RUNTIME allows libc++ to use its standard
         * functor template, which natively and safely supports Objective-C blocks
         * with both copy and move semantics.
         */
        output <<
            "#if defined(__cplusplus) && defined(__has_include)\n"
            "#  if __has_include(<__config>)\n"
            "#    include <__config>\n"
            "#    undef _LIBCPP_HAS_BLOCKS_RUNTIME\n"
            "#    define _LIBCPP_HAS_BLOCKS_RUNTIME 0\n"
            "#  endif\n"
            "#endif\n";
    }

    for (const auto& item : overrides) {
        output << "#ifdef " << item.name << "\n";
        output << "#undef " << item.name << "\n";
        output << "#endif\n";
        output << "#define " << item.name << " ";

        if (item.objc) {
            output << "@";
        }

        output << '"' << item.value << '"' << "\n";
    }

    if (!output) {
        output.close();
        fs::remove(header, ec);
        return {};
    }

    output.close();
    return header;
}

bool IsSwiftTargetInvocation(int argc, char* argv[]) {
    if (argc <= 0 || argv[0] == nullptr) {
        return false;
    }
    return EndsWithCaseInsensitive(
        fs::path(argv[0]).filename().string(),
        "swiftc.exe"
    );
}

bool IsSwiftCompilerCrash(const ProcessResult& result) {
    if (result.success) {
        return false;
    }
    const std::string diagnostics = result.std_out + "\n" + result.std_err;
    return diagnostics.find("Please submit a bug report") != std::string::npos ||
           diagnostics.find("Assertion failed:") != std::string::npos ||
           (diagnostics.find("Stack dump:") != std::string::npos &&
            diagnostics.find("swift-frontend") != std::string::npos);
}

bool RecommendsDisablingRoundTripDebugTypes(const ProcessResult& result) {
    const std::string diagnostics = result.std_out + "\n" + result.std_err;
    return diagnostics.find("-disable-round-trip-debug-types") !=
           std::string::npos;
}

void PrintBoundedDiagnostics(const ProcessResult& result) {
    constexpr std::size_t kLimit = 8192;
    const std::string diagnostics = result.std_out + result.std_err;
    if (diagnostics.size() <= kLimit * 2) {
        std::cerr << diagnostics;
        return;
    }
    std::cerr << diagnostics.substr(0, kLimit)
              << "\n... OPENFRUIT truncated "
              << (diagnostics.size() - kLimit * 2)
              << " bytes of repeated compiler crash diagnostics ...\n"
              << diagnostics.substr(diagnostics.size() - kLimit);
}

bool LooksLikeWindowsPath(const std::wstring& value, std::size_t offset = 0) {
    return value.size() >= offset + 3 &&
           std::iswalpha(value[offset]) &&
           value[offset + 1] == L':' &&
           (value[offset + 2] == L'\\' || value[offset + 2] == L'/');
}

std::wstring TranslateEmbeddedWindowsPath(const std::wstring& value) {
    if (LooksLikeWindowsPath(value)) {
        return Win32Process::ToWide(WSLBridge::WindowsToWslPath(value));
    }

    const std::size_t hash = value.find(L'#');
    if (hash != std::wstring::npos) {
        const std::wstring left = value.substr(0, hash);
        const std::wstring right = value.substr(hash + 1);
        if (LooksLikeWindowsPath(left) || LooksLikeWindowsPath(right)) {
            return TranslateEmbeddedWindowsPath(left) + L"#" +
                   TranslateEmbeddedWindowsPath(right);
        }
    }

    const std::size_t equals = value.find(L'=');
    if (equals != std::wstring::npos && LooksLikeWindowsPath(value, equals + 1)) {
        return value.substr(0, equals + 1) +
               TranslateEmbeddedWindowsPath(value.substr(equals + 1));
    }

    if (!value.empty() && value.front() == L'@' && LooksLikeWindowsPath(value, 1)) {
        return L"@" + TranslateEmbeddedWindowsPath(value.substr(1));
    }
    return value;
}

bool LooksLikeWindowsPath(const std::string& value) {
    return value.size() >= 3 &&
           std::isalpha(static_cast<unsigned char>(value[0])) &&
           value[1] == ':' &&
           (value[2] == '\\' || value[2] == '/');
}

std::string DecodeModuleMapString(const std::string& value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size() &&
            (value[i + 1] == '\\' || value[i + 1] == '"')) {
            decoded += value[++i];
            continue;
        }
        decoded += value[i];
    }
    return decoded;
}

std::string TranslateModuleMapPathLiterals(
    const std::string& content,
    bool& changed
) {
    changed = false;
    std::string translated;
    translated.reserve(content.size());

    for (std::size_t i = 0; i < content.size();) {
        if (content[i] != '"') {
            translated += content[i++];
            continue;
        }

        const std::size_t opening = i++;
        std::size_t closing = i;
        bool escaped = false;
        for (; closing < content.size(); ++closing) {
            const char value = content[closing];
            if (value == '"' && !escaped) {
                break;
            }
            if (value == '\\') {
                escaped = !escaped;
            } else {
                escaped = false;
            }
        }
        if (closing == content.size()) {
            translated.append(content, opening, std::string::npos);
            break;
        }

        const std::string literal = content.substr(i, closing - i);
        std::string decoded = DecodeModuleMapString(literal);
        if (decoded.rfind("\\\\?\\", 0) == 0 &&
            decoded.size() >= 7 &&
            std::isalpha(static_cast<unsigned char>(decoded[4])) &&
            decoded[5] == ':') {
            decoded.erase(0, 4);
        }

        if (LooksLikeWindowsPath(decoded)) {
            const std::string wsl = WSLBridge::WindowsToWslPath(
                Win32Process::ToWide(decoded)
            );
            if (!wsl.empty()) {
                translated += '"';
                translated += wsl;
                translated += '"';
                changed = true;
                i = closing + 1;
                continue;
            }
        }

        translated.append(content, opening, closing - opening + 1);
        i = closing + 1;
    }
    return translated;
}

fs::path WriteWslModuleMap(const fs::path& source) {
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        return {};
    }
    const std::string content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );
    input.close();

    bool changed = false;
    const std::string translated =
        TranslateModuleMapPathLiterals(content, changed);
    if (!changed) {
        return {};
    }

    const fs::path output = source.wstring() + L".OPENFRUIT-wsl-modulemap-" +
                            std::to_wstring(GetCurrentProcessId());
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return {};
    }
    stream.write(translated.data(), static_cast<std::streamsize>(translated.size()));
    return stream ? output : fs::path{};
}

std::wstring ProjectModuleMapPath(
    const std::wstring& value,
    std::vector<fs::path>& temporary_maps
) {
    if (!LooksLikeWindowsPath(value)) {
        return TranslateEmbeddedWindowsPath(value);
    }

    const fs::path original(value);
    const fs::path projected = WriteWslModuleMap(original);
    const fs::path& selected = projected.empty() ? original : projected;
    if (!projected.empty()) {
        temporary_maps.push_back(projected);
    }
    return Win32Process::ToWide(
        WSLBridge::WindowsToWslPath(selected.wstring())
    );
}

fs::path WriteWslOutputMap(const fs::path& source) {
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        return {};
    }
    std::string content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );
    input.close();

    std::string translated;
    translated.reserve(content.size());
    for (std::size_t i = 0; i < content.size();) {
        if (i + 2 < content.size() &&
            std::isalpha(static_cast<unsigned char>(content[i])) &&
            content[i + 1] == ':' &&
            (content[i + 2] == '\\' || content[i + 2] == '/')) {
            translated += "/mnt/";
            translated += static_cast<char>(std::tolower(
                static_cast<unsigned char>(content[i])));
            translated += '/';
            i += 3;
            if (i < content.size() && content[i] == '\\') {
                ++i;
            }
            continue;
        }
        if (content[i] == '\\') {
            translated += '/';
            i += (i + 1 < content.size() && content[i + 1] == '\\') ? 2 : 1;
            continue;
        }
        translated += content[i++];
    }

    const fs::path output = source.wstring() + L".OPENFRUIT-wsl-" +
                            std::to_wstring(GetCurrentProcessId());
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return {};
    }
    stream.write(translated.data(), static_cast<std::streamsize>(translated.size()));
    return stream ? output : fs::path{};
}

bool RequiresBundleModuleAccessor(const ProcessResult& result) {
    const std::string text = result.std_out + "\n" + result.std_err;
    if (text.find("no member 'module'") != std::string::npos &&
        text.find("Bundle") != std::string::npos) return true;
    // With -enable-testing the internal accessor SwiftPM generated for a
    // dependency is visible, so this module's missing one is reported as that
    // declaration being inaccessible rather than as a missing member.
    return text.find("'module' is inaccessible due to 'internal' protection level") != std::string::npos &&
           text.find("resource_bundle_accessor.swift") != std::string::npos;
}

// Writes an Xcode-compatible Bundle.module accessor for `module_name` that
// finds the first of `bundle_names` beside the app's resources, and registers
// it in the driver's output file map. Returns the source to compile, or empty.
fs::path WriteBundleModuleAccessor(
    const std::string& module_name,
    const fs::path& output_file_map_path,
    const std::vector<std::string>& bundle_names
) {
    std::error_code ec;
    fs::path build_dir;
    if (!output_file_map_path.empty() && fs::exists(output_file_map_path, ec)) {
        build_dir = output_file_map_path.parent_path();
    } else {
        build_dir = fs::temp_directory_path(ec);
        if (ec) {
            return {};
        }
    }

    const fs::path accessor_path =
        build_dir /
        ("OPENFRUIT-bundle-accessor-" + module_name + ".swift");
    const fs::path accessor_obj =
        build_dir /
        ("OPENFRUIT-bundle-accessor-" + module_name + ".o");

    std::ofstream out(accessor_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return {};
    }

    std::string names;
    for (const auto& name : bundle_names) {
        names += (names.empty() ? "\"" : ", \"") + name + "\"";
    }
    out << "import Foundation\n\n"
        << "private class BundleFinder {}\n\n"
        << "extension Foundation.Bundle {\n"
        << "    static let module: Bundle = {\n"
        << "        let bundleNames = [" << names << "]\n"
        << "        let candidates = [\n"
        << "            Bundle.main.resourceURL,\n"
        << "            Bundle(for: BundleFinder.self).resourceURL,\n"
        << "            Bundle.main.bundleURL,\n"
        << "        ]\n"
        << "        for candidate in candidates {\n"
        << "            for name in bundleNames {\n"
        << "                let bundlePath = candidate?.appendingPathComponent(name + \".bundle\")\n"
        << "                if let bundle = bundlePath.flatMap(Bundle.init(url:)) {\n"
        << "                    return bundle\n"
        << "                }\n"
        << "            }\n"
        << "        }\n"
        << "        return Bundle(for: BundleFinder.self)\n"
        << "    }()\n"
        << "}\n";
    out.close();

    if (!output_file_map_path.empty() && fs::exists(output_file_map_path, ec)) {
        std::ifstream ifm(output_file_map_path, std::ios::binary);
        std::string map_text((std::istreambuf_iterator<char>(ifm)), std::istreambuf_iterator<char>());
        ifm.close();

        std::string parse_err;
        if (auto parsed = JsonValue::Parse(map_text, &parse_err)) {
            if (parsed->IsObject()) {
                JsonValue::Object entry;
                entry["object"] = JsonValue::String(accessor_obj.string());
                entry["swift-dependencies"] = JsonValue::String(
                    (build_dir / (accessor_path.stem().string() + ".swiftdeps")).string());
                entry["dependencies"] = JsonValue::String(
                    (build_dir / (accessor_path.stem().string() + ".d")).string());
                entry["diagnostics"] = JsonValue::String(
                    (build_dir / (accessor_path.stem().string() + ".dia")).string());
                parsed->Set(accessor_path.string(), JsonValue::ObjectValue(entry));
                std::ofstream ofm(output_file_map_path, std::ios::binary | std::ios::trunc);
                ofm << parsed->Serialize(true);
            }
        }
    }
    return accessor_path;
}

// SwiftPM's own build leaves string catalogs unhandled; Xcode builds a
// package target's .xcstrings into that target's resource bundle, which then
// needs a Bundle.module accessor. Compiles them into the bundle (the existing
// one when SwiftPM generated an accessor) and adds the accessor when missing.
bool PrepareStringCatalogResources(std::vector<std::wstring>& arguments) {
    std::string module_name, package_name;
    fs::path output_file_map_path;
    std::vector<fs::path> sources;
    const auto add_source = [&sources](const fs::path& path) {
        std::wstring extension = path.extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
        if (extension == L".swift") sources.push_back(path);
    };
    for (std::size_t i = 1; i < arguments.size(); ++i) {
        const auto& argument = arguments[i];
        if (argument == L"-module-name" && i + 1 < arguments.size()) {
            module_name = Win32Process::ToNarrow(arguments[++i]);
        } else if (argument == L"-package-name" && i + 1 < arguments.size()) {
            package_name = Win32Process::ToNarrow(arguments[++i]);
        } else if (argument == L"-output-file-map" && i + 1 < arguments.size()) {
            output_file_map_path = fs::path(arguments[++i]);
        } else if (argument.size() > 1 && argument[0] == L'@') {
            std::ifstream list(fs::path(argument.substr(1)), std::ios::binary);
            for (std::string line; std::getline(list, line);) {
                while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
                if (line.size() >= 2 && line.front() == '"' && line.back() == '"') line = line.substr(1, line.size() - 2);
                if (!line.empty()) add_source(Utf8Path(line));
            }
        } else if (!argument.empty() && argument[0] != L'-') {
            add_source(fs::path(argument));
        }
    }
    if (module_name.empty() || output_file_map_path.empty() || sources.empty()) return true;

    // A target without a custom path lives in a predefined source directory
    // under its own name, which SwiftPM turns into the module name.
    const auto c99 = [](std::wstring name) {
        for (auto& c : name) if (!iswalnum(c) && c != L'_') c = L'_';
        if (!name.empty() && iswdigit(name.front())) name.insert(name.begin(), L'_');
        return Win32Process::ToNarrow(name);
    };
    fs::path target_root;
    for (const auto& source : sources) {
        for (auto directory = source.parent_path(); directory.has_relative_path(); directory = directory.parent_path()) {
            std::wstring parent = directory.parent_path().filename().wstring();
            std::transform(parent.begin(), parent.end(), parent.begin(), ::towlower);
            if (c99(directory.filename().wstring()) == module_name &&
                (parent == L"sources" || parent == L"source" || parent == L"src" || parent == L"srcs")) {
                target_root = directory;
                break;
            }
        }
        if (!target_root.empty()) break;
    }
    if (target_root.empty()) return true;

    std::vector<fs::path> catalogs;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(target_root, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) break;
        std::wstring extension = it->path().extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
        if (extension == L".xcstrings" && it->is_regular_file(ec)) catalogs.push_back(it->path());
    }
    if (catalogs.empty()) return true;
    std::sort(catalogs.begin(), catalogs.end());

    // SwiftPM's generated accessor names the bundle it expects.
    std::string bundle_name;
    bool has_accessor = false;
    for (const auto& source : sources) {
        if (source.filename() != L"resource_bundle_accessor.swift") continue;
        has_accessor = true;
        std::ifstream accessor(source, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(accessor)), std::istreambuf_iterator<char>());
        std::smatch match;
        if (std::regex_search(text, match, std::regex(R"re("([^"/\\]+)\.bundle")re"))) bundle_name = match[1].str();
    }
    if (bundle_name.empty()) bundle_name = (package_name.empty() ? module_name : package_name) + "_" + module_name;

    const fs::path bundle_dir = output_file_map_path.parent_path().parent_path() / Utf8Path(bundle_name + ".bundle");
    std::string development_region, error;
    if (!StringCatalogCompiler::Compile(catalogs, bundle_dir, development_region, error)) {
        std::cerr << "OPENFRUIT SwiftPM: string catalog compilation failed for " << module_name << ": " << error << '\n';
        return false;
    }
    const fs::path info_plist = bundle_dir / "Info.plist";
    if (!fs::exists(info_plist, ec)) {
        std::string identifier = bundle_name;
        for (auto& c : identifier) if (!isalnum(static_cast<unsigned char>(c)) && c != '.') c = '-';
        std::ofstream info(info_plist, std::ios::binary | std::ios::trunc);
        info << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\">\n<dict>\n"
                "\t<key>CFBundleDevelopmentRegion</key>\n\t<string>" << development_region << "</string>\n"
                "\t<key>CFBundleIdentifier</key>\n\t<string>" << identifier << ".resources</string>\n"
                "\t<key>CFBundleInfoDictionaryVersion</key>\n\t<string>6.0</string>\n"
                "\t<key>CFBundleName</key>\n\t<string>" << bundle_name << "</string>\n"
                "\t<key>CFBundlePackageType</key>\n\t<string>BNDL</string>\n"
                "</dict>\n</plist>\n";
    }
    std::cerr << "OPENFRUIT SwiftPM: compiled " << catalogs.size() << " string catalog(s) for " << module_name
              << " into " << bundle_dir.filename().string() << ".\n";

    if (!has_accessor) {
        const auto accessor = WriteBundleModuleAccessor(module_name, output_file_map_path, {bundle_name});
        if (accessor.empty()) {
            std::cerr << "OPENFRUIT SwiftPM: cannot write the Bundle.module accessor for " << module_name << ".\n";
            return false;
        }
        arguments.push_back(accessor.wstring());
    }
    return true;
}

std::optional<ImportRecoveryOutcome> RecoverMissingBundleModuleAccessor(
    const std::wstring& swiftc,
    const std::vector<std::wstring>& baseline_arguments,
    const ProcessResult& baseline
) {
    std::string module_name;
    fs::path output_file_map_path;
    for (std::size_t i = 0; i < baseline_arguments.size(); ++i) {
        if (baseline_arguments[i] == L"-module-name" && i + 1 < baseline_arguments.size()) {
            module_name = Win32Process::ToNarrow(baseline_arguments[i + 1]);
        } else if (baseline_arguments[i] == L"-output-file-map" && i + 1 < baseline_arguments.size()) {
            output_file_map_path = fs::path(baseline_arguments[i + 1]);
        }
    }

    if (module_name.empty()) {
        return std::nullopt;
    }

    const fs::path accessor_path = WriteBundleModuleAccessor(
        module_name, output_file_map_path, {module_name + "_" + module_name, module_name});
    if (accessor_path.empty()) {
        return std::nullopt;
    }

    std::vector<std::wstring> retry_args = baseline_arguments;
    retry_args.push_back(accessor_path.wstring());

    std::cerr
        << "OPENFRUIT Swift recovery: synthesized Xcode-compatible Bundle.module accessor for "
        << module_name
        << "; retrying module compilation.\n";

    ProcessResult retried = Win32Process::Run(swiftc, retry_args);

    if (retried.success) {
        return ImportRecoveryOutcome{std::move(retried), std::move(retry_args)};
    }

    return std::nullopt;
}

int RunSwiftTargetProxy(int argc, char* argv[]) {
    const std::wstring windows_swiftc =
        ReadEnv(L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL");
    if (windows_swiftc.empty()) {
        return 127;
    }

    std::vector<std::wstring> native_args;
    native_args.reserve(static_cast<std::size_t>(argc));
    native_args.push_back(windows_swiftc);
    for (int i = 1; i < argc; ++i) {
        native_args.push_back(Win32Process::ToWide(argv[i] ? argv[i] : ""));
    }

    // SwiftPM appends source-built plugin executables after destination toolset
    // options. Resolve priority from the real consumer command, not option order.
    DarwinMacroProvider macro_provider;
    const auto provider_receipt = ReadEnv(kDarwinMacroProviderEnvironment);
    const auto managed_macro_host = (ToolPaths::LocalHome() / "bin" / "openfruit-macro-host.exe").wstring();
    const auto managed_registration_marker = L"#" + managed_macro_host + L"#";
    const bool uses_managed_provider = std::any_of(native_args.begin(), native_args.end(),
        [&](const auto& argument) { return argument.find(managed_registration_marker) != std::wstring::npos; });
    // The driver dispatches -modulewrap to the AST wrapper, whose option
    // parser does not accept frontend compilation flags. No SIL is generated
    // by this mode. Keep release-toolchain verifier semantics for compilation.
    const bool module_wrap = native_args.size() > 1 && native_args[1] == L"-modulewrap";
    if (!module_wrap && std::none_of(native_args.begin(), native_args.end(),
                     [](const auto& a) { return a == L"-sil-verify-none"; })) {
        native_args.push_back(L"-Xfrontend");
        native_args.push_back(L"-sil-verify-none");
    }

    // SWIFT_EXEC also reaches host tools. Only destination commands carrying
    // our managed registrations belong to this provider boundary.
    if (!provider_receipt.empty() && uses_managed_provider) {
        std::wstring selected_sdk;
        for (std::size_t index = 0; index + 1 < native_args.size(); ++index)
            if (native_args[index] == L"-sdk") selected_sdk = native_args[index + 1];
        std::string error;
        if (!ReadDarwinMacroProvider(provider_receipt, ToolPaths::LocalHome(), macro_provider, error, selected_sdk)) {
            std::cerr << "OPENFRUIT target macro provider rejected: " << error << '\n'; return 2;
        }
        MacroEngine::PreferNativePluginExecutables(native_args, macro_provider, managed_macro_host);
    }

    if (!module_wrap && !PrepareStringCatalogResources(native_args)) return 1;
    // An explicit-module scan builds scanning modules of its own in the module
    // cache. Each SwiftPM module runs its own driver, concurrently and with
    // its own Clang options, so a cache shared with other modules' scans (or
    // with the implicit modules of C-family targets) makes the SDK's modules
    // appear as conflicting variants. Xcode shares one scanning service; here
    // every module scans in a cache of its own, and the CAS still shares the
    // built modules and compile results across modules and builds.
    if (std::find(native_args.begin(), native_args.end(), L"-explicit-module-build") != native_args.end()) {
        std::wstring module_name;
        for (std::size_t index = 1; index + 1 < native_args.size(); ++index)
            if (native_args[index] == L"-module-name") module_name = native_args[index + 1];
        for (std::size_t index = 1; index + 1 < native_args.size(); ++index)
            if (native_args[index] == L"-module-cache-path" && !module_name.empty())
                native_args[index + 1] = (fs::path(native_args[index + 1]).parent_path() /
                    "ExplicitPrecompiledModules" / module_name).wstring();
    }
    ProcessResult native = Win32Process::Run(windows_swiftc, native_args);
    if (!native.success && RequiresBundleModuleAccessor(native)) {
        if (auto recovery = RecoverMissingBundleModuleAccessor(
                windows_swiftc, native_args, native)) {
            native = std::move(recovery->result);
            native_args = std::move(recovery->arguments);
        }
    }
    if (!native.success) {
        if (auto recovery = RecoverImplicitSwiftImports(
                windows_swiftc, native_args, native,
                fs::path(ReadEnv(L"OPENFRUIT_SWIFT_IMPORT_RECOVERY_GRAPH")),
                fs::path(ReadEnv(L"OPENFRUIT_SWIFT_IMPORT_RECOVERY_ROOT")))) {
            native = std::move(recovery->result);
            native_args = std::move(recovery->arguments);
        }
    }
    if (native.success || !IsSwiftCompilerCrash(native)) {
        std::cout << native.std_out;
        std::cerr << native.std_err;
        return native.exit_code;
    }

    if (RecommendsDisablingRoundTripDebugTypes(native)) {
        std::vector<std::wstring> retry_args = native_args;
        retry_args.push_back(L"-Xfrontend");
        retry_args.push_back(L"-disable-round-trip-debug-types");
        std::cerr << "OPENFRUIT Swift recovery: the native compiler requested "
                     "-disable-round-trip-debug-types; retrying natively.\n";
        ProcessResult retry = Win32Process::Run(windows_swiftc, retry_args);
        if (retry.success || !IsSwiftCompilerCrash(retry)) {
            std::cout << retry.std_out;
            std::cerr << retry.std_err;
            return retry.exit_code;
        }
        native = std::move(retry);
    }

    const std::wstring linux_swiftc = ReadEnv(L"OPENFRUIT_SWIFT_FALLBACK_BIN");
    const std::wstring prebuilt = ReadEnv(L"OPENFRUIT_SWIFT_FALLBACK_PREBUILT");
    const std::wstring module_cache = ReadEnv(L"OPENFRUIT_SWIFT_FALLBACK_MODULE_CACHE");
    const std::wstring sdk = ReadEnv(L"OPENFRUIT_SWIFT_FALLBACK_SDK");
    const std::wstring resource_dir =
        ReadEnv(L"OPENFRUIT_SWIFT_FALLBACK_RESOURCE_DIR");
    const std::wstring plugin_server =
        ReadEnv(L"OPENFRUIT_SWIFT_FALLBACK_PLUGIN_SERVER");
    if (linux_swiftc.empty() || prebuilt.empty() || module_cache.empty() ||
        sdk.empty() || resource_dir.empty()) {
        std::cout << native.std_out;
        std::cerr << native.std_err;
        std::cerr << "OPENFRUIT Swift fallback: compiler crash detected, but the "
                     "verified fallback provider is unavailable.\n";
        return native.exit_code;
    }

    std::vector<fs::path> temporary_maps;
    std::vector<std::wstring> fallback_args;
    fallback_args.push_back(linux_swiftc);
    /* Prefer compiler-version-matched binary SDK modules over SDK textual
       interfaces. This avoids rebuilding Apple modules in every fallback and
       is required for deterministic cross-host module compatibility. */
    fallback_args.push_back(L"-I");
    fallback_args.push_back(prebuilt);
    fallback_args.push_back(L"-resource-dir");
    fallback_args.push_back(resource_dir);
    for (int i = 1; i < argc; ++i) {
        const std::wstring argument = Win32Process::ToWide(argv[i] ? argv[i] : "");

        if (argument == L"-vfsoverlay") {
            ++i;
            continue;
        }
        if (argument.rfind(L"-vfsoverlay=", 0) == 0) {
            continue;
        }
        if (argument == L"-Xcc" && i + 3 < argc &&
            std::string(argv[i + 1] ? argv[i + 1] : "") == "-ivfsoverlay" &&
            std::string(argv[i + 2] ? argv[i + 2] : "") == "-Xcc") {
            i += 3;
            continue;
        }
        if (argument == L"-module-cache-path") {
            ++i;
            fallback_args.push_back(L"-module-cache-path");
            fallback_args.push_back(module_cache);
            continue;
        }
        if (argument == L"-in-process-plugin-server-path") {
            ++i;
            if (!plugin_server.empty()) {
                fallback_args.push_back(argument);
                fallback_args.push_back(plugin_server);
            }
            continue;
        }
        if (argument == L"-plugin-path") {
            ++i;
            continue;
        }
        if ((argument == L"-supplementary-output-file-map" ||
             argument == L"-output-file-map") && i + 1 < argc) {
            const fs::path original(Win32Process::ToWide(argv[++i]));
            const fs::path translated = WriteWslOutputMap(original);
            fallback_args.push_back(argument);
            fallback_args.push_back(Win32Process::ToWide(
                WSLBridge::WindowsToWslPath(
                    translated.empty() ? original.wstring() : translated.wstring())));
            if (!translated.empty()) {
                temporary_maps.push_back(translated);
            }
            continue;
        }
        if (!argument.empty() && argument.front() == L'@' &&
            LooksLikeWindowsPath(argument, 1)) {
            const fs::path original(argument.substr(1));
            const fs::path translated = WriteWslOutputMap(original);
            fallback_args.push_back(L"@" + Win32Process::ToWide(
                WSLBridge::WindowsToWslPath(
                    translated.empty() ? original.wstring() : translated.wstring())));
            if (!translated.empty()) {
                temporary_maps.push_back(translated);
            }
            continue;
        }
        constexpr const wchar_t* kModuleMapPrefix = L"-fmodule-map-file=";
        if (argument.rfind(kModuleMapPrefix, 0) == 0) {
            const std::wstring path = argument.substr(
                std::char_traits<wchar_t>::length(kModuleMapPrefix)
            );
            fallback_args.push_back(
                std::wstring(kModuleMapPrefix) +
                ProjectModuleMapPath(path, temporary_maps)
            );
            continue;
        }
        if (argument == L"-fmodule-map-file" && i + 1 < argc) {
            fallback_args.push_back(argument);
            std::wstring path = Win32Process::ToWide(argv[++i] ? argv[i] : "");
            if (path == L"-Xcc" && i + 1 < argc) {
                fallback_args.push_back(path);
                path = Win32Process::ToWide(argv[++i] ? argv[i] : "");
            }
            fallback_args.push_back(
                ProjectModuleMapPath(path, temporary_maps)
            );
            continue;
        }
        fallback_args.push_back(TranslateEmbeddedWindowsPath(argument));
    }

    /*
     * Do not pin SwiftShims to the PCM produced by provider validation. A
     * SwiftPM graph may contain targets with deployment versions different
     * from the application's destination. Clang's module cache includes the
     * target configuration and will create a compatible PCM for each one;
     * forcing a PCM from another target causes an Objective-C runtime/target
     * mismatch instead.
     */
    fallback_args.insert(fallback_args.end(), {
        L"-Xcc", L"-fmodule-map-file=" + sdk + L"/usr/lib/swift/shims/module.modulemap"
    });

    const std::wstring distro = ReadEnv(L"OPENFRUIT_WSL_DISTRO").empty()
        ? L"Ubuntu" : ReadEnv(L"OPENFRUIT_WSL_DISTRO");
    const std::string working_directory_narrow =
        WSLBridge::WindowsToWslPath(fs::current_path().wstring());
    const std::wstring working_directory = working_directory_narrow.empty()
        ? L"/" : Win32Process::ToWide(working_directory_narrow);
    std::vector<std::wstring> wsl_args = {
        L"wsl.exe", L"-d", distro, L"--cd", working_directory, L"--"
    };
    wsl_args.insert(wsl_args.end(), fallback_args.begin(), fallback_args.end());

    std::cerr << "OPENFRUIT Swift fallback: native compiler crashed internally; "
                 "retrying the unchanged invocation with the verified Linux "
                 "Swift provider.\n";
    const ProcessResult fallback = Win32Process::Run(
        SystemInfo::GetWslExecutable(), wsl_args, L"", {},
        [](const std::string& output) { std::cout << output; },
        [](const std::string& error) { std::cerr << error; }
    );
    for (const fs::path& temporary : temporary_maps) {
        std::error_code ec;
        fs::remove(temporary, ec);
    }
    if (!fallback.success) {
        std::cerr << "OPENFRUIT Swift fallback: fallback compilation failed; "
                     "the original native crash diagnostics follow.\n"
                  << std::flush;
        PrintBoundedDiagnostics(native);
    }
    return fallback.exit_code;
}

} // namespace


bool CompilerProxy::IsActive() {
    return !ReadEnv(
               L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL"
           ).empty() ||
           !ReadEnv(
               L"OPENFRUIT_COMPILER_PROXY_REAL"
           ).empty() ||
           !ReadEnv(
               L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL"
           ).empty();
}

int CompilerProxy::Run(
    int argc,
    char* argv[]
) {
    if (IsSwiftTargetInvocation(argc, argv) &&
        !ReadEnv(L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL").empty()) {
        return RunSwiftTargetProxy(argc, argv);
    }

    const std::wstring manifest_compiler =
        ReadEnv(L"OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL");
    const std::wstring manifest_sdk =
        ReadEnv(L"OPENFRUIT_SWIFT_MANIFEST_SDK");

    bool swift_manifest_invocation = false;
    for (int index = 1; index < argc; ++index) {
        const std::string argument =
            argv[index] ? argv[index] : "";
        if (argument == "-package-description-version" ||
            argument.rfind("-package-description-version=", 0) == 0) {
            swift_manifest_invocation = true;
            break;
        }
    }

    if (swift_manifest_invocation &&
        !manifest_compiler.empty() &&
        !manifest_sdk.empty()) {
        // Evaluate the original manifest source. Host SDK routing must not
        // rewrite platform predicates, string literals or source operands.
        std::vector<std::wstring> forwarded;
        forwarded.reserve(
            static_cast<std::size_t>(argc + 2)
        );
        forwarded.push_back(manifest_compiler);

        bool replaced_sdk = false;
        for (int index = 1; index < argc; ++index) {
            const std::wstring argument =
                Win32Process::ToWide(
                    argv[index] ? argv[index] : ""
                );

            if (argument == L"-sdk" && index + 1 < argc) {
                forwarded.push_back(L"-sdk");
                forwarded.push_back(manifest_sdk);
                ++index;
                replaced_sdk = true;
                continue;
            }

            if (argument.rfind(L"-sdk=", 0) == 0) {
                forwarded.push_back(L"-sdk=" + manifest_sdk);
                replaced_sdk = true;
                continue;
            }

            forwarded.push_back(argument);
        }

        if (!replaced_sdk) {
            forwarded.push_back(L"-sdk");
            forwarded.push_back(manifest_sdk);
        }

        const std::string observation_id = []() noexcept {
            try { return CurrentOperationContext() ? NewOperationId() : std::string{}; }
            catch (...) { return std::string{}; }
        }();
        ObserveManifestFiles(forwarded, observation_id, "before");
        const ProcessResult result = Win32Process::Run(
            manifest_compiler,
            forwarded,
            L"",
            {
                { L"SDKROOT", manifest_sdk }
            },
            [](const std::string& output) {
                std::cout << output;
            },
            [](const std::string& error) {
                std::cerr << error;
            }
        );

        ObserveManifestFiles(forwarded, observation_id, "after");
        return result.exit_code;
    }

    const std::wstring real_compiler =
        ReadEnv(
            L"OPENFRUIT_COMPILER_PROXY_REAL"
        );

    if (real_compiler.empty()) {
        return 127;
    }

    const auto string_macros =
        ParseSemicolonSet(
            ReadEnv(
                L"OPENFRUIT_COMPILER_STRING_MACROS"
            )
        );

    const auto objc_string_macros =
        ParseSemicolonSet(
            ReadEnv(
                L"OPENFRUIT_COMPILER_OBJC_STRING_MACROS"
            )
        );

    const bool objective_c_invocation =
        IsObjectiveCInvocation(
            argc,
            argv
        );

    const bool cxx_invocation =
        IsCXXInvocation(
            argc,
            argv
        );

    const bool compile_only_invocation =
        IsCompileOnlyInvocation(
            argc,
            argv
        );

    const auto include_root_mappings =
        ReadIncludeRootMappings();

    std::vector<StringDefineOverride>
        string_define_overrides;

    bool clang_modules_in_use = false;
    bool removed_explicit_only_module_flag = false;
    bool stripped_cxx_dependency_module_map = false;
    bool inserted_canonical_git_include_root = false;

    std::string compile_output_path;
    std::string compile_dep_path;
    std::string compile_dep_target = "dependencies";
    std::string modulemap_input;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] ? argv[i] : "";
        if (arg == "-o" && i + 1 < argc) {
            compile_output_path = argv[i + 1] ? argv[i + 1] : "";
        } else if (arg.rfind("-o=", 0) == 0) {
            compile_output_path = arg.substr(3);
        } else if (arg == "-MF" && i + 1 < argc) {
            compile_dep_path = argv[i + 1] ? argv[i + 1] : "";
        } else if (arg.rfind("-MF=", 0) == 0) {
            compile_dep_path = arg.substr(4);
        } else if (arg == "-MT" && i + 1 < argc) {
            compile_dep_target = argv[i + 1] ? argv[i + 1] : "";
        } else if (arg.rfind("-MT=", 0) == 0) {
            compile_dep_target = arg.substr(4);
        }

        if (compile_only_invocation && !arg.empty() && arg[0] != '-') {
            if (EndsWithCaseInsensitive(arg, ".modulemap") ||
                EndsWithCaseInsensitive(arg, ".map")) {
                modulemap_input = arg;
            }
        }
    }

    fs::path modulemap_stub_file;
    if (compile_only_invocation && !modulemap_input.empty()) {
        std::error_code ec;
        fs::path stub_dir;
        if (!compile_output_path.empty()) {
            stub_dir = fs::path(Win32Process::ToWide(compile_output_path)).parent_path();
        } else {
            stub_dir = fs::temp_directory_path(ec);
        }
        fs::create_directories(stub_dir, ec);
        modulemap_stub_file = stub_dir / (L"OPENFRUIT-modulemap-stub-" + std::to_wstring(GetCurrentProcessId()) + L".c");
        std::ofstream stub_out(modulemap_stub_file, std::ios::binary | std::ios::trunc);
        if (stub_out) {
            stub_out << "/* OPENFRUIT modulemap compilation stub */\n";
            stub_out.close();
        }
    }

    std::vector<std::wstring> forwarded;
    forwarded.reserve(
        static_cast<std::size_t>(
            argc > 0 ? argc + 2 : 3
        )
    );

    forwarded.push_back(
        real_compiler
    );

    for (int i = 1;
         i < argc;
         ++i) {
        const std::string argument =
            argv[i] ? argv[i] : "";

        if (!modulemap_stub_file.empty() && argument == modulemap_input) {
            forwarded.push_back(modulemap_stub_file.wstring());
            continue;
        }

        if (EndsWithCaseInsensitive(
                argument,
                "resource_bundle_accessor.m")) {
            if (!PatchGeneratedResourceAccessor(
                    fs::path(
                        Win32Process::ToWide(
                            argument
                        )
                    ))) {
                return 1;
            }
        }

        /*
         * Git symlink export trees can expose a header through an alias root
         * and through its source root. On Windows, even NTFS hard links can be
         * observed as separate logical FileEntry instances when the compiler
         * reaches them through different search/VFS paths. For C++/ObjC++,
         * place the canonical target include root immediately before the alias
         * root while retaining the original root as a fallback for non-symlink
         * headers.
         */
        if (cxx_invocation &&
            argument == "-I" &&
            i + 1 < argc) {
            const std::string raw_path =
                argv[i + 1]
                    ? argv[i + 1]
                    : "";

            const fs::path include_path =
                fs::path(
                    Win32Process::ToWide(
                        raw_path
                    )
                );

            if (const auto canonical =
                    CanonicalizeAliasedIncludeRoot(
                        include_path,
                        include_root_mappings)) {
                forwarded.push_back(L"-I");
                forwarded.push_back(
                    canonical->wstring()
                );
                inserted_canonical_git_include_root =
                    true;
            }

            forwarded.push_back(L"-I");
            forwarded.push_back(
                Win32Process::ToWide(
                    raw_path
                )
            );

            ++i;
            continue;
        }

        if (cxx_invocation &&
            IsJoinedIncludePathArgument(
                argument)) {
            const std::string raw_path =
                argument.substr(2);

            const fs::path include_path =
                fs::path(
                    Win32Process::ToWide(
                        raw_path
                    )
                );

            if (const auto canonical =
                    CanonicalizeAliasedIncludeRoot(
                        include_path,
                        include_root_mappings)) {
                forwarded.push_back(L"-I");
                forwarded.push_back(
                    canonical->wstring()
                );
                inserted_canonical_git_include_root =
                    true;
            }

            forwarded.push_back(
                Win32Process::ToWide(
                    argument
                )
            );
            continue;
        }

        /*
         * SwiftPM deliberately does not enable Clang modules for Darwin C++
         * translation units, but BuildPlan+Clang still forwards generated
         * dependency module maps alongside the dependency include paths.
         * Clang can then implicitly associate a textual include with one of
         * those maps even though C++ module compilation is intentionally off.
         *
         * Keep SwiftPM's -I dependency paths and drop only dependency module
         * maps for C++ / Objective-C++. This restores normal textual include
         * semantics and avoids trying to synthesize fragile umbrella modules
         * from C libraries whose public headers require an include order.
         */
        if (cxx_invocation &&
            IsDependencyModuleMapArgument(argument)) {
            stripped_cxx_dependency_module_map = true;

            if (argument == "-fmodule-map-file" &&
                i + 1 < argc) {
                ++i;
            }

            continue;
        }

        if (cxx_invocation &&
            argument == "-Xclang" &&
            i + 1 < argc) {
            const std::string next =
                argv[i + 1] ? argv[i + 1] : "";

            if (IsDependencyModuleMapArgument(next)) {
                stripped_cxx_dependency_module_map = true;
                ++i;

                if (next == "-fmodule-map-file" &&
                    i + 1 < argc) {
                    ++i;
                }

                continue;
            }
        }

        if (IsClangModuleModeArgument(argument)) {
            clang_modules_in_use = true;
        }

        /*
         * SwiftPM's native Clang build can disable implicit header modules
         * while failing to provide every transitive PCM on Windows/Linux
         * hosts. This is observable for ordinary C/C++ target dependencies
         * (for example a target including a header from another target whose
         * generated module map is visible). The compiler then diagnoses that
         * the module is needed but has not been provided.
         *
         * OPENFRUIT keeps SwiftPM's generated module maps and any explicit
         * -fmodule-file entries, but removes only the explicit-only switches.
         * Once the complete argv has been inspected, implicit module building
         * is re-enabled at the end of the command line.
         */
        if (!cxx_invocation &&
            IsImplicitModuleDisableArgument(argument)) {
            clang_modules_in_use = true;
            removed_explicit_only_module_flag = true;
            continue;
        }

        if (!cxx_invocation &&
            argument == "-Xclang" &&
            i + 1 < argc) {
            const std::string next =
                argv[i + 1] ? argv[i + 1] : "";

            if (IsImplicitModuleDisableArgument(next)) {
                clang_modules_in_use = true;
                removed_explicit_only_module_flag = true;
                ++i;
                continue;
            }
        }

        StringDefineOverride override_value;

        if (ExtractStringDefineOverride(
                argument,
                string_macros,
                objc_string_macros,
                objective_c_invocation,
                &override_value)) {
            string_define_overrides.push_back(
                std::move(override_value)
            );
            continue;
        }

        forwarded.push_back(
            Win32Process::ToWide(
                argument
            )
        );
    }

    const bool objc_cxx_compat =
        objective_c_invocation && cxx_invocation;

    const fs::path forced_header =
        WriteForcedStringDefineHeader(
            string_define_overrides,
            objc_cxx_compat
        );

    if ((!string_define_overrides.empty() || objc_cxx_compat) &&
        forced_header.empty()) {
        std::cerr
            << "OPENFRUIT compiler proxy: unable to create forced header."
            << std::endl;
        return 1;
    }

    if (!forced_header.empty()) {
        forwarded.push_back(L"-include");
        forwarded.push_back(
            forced_header.wstring()
        );
    }

    /*
     * Preserve SwiftPM's module cache/map configuration, but allow Clang to
     * synthesize a missing transitive header-module PCM when SwiftPM did not
     * pass one explicitly. Appending the positive switches makes the final
     * driver state deterministic even when an older SwiftPM emitted a disable
     * flag through a response-file-expanded argv.
     */
    if (!cxx_invocation &&
        clang_modules_in_use) {
        forwarded.push_back(
            L"-fimplicit-modules"
        );
        forwarded.push_back(
            L"-fimplicit-module-maps"
        );
    }

    // Structured OPENFRUIT events are decoded from the compiler's supported
    // diagnostics by Win32Process. Renderer selection must not change the
    // compiler invocation: upstream Clang does not support a JSON format.

    if (removed_explicit_only_module_flag &&
        ReadEnv(L"OPENFRUIT_COMPILER_PROXY_TRACE") == L"1") {
        std::cout
            << "OPENFRUIT compiler proxy: enabled implicit Clang header modules for incomplete explicit-module graph."
            << std::endl;
    }

    if (stripped_cxx_dependency_module_map &&
        ReadEnv(L"OPENFRUIT_COMPILER_PROXY_TRACE") == L"1") {
        std::cout
            << "OPENFRUIT compiler proxy: using textual C/C++ dependency headers; dependency module maps suppressed."
            << std::endl;
    }

    if (inserted_canonical_git_include_root &&
        ReadEnv(L"OPENFRUIT_COMPILER_PROXY_TRACE") == L"1") {
        std::cout
            << "OPENFRUIT compiler proxy: canonical Git symlink include root inserted before alias root."
            << std::endl;
    }

    const std::wstring apple_linker =
        ReadEnv(
            L"OPENFRUIT_APPLE_LINKER"
        );

    if (!compile_only_invocation &&
        !apple_linker.empty()) {
        /*
         * Clang accepts an exact linker path through --ld-path. Also identify
         * the selected binary as LLD so Darwin driver behavior that depends on
         * LinkerIsLLD remains enabled.
         */
        forwarded.push_back(
            L"-fuse-ld=lld"
        );

        forwarded.push_back(
            L"--ld-path=" +
            apple_linker
        );

        if (ReadEnv(L"OPENFRUIT_COMPILER_PROXY_TRACE") == L"1") {
            std::cout
                << "OPENFRUIT compiler proxy: upstream Apple linker override active: "
                << Win32Process::ToNarrow(
                    apple_linker
                )
                << std::endl;
        }
    }

    if (!compile_output_path.empty()) {
        std::error_code ec;
        fs::create_directories(
            fs::path(Win32Process::ToWide(compile_output_path)).parent_path(),
            ec
        );
    }
    if (!compile_dep_path.empty()) {
        std::error_code ec;
        fs::create_directories(
            fs::path(Win32Process::ToWide(compile_dep_path)).parent_path(),
            ec
        );
    }

    const ProcessResult result =
        Win32Process::Run(
            real_compiler,
            forwarded,
            L"",
            {},
            [](const std::string& output) {
                std::cout << output;
            },
            [](const std::string& error) {
                std::cerr << error;
            }
        );

    if (!modulemap_stub_file.empty()) {
        std::error_code ec;
        fs::remove(modulemap_stub_file, ec);

        if (!compile_dep_path.empty()) {
            fs::path dep_fs(Win32Process::ToWide(compile_dep_path));
            std::ofstream dep_out(dep_fs, std::ios::binary | std::ios::trunc);
            if (dep_out) {
                dep_out << compile_dep_target << ": \\\n  " << modulemap_input << "\n";
                dep_out.close();
            }
        }
    }

    if (!forced_header.empty()) {
        std::error_code ec;
        fs::remove(forced_header, ec);
    }

    return result.exit_code;
}

} // namespace OpenFruit
