#include "utf8_path.hpp"
#include "app_builder.hpp"
#include "asset_catalog_compiler.hpp"
#include "core_data_compiler.hpp"
#include "intent_definition_compiler.hpp"
#include "interface_builder_compiler.hpp"
#include "macro_engine.hpp"
#include "system_info.hpp"
#include "win32_process.hpp"
#include "tool_paths.hpp"
#include "compiler_rt_support.hpp"
#include "preview_agent.hpp"
#include "compiler_module_cache.hpp"
#include "sdk_target_runtime.hpp"
#include "universal_project.hpp"
#include "xcode_project.hpp"
#include "header_map.hpp"
#include "git_symlinks.hpp"
#include "operation_events.hpp"
#include "swift_telemetry.hpp"
#include "build_graph.hpp"
#include "content_hash.hpp"
#include "environment_manager.hpp"
#include "package_engine.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwctype>
#include <functional>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

std::string FormatDuration(const std::chrono::steady_clock::time_point& start) {
    const auto end = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(end - start).count();
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1) << seconds << "s";
    return ss.str();
}

std::string ReadWholeFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return input ? std::string((std::istreambuf_iterator<char>(input)), {}) : std::string{};
}

// A link is up to date, as in Xcode, when its command is unchanged, its
// output is newer than every input recorded in the linker's
// -dependency_info, and nothing it searched for without finding exists now.
// Records are one opcode byte and a NUL-terminated path: 0x10 an input read,
// 0x11 a path searched and not found.
bool LinkOutputUpToDate(const fs::path& output, const fs::path& dependency_info,
                        const fs::path& stamp, const std::string& identity) {
    std::error_code ec;
    if (identity.empty() || ReadWholeFile(stamp) != identity) return false;
    const auto built = fs::last_write_time(output, ec);
    if (ec || !fs::is_regular_file(output, ec)) return false;
    const auto records = ReadWholeFile(dependency_info);
    std::size_t inputs = 0;
    for (std::size_t at = 0; at < records.size();) {
        const auto opcode = static_cast<unsigned char>(records[at]);
        const auto end = records.find('\0', at + 1);
        if (end == std::string::npos) return false;
        const auto path = Utf8Path(records.substr(at + 1, end - at - 1));
        at = end + 1;
        // lld also records each archive member by its bare member name; the
        // archive that contains it is recorded by its full path.
        if (!path.is_absolute()) continue;
        if (opcode == 0x10) {
            const auto time = fs::last_write_time(path, ec);
            if (ec || time > built) return false;
            ++inputs;
        } else if (opcode == 0x11) {
            if (fs::exists(path, ec) || (ec && ec != std::errc::no_such_file_or_directory)) return false;
        }
    }
    return inputs > 0;
}

std::string ShellSingleQuote(const std::string& value) {
    std::string result = "'";
    for (const char c : value) {
        if (c == '\'') {
            result += "'\\''";
        } else {
            result.push_back(c);
        }
    }
    result.push_back('\'');
    return result;
}

// Shell phases run in the existing Windows Git POSIX environment. Never probe
// Windows bash.exe: on older systems that name is a WSL launcher.
struct NativeShellProvider {
    fs::path usr_bin;
    fs::path shell;
    fs::path cygpath;
    std::vector<std::pair<std::wstring, std::wstring>> environment;
    std::vector<std::pair<std::wstring, std::string>> mapped_paths;

    bool Path(const std::wstring& value, std::string& result) {
        if (!fs::path(value).is_absolute()) {
            result = Win32Process::ToNarrow(value);
            return true;
        }
        for (const auto& item : mapped_paths) {
            if (item.first == value) { result = item.second; return true; }
        }
        ProcessRunOptions options;
        options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        const auto process = Win32Process::Run(
            cygpath.wstring(), {cygpath.wstring(), L"-m", L"--", value}, L"", environment,
            nullptr, nullptr, options);
        if (!process.success) {
            std::cerr << "OPENFRUIT shell provider: path conversion failed: "
                      << process.std_err << std::endl;
            return false;
        }
        result = process.std_out;
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
            result.pop_back();
        if (result.empty()) return false;
        mapped_paths.emplace_back(value, result);
        return true;
    }
};

bool IsNativeShellExecutable(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    IMAGE_DOS_HEADER dos{};
    input.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!input || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
        dos.e_lfanew > 1024 * 1024) return false;
    input.seekg(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER header{};
    WORD optional_magic = 0;
    input.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    input.read(reinterpret_cast<char*>(&header), sizeof(header));
    input.read(reinterpret_cast<char*>(&optional_magic), sizeof(optional_magic));
#if defined(_M_ARM64)
    const WORD host_machine = IMAGE_FILE_MACHINE_ARM64;
#else
    const WORD host_machine = IMAGE_FILE_MACHINE_AMD64;
#endif
    return input && signature == IMAGE_NT_SIGNATURE &&
        header.Machine == host_machine && optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        (header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0 &&
        (header.Characteristics & IMAGE_FILE_DLL) == 0;
}

void EnsureDittoShim(const fs::path& usr_bin) {
    const fs::path ditto_path = usr_bin / "ditto";
    if (!fs::exists(ditto_path)) {
        std::ofstream out(ditto_path, std::ios::binary | std::ios::trunc);
        if (out) {
            out << "#!/usr/bin/env bash\n"
                   "# Apple ditto compatibility shim for OPENFRUIT\n"
                   "set -e\n"
                   "args=()\n"
                   "for a in \"$@\"; do\n"
                   "  case \"$a\" in\n"
                   "    -*) ;; # ignore options like --rsrc, -v, --arch\n"
                   "    *) args+=(\"$a\") ;;\n"
                   "  esac\n"
                   "done\n"
                   "if [ ${#args[@]} -lt 2 ]; then exit 0; fi\n"
                   "dst=\"${args[${#args[@]}-1]}\"\n"
                   "unset 'args[${#args[@]}-1]'\n"
                   "for src in \"${args[@]}\"; do\n"
                   "  if [ -d \"$src\" ]; then\n"
                   "    mkdir -p \"$dst\" 2>/dev/null || true\n"
                   "    cp -R \"$src/.\" \"$dst/\"\n"
                   "  else\n"
                   "    if [ -d \"$dst\" ]; then\n"
                   "      cp -f \"$src\" \"$dst/\"\n"
                   "    else\n"
                   "      mkdir -p \"$(dirname \"$dst\")\" 2>/dev/null || true\n"
                   "      cp -f \"$src\" \"$dst\"\n"
                   "    fi\n"
                   "  fi\n"
                   "done\n";
        }
    }
}

void NormalizeModuleMaps(const fs::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    if (!fs::exists(dir, ec)) return;
    for (fs::recursive_directory_iterator it(dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec) || it->path().extension() != ".modulemap") continue;
        std::ifstream in(it->path(), std::ios::binary);
        if (!in) continue;
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
        bool modified = false;
        std::string updated;
        updated.reserve(content.size());
        for (size_t i = 0; i < content.size(); ++i) {
            if ((content[i] == '"' || content[i] == '\'') && i + 3 < content.size() &&
                content[i + 1] == '/' &&
                ((content[i + 2] >= 'a' && content[i + 2] <= 'z') || (content[i + 2] >= 'A' && content[i + 2] <= 'Z')) &&
                content[i + 3] == '/') {
                updated.push_back(content[i]);
                updated.push_back(static_cast<char>(std::toupper(content[i + 2])));
                updated.push_back(':');
                updated.push_back('/');
                i += 3;
                modified = true;
            } else {
                updated.push_back(content[i]);
            }
        }
        if (modified) {
            std::ofstream out(it->path(), std::ios::binary | std::ios::trunc);
            if (out) {
                out.write(updated.data(), static_cast<std::streamsize>(updated.size()));
            }
        }
    }
}

void NormalizeSwiftInterfaces(const fs::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    if (!fs::exists(dir, ec)) return;
    for (fs::recursive_directory_iterator it(dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        const auto ext = it->path().extension().string();
        if (ext != ".swiftinterface") continue;
        std::ifstream in(it->path(), std::ios::binary);
        if (!in) continue;
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
        if (content.find("\r\n") == std::string::npos) continue;
        std::string normalized;
        normalized.reserve(content.size());
        for (size_t i = 0; i < content.size(); ++i) {
            if (content[i] == '\r' && i + 1 < content.size() && content[i + 1] == '\n') {
                continue;
            }
            normalized.push_back(content[i]);
        }
        std::ofstream out(it->path(), std::ios::binary | std::ios::trunc);
        if (out) {
            out.write(normalized.data(), static_cast<std::streamsize>(normalized.size()));
        }
    }
}

bool FindNativeShellProvider(NativeShellProvider& provider) {
    const fs::path git = ToolPaths::Git();
    if (git.empty()) return false;
    fs::path root = git.parent_path();
    for (unsigned int depth = 0; depth < 4 && !root.empty(); ++depth) {
        const fs::path bin = root / "usr" / "bin";
        if (IsNativeShellExecutable(bin / "sh.exe") &&
            IsNativeShellExecutable(bin / "bash.exe") &&
            IsNativeShellExecutable(bin / "cygpath.exe")) {
            provider.usr_bin = bin;
            provider.cygpath = bin / "cygpath.exe";
            std::wstring path = bin.wstring();
            const fs::path local_bin = ToolPaths::LocalHome() / "bin";
            if (fs::is_directory(local_bin)) path += L";" + local_bin.wstring();
            for (const wchar_t* key : {L"OPENFRUIT_SWIFT_BIN", L"OPENFRUIT_LLVM_BIN", L"PATH"}) {
                const DWORD size = GetEnvironmentVariableW(key, nullptr, 0);
                if (size == 0) continue;
                std::wstring value(size, L'\0');
                const DWORD written = GetEnvironmentVariableW(key, value.data(), size);
                value.resize(written);
                if (!value.empty()) path += L";" + value;
            }
            provider.environment = {{L"PATH", path}};
            EnsureDittoShim(bin);
            return true;
        }
        const auto parent = root.parent_path();
        if (parent == root) break;
        root = parent;
    }
    return false;
}

std::string NormalizeShellScript(std::string script) {
    script.erase(
        std::remove(script.begin(), script.end(), '\r'),
        script.end());
    return script;
}

fs::path ResolveProjectedFileSource(fs::path source) {
    static const std::string marker =
        "/* OPENFRUIT filesystem projection of a Git symlink. */";
    for (unsigned int depth = 0; depth < 8; ++depth) {
        std::ifstream input(source, std::ios::binary);
        if (!input) break;
        const std::string text{
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
        if (text.rfind(marker, 0) != 0) break;

        const std::size_t include = text.find("#include \"");
        if (include == std::string::npos) break;
        const std::size_t begin = include + 10;
        const std::size_t end = text.find('"', begin);
        if (end == std::string::npos) break;

        const fs::path target = (
            source.parent_path() / fs::path(text.substr(begin, end - begin))
        ).lexically_normal();
        std::error_code ec;
        if (!fs::is_regular_file(target, ec) || ec) break;
        source = target;
    }
    return source;
}

void CopyStagedFile(
    const fs::path& source,
    const fs::path& destination,
    std::error_code& ec
) {
    fs::copy_file(
        ResolveProjectedFileSource(source),
        destination,
        fs::copy_options::overwrite_existing,
        ec);
}


void ReplaceAll(
    std::string& value,
    const std::string& needle,
    const std::string& replacement
) {
    if (needle.empty()) return;
    std::size_t offset = 0;
    while ((offset = value.find(needle, offset)) != std::string::npos) {
        value.replace(offset, needle.size(), replacement);
        offset += replacement.size();
    }
}

void ReplaceAllWide(
    std::wstring& value,
    const std::wstring& needle,
    const std::wstring& replacement
) {
    if (needle.empty()) return;
    std::size_t offset = 0;
    while ((offset = value.find(needle, offset)) != std::wstring::npos) {
        value.replace(offset, needle.size(), replacement);
        offset += replacement.size();
    }
}

std::wstring ExpandShellPhasePath(
    std::wstring value,
    const AppBuildSpec& spec,
    const fs::path& object_dir
) {
    std::vector<std::pair<std::wstring, std::wstring>> settings =
        spec.build_settings;
    settings.emplace_back(L"DERIVED_SOURCES_DIR", object_dir.wstring());
    settings.emplace_back(L"DERIVED_FILE_DIR", object_dir.wstring());
    if (!spec.project_path.empty()) {
        settings.emplace_back(L"SRCROOT", spec.project_path);
        settings.emplace_back(L"SOURCE_ROOT", spec.project_path);
        settings.emplace_back(L"PROJECT_DIR", spec.project_path);
    }

    for (unsigned int pass = 0; pass < 16; ++pass) {
        const std::wstring before = value;
        for (const auto& [key, replacement] : settings) {
            if (key.empty()) continue;
            ReplaceAllWide(value, L"$(" + key + L")", replacement);
            ReplaceAllWide(value, L"${" + key + L"}", replacement);
        }
        if (value == before) break;
    }
    return value;
}

bool HasCarriageReturns(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    return std::find(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>(),
        '\r') != std::istreambuf_iterator<char>();
}

bool HasShellShebang(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    char first = 0;
    char second = 0;
    return input.get(first) && input.get(second) &&
        first == '#' && second == '!';
}


std::string PrepareShellPhaseScript(
    const AppBuildSpec& spec,
    const AppShellScriptPhase& phase,
    NativeShellProvider& provider
) {
    std::string script = NormalizeShellScript(phase.script);
    if (spec.project_path.empty()) return script;

    const fs::path source_root =
        fs::absolute(fs::path(spec.project_path)).lexically_normal();
    std::set<std::string> adapted_expressions;
    const auto adapt_crlf_invocation =
        [&](const std::string& expression) {
            if (!adapted_expressions.insert(expression).second) return;
            const std::string quoted = "\"" + expression + "\"";
            const std::string replacement = "OPENFRUIT_run_crlf_script " + quoted;
            bool replaced_prefix = false;
            for (const std::string& prefix : {
                     "/usr/bin/env bash ",
                     "/usr/bin/env sh ",
                     "/bin/bash ",
                     "/bin/sh ",
                     "bash ",
                     "sh "}) {
                if (script.find(prefix + quoted) != std::string::npos) {
                    ReplaceAll(script, prefix + quoted, replacement);
                    replaced_prefix = true;
                }
                if (script.find(prefix + expression) != std::string::npos) {
                    ReplaceAll(script, prefix + expression, replacement);
                    replaced_prefix = true;
                }
            }
            if (!replaced_prefix) {
                ReplaceAll(script, quoted, replacement);
            }
        };
    for (std::size_t index = 0; index < phase.input_paths.size(); ++index) {
        const fs::path input = fs::absolute(
            fs::path(phase.input_paths[index])).lexically_normal();
        const bool is_shell_script =
            ToLowerAscii(input.extension().string()) == ".sh" ||
            HasShellShebang(input);
        if (!fs::is_regular_file(input) ||
            !is_shell_script ||
            !HasCarriageReturns(input)) {
            continue;
        }

        const fs::path relative = input.lexically_relative(source_root);
        if (!relative.empty() && *relative.begin() != L"..") {
            std::string suffix = relative.generic_string();
            if (!suffix.empty() && suffix.front() != '/') suffix.insert(suffix.begin(), '/');
            for (const std::string& variable : {
                     std::string("$SRCROOT"),
                     std::string("${SRCROOT}"),
                     std::string("$SOURCE_ROOT"),
                     std::string("${SOURCE_ROOT}"),
                     std::string("$PROJECT_DIR"),
                     std::string("${PROJECT_DIR}")}) {
                const std::string expression = variable + suffix;
                adapt_crlf_invocation(expression);
            }
        }

        // Generated phases often invoke a declared input through a build
        // setting rooted path (for example ${PODS_ROOT}/...). Match every
        // resolved directory-valued setting so the CRLF adapter is generic.
        for (const auto& [key, value] : spec.build_settings) {
            if (key.empty() || value.empty() ||
                value.find(L"$(") != std::wstring::npos ||
                value.find(L"${") != std::wstring::npos) {
                continue;
            }
            const fs::path setting_root =
                fs::absolute(fs::path(value)).lexically_normal();
            const fs::path setting_relative =
                input.lexically_relative(setting_root);
            if (setting_relative.empty() ||
                *setting_relative.begin() == L"..") {
                continue;
            }
            std::string suffix = setting_relative.generic_string();
            if (!suffix.empty() && suffix.front() != '/') {
                suffix.insert(suffix.begin(), '/');
            }
            const std::string narrow_key = Win32Process::ToNarrow(key);
            for (const std::string& variable : {
                     "$" + narrow_key,
                     "${" + narrow_key + "}"}) {
                const std::string expression = variable + suffix;
                adapt_crlf_invocation(expression);
            }
        }

        const std::string input_variable =
            "$SCRIPT_INPUT_FILE_" + std::to_string(index);
        adapt_crlf_invocation(input_variable);

        std::string absolute;
        if (provider.Path(input.wstring(), absolute)) adapt_crlf_invocation(absolute);
    }
    return script;
}

class ShellPhaseSourceOutputGuard {
public:
    ShellPhaseSourceOutputGuard(
        const AppBuildSpec& spec,
        const fs::path& backup_root
    ) {
        if (spec.project_path.empty()) return;

        const fs::path source_root =
            fs::absolute(fs::path(spec.project_path)).lexically_normal();
        const fs::path products_root = spec.products_dir.empty()
            ? fs::path()
            : fs::absolute(fs::path(spec.products_dir)).lexically_normal();
        std::size_t index = 0;
        for (const auto& phase : spec.shell_script_phases) {
            for (const auto& declared_output : phase.output_paths) {
                if (declared_output.empty()) continue;
                if (declared_output.find(L"$(") != std::wstring::npos ||
                    declared_output.find(L"${") != std::wstring::npos) continue;
                const fs::path output = fs::absolute(
                    fs::path(declared_output)).lexically_normal();
                const fs::path relative = output.lexically_relative(source_root);
                if (relative.empty() || *relative.begin() == L"..") continue;
                if (!products_root.empty()) {
                    const fs::path product_relative =
                        output.lexically_relative(products_root);
                    if (product_relative.empty() ||
                        *product_relative.begin() != L"..") continue;
                }

                Entry entry;
                entry.output = output;
                entry.backup = backup_root / std::to_wstring(index++);

                std::error_code ec;
                const auto status = fs::symlink_status(output, ec);
                // A declared generator output may legitimately not exist yet.
                // exists(path, ec) clears not-found, but is_symlink(path, ec)
                // sets it again; inspect one status and preserve other errors.
                if (status.type() == fs::file_type::not_found) ec.clear();
                entry.existed = fs::exists(status) || fs::is_symlink(status);
                if (ec) {
                    valid_ = false;
                    error_ = "unable to inspect declared source-tree output: " +
                        output.string() + ": " + ec.message();
                    return;
                }
                if (entry.existed) {
                    fs::remove_all(entry.backup, ec);
                    ec.clear();
                    fs::create_directories(entry.backup.parent_path(), ec);
                    if (!ec) {
                        fs::copy(
                            output,
                            entry.backup,
                            fs::copy_options::recursive |
                                fs::copy_options::copy_symlinks,
                            ec);
                    }
                    if (ec) {
                        valid_ = false;
                        error_ = "unable to preserve declared source-tree output: " +
                            output.string() + ": " + ec.message();
                        return;
                    }
                }
                entries_.push_back(std::move(entry));
            }
        }
    }

    ~ShellPhaseSourceOutputGuard() {
        for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
            std::error_code ec;
            fs::remove_all(it->output, ec);
            ec.clear();
            if (!it->existed) continue;
            fs::create_directories(it->output.parent_path(), ec);
            if (!ec) {
                fs::copy(
                    it->backup,
                    it->output,
                    fs::copy_options::recursive |
                        fs::copy_options::copy_symlinks,
                    ec);
            }
            if (ec) {
                std::cerr << "OPENFRUIT AppBuilder: unable to restore declared source-tree output: "
                          << it->output.string() << ": " << ec.message() << std::endl;
            }
        }
    }

    bool valid() const { return valid_; }
    const std::string& error() const { return error_; }

private:
    struct Entry {
        fs::path output;
        fs::path backup;
        bool existed = false;
    };

    std::vector<Entry> entries_;
    bool valid_ = true;
    std::string error_;
};

bool RunShellScriptPhases(
    const AppBuildSpec& spec,
    bool after_sources,
    const fs::path& object_dir
) {
    std::vector<const AppShellScriptPhase*> selected;
    for (const auto& phase : spec.shell_script_phases) {
        if (phase.after_sources == after_sources) {
            selected.push_back(&phase);
        }
    }
    if (selected.empty()) return true;
    NativeShellProvider provider;
    if (!FindNativeShellProvider(provider)) {
        std::cerr << "OPENFRUIT AppBuilder: shell phase requires a full native Windows Git POSIX provider (usr/bin/sh.exe, bash.exe, cygpath.exe)." << std::endl;
        return false;
    }

    std::sort(selected.begin(), selected.end(), [](const auto* left, const auto* right) {
        return left->order < right->order;
    });

    for (const auto* phase : selected) {
        bool requires_dsym = false;
        for (const auto& input : phase->input_paths) {
            if (input.find(L"DWARF_DSYM") != std::wstring::npos ||
                input.find(L".dSYM") != std::wstring::npos) {
                requires_dsym = true;
                break;
            }
        }
        if (requires_dsym) {
            const auto it = std::find_if(
                spec.build_settings.begin(),
                spec.build_settings.end(),
                [](const auto& pair) { return pair.first == L"DEBUG_INFORMATION_FORMAT"; });
            const bool has_dsym = (it != spec.build_settings.end() &&
                                   it->second == L"dwarf-with-dsym");
            if (!has_dsym) {
                std::cout << "OPENFRUIT AppBuilder: Skipping shell build phase '"
                          << Win32Process::ToNarrow(phase->name)
                          << "' (requires dSYM, but DEBUG_INFORMATION_FORMAT is not dwarf-with-dsym)."
                          << std::endl;
                continue;
            }
        }

        const std::wstring declared_shell = phase->shell_path.empty() ? L"/bin/sh" : phase->shell_path;
        if (declared_shell == L"/bin/sh") provider.shell = provider.usr_bin / "sh.exe";
        else if (declared_shell == L"/bin/bash") provider.shell = provider.usr_bin / "bash.exe";
        else if (declared_shell == L"/usr/bin/sh") provider.shell = provider.usr_bin / "sh.exe";
        else if (declared_shell == L"/usr/bin/bash") provider.shell = provider.usr_bin / "bash.exe";
        else {
            std::cerr << "OPENFRUIT AppBuilder: unsupported phase shell contract: "
                      << Win32Process::ToNarrow(declared_shell) << std::endl;
            return false;
        }
        if (!IsNativeShellExecutable(provider.shell)) {
            std::cerr << "OPENFRUIT AppBuilder: unsupported native phase interpreter: "
                      << Win32Process::ToNarrow(declared_shell) << std::endl;
            return false;
        }
        // A wrapper establishes Xcode's derived environment; original phase text
        // is executed below without substituting Apple resource/tool semantics.
        std::string wrapper = "#!/bin/sh\n";
        wrapper += "OPENFRUIT_run_crlf_script() {\n"
                   "  script=\"$1\"\n"
                   "  shift\n"
                   "  tmp_script=\"$(mktemp)\"\n"
                   "  /usr/bin/sed 's#\\[\\[ \"\\$1\" = /\\* \\]\\]#[[ \"$1\" = /* || \"$1\" = [a-zA-Z]:/* || \"$1\" = [a-zA-Z]:\\\\* ]]#g' \"$script\" | /usr/bin/tr -d '\\r' > \"$tmp_script\"\n"
                   "  /usr/bin/bash \"$tmp_script\" \"$@\"\n"
                   "  status=$?\n"
                   "  rm -f \"$tmp_script\"\n"
                   "  return $status\n"
                   "}\n";
        wrapper += "if [ -n \"${BASH_VERSION:-}\" ]; then export -f OPENFRUIT_run_crlf_script; fi\n";
        wrapper += "ditto() {\n"
                   "  args=()\n"
                   "  for a in \"$@\"; do\n"
                   "    case \"$a\" in\n"
                   "      -*) ;; # ignore options\n"
                   "      *) args+=(\"$a\") ;;\n"
                   "    esac\n"
                   "  done\n"
                   "  if [ ${#args[@]} -lt 2 ]; then return 0; fi\n"
                   "  dst=\"${args[${#args[@]}-1]}\"\n"
                   "  unset 'args[${#args[@]}-1]'\n"
                   "  for src in \"${args[@]}\"; do\n"
                   "    if [ -d \"$src\" ]; then\n"
                   "      mkdir -p \"$dst\" 2>/dev/null || true\n"
                   "      cp -R \"$src/.\" \"$dst/\"\n"
                   "    else\n"
                   "      if [ -d \"$dst\" ]; then\n"
                   "        cp -f \"$src\" \"$dst/\"\n"
                   "      else\n"
                   "        mkdir -p \"$(dirname \"$dst\")\" 2>/dev/null || true\n"
                   "        cp -f \"$src\" \"$dst\"\n"
                   "      fi\n"
                   "    fi\n"
                   "  done\n"
                   "}\n";
        wrapper += "if [ -n \"${BASH_VERSION:-}\" ]; then export -f ditto; fi\n";
        wrapper += "rsync() {\n"
                   "  files_from=\"\"\n"
                   "  args=()\n"
                   "  for a in \"$@\"; do\n"
                   "    case \"$a\" in\n"
                   "      --files-from=*) files_from=\"${a#--files-from=}\" ;;\n"
                   "      -*) ;;\n"
                   "      *) args+=(\"$a\") ;;\n"
                   "    esac\n"
                   "  done\n"
                   "  if [ -n \"$files_from\" ]; then\n"
                   "    dst=\"${args[${#args[@]}-1]}\"\n"
                   "    mkdir -p \"$dst\" 2>/dev/null || true\n"
                   "    while IFS= read -r file || [ -n \"$file\" ]; do\n"
                   "      if [ -n \"$file\" ] && [ -e \"$file\" ]; then\n"
                   "        if [ -d \"$file\" ]; then\n"
                   "          mkdir -p \"$dst/$(basename \"$file\")\" 2>/dev/null || true\n"
                   "          cp -R \"$file/.\" \"$dst/$(basename \"$file\")/\" 2>/dev/null || true\n"
                   "        else\n"
                   "          cp -f \"$file\" \"$dst/\" 2>/dev/null || true\n"
                   "        fi\n"
                   "      fi\n"
                   "    done < \"$files_from\"\n"
                   "    return 0\n"
                   "  fi\n"
                   "  if [ ${#args[@]} -ge 2 ]; then\n"
                   "    dst=\"${args[${#args[@]}-1]}\"\n"
                   "    unset 'args[${#args[@]}-1]'\n"
                   "    mkdir -p \"$dst\" 2>/dev/null || true\n"
                   "    for src in \"${args[@]}\"; do\n"
                   "      if [ -e \"$src\" ]; then\n"
                   "        if [ -d \"$src\" ]; then\n"
                   "          mkdir -p \"$dst/$(basename \"$src\")\" 2>/dev/null || true\n"
                   "          cp -R \"$src/.\" \"$dst/$(basename \"$src\")/\" 2>/dev/null || true\n"
                   "        else\n"
                   "          cp -f \"$src\" \"$dst/\" 2>/dev/null || true\n"
                   "        fi\n"
                   "      fi\n"
                   "    done\n"
                   "  fi\n"
                   "  return 0\n"
                   "}\n";
        wrapper += "if [ -n \"${BASH_VERSION:-}\" ]; then export -f rsync; fi\n";
        // `xcrun --sdk macosx` selects the build host: on Windows, the selected
        // Swift toolchain with its matching runtime and Windows SDK. The Windows
        // Swift interpreter cannot load/JIT the standard library, so host
        // `swift <file.swift>` compiles the unchanged script with the same
        // compiler into the target's derived directory and runs it.
        wrapper += "OPENFRUIT_host_tool() {\n"
                   "  if [ -z \"${OPENFRUIT_HOST_SWIFT_BIN:-}\" ]; then\n"
                   "    echo \"OPENFRUIT: no host Swift toolchain is available for xcrun --sdk macosx\" >&2\n"
                   "    return 1\n"
                   "  fi\n"
                   "  (\n"
                   "    export SDKROOT=\"$OPENFRUIT_HOST_SDKROOT\"\n"
                   "    PATH=\"$(cygpath -u \"$OPENFRUIT_HOST_SWIFT_RUNTIME\"):$(cygpath -u \"$OPENFRUIT_HOST_SWIFT_BIN\"):$PATH\"\n"
                   "    if [ \"$1\" = swift ]; then\n"
                   "      shift\n"
                   "      OPENFRUIT_swift_options=()\n"
                   "      while [ $# -gt 0 ]; do\n"
                   "        case \"$1\" in\n"
                   "          -*) OPENFRUIT_swift_options+=(\"$1\"); shift ;;\n"
                   "          *) break ;;\n"
                   "        esac\n"
                   "      done\n"
                   "      case \"${1:-}\" in\n"
                   "        *.swift)\n"
                   "          OPENFRUIT_script=\"$1\"\n"
                   "          shift\n"
                   "          OPENFRUIT_script_dir=\"${DERIVED_FILE_DIR:?}/.OPENFRUIT-host-scripts\"\n"
                   "          mkdir -p \"$OPENFRUIT_script_dir\" || exit 1\n"
                   "          OPENFRUIT_script_exe=\"$OPENFRUIT_script_dir/$(basename \"$OPENFRUIT_script\" .swift).exe\"\n"
                   "          swiftc.exe \"${OPENFRUIT_swift_options[@]}\" \"$OPENFRUIT_script\" -o \"$OPENFRUIT_script_exe\" >&2 || exit $?\n"
                   "          exec \"$OPENFRUIT_script_exe\" \"$@\"\n"
                   "          ;;\n"
                   "        *) exec swift.exe \"${OPENFRUIT_swift_options[@]}\" \"$@\" ;;\n"
                   "      esac\n"
                   "    fi\n"
                   "    exec \"$@\"\n"
                   "  )\n"
                   "}\n";
        wrapper += "if [ -n \"${BASH_VERSION:-}\" ]; then export -f OPENFRUIT_host_tool; fi\n";
        wrapper += "xcrun() {\n"
                   "  local OPENFRUIT_xcrun_sdk=\"\"\n"
                   "  while [ $# -gt 0 ]; do\n"
                   "    case \"$1\" in\n"
                   "      -sdk|--sdk) OPENFRUIT_xcrun_sdk=\"$2\"; shift 2 ;;\n"
                   "      --sdk=*) OPENFRUIT_xcrun_sdk=\"${1#--sdk=}\"; shift ;;\n"
                   "      -toolchain|--toolchain) shift 2 ;;\n"
                   "      --toolchain=*) shift ;;\n"
                   "      -v|--verbose|-l|--log|-n|--no-cache|-k|--kill-cache) shift ;;\n"
                   "      -r|--run|--) shift; break ;;\n"
                   "      -show-sdk-*|--show-sdk-*|--show-toolchain-path)\n"
                   "        echo \"xcrun: error: $1 is not implemented by OPENFRUIT\" >&2\n"
                   "        return 1\n"
                   "        ;;\n"
                   "      *) break ;;\n"
                   "    esac\n"
                   "  done\n"
                   "  case \"$1\" in\n"
                   "    momc)\n"
                   "      shift\n"
                   "      src=\"$1\"\n"
                   "      dst=\"$2\"\n"
                   "      mkdir -p \"$dst\" 2>/dev/null || true\n"
                   "      cp -R \"$src/.\" \"$dst/\" 2>/dev/null || true\n"
                   "      ;;\n"
                   "    mapc)\n"
                   "      shift\n"
                   "      src=\"$1\"\n"
                   "      dst=\"$2\"\n"
                   "      mkdir -p \"$(dirname \"$dst\")\" 2>/dev/null || true\n"
                   "      if [ -d \"$src\" ]; then\n"
                   "        if [ -f \"$src/xcmapping.xml\" ]; then\n"
                   "          cp -f \"$src/xcmapping.xml\" \"$dst\" 2>/dev/null || true\n"
                   "        else\n"
                   "          mkdir -p \"$dst\" 2>/dev/null || true\n"
                   "          cp -R \"$src/.\" \"$dst/\" 2>/dev/null || true\n"
                   "        fi\n"
                   "      else\n"
                   "        cp -f \"$src\" \"$dst\" 2>/dev/null || true\n"
                   "      fi\n"
                   "      ;;\n"
                   "    -f|--find)\n"
                   "      return 1\n"
                   "      ;;\n"
                   "    *)\n"
                   "      case \"$OPENFRUIT_xcrun_sdk\" in\n"
                   "        macosx|macosx[0-9]*) OPENFRUIT_host_tool \"$@\" ;;\n"
                   "        *) \"$@\" ;;\n"
                   "      esac\n"
                   "      ;;\n"
                   "  esac\n"
                   "}\n";
        wrapper += "if [ -n \"${BASH_VERSION:-}\" ]; then export -f xcrun; fi\n";
        wrapper += "ibtool() {\n"
                   "  compile_dst=\"\"\n"
                   "  input=\"\"\n"
                   "  while [ $# -gt 0 ]; do\n"
                   "    case \"$1\" in\n"
                   "      --compile)\n"
                   "        compile_dst=\"$2\"\n"
                   "        shift 2\n"
                   "        ;;\n"
                   "      *.xib|*.storyboard)\n"
                   "        input=\"$1\"\n"
                   "        shift\n"
                   "        ;;\n"
                   "      *)\n"
                   "        shift\n"
                   "        ;;\n"
                   "    esac\n"
                   "  done\n"
                   "  if [ -n \"$compile_dst\" ] && [ -n \"$input\" ]; then\n"
                   "    mkdir -p \"$(dirname \"$compile_dst\")\" 2>/dev/null || true\n"
                   "    if command -v openib >/dev/null 2>&1; then\n"
                   "      openib compile \"$input\" -o \"$compile_dst\" 2>/dev/null || cp -f \"$input\" \"$compile_dst\" 2>/dev/null || true\n"
                   "    else\n"
                   "      cp -f \"$input\" \"$compile_dst\" 2>/dev/null || true\n"
                   "    fi\n"
                   "  fi\n"
                   "  return 0\n"
                   "}\n";
        wrapper += "if [ -n \"${BASH_VERSION:-}\" ]; then export -f ibtool; fi\n";
        bool path_error = false;
        const auto environment_value = [&](const std::wstring& value) {
            std::string result;
            if (!provider.Path(value, result)) path_error = true;
            return result;
        };
        for (const auto& [key, value] : spec.build_settings) {
            if (key.empty() || !(std::iswalpha(key.front()) || key.front() == L'_') ||
                !std::all_of(key.begin(), key.end(), [](wchar_t c) {
                    return std::iswalnum(c) || c == L'_';
                })) continue;
            if (value.find(L"$(") != std::wstring::npos ||
                value.find(L"${") != std::wstring::npos) continue;
            wrapper += "export " + Win32Process::ToNarrow(key) + "=" +
                ShellSingleQuote(environment_value(value)) + "\n";
        }
        if (const fs::path host_swift_bin = ToolPaths::SwiftBin({}); !host_swift_bin.empty()) {
            const auto host = EnvironmentManager::ResolveSwiftHostPlatform(host_swift_bin);
            std::wstring host_sdk;
            for (const auto& [key, value] : PackageEngine::HostEnvironment(host_swift_bin))
                if (key == L"SDKROOT") host_sdk = value;
            if (!host.runtime_bin.empty() && !host_sdk.empty()) {
                wrapper += "export OPENFRUIT_HOST_SWIFT_BIN=" +
                    ShellSingleQuote(environment_value(host_swift_bin.wstring())) + "\n";
                wrapper += "export OPENFRUIT_HOST_SWIFT_RUNTIME=" +
                    ShellSingleQuote(environment_value(host.runtime_bin.wstring())) + "\n";
                wrapper += "export OPENFRUIT_HOST_SDKROOT=" +
                    ShellSingleQuote(environment_value(host_sdk)) + "\n";
            }
        }
        if (!spec.project_path.empty()) {
            const std::string project_root = environment_value(
                fs::path(spec.project_path).lexically_normal().wstring());
            wrapper += "export SRCROOT=" + ShellSingleQuote(project_root) + "\n";
            wrapper += "export SOURCE_ROOT=\"$SRCROOT\"\n";
            wrapper += "export PROJECT_DIR=\"$SRCROOT\"\n";
        }
        wrapper += "export DERIVED_SOURCES_DIR=" + ShellSingleQuote(
            environment_value(object_dir.wstring())) + "\n";
        wrapper += "export DERIVED_FILE_DIR=\"$DERIVED_SOURCES_DIR\"\n";
        wrapper += "export SCRIPT_INPUT_FILE_COUNT=" +
            std::to_string(phase->input_paths.size()) + "\n";
        wrapper += "export SCRIPT_OUTPUT_FILE_COUNT=" +
            std::to_string(phase->output_paths.size()) + "\n";
        for (std::size_t index = 0; index < phase->input_paths.size(); ++index) {
            const std::wstring input = ExpandShellPhasePath(
                phase->input_paths[index], spec, object_dir);
            wrapper += "export SCRIPT_INPUT_FILE_" + std::to_string(index) + "=" +
                ShellSingleQuote(environment_value(input)) + "\n";
        }
        for (std::size_t index = 0; index < phase->output_paths.size(); ++index) {
            const std::wstring output = ExpandShellPhasePath(
                phase->output_paths[index], spec, object_dir);
            wrapper += "export SCRIPT_OUTPUT_FILE_" + std::to_string(index) + "=" +
                ShellSingleQuote(environment_value(output)) + "\n";
        }
        if (!spec.project_path.empty()) {
            wrapper += "cd " + ShellSingleQuote(
                environment_value(spec.project_path)) + " || exit 1\n";
        }
        wrapper += PrepareShellPhaseScript(spec, *phase, provider);
        if (wrapper.empty() || wrapper.back() != '\n') wrapper.push_back('\n');

        const fs::path wrapper_path = object_dir /
            (std::string(".OPENFRUIT-shell-phase-") +
             (after_sources ? "post-" : "pre-") +
             std::to_string(phase->order) + ".sh");
        {
            std::ofstream out(wrapper_path, std::ios::binary | std::ios::trunc);
            if (!out) {
                std::cerr << "OPENFRUIT AppBuilder: unable to write shell build phase wrapper: "
                          << wrapper_path.string() << std::endl;
                return false;
            }
            out.write(wrapper.data(), static_cast<std::streamsize>(wrapper.size()));
        }

        if (path_error) return false;
        std::cout << "OPENFRUIT AppBuilder: Running native shell build phase '"
                  << Win32Process::ToNarrow(phase->name) << "'." << std::endl;
        const ProcessResult process = Win32Process::Run(
            provider.shell.wstring(), {provider.shell.wstring(), wrapper_path.wstring()}, spec.project_path,
            provider.environment);
        if (!process.std_out.empty()) std::cout << process.std_out << std::flush;
        if (!process.std_err.empty()) std::cerr << process.std_err << std::flush;
        if (!process.success) {
            std::cerr << "OPENFRUIT AppBuilder: shell build phase failed with exit code "
                      << process.exit_code << "." << std::endl;
            return false;
        }
        for (const auto& output : phase->output_paths) {
            const std::wstring resolved_output = ExpandShellPhasePath(
                output, spec, object_dir);
            if (!resolved_output.empty() && !fs::exists(resolved_output)) {
                std::cerr << "OPENFRUIT AppBuilder: shell build phase did not produce declared output: "
                          << Win32Process::ToNarrow(resolved_output) << std::endl;
                return false;
            }
        }
    }
    if (!spec.products_dir.empty()) {
        NormalizeModuleMaps(fs::path(spec.products_dir));
    }
    NormalizeModuleMaps(object_dir);
    return true;
}

void AddUnique(
    std::vector<std::wstring>& values,
    const std::wstring& value
) {
    if (value.empty()) {
        return;
    }

    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

fs::path CurrentExecutablePath() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size())
    );
    if (length == 0 || length >= buffer.size()) return {};
    buffer.resize(length);
    return fs::path(buffer);
}

void AddSwiftSourcesFromPath(
    const fs::path& path,
    std::vector<std::wstring>& sources
) {
    std::error_code ec;

    if (!fs::exists(path, ec)) {
        return;
    }

    if (fs::is_regular_file(path, ec)) {
        if (ToLowerAscii(path.extension().string()) == ".swift") {
            AddUnique(sources, path.wstring());
        }
        return;
    }

    if (!fs::is_directory(path, ec)) {
        return;
    }

    for (fs::recursive_directory_iterator it(
             path,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) {
            ec.clear();
            continue;
        }

        if (!it->is_regular_file(ec)) {
            continue;
        }

        if (ToLowerAscii(it->path().extension().string()) == ".swift") {
            AddUnique(sources, it->path().wstring());
        }
    }
}

std::vector<std::wstring> CollectProjectHeaderSearchPaths(
    const fs::path& project_root,
    const fs::path& repo_root = {},
    const std::vector<std::wstring>& project_headers = {}
) {
    std::vector<std::wstring> paths;
    if (!project_headers.empty()) {
        for (const auto& h : project_headers) {
            fs::path p(h);
            fs::path parent = p.parent_path();
            if (fs::exists(parent)) {
                AddUnique(paths, parent.wstring());
            }
            fs::path resolved = ResolveGitSymlinkPlaceholderTarget(p);
            if (resolved != p && fs::exists(resolved.parent_path())) {
                AddUnique(paths, resolved.parent_path().wstring());
            }
        }
        return paths;
    }

    std::error_code ec;

    if (!fs::is_directory(project_root, ec)) {
        return paths;
    }

    static std::unordered_map<std::wstring, std::vector<std::wstring>> s_project_header_paths_cache;
    static std::mutex s_project_header_paths_mutex;

    const std::wstring cache_key = project_root.lexically_normal().wstring() + L"|" + repo_root.lexically_normal().wstring();
    {
        std::lock_guard<std::mutex> lock(s_project_header_paths_mutex);
        auto it = s_project_header_paths_cache.find(cache_key);
        if (it != s_project_header_paths_cache.end()) {
            return it->second;
        }
    }

    const bool is_repo_root = (!repo_root.empty() && fs::equivalent(project_root, repo_root, ec));
    ec.clear();

    for (fs::recursive_directory_iterator it(
             project_root,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (it->is_directory(ec)) {
            const std::string name =
                ToLowerAscii(it->path().filename().string());
            if (name == ".git" || name == ".build" || name == "build" ||
                name == "deriveddata" || name == "msvc" || name == "dependencies" ||
                name == "win32" || name == "windows" || name.rfind("vs20", 0) == 0 ||
                (is_repo_root && (name == "cores" || name == "submodules"))) {
                it.disable_recursion_pending();
            }
            continue;
        }
        if (!it->is_regular_file(ec)) {
            continue;
        }
        const std::string extension =
            ToLowerAscii(it->path().extension().string());
        if (extension == ".h" || extension == ".hpp" ||
            extension == ".hh" || extension == ".hxx") {
            const fs::path parent = it->path().parent_path();
            const std::string parent_str = ToLowerAscii(parent.string());
            if (parent_str.find("msvc") == std::string::npos &&
                parent_str.find("win32") == std::string::npos &&
                parent_str.find("windows") == std::string::npos) {
                AddUnique(paths, parent.wstring());
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(s_project_header_paths_mutex);
        s_project_header_paths_cache[cache_key] = paths;
    }

    return paths;
}

std::vector<fs::path> GeneratedSwiftHeaderModuleMaps(
    const fs::path& generated_header,
    const fs::path& package_configuration
) {
    std::vector<fs::path> result;
    std::ifstream header(generated_header, std::ios::binary);
    if (!header || !fs::is_directory(package_configuration)) return result;

    const std::string content(
        (std::istreambuf_iterator<char>(header)),
        std::istreambuf_iterator<char>()
    );
    const std::regex import_pattern(
        R"(@import\s+([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_]+)*\s*;)"
    );
    std::set<std::string> imported_roots;
    for (std::sregex_iterator it(content.begin(), content.end(), import_pattern),
                              end;
         it != end;
         ++it) {
        imported_roots.insert((*it)[1].str());
    }

    std::error_code ec;
    for (fs::directory_iterator it(
             package_configuration,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (!it->is_directory(ec)) continue;
        const fs::path module_map =
            it->path() / "include" / "module.modulemap";
        if (!fs::is_regular_file(module_map, ec)) {
            ec.clear();
            continue;
        }
        std::ifstream map_input(module_map, std::ios::binary);
        const std::string map_text(
            (std::istreambuf_iterator<char>(map_input)),
            std::istreambuf_iterator<char>()
        );
        bool required = false;
        for (const auto& imported : imported_roots) {
            const std::regex declaration(
                "(?:framework\\s+)?module\\s+" + imported +
                "(?:\\s|\\{|\\.)"
            );
            if (std::regex_search(map_text, declaration)) {
                required = true;
                break;
            }
        }
        if (required) result.push_back(module_map);
    }
    return result;
}

std::string EscapeResponseArgument(
    const std::wstring& argument,
    bool slash_normalize
) {
    std::string value = Win32Process::ToNarrow(argument);

    if (slash_normalize) {
        std::replace(value.begin(), value.end(), '\\', '/');
    }

    const bool needs_quotes =
        value.find_first_of(" \t\"") != std::string::npos;

    if (!needs_quotes) {
        return value;
    }

    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');

    std::size_t backslashes = 0;

    for (const char c : value) {
        if (c == '\\') {
            ++backslashes;
            continue;
        }

        if (c == '"') {
            escaped.append(backslashes * 2 + 1, '\\');
            escaped.push_back('"');
            backslashes = 0;
            continue;
        }

        escaped.append(backslashes, '\\');
        backslashes = 0;
        escaped.push_back(c);
    }

    escaped.append(backslashes * 2, '\\');
    escaped.push_back('"');

    return escaped;
}

bool WriteResponseFile(
    const fs::path& path,
    const std::vector<std::wstring>& arguments,
    std::size_t first_argument,
    bool slash_normalize
) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }

    for (std::size_t i = first_argument; i < arguments.size(); ++i) {
        output
            << EscapeResponseArgument(arguments[i], slash_normalize)
            << '\n';
    }

    return static_cast<bool>(output);
}

std::wstring DetectSDKPlatformVersion(const SDKInfo& sdk_info) {
    const fs::path sdk_root(sdk_info.sdk_path);
    const fs::path json = sdk_root / "SDKSettings.json";

    if (fs::exists(json)) {
        std::ifstream input(json, std::ios::binary);
        const std::string content(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>()
        );

        {
            const std::regex version_regex(
                "\\\"Version\\\"\\s*:\\s*\\\"([0-9]+(?:\\.[0-9]+){1,2})\\\""
            );
            std::smatch match;
            if (std::regex_search(content, match, version_regex) &&
                match.size() > 1) {
                return Win32Process::ToWide(match[1].str());
            }
        }

        {
            const std::regex canonical_regex(
                "\\\"CanonicalName\\\"\\s*:\\s*\\\"iphoneos([0-9]+(?:\\.[0-9]+){1,2})\\\"",
                std::regex::icase
            );
            std::smatch match;
            if (std::regex_search(content, match, canonical_regex) &&
                match.size() > 1) {
                return Win32Process::ToWide(match[1].str());
            }
        }
    }

    // Current extracted Xcode baseline. Keep existing behavior as fallback.
    return L"26.5";
}

std::vector<std::wstring> CollectFrameworkSearchPaths(
    const AppBuildSpec& spec,
    const PackageBuildResult& package_info
) {
    std::vector<std::wstring> paths;

    for (const auto& value : spec.embedded_framework_dirs) {
        AddUnique(paths, value);
    }

    if (!spec.products_dir.empty() && fs::is_directory(spec.products_dir)) {
        AddUnique(paths, spec.products_dir);
    }

    for (const auto& framework : package_info.frameworks) {
        const fs::path path(framework);
        if (fs::exists(path)) {
            if (path.extension() == ".framework") {
                AddUnique(paths, path.parent_path().wstring());
            } else if (fs::is_directory(path)) {
                AddUnique(paths, path.wstring());
            }
        }
    }

    return paths;
}

void PrintMacroDiagnostics(const PackageBuildResult& package_info) {
    if (package_info.macro_plugins.empty()) {
        return;
    }

    std::cout
        << "OPENFRUIT: Host macro plugins: "
        << package_info.macro_plugins.size()
        << std::endl;

    for (const auto& plugin : package_info.macro_plugins) {
        std::wstring executable = plugin;
        const std::size_t separator = executable.rfind(L'#');
        if (separator != std::wstring::npos) {
            executable = executable.substr(0, separator);
        }

        const fs::path path(executable);
        std::error_code ec;
        const auto size = fs::file_size(path, ec);

        std::cout << "  - " << Win32Process::ToNarrow(plugin);

        if (!ec) {
            std::cout << " [" << size << " bytes]";
        }
        if (!fs::exists(path)) {
            std::cout << " [MISSING]";
        }
        std::cout << std::endl;
    }
}



std::string EscapeSwiftString(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());

    for (const char c : value) {
        switch (c) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(c);
            break;
        }
    }

    return escaped;
}

bool IsSwiftKeyword(const std::string& value) {
    static const std::set<std::string> keywords = {
        "associatedtype", "class", "deinit", "enum", "extension",
        "fileprivate", "func", "import", "init", "inout", "internal",
        "let", "open", "operator", "private", "protocol", "public",
        "rethrows", "static", "struct", "subscript", "typealias",
        "var", "break", "case", "continue", "default", "defer", "do",
        "else", "fallthrough", "for", "guard", "if", "in", "repeat",
        "return", "switch", "where", "while", "as", "Any", "catch",
        "false", "is", "nil", "super", "self", "Self", "throw",
        "throws", "true", "try"
    };

    return keywords.count(value) != 0;
}

std::string MakeSwiftAssetIdentifier(const std::string& asset_name) {
    std::vector<std::string> parts;
    std::string current;

    for (const unsigned char c : asset_name) {
        if (std::isalnum(c)) {
            current.push_back(static_cast<char>(c));
        } else if (!current.empty()) {
            parts.push_back(current);
            current.clear();
        }
    }

    if (!current.empty()) {
        parts.push_back(current);
    }

    if (parts.empty()) {
        return "_asset";
    }

    std::string identifier;

    for (std::size_t i = 0; i < parts.size(); ++i) {
        std::string part = parts[i];

        if (i == 0) {
            if (!part.empty()) {
                part[0] = static_cast<char>(
                    std::tolower(
                        static_cast<unsigned char>(part[0])
                    )
                );
            }
            identifier += part;
        } else {
            if (!part.empty()) {
                part[0] = static_cast<char>(
                    std::toupper(
                        static_cast<unsigned char>(part[0])
                    )
                );
            }
            identifier += part;
        }
    }

    // Remove characters that cannot occur in an identifier.
    identifier.erase(
        std::remove_if(
            identifier.begin(),
            identifier.end(),
            [](unsigned char c) {
                return !(std::isalnum(c) || c == '_');
            }
        ),
        identifier.end()
    );

    if (identifier.empty()) {
        identifier = "_asset";
    }

    if (std::isdigit(
            static_cast<unsigned char>(identifier.front()))) {
        identifier.insert(
            identifier.begin(),
            '_'
        );
    }

    if (IsSwiftKeyword(identifier)) {
        identifier =
            "`" +
            identifier +
            "`";
    }

    return identifier;
}

struct AssetSymbol {
    std::string symbol;
    std::string resource_name;
};

fs::path GenerateAssetSymbols(
    const fs::path& build_root,
    const AppBuildSpec& spec,
    std::size_t& out_symbol_count
) {
    out_symbol_count = 0;

    if (!spec.generate_asset_symbols ||
        spec.asset_catalog_dirs.empty()) {
        return {};
    }

    std::vector<AssetSymbol> images;
    std::vector<AssetSymbol> colors;

    std::set<std::string> seen_image_symbols;
    std::set<std::string> seen_color_symbols;

    const auto options =
        fs::directory_options::skip_permission_denied;

    for (const auto& catalog_value :
         spec.asset_catalog_dirs) {

        const fs::path catalog(catalog_value);

        if (!fs::exists(catalog) ||
            !fs::is_directory(catalog)) {
            continue;
        }

        std::error_code ec;

        for (fs::recursive_directory_iterator it(
                 catalog,
                 options,
                 ec);
             it != fs::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                ec.clear();
                continue;
            }

            if (!it->is_directory(ec)) {
                continue;
            }

            const std::string extension =
                ToLowerAscii(
                    it->path().extension().string()
                );

            const bool is_image =
                extension == ".imageset" ||
                extension == ".symbolset";

            const bool is_color =
                extension == ".colorset";

            if (!is_image && !is_color) {
                continue;
            }

            const std::string resource_name =
                it->path().stem().string();

            const std::string symbol =
                MakeSwiftAssetIdentifier(
                    resource_name
                );

            if (is_image) {
                if (seen_image_symbols.insert(symbol).second) {
                    images.push_back(
                        { symbol, resource_name }
                    );
                }
            } else {
                if (seen_color_symbols.insert(symbol).second) {
                    colors.push_back(
                        { symbol, resource_name }
                    );
                }
            }

            it.disable_recursion_pending();
        }
    }

    if (images.empty() &&
        colors.empty()) {
        return {};
    }

    const auto compare_symbol =
        [](const AssetSymbol& lhs,
           const AssetSymbol& rhs) {
            return lhs.symbol < rhs.symbol;
        };

    std::sort(
        images.begin(),
        images.end(),
        compare_symbol
    );

    std::sort(
        colors.begin(),
        colors.end(),
        compare_symbol
    );

    const fs::path derived_sources =
        build_root /
        "DerivedSources";

    fs::create_directories(
        derived_sources
    );

    const fs::path output_path =
        derived_sources /
        "GeneratedAssetSymbols.swift";

    std::ostringstream output;

    /*
     * Equivalent build-time derived source for Xcode's typed asset symbols.
     * This file is written only under build/, never into the upstream source
     * checkout.
     */
    output
        << "// Generated by OPENFRUIT from the target asset catalogs.\n"
        << "// Do not edit.\n\n"
        << "import Foundation\n\n"
        << "private let OPENFRUITAssetBundle = Bundle.main\n\n"
        << "#if canImport(DeveloperToolsSupport)\n"
        << "import DeveloperToolsSupport\n\n";

    if (!images.empty()) {
        output
            // Xcode's generated resource symbols carry the resource types'
            // availability, so older deployment targets still compile.
            << "@available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *)\n"
            << "extension DeveloperToolsSupport.ImageResource {\n";

        for (const auto& asset : images) {
            output
                << "    static let "
                << asset.symbol
                << " = DeveloperToolsSupport.ImageResource(name: \""
                << EscapeSwiftString(asset.resource_name)
                << "\", bundle: OPENFRUITAssetBundle)\n";
        }

        output << "}\n\n";
    }

    if (!colors.empty()) {
        output
            << "@available(iOS 17.0, macOS 14.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *)\n"
            << "extension DeveloperToolsSupport.ColorResource {\n";

        for (const auto& asset : colors) {
            output
                << "    static let "
                << asset.symbol
                << " = DeveloperToolsSupport.ColorResource(name: \""
                << EscapeSwiftString(asset.resource_name)
                << "\", bundle: OPENFRUITAssetBundle)\n";
        }

        output << "}\n\n";
    }

    output << "#endif\n\n#if canImport(UIKit)\nimport UIKit\n\n";

    if (!images.empty()) {
        output << "extension UIKit.UIImage {\n";
        for (const auto& asset : images) {
            output
                << "    static var "
                << asset.symbol
                << ": UIKit.UIImage { UIKit.UIImage(named: \""
                << EscapeSwiftString(asset.resource_name)
                << "\", in: OPENFRUITAssetBundle, compatibleWith: nil)! }\n";
        }
        output << "}\n\n";
    }

    if (!colors.empty()) {
        output << "extension UIKit.UIColor {\n";
        for (const auto& asset : colors) {
            output
                << "    static var "
                << asset.symbol
                << ": UIKit.UIColor { UIKit.UIColor(named: \""
                << EscapeSwiftString(asset.resource_name)
                << "\", in: OPENFRUITAssetBundle, compatibleWith: nil)! }\n";
        }
        output << "}\n\n";
    }

    output << "#endif\n";

    const std::string content = output.str();
    bool content_changed = true;
    std::error_code ec;
    if (fs::exists(output_path, ec)) {
        std::ifstream existing(output_path, std::ios::binary);
        if (existing) {
            std::string existing_content(
                (std::istreambuf_iterator<char>(existing)),
                std::istreambuf_iterator<char>()
            );
            if (existing_content == content) {
                content_changed = false;
            }
        }
    }

    if (content_changed) {
        std::ofstream file(
            output_path,
            std::ios::binary |
            std::ios::trunc
        );
        if (!file) {
            return {};
        }
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    out_symbol_count =
        images.size() +
        colors.size();

    return output_path;
}


std::wstring ReadEnvironmentVariable(
    const wchar_t* name
) {
    const DWORD required =
        GetEnvironmentVariableW(
            name,
            nullptr,
            0
        );

    if (required == 0) {
        return L"";
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
        return L"";
    }

    value.resize(written);
    return value;
}

struct RuntimeVersion {
    int major = -1;
    int minor = -1;
    int patch = -1;
};

bool ParseRuntimeVersion(
    const std::wstring& text,
    RuntimeVersion& version
) {
    static const std::wregex expression(
        LR"(^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?)"
    );

    std::wsmatch match;

    if (!std::regex_search(
            text,
            match,
            expression) ||
        match.size() < 3) {
        return false;
    }

    version.major =
        std::stoi(match[1].str());

    version.minor =
        std::stoi(match[2].str());

    version.patch =
        match.size() > 3 &&
        match[3].matched
            ? std::stoi(match[3].str())
            : 0;

    return true;
}

bool RuntimeVersionLess(
    const RuntimeVersion& lhs,
    const RuntimeVersion& rhs
) {
    if (lhs.major != rhs.major) {
        return lhs.major < rhs.major;
    }

    if (lhs.minor != rhs.minor) {
        return lhs.minor < rhs.minor;
    }

    return lhs.patch < rhs.patch;
}

bool DetectCompilerMajorMinor(
    const fs::path& swiftc,
    int& out_major,
    int& out_minor
) {
    const std::vector<std::wstring> args = {
        swiftc.wstring(),
        L"-version"
    };

    const ProcessResult process =
        Win32Process::Run(
            swiftc.wstring(),
            args
        );

    const std::string version_text =
        process.std_out +
        "\n" +
        process.std_err;

    const std::regex expression(
        R"(Swift version\s+([0-9]+)\.([0-9]+))",
        std::regex::icase
    );

    std::smatch match;

    if (!std::regex_search(
            version_text,
            match,
            expression) ||
        match.size() < 3) {
        return false;
    }

    out_major =
        std::stoi(match[1].str());

    out_minor =
        std::stoi(match[2].str());

    return true;
}

fs::path FindCompatibleSwiftRuntime(
    const fs::path& swiftc
) {
    const std::wstring local_app_data =
        ReadEnvironmentVariable(
            L"LOCALAPPDATA"
        );

    if (local_app_data.empty()) {
        return {};
    }

    const fs::path runtimes_root =
        fs::path(local_app_data) /
        "Programs" /
        "Swift" /
        "Runtimes";

    if (!fs::exists(runtimes_root)) {
        return {};
    }

    int compiler_major = -1;
    int compiler_minor = -1;

    if (!DetectCompilerMajorMinor(
            swiftc,
            compiler_major,
            compiler_minor)) {
        return {};
    }

    fs::path best_runtime_bin;
    RuntimeVersion best_version;
    bool found = false;

    std::error_code ec;

    for (fs::directory_iterator it(
             runtimes_root,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::directory_iterator();
         it.increment(ec)) {

        if (ec) {
            ec.clear();
            continue;
        }

        if (!it->is_directory(ec)) {
            continue;
        }

        RuntimeVersion candidate_version;

        if (!ParseRuntimeVersion(
                it->path().filename().wstring(),
                candidate_version)) {
            continue;
        }

        if (candidate_version.major != compiler_major ||
            candidate_version.minor != compiler_minor) {
            continue;
        }

        const fs::path candidate_bin =
            it->path() /
            "usr" /
            "bin";

        if (!fs::exists(candidate_bin)) {
            continue;
        }

        if (!found ||
            RuntimeVersionLess(
                best_version,
                candidate_version)) {
            best_version =
                candidate_version;

            best_runtime_bin =
                candidate_bin;

            found = true;
        }
    }

    return best_runtime_bin;
}

std::vector<std::pair<std::wstring, std::wstring>>
BuildSwiftCompileEnvironment(
    const fs::path& swiftc,
    const PackageBuildResult& package_info
) {
    std::vector<
        std::pair<std::wstring, std::wstring>
    > environment;

    /*
     * Host macro executables are native Windows Swift programs. They inherit
     * the swiftc environment, including PATH, when swift-frontend launches
     * them through -load-plugin-executable.
     *
     * Package tools may be built by a newer Swift than the first one on PATH.
     * If PATH resolves Swift 6.3.3 first, swiftCore.dll is ABI-incompatible
     * and the plugin can crash/emit a malformed framed response.
     *
     * Only alter PATH when host macro executables are actually present.
     */
    if (package_info.macro_plugins.empty()) {
        return environment;
    }

    const fs::path runtime_bin =
        FindCompatibleSwiftRuntime(
            swiftc
        );

    if (runtime_bin.empty()) {
        std::cerr
            << "OPENFRUIT: warning: no Swift runtime matching the patched "
               "compiler was found for host macro execution."
            << std::endl;

        return environment;
    }

    const std::wstring current_path =
        ReadEnvironmentVariable(
            L"PATH"
        );

    std::wstring compile_path =
        runtime_bin.wstring();

    if (!current_path.empty()) {
        compile_path += L";";
        compile_path += current_path;
    }

    environment.emplace_back(
        L"PATH",
        std::move(compile_path)
    );

    std::cout
        << "OPENFRUIT: Host macro Swift runtime: "
        << runtime_bin.string()
        << std::endl;

    return environment;
}

} // namespace

bool AppBuilder::CompileAvailabilityRuntime(
    const std::wstring& repo_root,
    const SDKInfo& sdk_info,
    std::wstring& out_version_obj
) {
    const fs::path root(repo_root);
    std::cout
        << "OPENFRUIT AppBuilder: Preparing LLVM availability runtime..."
        << std::endl;

    fs::path clang = ToolPaths::SwiftBin(root) / "clang.exe";

    if (!fs::exists(clang)) {
        const fs::path llvm_clang = ToolPaths::LlvmBin(root) / "clang.exe";
        clang = fs::exists(llvm_clang) ? llvm_clang : fs::path(L"clang.exe");
    }

    bool success = true;

    const fs::path availability_object = EnsureIosAvailabilityRuntimeObject(
        root, clang, sdk_info);
    if (!availability_object.empty()) {
        out_version_obj = availability_object.wstring();
        std::cout
            << "OPENFRUIT AppBuilder: Availability runtime object: "
            << availability_object.string()
            << std::endl;
    } else {
        out_version_obj.clear();
        success = false;
        std::cerr
            << "OPENFRUIT: warning: iOS compiler-rt availability support could not be prepared."
            << std::endl;
    }

    return success;
}

namespace {
// Xcode stops the build when a Copy Bundle Resources input does not exist
// ("Build input file cannot be found"); an app built without it would only
// fail later, at run time. Checked where the resources are copied, after the
// target's own phases had the chance to generate them.
bool RequireResourceInputs(const AppBuildSpec& spec) {
    bool complete = true;
    for (const auto& resource : spec.resource_files) {
        std::error_code ec;
        if (fs::exists(fs::path(resource), ec)) continue;
        std::cerr << "error: Build input file cannot be found: '" << Win32Process::ToNarrow(resource)
                  << "'. Did you forget to declare this file as an output of a script phase or custom build rule which produces it?"
                  << std::endl;
        complete = false;
    }
    return complete;
}
} // namespace

AppBuildResult AppBuilder::Build(
    const std::wstring& repo_root,
    const AppBuildSpec& spec,
    const SDKInfo& base_sdk_info,
    const PackageBuildResult& package_info
) {
    AppBuildResult result;
    SDKInfo sdk_info = base_sdk_info;
    if (!spec.deployment_version.empty()) {
        sdk_info.deployment_version = spec.deployment_version;
        const std::wstring prefix = L"arm64-apple-ios";
        if (sdk_info.target_triple.starts_with(prefix) &&
            sdk_info.target_triple.find(L"-simulator") == std::wstring::npos)
            sdk_info.target_triple = prefix + spec.deployment_version;
    }
    const std::wstring effective_product_name =
        spec.product_name.empty() ? spec.app_name : spec.product_name;
    const std::wstring effective_target_name =
        spec.app_name.empty() ? effective_product_name : spec.app_name;
    auto target_metadata = JsonValue::ObjectValue();
    target_metadata.Set("target", JsonValue::String(Win32Process::ToNarrow(spec.module_name)));
    target_metadata.Set("configuration", JsonValue::String(Win32Process::ToNarrow(spec.configuration)));
    target_metadata.Set("target_triple", JsonValue::String(Win32Process::ToNarrow(sdk_info.target_triple)));
    OperationSpan target_activity("target.build", std::move(target_metadata), [&] { return result.success; });
    const fs::path root(repo_root);

    std::cout << "\n=========================================================\n"
              << "  OPENFRUIT AppBuilder: Building Target '" << Win32Process::ToNarrow(spec.app_name) << "'\n"
              << "  Configuration: " << Win32Process::ToNarrow(spec.configuration) << "\n"
              << "  Target triple: " << Win32Process::ToNarrow(sdk_info.target_triple) << "\n"
              << "  SDK:           " << Win32Process::ToNarrow(sdk_info.sdk_path) << "\n"
              << "=========================================================" << std::endl;

    if (spec.target_kind == XcodeTargetKind::Legacy) {
        std::cerr << "OPENFRUIT AppBuilder: PBXLegacyTarget external build tool execution is unsupported." << std::endl;
        return result;
    }
    if (spec.target_kind == XcodeTargetKind::Aggregate) {
        std::wstring project_file;
        for (const auto& [key, value] : spec.build_settings)
            if (key == L"PROJECT_FILE_PATH") { project_file = value; break; }
        if (spec.target_id.empty() || project_file.empty()) {
            std::cerr << "OPENFRUIT AppBuilder: aggregate requires an authoritative project and target UUID." << std::endl;
            return result;
        }
        const auto identity = Sha256(Win32Process::ToNarrow(project_file) + "\n" + spec.target_id + "\n" +
            Win32Process::ToNarrow(spec.configuration) + "\n" + Win32Process::ToNarrow(sdk_info.target_triple));
        if (!identity) return result;
        const auto object_dir = root / "build" /
            (spec.app_name + L"-aggregate-" + Win32Process::ToWide(identity->substr(0, 24))) /
            spec.configuration / "objects";
        std::error_code ec;
        fs::create_directories(object_dir, ec);
        if (ec) {
            std::cerr << "OPENFRUIT AppBuilder: unable to create aggregate derived directory: " << ec.message() << std::endl;
            return result;
        }
        result.build_root = object_dir.parent_path().wstring();
        result.generated_source_lifetime = package_info.generated_source_lifetime
            ? package_info.generated_source_lifetime : std::make_shared<GeneratedSourceLifetime>();
        // Retain consumer leases before the guard. This also protects cleanup
        // when a PackageBuildResult is reassigned (member assignment order).
        for (const auto& lease : package_info.artifact_leases)
            result.generated_source_lifetime->Retain(lease);
        auto guard = std::make_shared<ShellPhaseSourceOutputGuard>(spec,
            object_dir / ".OPENFRUIT-source-output-backup");
        if (!guard->valid()) {
            std::cerr << "OPENFRUIT AppBuilder: " << guard->error() << std::endl;
            return result;
        }
        result.generated_source_lifetime->Retain(guard);
        // Aggregate targets have no compilation phase: all scripts execute in
        // their original PBX order through the existing native provider.
        AppBuildSpec shell_spec = spec;
        for (auto& phase : shell_spec.shell_script_phases) phase.after_sources = false;
        result.success = RunShellScriptPhases(shell_spec, false, object_dir);
        return result;
    }

    const bool is_framework =
        (spec.product_type == "com.apple.product-type.framework");
    const bool is_static_lib =
        (spec.product_type == "com.apple.product-type.library.static");
    const bool is_bundle =
        (spec.product_type == "com.apple.product-type.bundle");
    const bool is_extension =
        (spec.product_type.find("extension") != std::string::npos ||
         spec.product_type == "com.apple.product-type.app-extension");
    const bool is_app = !is_framework && !is_static_lib && !is_bundle && !is_extension;
    (void)is_app;

    fs::path products_root;
    if (!spec.products_dir.empty()) {
        products_root = fs::path(spec.products_dir);
    } else {
        products_root = root / "build" / "Products" / spec.configuration;
    }

    fs::path build_root;
    fs::path intermediates_root = root / "build";
    if (!spec.intermediates_namespace.empty()) {
        std::wstring owner;
        for (const auto& [key, value] : spec.build_settings)
            if (key == L"PROJECT_FILE_PATH") { owner = value; break; }
        if (spec.target_id.empty() || owner.empty()) {
            std::cerr << "OPENFRUIT AppBuilder: isolated intermediates require project/UUID identity.\n";
            return result;
        }
        const auto identity = Sha256(Win32Process::ToNarrow(owner) + "\n" + spec.target_id);
        if (!identity) return result;
        intermediates_root = fs::path(spec.intermediates_namespace) / ("t1-" + identity->substr(0, 24));
    }
    fs::path object_dir;
    fs::path app_dir;
    fs::path framework_dir;
    fs::path executable;

    if (is_bundle) {
        fs::path bundle_products_root = products_root;
        for (const auto& [key, value] : spec.build_settings) {
            if (key == L"CONFIGURATION_BUILD_DIR" && !value.empty() &&
                value.find(L"$(") == std::wstring::npos &&
                value.find(L"${") == std::wstring::npos) {
                bundle_products_root = fs::path(value);
                break;
            }
        }
        const std::wstring bundle_product_name =
            spec.product_name.empty() ? spec.app_name : spec.product_name;
        fs::path bundle_dir =
            bundle_products_root / (bundle_product_name + L".bundle");
        build_root = intermediates_root / (Win32Process::ToNarrow(spec.app_name) + "-bundle") / spec.configuration;
        object_dir = build_root / "objects";
        executable = bundle_dir;

        std::cout << "OPENFRUIT AppBuilder: Target resource bundle: " << bundle_dir.string() << std::endl;

        std::error_code ec;
        fs::create_directories(bundle_dir, ec);
        fs::create_directories(object_dir, ec);

        if (!RequireResourceInputs(spec)) return result;
        for (const auto& res : spec.resource_files) {
            fs::path rpath(res);
            if (fs::exists(rpath, ec)) {
                fs::path destination;
                const fs::path parent = rpath.parent_path();
                if (ToLowerAscii(parent.extension().string()) == ".lproj") {
                    const fs::path lproj_dir = bundle_dir / parent.filename();
                    fs::create_directories(lproj_dir, ec);
                    ec.clear();
                    destination = lproj_dir / rpath.filename();
                } else {
                    destination = bundle_dir / rpath.filename();
                }
                if (fs::is_directory(rpath, ec)) {
                    fs::copy(
                        rpath,
                        destination,
                        fs::copy_options::recursive |
                            fs::copy_options::overwrite_existing,
                        ec);
                } else {
                    fs::copy_file(
                        rpath,
                        destination,
                        fs::copy_options::overwrite_existing,
                        ec);
                }
                ec.clear();
            }
        }

        std::string core_data_error;
        if (!CoreDataCompiler::Compile(spec.core_data_models, bundle_dir, core_data_error)) {
            std::cerr << "OPENFRUIT AppBuilder: Core Data compilation failed: "
                      << core_data_error << std::endl;
            return result;
        }
        if (!CoreDataCompiler::CompileUncompiledInBundle(bundle_dir, core_data_error)) {
            std::cerr << "OPENFRUIT AppBuilder: in-bundle Core Data compilation failed: "
                      << core_data_error << std::endl;
            return result;
        }
        std::string asset_error;
        if (!AssetCatalogCompiler::Compile(
                spec.asset_catalog_dirs,
                bundle_dir,
                spec.deployment_version,
                AppIconSelection(spec.app_icon_name, spec.include_all_app_icons, spec.alternate_app_icons),
                asset_error)) {
            std::cerr << "OPENFRUIT AppBuilder: asset catalog compilation failed: "
                      << asset_error << std::endl;
            return result;
        }

        result.build_root = build_root.wstring();
        result.executable_path = executable.wstring();
        result.product_path = bundle_dir.wstring();
        result.success = true;
        return result;
    } else if (is_framework) {
        const std::wstring framework_product_name =
            spec.product_name.empty() ? spec.app_name : spec.product_name;
        framework_dir = products_root / (framework_product_name + L".framework");
        build_root = intermediates_root / (Win32Process::ToNarrow(spec.app_name) + "-framework") / spec.configuration;
        object_dir = build_root / "objects";
        executable = framework_dir / framework_product_name;

        std::cout << "OPENFRUIT AppBuilder: Staging framework bundle at: " << framework_dir.string() << std::endl;

        std::error_code ec;
        fs::create_directories(object_dir, ec);
        fs::create_directories(framework_dir, ec);
        fs::create_directories(framework_dir / "Headers", ec);
        fs::create_directories(framework_dir / "Modules", ec);

        for (const auto& h : spec.public_headers) {
            fs::path src(h);
            if (fs::exists(src, ec)) {
                CopyStagedFile(src, framework_dir / "Headers" / src.filename(), ec);
                ec.clear();
            }
        }

        std::string mod_name = Win32Process::ToNarrow(spec.module_name);
        fs::path umbrella_header = framework_dir / "Headers" / (spec.module_name + L".h");
        std::string map_content;
        if (fs::exists(umbrella_header, ec)) {
            map_content = "framework module " + mod_name + " {\n"
                          "    umbrella header \"" + mod_name + ".h\"\n"
                          "    export *\n"
                          "    module * { export * }\n"
                          "}\n";
        } else {
            map_content = "framework module " + mod_name + " {\n"
                          "    umbrella \"Headers\"\n"
                          "    export *\n"
                          "    module * { export * }\n"
                          "}\n";
        }
        std::ofstream map_out(framework_dir / "Modules" / "module.modulemap", std::ios::binary | std::ios::trunc);
        if (map_out) {
            map_out.write(map_content.data(), map_content.size());
        }

        result.build_root = build_root.wstring();
        result.executable_path = executable.wstring();
        result.product_path = framework_dir.wstring();
        result.object_path = (object_dir / (spec.app_name + L".o")).wstring();
    } else if (is_static_lib) {
        std::wstring base_name = effective_product_name;
        std::wstring file_name;
        if (base_name.rfind(L"lib", 0) == 0 || base_name.rfind(L"Lib", 0) == 0) {
            file_name = base_name + L".a";
        } else {
            file_name = L"lib" + base_name + L".a";
        }
        fs::path lib_path = products_root / file_name;
        build_root = intermediates_root / (Win32Process::ToNarrow(effective_target_name) + "-static") / spec.configuration;
        object_dir = build_root / "objects";
        executable = lib_path;

        std::cout << "OPENFRUIT AppBuilder: Target static library: " << lib_path.string() << std::endl;

        std::error_code ec;
        fs::create_directories(object_dir, ec);
        fs::create_directories(products_root, ec);

        result.build_root = build_root.wstring();
        result.executable_path = executable.wstring();
        result.product_path = lib_path.wstring();
        result.object_path = (object_dir / (effective_target_name + L".o")).wstring();
    } else if (is_extension) {
        build_root = intermediates_root / (Win32Process::ToNarrow(effective_target_name) + "-extension") / spec.configuration;
        object_dir = build_root / "objects";
        app_dir = products_root / (effective_product_name + L".appex");
        executable = app_dir / effective_product_name;

        std::cout << "OPENFRUIT AppBuilder: Staging app extension bundle at: " << app_dir.string() << std::endl;

        std::error_code staging_ec;
        fs::remove_all(app_dir, staging_ec);
        if (staging_ec) {
            std::cerr
                << "OPENFRUIT AppBuilder: unable to reset staged app extension bundle: "
                << staging_ec.message()
                << std::endl;
            return result;
        }

        fs::create_directories(object_dir);
        fs::create_directories(app_dir);

        result.build_root = build_root.wstring();
        result.executable_path = executable.wstring();
        result.product_path = app_dir.wstring();
        result.object_path = (object_dir / (effective_target_name + L".o")).wstring();
    } else {
        build_root = intermediates_root / (Win32Process::ToNarrow(effective_target_name) + "-app") / spec.configuration;
        object_dir = build_root / "objects";
        const fs::path payload_dir = build_root / "Payload";
        app_dir = payload_dir / (effective_product_name + L".app");
        executable = app_dir / effective_product_name;

        std::cout << "OPENFRUIT AppBuilder: Staging application bundle at: " << app_dir.string() << std::endl;

        std::error_code staging_ec;
        fs::remove_all(app_dir, staging_ec);
        if (staging_ec) {
            std::cerr
                << "OPENFRUIT AppBuilder: unable to reset staged app bundle: "
                << staging_ec.message()
                << std::endl;
            return result;
        }

        fs::create_directories(object_dir);
        fs::create_directories(app_dir);

        result.build_root = build_root.wstring();
        result.executable_path = executable.wstring();
        result.product_path = app_dir.wstring();
        result.object_path = (object_dir / (effective_target_name + L".o")).wstring();
    }

    if (!is_static_lib && !is_bundle && !spec.core_data_models.empty()) {
        const fs::path resource_destination = is_framework ? framework_dir : app_dir;
        std::string core_data_error;
        if (!CoreDataCompiler::Compile(spec.core_data_models, resource_destination, core_data_error)) {
            std::cerr << "OPENFRUIT AppBuilder: Core Data compilation failed: "
                      << core_data_error << std::endl;
            return result;
        }
    }

    AppBuildSpec shell_spec = spec;
    const auto set_shell_setting =
        [&](const std::wstring& key, const std::wstring& value) {
            for (auto& setting : shell_spec.build_settings) {
                if (setting.first == key) {
                    setting.second = value;
                    return;
                }
            }
            shell_spec.build_settings.emplace_back(key, value);
        };
    if (is_app) {
        std::wstring previous_target_build_dir;
        for (const auto& [key, value] : shell_spec.build_settings) {
            if (key == L"TARGET_BUILD_DIR") {
                previous_target_build_dir = value;
                break;
            }
        }
        const std::wstring target_build_dir = app_dir.parent_path().wstring();
        const std::wstring wrapper_name = app_dir.filename().wstring();
        if (!previous_target_build_dir.empty() &&
            previous_target_build_dir != target_build_dir) {
            for (auto& phase : shell_spec.shell_script_phases) {
                for (auto& path : phase.input_paths) {
                    if (path.rfind(previous_target_build_dir, 0) == 0) {
                        path.replace(
                            0,
                            previous_target_build_dir.size(),
                            target_build_dir);
                    }
                }
                for (auto& path : phase.output_paths) {
                    if (path.rfind(previous_target_build_dir, 0) == 0) {
                        path.replace(
                            0,
                            previous_target_build_dir.size(),
                            target_build_dir);
                    }
                }
            }
        }
        set_shell_setting(L"TARGET_BUILD_DIR", target_build_dir);
        set_shell_setting(L"BUILT_PRODUCTS_DIR", target_build_dir);
        set_shell_setting(L"CONFIGURATION_BUILD_DIR", target_build_dir);
        set_shell_setting(L"UNLOCALIZED_RESOURCES_FOLDER_PATH", wrapper_name);
        set_shell_setting(L"CONTENTS_FOLDER_PATH", wrapper_name);
        set_shell_setting(L"WRAPPER_NAME", wrapper_name);
        set_shell_setting(L"WRAPPER_EXTENSION", L"app");
        set_shell_setting(L"PRODUCT_NAME", effective_product_name);
        set_shell_setting(L"EXECUTABLE_NAME", effective_product_name);
        set_shell_setting(L"PRODUCT_MODULE_NAME", spec.module_name);
        set_shell_setting(L"TARGET_NAME", effective_target_name);
        set_shell_setting(L"TARGETNAME", effective_target_name);
        set_shell_setting(L"ACTION", L"build");
        set_shell_setting(
            L"DEPLOYMENT_TARGET_SETTING_NAME",
            L"IPHONEOS_DEPLOYMENT_TARGET");
    }

    result.generated_source_lifetime = package_info.generated_source_lifetime;
    if (result.generated_source_lifetime)
        for (const auto& lease : package_info.artifact_leases)
            result.generated_source_lifetime->Retain(lease);
    auto source_output_guard = std::make_shared<ShellPhaseSourceOutputGuard>(
        shell_spec, object_dir / ".OPENFRUIT-source-output-backup");
    if (!source_output_guard->valid()) {
        std::cerr << "OPENFRUIT AppBuilder: " << source_output_guard->error() << std::endl;
        return result;
    }
    if (result.generated_source_lifetime)
        result.generated_source_lifetime->Retain(source_output_guard);

    if (!RunShellScriptPhases(shell_spec, false, object_dir)) {
        return result;
    }

    // Preserve explicitly declared inputs until their producers run, then fail
    // if absent instead of silently compiling a different Swift source set.
    for (const auto& source : spec.additional_sources) {
        if (!fs::exists(source)) {
            std::cerr << "OPENFRUIT AppBuilder: declared Swift input is missing: "
                      << Win32Process::ToNarrow(source) << std::endl;
            return result;
        }
    }

    // 1. Collect application + generated/derived Swift sources.
    std::cout << "OPENFRUIT AppBuilder: Discovering application sources..." << std::endl;
    std::vector<std::wstring> sources;

    if (!spec.additional_sources.empty()) {
        for (const auto& additional : spec.additional_sources) {
            AddSwiftSourcesFromPath(fs::path(additional), sources);
        }
    } else if (!spec.source_root.empty()) {
        AddSwiftSourcesFromPath(fs::path(spec.source_root), sources);
    }

    std::cout << "OPENFRUIT AppBuilder: Discovered " << sources.size()
              << " Swift source file(s) from project." << std::endl;

    std::size_t generated_asset_symbol_count = 0;

    std::cout << "OPENFRUIT AppBuilder: Scanning asset catalogs for symbol generation..." << std::endl;
    const fs::path generated_asset_symbols =
        GenerateAssetSymbols(
            build_root,
            spec,
            generated_asset_symbol_count
        );

    if (!generated_asset_symbols.empty()) {
        AddSwiftSourcesFromPath(
            generated_asset_symbols,
            sources
        );

        std::cout
            << "OPENFRUIT AppBuilder: Generated "
            << generated_asset_symbol_count
            << " asset symbol(s) at "
            << generated_asset_symbols.string()
            << std::endl;
    } else {
        std::cout
            << "OPENFRUIT AppBuilder: No asset catalogs requiring symbol generation."
            << std::endl;
    }

    if (!spec.intent_definitions.empty()) {
        std::cout << "OPENFRUIT AppBuilder: Compiling intent definitions..." << std::endl;
        const fs::path derived_sources = build_root / "DerivedSources";
        for (const auto& intent_def_w : spec.intent_definitions) {
            const fs::path intent_def_path(intent_def_w);
            if (!fs::exists(intent_def_path)) {
                std::cerr << "OPENFRUIT AppBuilder: declared intent definition is missing: "
                          << intent_def_path.string() << std::endl;
                return result;
            }
            std::string err;
            const fs::path generated_intent_source =
                IntentDefinitionCompiler::Compile(
                    intent_def_path,
                    derived_sources,
                    err
                );
            if (!generated_intent_source.empty()) {
                AddSwiftSourcesFromPath(
                    generated_intent_source,
                    sources
                );
                std::cout << "OPENFRUIT AppBuilder: Generated intent source at "
                          << generated_intent_source.string() << std::endl;
            } else {
                std::cerr << "OPENFRUIT AppBuilder: intent compilation failed: "
                          << (err.empty() ? "compiler produced no generated source" : err)
                          << std::endl;
                return result;
            }
        }
    }

    result.contains_swift_sources = !sources.empty();
    std::sort(sources.begin(), sources.end());

    const bool has_static_lib_non_source_inputs =
        is_static_lib &&
        (!spec.public_headers.empty() || !spec.project_headers.empty() ||
         !spec.shell_script_phases.empty());
    if (sources.empty() && spec.native_sources.empty() && !has_static_lib_non_source_inputs) {
        std::cerr
            << "OPENFRUIT AppBuilder: no Swift or C-family source files found for "
            << Win32Process::ToNarrow(spec.app_name)
            << std::endl;
        return result;
    }

    if (!spec.native_sources.empty()) {
        std::cout
            << "OPENFRUIT AppBuilder: Discovered "
            << spec.native_sources.size()
            << " C-family source file(s)."
            << std::endl;
    }

    fs::path hmap_path;
    const auto symlink_header_mappings =
        DiscoverGitSymlinkHeaderMappings(fs::path(repo_root));
    if (!spec.project_headers.empty() || !symlink_header_mappings.empty()) {
        hmap_path = object_dir / (effective_target_name + L"-project-headers.hmap");
        HeaderMapWriter hmap;
        for (const auto& header_w : spec.project_headers) {
            const fs::path hp = ResolveGitSymlinkPlaceholderTarget(fs::path(header_w));
            std::string filename = hp.filename().string();
            hmap.AddMapping(filename, hp);
            if (!effective_target_name.empty()) {
                hmap.AddMapping(Win32Process::ToNarrow(effective_target_name) + "/" + filename, hp);
            }
            if (!effective_product_name.empty() && effective_product_name != effective_target_name) {
                hmap.AddMapping(Win32Process::ToNarrow(effective_product_name) + "/" + filename, hp);
            }
            if (!spec.module_name.empty()) {
                hmap.AddMapping(Win32Process::ToNarrow(spec.module_name) + "/" + filename, hp);
            }
        }
        for (const auto& sym_map : symlink_header_mappings) {
            hmap.AddMapping(sym_map.include_key, sym_map.target_path);
        }
        if (hmap.Write(hmap_path)) {
            std::cout << "OPENFRUIT AppBuilder: Generated header map with "
                      << hmap.Size() << " entries: "
                      << hmap_path.filename().string() << std::endl;
        } else {
            hmap_path.clear();
        }
    }

    const auto project_header_search_paths =
        CollectProjectHeaderSearchPaths(fs::path(spec.project_path), fs::path(repo_root), spec.project_headers);

    const auto framework_search_paths =
        CollectFrameworkSearchPaths(spec, package_info);

    if (!framework_search_paths.empty()) {
        std::cout
            << "OPENFRUIT AppBuilder: Framework search path(s) ("
            << framework_search_paths.size()
            << "):"
            << std::endl;
        for (const auto& framework_path : framework_search_paths) {
            std::cout
                << "  -F "
                << Win32Process::ToNarrow(framework_path)
                << std::endl;
            NormalizeSwiftInterfaces(fs::path(framework_path));
        }
    }
    NormalizeSwiftInterfaces(fs::path(repo_root));

    fs::path generated_objc_header;
    fs::path swiftmodule_file;
    fs::path swiftmodule_dir;

    if (is_framework) {
        generated_objc_header = framework_dir / "Headers" / (spec.module_name + L"-Swift.h");
        swiftmodule_dir = framework_dir / "Modules" / (spec.module_name + L".swiftmodule");
        if (!sources.empty()) {
            std::error_code sm_ec;
            fs::create_directories(swiftmodule_dir, sm_ec);
        }
        swiftmodule_file = swiftmodule_dir / (sdk_info.target_triple + L".swiftmodule");
    } else if (is_static_lib) {
        generated_objc_header = object_dir / (spec.module_name + L"-Swift.h");
        swiftmodule_file = products_root / (spec.module_name + L".swiftmodule");
    } else {
        generated_objc_header = object_dir / (spec.module_name + L"-Swift.h");
    }

    const unsigned int active_jobs =
        spec.jobs > 0
            ? spec.jobs
            : SystemInfo::GetOptimalThreadCount();

    const fs::path system_frameworks =
        fs::path(sdk_info.sdk_path) /
        "System" /
        "Library" /
        "Frameworks";

    // Objects produced by the Swift compiler for this target: one in
    // whole-module mode, one per source in incremental mode.
    std::vector<std::wstring> swift_objects;
    // Incremental Swift: each object with the dependency file its compile wrote.
    std::vector<std::pair<fs::path, fs::path>> swift_dependency_files;
    fs::path emitted_module;

    if (sources.empty()) {
        auto swift_metadata = JsonValue::ObjectValue();
        swift_metadata.Set("target", JsonValue::String(Win32Process::ToNarrow(spec.module_name)));
        swift_metadata.Set("inputs", StringArray(sources));
        swift_metadata.Set("compilation_mode", JsonValue::String("whole_module"));
        swift_metadata.Set("cache_hit", JsonValue::Boolean(false));
        OperationSpan swift_activity("compile.swift.module", std::move(swift_metadata));
        std::cout
            << "OPENFRUIT AppBuilder: Target has no Swift sources; skipping Swift compiler."
            << std::endl;
        swift_activity.Complete(JsonValue::ObjectValue(), true);
    } else {
        // 2. Prepare Swift compiler invocation.
        const fs::path swiftc =
            ToolPaths::SwiftBin(root) /
            "swiftc.exe";

        if (!fs::exists(swiftc)) {
            std::cerr
                << "OPENFRUIT AppBuilder: patched swiftc not found: "
                << swiftc.string()
                << std::endl;
            return result;
        }

        const auto cache_context = PrepareCompilerModuleCache(ToolPaths::CacheRoot(),
            swiftc, fs::path(sdk_info.sdk_path), sdk_info.target_triple,
            spec.configuration, spec.module_name, kSDKInputPolicy);
        if (!cache_context.success) {
            std::cerr << "OPENFRUIT AppBuilder: cannot prepare compiler module cache: "
                      << cache_context.error << std::endl;
            return result;
        }
        const fs::path module_cache = cache_context.path;
        // One physical spelling and a certified compiler/SDK context for every
        // consumer. Legacy PCMs can contain incompatible serialized path aliases;
        // preserve them rather than importing them into this identity namespace.
        // Clang owns its construction locks; never delete another compiler's locks.

        std::vector<std::wstring> compile_args = {
            swiftc.wstring(),
            L"-target", sdk_info.target_triple,
            L"-sdk", sdk_info.sdk_path,
            L"-Xfrontend", L"-sil-verify-none"
        };
        if (!sdk_info.vfs_overlay_path.empty()) {
            compile_args.insert(compile_args.end(), {
                L"-vfsoverlay", sdk_info.vfs_overlay_path,
                L"-Xcc", L"-ivfsoverlay", L"-Xcc", sdk_info.vfs_overlay_path
            });
        }

        if (!sdk_info.cryptex_frameworks_path.empty() &&
            fs::exists(sdk_info.cryptex_frameworks_path)) {
            compile_args.push_back(L"-F");
            compile_args.push_back(sdk_info.cryptex_frameworks_path);
        }

        if (fs::exists(system_frameworks)) {
            compile_args.push_back(L"-F");
            compile_args.push_back(system_frameworks.wstring());
        }

        std::cout
            << "OPENFRUIT AppBuilder: Preparing Swift compiler configuration..."
            << std::endl;
        std::cout
            << "OPENFRUIT AppBuilder: Module name: "
            << Win32Process::ToNarrow(spec.module_name)
            << std::endl;
        std::cout
            << "OPENFRUIT AppBuilder: Module cache: "
            << module_cache.string()
            << std::endl;

        const auto build_setting = [&](const wchar_t* name) -> std::wstring {
            for (const auto& [key, value] : spec.build_settings)
                if (key == name) return value;
            return {};
        };
        const auto setting_enabled = [&](const wchar_t* name) {
            auto value = build_setting(name);
            std::transform(value.begin(), value.end(), value.begin(), towlower);
            return value == L"yes" || value == L"true" || value == L"1";
        };
        // Xcode's explicit-module eligibility (swift-build
        // swiftExplicitModuleBuildEnabled): not with C++ interoperability,
        // and not in pre-Swift-5 language modes, whose versioned API notes
        // would import SDK Clang modules differently from the Swift 5+ SDK
        // interfaces built against them; each has an opt-in override.
        const bool explicit_modules_eligible = [&] {
            if (build_setting(L"SWIFT_ENABLE_EXPLICIT_MODULES") == L"NO") return false;
            if (build_setting(L"SWIFT_OBJC_INTEROP_MODE") == L"objcxx" ||
                build_setting(L"OTHER_SWIFT_FLAGS").find(L"-cxx-interoperability-mode=default") != std::wstring::npos)
                if (!setting_enabled(L"_SWIFT_EXPLICIT_MODULES_ALLOW_CXX_INTEROP")) return false;
            int language_major = 5;
            for (std::size_t i = 0; i + 1 < spec.swift_flags.size(); ++i)
                if (spec.swift_flags[i] == L"-swift-version") {
                    try { language_major = std::stoi(spec.swift_flags[i + 1]); } catch (...) { language_major = 0; }
                }
            return language_major >= 5 || setting_enabled(L"_SWIFT_EXPLICIT_MODULES_ALLOW_BEFORE_SWIFT_5");
        }();
        // Explicitly built modules (compilation caching) stay apart from the
        // implicit modules C-family compiles put in the module cache. As in
        // Xcode, caching requires explicit modules.
        const bool compilation_caching = explicit_modules_eligible &&
            build_setting(L"COMPILATION_CACHE_ENABLE_CACHING") != L"NO";
        if (!explicit_modules_eligible)
            std::cout << "OPENFRUIT AppBuilder: explicit modules and compilation caching are off for this target "
                         "(Xcode's rule for its Swift language mode or C++ interoperability)." << std::endl;
        compile_args.push_back(L"-module-cache-path");
        compile_args.push_back(compilation_caching
            ? (module_cache.parent_path() / (module_cache.filename().wstring() + L"-explicit") / spec.module_name).wstring()
            : module_cache.wstring());
        compile_args.push_back(L"-module-name");
        compile_args.push_back(spec.module_name);
        // Xcode's SWIFT_COMPILATION_MODE defaults to `singlefile` (incremental);
        // the legacy whole-module spellings still select whole-module mode.
        const bool whole_module =
            build_setting(L"SWIFT_COMPILATION_MODE") == L"wholemodule" ||
            build_setting(L"SWIFT_WHOLE_MODULE_OPTIMIZATION") == L"YES" ||
            build_setting(L"SWIFT_OPTIMIZATION_LEVEL") == L"-Owholemodule";
        if (whole_module) {
            compile_args.push_back(L"-whole-module-optimization");
        } else {
            compile_args.push_back(L"-incremental");
            compile_args.push_back(L"-enable-batch-mode");
            compile_args.push_back(L"-j" + std::to_wstring(active_jobs));
        }
        // Compilation caching, as Xcode's COMPILATION_CACHE_ENABLE_CACHING:
        // the driver builds the module's dependencies explicitly and every
        // compile job replays its outputs from a content-addressable store
        // when its inputs are unchanged. OPENFRUIT enables it for every
        // build; a project or command line can still turn it off with NO.
        if (compilation_caching) {
            compile_args.push_back(L"-explicit-module-build");
            compile_args.push_back(L"-cache-compile-job");
            compile_args.push_back(L"-cas-path");
            compile_args.push_back((ToolPaths::CacheRoot() / "compilation-cache" / "swift").wstring());
            std::cout << "OPENFRUIT AppBuilder: compilation caching enabled (explicit modules, CAS)." << std::endl;
        }
        compile_args.push_back(L"-Xfrontend");
        compile_args.push_back(L"-disable-ast-verifier");

        // UniversalProject owns Swift version, isolation, DEBUG, etc.
        compile_args.insert(
            compile_args.end(),
            spec.swift_flags.begin(),
            spec.swift_flags.end()
        );

        if (!spec.bridging_header.empty() &&
            fs::exists(spec.bridging_header)) {
            std::cout
                << "OPENFRUIT AppBuilder: Using bridging header: "
                << Win32Process::ToNarrow(spec.bridging_header)
                << std::endl;
            compile_args.push_back(L"-import-objc-header");
            compile_args.push_back(spec.bridging_header);
        }

        // Configured target header search paths
        for (const auto& header_path : spec.header_search_paths) {
            if (!header_path.empty() && fs::exists(header_path)) {
                compile_args.push_back(L"-Xcc");
                compile_args.push_back(L"-I");
                compile_args.push_back(L"-Xcc");
                compile_args.push_back(header_path);
            }
        }

        // Configured Swift include paths
        for (const auto& inc_path : spec.swift_include_paths) {
            if (!inc_path.empty() && fs::exists(inc_path)) {
                compile_args.push_back(L"-I");
                compile_args.push_back(inc_path);
            }
        }

        if (is_framework) {
            fs::path f_headers = framework_dir / "Headers";
            if (fs::exists(f_headers) && !fs::is_empty(f_headers)) {
                compile_args.push_back(L"-import-underlying-module");
                compile_args.push_back(L"-Xcc");
                compile_args.push_back(L"-I");
                compile_args.push_back(L"-Xcc");
                compile_args.push_back(f_headers.wstring());
            }
        }

        if (!hmap_path.empty() && fs::exists(hmap_path)) {
            compile_args.push_back(L"-Xcc");
            compile_args.push_back(L"-iquote");
            compile_args.push_back(L"-Xcc");
            compile_args.push_back(hmap_path.wstring());
        }

        for (const auto& header_root : project_header_search_paths) {
            compile_args.push_back(L"-Xcc");
            compile_args.push_back(L"-I");
            compile_args.push_back(L"-Xcc");
            compile_args.push_back(header_root);
        }

        std::vector<std::string> native_macro_modules;
        for (const auto& registration : package_info.macro_plugins) {
            const auto marker = registration.find(L'#');
            if (marker == std::wstring::npos) continue;
            std::wistringstream modules(registration.substr(marker + 1));
            std::wstring module;
            while (std::getline(modules, module, L','))
                if (!module.empty()) native_macro_modules.push_back(Win32Process::ToNarrow(module));
        }
        CompilerPluginConfiguration macro_configuration;
        std::string macro_error;
        if (!MacroEngine::ConfigureCompilerPlugins(repo_root, swiftc.parent_path().wstring(),
                sdk_info.sdk_path, macro_configuration, macro_error, native_macro_modules)) {
            std::cerr << "OPENFRUIT compiler plugin configuration failed: " << macro_error << std::endl;
            return result;
        }
        const auto macro_warmer = MacroEngine::KeepOriginalProviderWarm(macro_configuration);
        compile_args.insert(compile_args.end(), macro_configuration.arguments.begin(),
            macro_configuration.arguments.end());

        // SwiftPM host macros: real Windows executables, never wrapped here.
        PrintMacroDiagnostics(package_info);

        if (!package_info.macro_plugins.empty()) {
            std::cout
                << "OPENFRUIT AppBuilder: Registered "
                << package_info.macro_plugins.size()
                << " host compiler plugin/macro(s)."
                << std::endl;
        }

        for (const auto& macro : package_info.macro_plugins) {
            compile_args.push_back(L"-load-plugin-executable");
            compile_args.push_back(macro);
        }

        // Device-only SwiftPM include/module roots.
        for (const auto& include : package_info.module_include_dirs) {
            if (!include.empty() && fs::exists(include)) {
                if (!sdk_info.sdk_path.empty()) {
                    const fs::path rel = fs::path(include).lexically_relative(fs::path(sdk_info.sdk_path));
                    if (!rel.empty() && rel.native().rfind(L"..", 0) != 0) {
                        continue;
                    }
                }
                compile_args.push_back(L"-I");
                compile_args.push_back(include);
            }
        }

        for (const auto& flag : package_info.clang_importer_flags) {
            if (!flag.empty()) {
                compile_args.push_back(L"-Xcc");
                compile_args.push_back(flag);
            }
        }

        for (const auto& framework_path : framework_search_paths) {
            if (!fs::exists(framework_path)) {
                continue;
            }

            compile_args.push_back(L"-F");
            compile_args.push_back(framework_path);

            // The Clang importer needs the same framework roots.
            compile_args.push_back(L"-Xcc");
            compile_args.push_back(L"-F");
            compile_args.push_back(L"-Xcc");
            compile_args.push_back(framework_path);
        }

        const bool has_main_source = std::any_of(
            sources.begin(),
            sources.end(),
            [](const std::wstring& source) {
                return ToLowerAscii(
                    fs::path(source).filename().string()
                ) == "main.swift";
            }
        );
        if (!has_main_source || is_framework || is_static_lib) {
            compile_args.push_back(L"-parse-as-library");
        }

        if (is_framework) {
            compile_args.push_back(L"-emit-objc-header");
            compile_args.push_back(L"-emit-objc-header-path");
            compile_args.push_back(generated_objc_header.wstring());
            compile_args.push_back(L"-emit-module");
            compile_args.push_back(L"-emit-module-path");
            compile_args.push_back(swiftmodule_file.wstring());
        } else if (is_static_lib) {
            compile_args.push_back(L"-emit-objc-header");
            compile_args.push_back(L"-emit-objc-header-path");
            compile_args.push_back(generated_objc_header.wstring());
            compile_args.push_back(L"-emit-module");
            compile_args.push_back(L"-emit-module-path");
            compile_args.push_back(swiftmodule_file.wstring());
        } else {
            compile_args.push_back(L"-emit-objc-header");
            compile_args.push_back(L"-emit-objc-header-path");
            compile_args.push_back(generated_objc_header.wstring());
        }

        compile_args.push_back(L"-emit-object");
        if (whole_module) {
            compile_args.push_back(L"-o");
            compile_args.push_back(result.object_path);
            swift_objects.push_back(result.object_path);
        } else {
            // Per-source outputs and dependency records let the driver rebuild
            // only changed sources and their dependents on the next build.
            const fs::path swift_object_dir = object_dir / "swift";
            emitted_module = is_framework || is_static_lib ? fs::path{} : swift_object_dir / (spec.module_name + L".swiftmodule");
            std::error_code dir_ec;
            fs::create_directories(swift_object_dir, dir_ec);
            auto output_map = JsonValue::ObjectValue();
            auto module_entry = JsonValue::ObjectValue();
            module_entry.Set("swift-dependencies", JsonValue::String(
                Win32Process::ToNarrow((swift_object_dir / "module.swiftdeps").wstring())));
            output_map.Set("", std::move(module_entry));
            for (const auto& source : sources) {
                const std::string source_key = Win32Process::ToNarrow(source);
                const auto digest = Sha256(source_key);
                const std::wstring stem = fs::path(source).stem().wstring() + L"-" +
                    Win32Process::ToWide(digest ? digest->substr(0, 12) : std::string("0"));
                const fs::path object = swift_object_dir / (stem + L".o");
                auto entry = JsonValue::ObjectValue();
                entry.Set("object", JsonValue::String(Win32Process::ToNarrow(object.wstring())));
                entry.Set("swift-dependencies", JsonValue::String(
                    Win32Process::ToNarrow((swift_object_dir / (stem + L".swiftdeps")).wstring())));
                entry.Set("dependencies", JsonValue::String(
                    Win32Process::ToNarrow((swift_object_dir / (stem + L".d")).wstring())));
                output_map.Set(source_key, std::move(entry));
                swift_objects.push_back(object.wstring());
                swift_dependency_files.emplace_back(object, swift_object_dir / (stem + L".d"));
            }
            const fs::path output_file_map = swift_object_dir / "output-file-map.json";
            const std::string map_text = output_map.Serialize(true);
            std::ifstream existing_map(output_file_map, std::ios::binary);
            const std::string existing_text{std::istreambuf_iterator<char>(existing_map), {}};
            existing_map.close();
            if (existing_text != map_text) {
                std::ofstream map_out(output_file_map, std::ios::binary | std::ios::trunc);
                map_out << map_text;
                if (!map_out) {
                    std::cerr << "OPENFRUIT AppBuilder: failed to write Swift output file map." << std::endl;
                    return result;
                }
            }
            compile_args.push_back(L"-output-file-map");
            compile_args.push_back(output_file_map.wstring());
            // Each source's dependency file lists every input its compile read
            // (sources, imported modules, headers), as Xcode's build system
            // uses them to decide that a target is up to date.
            compile_args.push_back(L"-emit-dependencies");
            // As in Xcode, application targets also emit their module; the
            // incremental driver needs a stable path for it between builds.
            if (!is_framework && !is_static_lib) {
                compile_args.push_back(L"-emit-module");
                compile_args.push_back(L"-emit-module-path");
                compile_args.push_back((swift_object_dir / (spec.module_name + L".swiftmodule")).wstring());
            }
        }
        compile_args.push_back(L"-v");

        const fs::path compile_response = object_dir / "compile.resp";

        std::string response_content;
        for (size_t i = 1; i < compile_args.size(); ++i) {
            response_content += EscapeResponseArgument(compile_args[i], false) + "\n";
        }
        for (const auto& source : sources) {
            response_content += EscapeResponseArgument(source, false) + "\n";
        }

        bool response_changed = true;
        std::error_code resp_ec;
        if (fs::exists(compile_response, resp_ec)) {
            std::ifstream existing_file(compile_response, std::ios::binary);
            if (existing_file) {
                std::string existing_content(
                    (std::istreambuf_iterator<char>(existing_file)),
                    std::istreambuf_iterator<char>()
                );
                if (existing_content == response_content) {
                    response_changed = false;
                }
            }
        }

        if (response_changed) {
            std::ofstream output(
                compile_response,
                std::ios::binary | std::ios::trunc
            );

            if (!output) {
                std::cerr
                    << "OPENFRUIT AppBuilder: failed to write compiler response file."
                    << std::endl;
                return result;
            }

            output.write(
                response_content.data(),
                static_cast<std::streamsize>(response_content.size())
            );
        }

        const std::vector<std::wstring> run_compile_args = {
            swiftc.wstring(),
            L"-parseable-output",
            L"@" + compile_response.wstring()
        };

        // Incremental mode: like Xcode's build system, the driver is not even
        // started when its command is unchanged and no input recorded in any
        // source's dependency file is newer than that source's object. The
        // driver's own records still decide what to rebuild when it runs.
        // The driver may decide an input with a newer timestamp but the same
        // content needs no recompilation, leaving its object older. The stamp
        // records when the last successful run of this exact command began:
        // every input it saw then is accounted for.
        const fs::path driver_stamp = object_dir / "compile.driver-stamp";
        std::filesystem::file_time_type driver_started = std::filesystem::file_time_type::min();
        {
            std::error_code stamp_ec;
            if (!response_changed && ReadWholeFile(driver_stamp) == response_content) {
                const auto time = fs::last_write_time(driver_stamp, stamp_ec);
                if (!stamp_ec) driver_started = time;
            }
        }
        // Every source's dependency file repeats the module's shared inputs
        // (SDK and package modules, bridging headers): read each time once.
        std::unordered_map<std::string, std::optional<std::filesystem::file_time_type>> input_times;
        const bool incremental_up_to_date = !whole_module && !response_changed && !swift_dependency_files.empty() &&
            (emitted_module.empty() || fs::exists(emitted_module)) &&
            (generated_objc_header.empty() || fs::exists(generated_objc_header)) &&
            std::all_of(swift_dependency_files.begin(), swift_dependency_files.end(), [&](const auto& item) {
                const auto& [object, dependencies] = item;
                std::error_code ec;
                const auto built = std::max(fs::last_write_time(object, ec), driver_started);
                if (ec || !fs::exists(dependencies, ec)) return false;
                std::ifstream input(dependencies, std::ios::binary);
                const std::string text((std::istreambuf_iterator<char>(input)), {});
                // Make syntax: "target: input input \<newline> input"; a
                // space inside a path is escaped with a backslash.
                std::string current;
                bool after_colon = false;
                const auto check = [&](const std::string& path) {
                    if (path.empty()) return true;
                    auto [known, inserted] = input_times.try_emplace(path);
                    if (inserted) {
                        std::error_code time_ec;
                        const auto time = fs::last_write_time(Utf8Path(path), time_ec);
                        if (!time_ec) known->second = time;
                    }
                    return known->second && *known->second <= built;
                };
                for (std::size_t i = 0; i < text.size(); ++i) {
                    const char c = text[i];
                    const char next = i + 1 < text.size() ? text[i + 1] : '\0';
                    if (c == '\\' && next == ' ') { current += ' '; ++i; continue; }
                    if (c == '\\' && (next == '\n' || next == '\r')) continue;
                    if (c == ':' && !after_colon && (next == ' ' || next == '\n' || next == '\0')) {
                        current.clear();
                        after_colon = true;
                        continue;
                    }
                    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                        if (after_colon && !check(current)) return false;
                        current.clear();
                        if (c == '\n') after_colon = false;
                        continue;
                    }
                    current += c;
                }
                return after_colon ? check(current) : true;
            });
        bool can_reuse_object = false;
        std::error_code obj_ec;
        if (whole_module && !response_changed &&
            fs::exists(result.object_path, obj_ec) &&
            fs::file_size(result.object_path, obj_ec) > 0 &&
            (generated_objc_header.empty() || fs::exists(generated_objc_header, obj_ec))) {
            can_reuse_object = true;
            const auto obj_time = fs::last_write_time(result.object_path, obj_ec);
            for (const auto& src : sources) {
                if (fs::exists(src, obj_ec) && fs::last_write_time(src, obj_ec) > obj_time) {
                    can_reuse_object = false;
                    break;
                }
            }
        }

        auto swift_metadata = JsonValue::ObjectValue();
        swift_metadata.Set("target", JsonValue::String(Win32Process::ToNarrow(spec.module_name)));
        swift_metadata.Set("inputs", StringArray(sources));
        swift_metadata.Set("compilation_mode", JsonValue::String(whole_module ? "whole_module" : "incremental"));
        swift_metadata.Set("cache_hit", JsonValue::Boolean(can_reuse_object));
        OperationSpan swift_activity("compile.swift.module", std::move(swift_metadata));
        if (incremental_up_to_date) {
            std::cout << "OPENFRUIT AppBuilder: Swift module " << Win32Process::ToNarrow(spec.module_name)
                      << " is up to date; its compiler was not started." << std::endl;
        } else if (can_reuse_object) {
            if (const auto context = CurrentOperationContext()) {
                auto reused = JsonValue::ObjectValue();
                reused.Set("artifact", JsonValue::String(Win32Process::ToNarrow(result.object_path)));
                reused.Set("reason", JsonValue::String("unchanged response and up-to-date target product"));
                context->Emit("artifact.cache_hit", std::move(reused));
            }
            std::cout
                << "OPENFRUIT AppBuilder: Reusing up-to-date compiled Swift object -> "
                << Win32Process::ToNarrow(result.object_path)
                << " (" << fs::file_size(result.object_path, obj_ec) << " bytes)"
                << std::endl;
        } else {
            std::cout
                << "OPENFRUIT AppBuilder: Requested worker budget: "
                << active_jobs
                << " thread(s)"
                << std::endl;

            std::cout
                << "OPENFRUIT AppBuilder: Compiling "
                << sources.size()
                << " Swift source(s) for "
                << Win32Process::ToNarrow(spec.app_name)
                << (whole_module ? " (whole-module optimization, " : " (incremental, ")
                << active_jobs << " worker thread(s))..."
                << std::endl;

            auto compile_environment =
                BuildSwiftCompileEnvironment(
                    swiftc,
                    package_info
                );
            compile_environment.insert(compile_environment.end(), macro_configuration.environment.begin(),
                macro_configuration.environment.end());

            const auto compile_start = std::chrono::steady_clock::now();
            const auto driver_start_time = std::filesystem::file_time_type::clock::now();
            {
                std::error_code stamp_ec;
                fs::remove(driver_stamp, stamp_ec);
            }
            SwiftCompilerTelemetry telemetry(CurrentOperationContext(), [](const std::string& text) {
                std::cerr << text << std::flush;
            });
            ProcessResult compile_process = Win32Process::Run(
                swiftc.wstring(), run_compile_args, L"", compile_environment,
                [](const std::string& text) { std::cout << text << std::flush; },
                [&](const std::string& text) { telemetry.Consume(text); });
            telemetry.Finish();

            const bool objects_present = std::all_of(swift_objects.begin(), swift_objects.end(),
                [](const std::wstring& object) { return fs::exists(object); });
            // Decide from how the driver exited. Its output is streamed to the
            // telemetry callbacks; an incremental build's parseable job records
            // can exceed the in-memory capture cap without losing anything.
            const bool compiled = compile_process.launched && compile_process.exit_code == 0 &&
                !compile_process.timed_out && !compile_process.cancelled &&
                !compile_process.win32_error && !compile_process.callback_failed;
            if (!compiled || !objects_present) {
                std::cerr
                    << "OPENFRUIT AppBuilder: Swift compilation failed (exit code "
                    << compile_process.exit_code << ") after "
                    << FormatDuration(compile_start) << "."
                    << std::endl;
                return result;
            }

            if (!whole_module) {
                std::ofstream stamp(driver_stamp, std::ios::binary | std::ios::trunc);
                stamp << response_content;
                stamp.close();
                std::error_code stamp_ec;
                if (stamp) fs::last_write_time(driver_stamp, driver_start_time, stamp_ec);
                if (!stamp || stamp_ec) fs::remove(driver_stamp, stamp_ec);
            }

            std::uintmax_t object_bytes = 0;
            for (const auto& object : swift_objects) object_bytes += fs::file_size(object);
            std::cout
                << "OPENFRUIT AppBuilder: Swift compilation succeeded in "
                << FormatDuration(compile_start)
                << " -> "
                << (whole_module ? Win32Process::ToNarrow(result.object_path)
                                 : std::to_string(swift_objects.size()) + " object(s)")
                << " (" << object_bytes << " bytes)"
                << std::endl;
        }

        swift_activity.Complete(JsonValue::ObjectValue(), true);
    }

    if (is_framework && !sources.empty()) {
        std::error_code post_ec;
        if (fs::exists(swiftmodule_file, post_ec)) {
            fs::copy_file(swiftmodule_file, swiftmodule_dir / "arm64-apple-ios.swiftmodule", fs::copy_options::overwrite_existing, post_ec);
            post_ec.clear();
            fs::copy_file(swiftmodule_file, swiftmodule_dir / "arm64.swiftmodule", fs::copy_options::overwrite_existing, post_ec);
            post_ec.clear();
            fs::copy_file(swiftmodule_file, products_root / (spec.module_name + L".swiftmodule"), fs::copy_options::overwrite_existing, post_ec);
        }

        fs::path gen_swift_header = framework_dir / "Headers" / (spec.module_name + L"-Swift.h");
        if (fs::exists(gen_swift_header, post_ec)) {
            std::string mod_name = Win32Process::ToNarrow(spec.module_name);
            fs::path umbrella_header = framework_dir / "Headers" / (spec.module_name + L".h");
            std::string map_content;
            if (fs::exists(umbrella_header, post_ec)) {
                map_content = "framework module " + mod_name + " {\n"
                              "    umbrella header \"" + mod_name + ".h\"\n"
                              "    export *\n"
                              "    module * { export * }\n\n"
                              "    module Swift {\n"
                              "        header \"" + mod_name + "-Swift.h\"\n"
                              "        requires objc\n"
                              "        export *\n"
                              "    }\n"
                              "}\n";
            } else {
                map_content = "framework module " + mod_name + " {\n"
                              "    umbrella \"Headers\"\n"
                              "    export *\n"
                              "    module * { export * }\n\n"
                              "    module Swift {\n"
                              "        header \"" + mod_name + "-Swift.h\"\n"
                              "        requires objc\n"
                              "        export *\n"
                              "    }\n"
                              "}\n";
            }
            std::ofstream map_out(framework_dir / "Modules" / "module.modulemap", std::ios::binary | std::ios::trunc);
            if (map_out) {
                map_out.write(map_content.data(), map_content.size());
            }
        }
    }

    if (is_framework) {
        std::error_code post_ec;
        if (!RequireResourceInputs(spec)) return result;
        for (const auto& res : spec.resource_files) {
            fs::path rpath(res);
            if (fs::exists(rpath, post_ec)) {
                fs::path destination;
                const fs::path parent = rpath.parent_path();
                if (ToLowerAscii(parent.extension().string()) == ".lproj") {
                    const fs::path lproj_dir = framework_dir / parent.filename();
                    fs::create_directories(lproj_dir, post_ec);
                    post_ec.clear();
                    destination = lproj_dir / rpath.filename();
                } else {
                    destination = framework_dir / rpath.filename();
                }
                if (fs::is_directory(rpath, post_ec)) {
                    fs::copy(
                        rpath,
                        destination,
                        fs::copy_options::recursive |
                            fs::copy_options::overwrite_existing,
                        post_ec);
                } else {
                    fs::copy_file(
                        rpath,
                        destination,
                        fs::copy_options::overwrite_existing,
                        post_ec);
                }
                post_ec.clear();
            }
        }
        std::string asset_error;
        if (!AssetCatalogCompiler::Compile(
                spec.asset_catalog_dirs,
                framework_dir,
                spec.deployment_version,
                AppIconSelection(spec.app_icon_name, spec.include_all_app_icons, spec.alternate_app_icons),
                asset_error)) {
            std::cerr << "OPENFRUIT AppBuilder: asset catalog compilation failed: "
                      << asset_error << std::endl;
            return result;
        }

        fs::path f_plist = framework_dir / "Info.plist";
        if (!fs::exists(f_plist, post_ec)) {
            const std::wstring framework_product_name =
                spec.product_name.empty() ? spec.app_name : spec.product_name;
            std::string plist_content =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\">\n<dict>\n"
                "    <key>CFBundleDevelopmentRegion</key>\n    <string>en</string>\n"
                "    <key>CFBundleExecutable</key>\n    <string>" + Win32Process::ToNarrow(framework_product_name) + "</string>\n"
                "    <key>CFBundleIdentifier</key>\n    <string>" + Win32Process::ToNarrow(spec.bundle_id.empty() ? L"com.OPENFRUIT." + spec.app_name : spec.bundle_id) + "</string>\n"
                "    <key>CFBundleInfoDictionaryVersion</key>\n    <string>6.0</string>\n"
                "    <key>CFBundleName</key>\n    <string>" + Win32Process::ToNarrow(framework_product_name) + "</string>\n"
                "    <key>CFBundlePackageType</key>\n    <string>FMWK</string>\n"
                "    <key>CFBundleShortVersionString</key>\n    <string>1.0</string>\n"
                "    <key>CFBundleVersion</key>\n    <string>1</string>\n"
                "</dict>\n</plist>\n";
            std::ofstream plist_out(f_plist, std::ios::binary | std::ios::trunc);
            if (plist_out) {
                plist_out.write(plist_content.data(), plist_content.size());
            }
        }
    }

    if (is_extension || (!is_framework && !is_static_lib)) {
        std::error_code post_ec;
        if (!RequireResourceInputs(spec)) return result;
        for (const auto& res : spec.resource_files) {
            fs::path rpath(res);
            if (fs::exists(rpath, post_ec)) {
                fs::path destination;
                const fs::path parent = rpath.parent_path();
                if (ToLowerAscii(parent.extension().string()) == ".lproj") {
                    const fs::path lproj_dir = app_dir / parent.filename();
                    fs::create_directories(lproj_dir, post_ec);
                    post_ec.clear();
                    destination = lproj_dir / rpath.filename();
                } else {
                    destination = app_dir / rpath.filename();
                }
                if (fs::is_directory(rpath, post_ec)) {
                    fs::copy(
                        rpath,
                        destination,
                        fs::copy_options::recursive |
                            fs::copy_options::overwrite_existing,
                        post_ec);
                } else {
                    fs::copy_file(
                        rpath,
                        destination,
                        fs::copy_options::overwrite_existing,
                        post_ec);
                }
                post_ec.clear();
            }
        }
        std::string asset_error;
        if (!AssetCatalogCompiler::Compile(
                spec.asset_catalog_dirs,
                app_dir,
                spec.deployment_version,
                AppIconSelection(spec.app_icon_name, spec.include_all_app_icons, spec.alternate_app_icons),
                asset_error)) {
            std::cerr << "OPENFRUIT AppBuilder: asset catalog compilation failed: "
                      << asset_error << std::endl;
            return result;
        }

        std::string plist;
        if (!spec.info_plist_path.empty() && fs::exists(spec.info_plist_path)) {
            std::ifstream input(spec.info_plist_path, std::ios::binary);
            if (input) {
                std::string raw_content((std::istreambuf_iterator<char>(input)),
                                        std::istreambuf_iterator<char>());
                auto expand_var = [&](const std::string& var_name, const std::string& replacement) {
                    for (const std::string& pattern : {"$(" + var_name + ")", "${" + var_name + "}"}) {
                        size_t pos = 0;
                        while ((pos = raw_content.find(pattern, pos)) != std::string::npos) {
                            raw_content.replace(pos, pattern.length(), replacement);
                            pos += replacement.length();
                        }
                    }
                };
                std::string app_name_narrow = Win32Process::ToNarrow(effective_product_name);
                std::string target_name_narrow = Win32Process::ToNarrow(effective_target_name);
                std::string bundle_id_narrow = Win32Process::ToNarrow(spec.bundle_id);
                if (bundle_id_narrow.empty()) bundle_id_narrow = "com.OPENFRUIT." + app_name_narrow;
                std::string pkg_type = is_extension ? "XPC!" : (is_framework ? "FMWK" : "APPL");
                std::string module_name_narrow = Win32Process::ToNarrow(spec.module_name.empty() ? effective_product_name : spec.module_name);
                for (char& c : module_name_narrow) {
                    const unsigned char u = static_cast<unsigned char>(c);
                    const bool ascii_letter =
                        (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z');
                    const bool ascii_digit = u >= '0' && u <= '9';
                    if (!ascii_letter && !ascii_digit && c != '_') {
                        c = '_';
                    }
                }
                if (module_name_narrow.empty()) module_name_narrow = "_";
                if (module_name_narrow.front() >= '0' && module_name_narrow.front() <= '9') {
                    module_name_narrow.insert(module_name_narrow.begin(), '_');
                }
                expand_var("PRODUCT_NAME:c99extidentifier", module_name_narrow);
                expand_var("PRODUCT_MODULE_NAME", module_name_narrow);
                expand_var("EXECUTABLE_NAME", app_name_narrow);
                expand_var("PRODUCT_BUNDLE_IDENTIFIER", bundle_id_narrow);
                expand_var("PRODUCT_NAME", app_name_narrow);
                expand_var("TARGET_NAME", target_name_narrow);
                expand_var("PRODUCT_BUNDLE_PACKAGE_TYPE", pkg_type);
                expand_var("DEVELOPMENT_LANGUAGE", "en");
                expand_var("MARKETING_VERSION", "1.0");
                expand_var("CURRENT_PROJECT_VERSION", "1");
                for (const auto& [k, v] : spec.build_settings) {
                    expand_var(Win32Process::ToNarrow(k), Win32Process::ToNarrow(v));
                }
                plist = std::move(raw_content);
            }
        }

        std::string app_name_narrow = Win32Process::ToNarrow(effective_product_name);
        std::string bundle_id_narrow = Win32Process::ToNarrow(spec.bundle_id);
        if (bundle_id_narrow.empty()) bundle_id_narrow = "com.OPENFRUIT." + app_name_narrow;
        std::string pkg_type = is_extension ? "XPC!" : (is_framework ? "FMWK" : "APPL");

        if (plist.empty()) {
            plist =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<plist version=\"1.0\">\n<dict>\n"
                "    <key>CFBundleDevelopmentRegion</key>\n    <string>en</string>\n"
                "    <key>CFBundleExecutable</key>\n    <string>" + app_name_narrow + "</string>\n"
                "    <key>CFBundleIdentifier</key>\n    <string>" + bundle_id_narrow + "</string>\n"
                "    <key>CFBundleInfoDictionaryVersion</key>\n    <string>6.0</string>\n"
                "    <key>CFBundleName</key>\n    <string>" + app_name_narrow + "</string>\n"
                "    <key>CFBundlePackageType</key>\n    <string>" + pkg_type + "</string>\n"
                "    <key>CFBundleShortVersionString</key>\n    <string>1.0</string>\n"
                "    <key>CFBundleVersion</key>\n    <string>1</string>\n"
                "</dict>\n</plist>\n";
        } else {
            size_t last_dict_pos = plist.rfind("</dict>");
            if (last_dict_pos != std::string::npos) {
                std::string additions;
                auto has_key = [&](const std::string& key) {
                    return plist.find("<key>" + key + "</key>") != std::string::npos;
                };

                if (!has_key("CFBundleDevelopmentRegion")) {
                    additions += "    <key>CFBundleDevelopmentRegion</key>\n    <string>en</string>\n";
                }
                if (!has_key("CFBundleExecutable")) {
                    additions += "    <key>CFBundleExecutable</key>\n    <string>" + app_name_narrow + "</string>\n";
                }
                if (!has_key("CFBundleIdentifier")) {
                    additions += "    <key>CFBundleIdentifier</key>\n    <string>" + bundle_id_narrow + "</string>\n";
                }
                if (!has_key("CFBundleInfoDictionaryVersion")) {
                    additions += "    <key>CFBundleInfoDictionaryVersion</key>\n    <string>6.0</string>\n";
                }
                if (!has_key("CFBundleName")) {
                    additions += "    <key>CFBundleName</key>\n    <string>" + app_name_narrow + "</string>\n";
                }
                if (!has_key("CFBundlePackageType")) {
                    additions += "    <key>CFBundlePackageType</key>\n    <string>" + pkg_type + "</string>\n";
                }
                if (!has_key("CFBundleShortVersionString")) {
                    additions += "    <key>CFBundleShortVersionString</key>\n    <string>1.0</string>\n";
                }
                if (!has_key("CFBundleVersion")) {
                    additions += "    <key>CFBundleVersion</key>\n    <string>1</string>\n";
                }
                for (const auto& [k, v] : spec.build_settings) {
                    std::string narrow_k = Win32Process::ToNarrow(k);
                    if (narrow_k.rfind("INFOPLIST_KEY_", 0) == 0 && narrow_k.size() > 14) {
                        std::string plist_key = narrow_k.substr(14);
                        if (!has_key(plist_key)) {
                            additions += "    <key>" + plist_key + "</key>\n    <string>" + Win32Process::ToNarrow(v) + "</string>\n";
                        }
                    }
                }
                if (!additions.empty()) {
                    plist.insert(last_dict_pos, additions);
                }
            }
        }
        std::ofstream out(app_dir / "Info.plist", std::ios::binary | std::ios::trunc);
        if (out) {
            out.write(plist.data(), plist.size());
        }
    }

    // Compile the selected target's C-family sources exactly as separate
    // translation units, then pass their Mach-O objects to the final link.
    std::vector<std::wstring> native_objects;
    if (!spec.native_sources.empty()) {
        fs::path real_clang = ToolPaths::SwiftBin(root) / "clang-real.exe";
        if (!fs::exists(real_clang)) {
            real_clang = ToolPaths::SwiftBin(root) / "clang.exe";
        }
        const fs::path compiler_proxy = CurrentExecutablePath();
        if (!fs::exists(real_clang) || !fs::exists(compiler_proxy)) {
            std::cerr << "OPENFRUIT AppBuilder: native compiler is unavailable."
                      << std::endl;
            return result;
        }

        native_objects.resize(spec.native_sources.size());
        for (std::size_t i = 0; i < spec.native_sources.size(); ++i) {
            const fs::path source(spec.native_sources[i]);
            native_objects[i] = (
                object_dir /
                (L"native-" + std::to_wstring(i) + L"-" +
                 source.filename().wstring() + L".o")
            ).wstring();
        }

        const std::vector<std::pair<std::wstring, std::wstring>> native_env = {
            {L"OPENFRUIT_COMPILER_PROXY_REAL", real_clang.wstring()}
        };
        std::vector<fs::path> generated_module_maps;
        if (!package_info.package_archive_path.empty()) {
            generated_module_maps = GeneratedSwiftHeaderModuleMaps(
                generated_objc_header,
                fs::path(package_info.package_archive_path).parent_path()
            );
        }
        std::atomic<std::size_t> cursor{0};
        std::atomic<bool> failed{false};
        std::size_t completed_files = 0;
        std::mutex progress_mutex;
        std::mutex error_mutex;
        std::string first_error;
        const unsigned int native_jobs = std::max(
            1u,
            std::min<unsigned int>(
                active_jobs,
                static_cast<unsigned int>(spec.native_sources.size())
            )
        );
        std::vector<std::thread> workers;
        workers.reserve(native_jobs);

        const auto native_start = std::chrono::steady_clock::now();

        std::cout << "OPENFRUIT AppBuilder: Compiling " << spec.native_sources.size()
                  << " C-family source(s) with " << native_jobs
                  << " worker(s)..." << std::endl;

        auto native_metadata = JsonValue::ObjectValue();
        native_metadata.Set("target", JsonValue::String(Win32Process::ToNarrow(spec.module_name)));
        native_metadata.Set("inputs", StringArray(spec.native_sources));
        OperationSpan native_activity("compile.native.group", std::move(native_metadata), [&] { return !failed.load(); });
        const auto compilation_context = CurrentOperationContext();
        for (unsigned int worker = 0; worker < native_jobs; ++worker) {
            workers.emplace_back([&, compilation_context]() {
                OperationBinding worker_binding(compilation_context);
                while (!failed.load()) {
                    const std::size_t index = cursor.fetch_add(1);
                    if (index >= spec.native_sources.size()) break;
                    const fs::path source(spec.native_sources[index]);
                    bool file_succeeded = false;
                    auto file_metadata = JsonValue::ObjectValue();
                    file_metadata.Set("file", JsonValue::String(Win32Process::ToNarrow(source.wstring())));
                    file_metadata.Set("target", JsonValue::String(Win32Process::ToNarrow(spec.module_name)));
                    OperationSpan file_activity("compile.native.file", std::move(file_metadata), [&] { return file_succeeded; });
                    const std::size_t current_idx = index + 1;
                    std::cout << "OPENFRUIT AppBuilder: [" << current_idx << "/"
                              << spec.native_sources.size() << "] "
                              << source.filename().string() << "..." << std::endl;

                    const std::string extension =
                        ToLowerAscii(source.extension().string());
                    const bool is_cpp =
                        (extension == ".cpp" || extension == ".cxx" ||
                         extension == ".cc" || extension == ".mm");
                    const bool is_pure_cpp =
                        (extension == ".cpp" || extension == ".cxx" ||
                         extension == ".cc");
                    std::vector<std::wstring> args = {
                        compiler_proxy.wstring(),
                        L"-target", sdk_info.target_triple,
                        L"-isysroot", sdk_info.sdk_path,
                        L"-fblocks",
                        L"-O0", L"-g"
                    };
                    if (!sdk_info.vfs_overlay_path.empty() && fs::exists(sdk_info.vfs_overlay_path)) {
                        args.push_back(L"-ivfsoverlay");
                        args.push_back(sdk_info.vfs_overlay_path);
                    }
                    if (!is_pure_cpp) {
                        args.push_back(L"-fmodules");
                        args.push_back(L"-fmodules-cache-path=" +
                            (object_dir / "NativeModuleCache").wstring());
                    }
                    if (is_cpp) {
                        for (const auto& flag : spec.cxx_flags) {
                            args.push_back(flag);
                        }
                        args.push_back(L"-Wno-c++11-narrowing");
                    } else {
                        for (const auto& flag : spec.c_flags) {
                            args.push_back(flag);
                        }
                    }
                    if (extension == ".m" || extension == ".mm") {
                        args.push_back(L"-fobjc-arc");
                    }
                    if (ToLowerAscii(Win32Process::ToNarrow(spec.configuration)) ==
                        "debug") {
                        args.push_back(L"-DDEBUG=1");
                    }
                    args.push_back(L"-I");
                    args.push_back(object_dir.wstring());
                    if (!hmap_path.empty() && fs::exists(hmap_path)) {
                        args.push_back(L"-iquote");
                        args.push_back(hmap_path.wstring());
                    }
                    for (const auto& include : spec.header_search_paths) {
                        if (!include.empty() && fs::exists(include)) {
                            args.push_back(L"-I");
                            args.push_back(include);
                        }
                    }
                    for (const auto& include : project_header_search_paths) {
                        args.push_back(L"-I");
                        args.push_back(include);
                    }
                    if (is_framework) {
                        args.push_back(L"-I");
                        args.push_back((framework_dir / "Headers").wstring());
                    }
                    for (const auto& include : package_info.module_include_dirs) {
                        if (!include.empty() && fs::exists(include)) {
                            if (!sdk_info.sdk_path.empty()) {
                                const fs::path rel = fs::path(include).lexically_relative(fs::path(sdk_info.sdk_path));
                                if (!rel.empty() && rel.native().rfind(L"..", 0) != 0) {
                                    continue;
                                }
                            }
                            args.push_back(L"-I");
                            args.push_back(include);
                            const fs::path module_map =
                                fs::path(include) / "module.modulemap";
                            if (fs::exists(module_map)) {
                                args.push_back(
                                    L"-fmodule-map-file=" + module_map.wstring()
                                );
                            }
                        }
                    }
                    for (const auto& module_map : generated_module_maps) {
                        args.push_back(L"-I");
                        args.push_back(module_map.parent_path().wstring());
                        args.push_back(
                            L"-fmodule-map-file=" + module_map.wstring()
                        );
                    }
                    for (const auto& framework_path : framework_search_paths) {
                        if (fs::exists(framework_path)) {
                            args.push_back(L"-F");
                            args.push_back(framework_path);
                        }
                    }
                    // Xcode appends a build file's COMPILER_FLAGS last, so
                    // they override target settings (for example -fno-objc-arc).
                    for (const auto& [flagged, flags] : spec.native_source_flags)
                        if (flagged == spec.native_sources[index])
                            args.insert(args.end(), flags.begin(), flags.end());
                    args.push_back(L"-c");
                    args.push_back(source.wstring());
                    args.push_back(L"-o");
                    args.push_back(native_objects[index]);

                    std::error_code obj_ec;
                    const fs::path out_obj(native_objects[index]);
                    if (fs::exists(out_obj, obj_ec) &&
                        fs::file_size(out_obj, obj_ec) > 0 &&
                        fs::last_write_time(out_obj, obj_ec) >= fs::last_write_time(source, obj_ec)) {
                        file_succeeded = true;
                        std::lock_guard<std::mutex> lock(progress_mutex);
                        ++completed_files;
                        continue;
                    }

                    const ProcessResult process = Win32Process::Run(
                        compiler_proxy.wstring(),
                        args,
                        spec.project_path,
                        native_env
                    );
                    if (!process.success || !fs::exists(native_objects[index])) {
                        failed.store(true);
                        std::lock_guard<std::mutex> lock(error_mutex);
                        first_error = source.string() + "\n" + process.std_err;
                    } else {
                        file_succeeded = true;
                        std::lock_guard<std::mutex> lock(progress_mutex);
                        ++completed_files;
                        if (compilation_context) {
                            auto progress = JsonValue::ObjectValue();
                            progress.Set("basis", JsonValue::String("files"));
                            progress.Set("completed_units", JsonValue::Number(std::to_string(completed_files)));
                            progress.Set("planned_units", JsonValue::Number(std::to_string(spec.native_sources.size())));
                            progress.Set("percent", JsonValue::Number(std::to_string(100 * completed_files / spec.native_sources.size())));
                            compilation_context->Emit("compile.progress", std::move(progress));
                        }
                    }
                }
            });
        }
        for (auto& worker : workers) worker.join();
        if (failed.load()) {
            std::cerr << "OPENFRUIT AppBuilder: C-family compilation failed after "
                      << FormatDuration(native_start) << ": "
                      << first_error << std::endl;
            return result;
        }

        std::cout << "OPENFRUIT AppBuilder: C-family compilation completed in "
                  << FormatDuration(native_start) << "." << std::endl;
    }

    if (is_static_lib) {
        const bool has_archive_objects =
            std::any_of(swift_objects.begin(), swift_objects.end(),
                        [](const std::wstring& obj) { return fs::exists(obj); }) ||
            std::any_of(native_objects.begin(), native_objects.end(),
                        [](const std::wstring& obj) { return fs::exists(obj); });
        fs::path librarian = ToolPaths::SwiftBin(root) / "llvm-ar.exe";
        if (!fs::exists(librarian)) {
            librarian = ToolPaths::LlvmBin(root) / "llvm-ar.exe";
        }
        if (!fs::exists(librarian)) {
            if (!has_archive_objects) {
                if (!fs::exists(result.executable_path)) {
                    std::ofstream empty_ar(result.executable_path, std::ios::binary | std::ios::trunc);
                    empty_ar.write("!<arch>\n", 8);
                }
                if (!fs::exists(result.executable_path)) {
                    std::cerr << "OPENFRUIT AppBuilder: Static library archive failed: unable to materialize archive." << std::endl;
                    return result;
                }
            } else {
                std::cerr << "OPENFRUIT AppBuilder: llvm-ar not found for archiving static library." << std::endl;
                return result;
            }
        } else {
            const fs::path ar_rsp = object_dir / "ar_objects.rsp";
            {
                std::ofstream rsp_out(ar_rsp);
                for (const auto& obj : swift_objects) {
                    if (fs::exists(obj)) {
                        rsp_out << "\"" << fs::path(obj).string() << "\"\n";
                    }
                }
                for (const auto& obj : native_objects) {
                    if (fs::exists(obj)) {
                        rsp_out << "\"" << fs::path(obj).string() << "\"\n";
                    }
                }
            }

            std::vector<std::wstring> ar_args = {
                librarian.wstring(),
                L"rcs",
                result.executable_path,
                L"@" + ar_rsp.wstring()
            };

            std::cout << "OPENFRUIT AppBuilder: Archiving static library with llvm-ar -> "
                      << Win32Process::ToNarrow(result.executable_path) << std::endl;

            const ProcessResult ar_proc = Win32Process::Run(
                librarian.wstring(),
                ar_args,
                L"",
                {}
            );
            if (!ar_proc.success || !fs::exists(result.executable_path)) {
                std::cerr << "OPENFRUIT AppBuilder: Static library archive failed: "
                          << ar_proc.std_err << std::endl;
                return result;
            }
        }

        std::wstring base_name = effective_product_name;
        if (base_name.rfind(L"lib", 0) == 0 || base_name.rfind(L"Lib", 0) == 0) {
            std::wstring alt_name = L"lib" + base_name + L".a";
            std::error_code ec_alias;
            fs::copy_file(result.executable_path, products_root / alt_name, fs::copy_options::overwrite_existing, ec_alias);
        }

        // Stage static library into products_root / spec.module_name, effective_product_name, and effective_target_name subdirectories
        std::error_code stage_ec;
        fs::path mod_sub = products_root / spec.module_name;
        fs::create_directories(mod_sub, stage_ec);
        stage_ec.clear();
        fs::copy_file(result.executable_path, mod_sub / fs::path(result.executable_path).filename(), fs::copy_options::overwrite_existing, stage_ec);
        stage_ec.clear();

        if (effective_product_name != spec.module_name) {
            fs::path prod_sub = products_root / effective_product_name;
            fs::create_directories(prod_sub, stage_ec);
            stage_ec.clear();
            fs::copy_file(result.executable_path, prod_sub / fs::path(result.executable_path).filename(), fs::copy_options::overwrite_existing, stage_ec);
            stage_ec.clear();
        }
        if (effective_target_name != spec.module_name && effective_target_name != effective_product_name) {
            fs::path app_sub = products_root / effective_target_name;
            fs::create_directories(app_sub, stage_ec);
            stage_ec.clear();
            fs::copy_file(result.executable_path, app_sub / fs::path(result.executable_path).filename(), fs::copy_options::overwrite_existing, stage_ec);
            stage_ec.clear();
        }

        // Stage swiftmodule if produced
        if (!sources.empty() && fs::exists(swiftmodule_file, stage_ec)) {
            fs::copy_file(swiftmodule_file, mod_sub / (spec.module_name + L".swiftmodule"), fs::copy_options::overwrite_existing, stage_ec);
            stage_ec.clear();
            fs::copy_file(swiftmodule_file, products_root / (spec.module_name + L".swiftmodule"), fs::copy_options::overwrite_existing, stage_ec);
            stage_ec.clear();
            if (effective_product_name != spec.module_name) {
                fs::copy_file(swiftmodule_file, products_root / effective_product_name / (spec.module_name + L".swiftmodule"), fs::copy_options::overwrite_existing, stage_ec);
                stage_ec.clear();
            }
            if (effective_target_name != spec.module_name && effective_target_name != effective_product_name) {
                fs::copy_file(swiftmodule_file, products_root / effective_target_name / (spec.module_name + L".swiftmodule"), fs::copy_options::overwrite_existing, stage_ec);
                stage_ec.clear();
            }
        }

        // Remove legacy synthetic header/module copies. A static target product
        // does not publish headers merely by being a PBXTargetDependency; the
        // consumer's build settings and declared copy/script phases own those
        // paths. Keeping copies here creates a second Clang module identity.
        std::vector<fs::path> mm_search_dirs;
        fs::path proj_dir = !spec.project_path.empty()
            ? fs::path(spec.project_path)
            : (!spec.source_root.empty() ? fs::path(spec.source_root) : root);
        std::vector<fs::path> bases = {
            proj_dir,
            fs::path(spec.source_root),
            root,
            root / "Pods"
        };
        bases.erase(
            std::remove_if(
                bases.begin(), bases.end(),
                [](const fs::path& path) { return path.empty(); }),
            bases.end());
        for (const auto& base : bases) {
            mm_search_dirs.push_back(base / "Headers" / "Public" / effective_target_name);
            mm_search_dirs.push_back(base / "Headers" / "Public" / effective_product_name);
            mm_search_dirs.push_back(base / "Headers" / "Public" / spec.module_name);
            mm_search_dirs.push_back(base / "Headers" / "Private" / effective_target_name);
            mm_search_dirs.push_back(base / "Headers" / "Private" / effective_product_name);
            mm_search_dirs.push_back(base / "Headers" / "Private" / spec.module_name);
        }
        // Canonical CocoaPods support files must win over alias header trees.
        for (const auto& base : bases) {
            mm_search_dirs.push_back(base / "Target Support Files" / effective_target_name);
            mm_search_dirs.push_back(base / "Target Support Files" / effective_product_name);
            mm_search_dirs.push_back(base / "Target Support Files" / spec.module_name);
        }
        for (const auto& d : mm_search_dirs) {
            if (!fs::exists(d, stage_ec)) continue;
            for (fs::directory_iterator it(d, stage_ec); it != fs::directory_iterator(); it.increment(stage_ec)) {
                if (stage_ec) break;
                if (!it->is_regular_file(stage_ec)) continue;
                std::string ext = it->path().extension().string();
                if (ext == ".modulemap" || ext == ".h") {
                    fs::remove(mod_sub / it->path().filename(), stage_ec);
                    stage_ec.clear();
                    fs::remove(products_root / it->path().filename(), stage_ec);
                    stage_ec.clear();
                    if (effective_product_name != spec.module_name) {
                        fs::remove(
                            products_root / effective_product_name / it->path().filename(),
                            stage_ec);
                        stage_ec.clear();
                    }
                    if (effective_target_name != spec.module_name && effective_target_name != effective_product_name) {
                        fs::remove(
                            products_root / effective_target_name / it->path().filename(),
                            stage_ec);
                        stage_ec.clear();
                    }
                }
            }
        }

        if (!RunShellScriptPhases(shell_spec, true, object_dir)) {
            return result;
        }
        {
            std::string cd_error;
            if (!CoreDataCompiler::CompileUncompiledInBundle(framework_dir, cd_error)) {
                std::cerr << "OPENFRUIT AppBuilder: in-bundle Core Data compilation failed: "
                          << cd_error << std::endl;
                return result;
            }
        }
        result.success = true;
        return result;
    }

    std::vector<fs::path> target_runtime_directories;
    IosTargetRuntimeResult target_runtime;
    const auto requests_swift_library = [](const std::wstring& argument) {
        return argument.starts_with(L"-lswift") || argument.starts_with(L"libswift");
    };
    if (!sources.empty() || package_info.contains_swift_sources ||
        !package_info.package_archive_path.empty() ||
        std::any_of(spec.linker_flags.begin(), spec.linker_flags.end(), requests_swift_library) ||
        std::any_of(spec.link_libraries.begin(), spec.link_libraries.end(), requests_swift_library)) {
        target_runtime = EnsureIosTargetRuntime(fs::path(sdk_info.sdk_path),
            ToolPaths::LlvmBin(root), Win32Process::ToNarrow(sdk_info.deployment_version),
            ToolPaths::LocalHome());
        target_runtime_directories = target_runtime.library_directories;
        if (!target_runtime.available)
            std::cerr << "OPENFRUIT: iOS target runtime provider unavailable: "
                      << target_runtime.error << std::endl;
    }

    // 3. Genuine LLVM availability runtime. Swift compatibility providers must
    // come from the selected Apple target runtime archives and object autolink.
    std::wstring version_object;

    if (!CompileAvailabilityRuntime(
        repo_root,
        sdk_info,
        version_object
    )) {
        std::cerr << "OPENFRUIT: required iOS availability runtime could not be prepared."
                  << std::endl;
        return result;
    }

    // 4. Link Mach-O executable.
    fs::path linker = ToolPaths::LlvmBin(root) / "ld64.lld.exe";

    if (!fs::exists(linker)) {
        linker = ToolPaths::SwiftBin(root) / "ld64.lld.exe";
    }

    if (!fs::exists(linker)) {
        std::cerr << "OPENFRUIT AppBuilder: ld64.lld not found." << std::endl;
        return result;
    }

    std::wstring deployment_version =
        spec.deployment_version.empty()
            ? sdk_info.deployment_version
            : spec.deployment_version;

    if (deployment_version.empty()) {
        deployment_version = L"18.0";
    }

    const std::wstring platform_sdk_version =
        DetectSDKPlatformVersion(sdk_info);

    // The linker writes an intermediate product; the bundle receives a copy,
    // because signing rewrites the bundle's executable in place.
    const fs::path linked_output = object_dir / (fs::path(result.executable_path).filename().wstring() + L".linked");
    const fs::path link_dependency_info = object_dir / "link_dependency_info.dat";
    const fs::path link_stamp = object_dir / "link.stamp";
    std::vector<std::wstring> link_args = {
        linker.wstring(),
        L"-arch", L"arm64",
        L"-platform_version", L"ios", deployment_version, platform_sdk_version,
        L"-syslibroot", sdk_info.sdk_path,
        L"-o", linked_output.wstring(),
        L"-dependency_info", link_dependency_info.wstring(),
        L"-L", (fs::path(sdk_info.linker_overlay_path) / "usr" / "lib").wstring(),
        L"-L", (fs::path(sdk_info.linker_overlay_path) / "usr" / "lib" / "swift").wstring(),
        L"-L", (fs::path(sdk_info.sdk_path) / "usr" / "lib").wstring(),
        L"-L", (fs::path(sdk_info.sdk_path) / "usr" / "lib" / "swift").wstring(),
        L"-F", system_frameworks.wstring()
    };

    for (const auto& runtime_directory : target_runtime_directories) {
        link_args.push_back(L"-L");
        link_args.push_back(runtime_directory.wstring());
    }

    if (is_framework) {
        const std::wstring framework_product_name =
            spec.product_name.empty() ? spec.app_name : spec.product_name;
        link_args.push_back(L"-dylib");
        link_args.push_back(L"-install_name");
        link_args.push_back(
            L"@rpath/" + framework_product_name + L".framework/" +
            framework_product_name
        );
    } else {
        link_args.push_back(L"-e");
        if (is_extension) {
            bool has_main_entry = false;
            for (const auto& s : sources) {
                fs::path p(s);
                std::string fname = p.filename().string();
                if (fname == "main.swift" || fname == "main.m" || fname == "main.c" || fname == "main.cpp") {
                    has_main_entry = true;
                    break;
                }
                std::ifstream ifs(p);
                std::string line;
                while (std::getline(ifs, line)) {
                    if (line.find("@main") != std::string::npos) {
                        has_main_entry = true;
                        break;
                    }
                }
                if (has_main_entry) break;
            }
            if (has_main_entry) {
                link_args.push_back(L"_main");
            } else {
                link_args.push_back(L"_NSExtensionMain");
            }
            link_args.push_back(L"-application_extension");
        } else {
            link_args.push_back(L"_main");
        }
        link_args.push_back(L"-dead_strip");
    }

    link_args.push_back(L"-rpath");
    link_args.push_back(L"@executable_path/Frameworks");
    link_args.push_back(L"-rpath");
    link_args.push_back(L"@loader_path/Frameworks");
    if (is_extension) {
        link_args.push_back(L"-rpath");
        link_args.push_back(L"@executable_path/../../Frameworks");
    }
    link_args.push_back(L"-rpath");
    link_args.push_back(L"/usr/lib/swift");
    link_args.push_back(L"-adhoc_codesign");
    link_args.push_back(L"-ObjC");

    const fs::path system_subframeworks =
        fs::path(sdk_info.sdk_path) /
        "System" /
        "Library" /
        "SubFrameworks";

    if (fs::exists(system_subframeworks)) {
        link_args.push_back(L"-F");
        link_args.push_back(system_subframeworks.wstring());
    }

    if (!sdk_info.cryptex_frameworks_path.empty() &&
        fs::exists(sdk_info.cryptex_frameworks_path)) {
        link_args.push_back(L"-F");
        link_args.push_back(sdk_info.cryptex_frameworks_path);
    }

    const fs::path cryptex_subframeworks =
        fs::path(sdk_info.sdk_path) /
        "System" /
        "Cryptexes" /
        "OS" /
        "System" /
        "Library" /
        "SubFrameworks";

    if (fs::exists(cryptex_subframeworks)) {
        link_args.push_back(L"-F");
        link_args.push_back(cryptex_subframeworks.wstring());
    }

    /*
     * Link frameworks derived from PBXFrameworksBuildPhase, project configuration,
     * embedded/system frameworks, and package dependencies.
     * Compiler and linker autolinking handles transitive and imported framework links.
     */
    std::vector<std::wstring> linked_frameworks;
    for (const auto& framework : spec.frameworks) {
        AddUnique(linked_frameworks, framework);
    }
    for (const auto& framework : package_info.linked_frameworks) {
        const fs::path path(framework);
        if (path.extension() == ".framework") {
            AddUnique(linked_frameworks, path.stem().wstring());
        }
    }

    for (const auto& framework : linked_frameworks) {
        link_args.push_back(L"-framework");
        link_args.push_back(framework);
    }

    for (const auto& framework_path : framework_search_paths) {
        if (fs::exists(framework_path)) {
            link_args.push_back(L"-F");
            link_args.push_back(framework_path);
        }
    }

    if (fs::exists(products_root)) {
        link_args.push_back(L"-L");
        link_args.push_back(products_root.wstring());
    }

    for (const auto& lib_dir : spec.library_search_paths) {
        if (fs::exists(lib_dir)) {
            link_args.push_back(L"-L");
            link_args.push_back(lib_dir);
        }
    }

    link_args.push_back(L"-lSystem");
    link_args.push_back(L"-lobjc");
    link_args.push_back(L"-lc++");
    link_args.push_back(L"-lz");
    link_args.push_back(L"-lsqlite3");
    link_args.push_back(L"-lbz2");
    link_args.push_back(L"-liconv");
    link_args.push_back(L"-lresolv");
    link_args.push_back(L"-lxml2");

    // Swift objects of the target.
    for (const auto& object : swift_objects) {
        if (fs::exists(object)) link_args.push_back(object);
    }

    for (const auto& native_object : native_objects) {
        if (fs::exists(native_object)) link_args.push_back(native_object);
    }

    if (package_info.package_archive_path.empty() ||
        !fs::exists(package_info.package_archive_path)) {
        for (const auto& extra_obj : package_info.extra_link_objects) {
            if (fs::exists(extra_obj)) link_args.push_back(extra_obj);
        }
    }

    const auto archive_link_inputs =
        ResolveArchiveLinkInputs(spec, products_root.wstring(), package_info);
    link_args.insert(
        link_args.end(),
        archive_link_inputs.begin(),
        archive_link_inputs.end()
    );

    // Dynamic SwiftPM products are listed by the official product link plan
    // but cannot be members of the aggregate static archive.
    for (const auto& dynamic_library : package_info.dynamic_libraries) {
        if (fs::exists(dynamic_library)) {
            link_args.push_back(dynamic_library);
        }
    }

    // Runtime markers.
    if (!version_object.empty() && fs::exists(version_object)) {
        link_args.push_back(version_object);
    }

    // Preview builds only: the application (never an extension or framework)
    // carries the OPENFRUIT preview agent.
    if (spec.preview_agent && is_app) {
        fs::path clang = ToolPaths::SwiftBin(fs::path(repo_root)) / "clang.exe";
        if (!fs::exists(clang)) clang = ToolPaths::LlvmBin(fs::path(repo_root)) / "clang.exe";
        const auto agent = EnsurePreviewAgentObject(fs::path(repo_root), clang, sdk_info);
        if (agent.empty()) {
            std::cerr << "OPENFRUIT AppBuilder: preview agent unavailable." << std::endl;
            return result;
        }
        link_args.push_back(agent.wstring());
        for (const auto& framework : PreviewAgentFrameworks()) {
            link_args.push_back(L"-framework");
            link_args.push_back(framework);
        }
    }

    std::unordered_set<std::string> linked_lib_names;
    for (const auto& arg : link_args) {
        fs::path p(arg);
        if (p.extension() == ".a") {
            std::string stem = ToLowerAscii(p.stem().string());
            if (stem.starts_with("lib")) {
                linked_lib_names.insert(stem.substr(3));
            }
            linked_lib_names.insert(stem);
        }
    }

    // Project-specific linker flags last, filtering out duplicate -l<name> if already explicitly linked.
    for (const auto& flag : spec.linker_flags) {
        if (flag.rfind(L"-l", 0) == 0 && flag.size() > 2) {
            std::string lib_name = ToLowerAscii(Win32Process::ToNarrow(flag.substr(2)));
            if (linked_lib_names.contains(lib_name)) {
                continue;
            }
        }
        link_args.push_back(flag);
    }

    const fs::path link_response = object_dir / "link.resp";

    if (!WriteResponseFile(link_response, link_args, 1, true)) {
        std::cerr
            << "OPENFRUIT AppBuilder: failed to write linker response file."
            << std::endl;
        return result;
    }

    const std::vector<std::wstring> run_link_args = {
        linker.wstring(),
        L"@" + link_response.wstring()
    };

    std::cout
        << "OPENFRUIT AppBuilder: Preparing Mach-O linking with ld64.lld..."
        << std::endl;
    std::cout
        << "OPENFRUIT AppBuilder: Linker: " << linker.string() << std::endl;
    std::cout
        << "OPENFRUIT AppBuilder: Target platform: ios "
        << Win32Process::ToNarrow(deployment_version)
        << " (platform SDK " << Win32Process::ToNarrow(platform_sdk_version) << ")"
        << std::endl;
    std::cout
        << "OPENFRUIT AppBuilder: Output executable: "
        << Win32Process::ToNarrow(result.executable_path)
        << std::endl;
    std::cout
        << "OPENFRUIT AppBuilder: Linking " << linked_frameworks.size() << " framework(s): ";
    for (std::size_t i = 0; i < linked_frameworks.size(); ++i) {
        std::cout << Win32Process::ToNarrow(linked_frameworks[i])
                  << (i + 1 < linked_frameworks.size() ? ", " : "\n");
    }

    if (!package_info.package_archive_path.empty() &&
        fs::exists(package_info.package_archive_path)) {
        std::cout
            << "OPENFRUIT AppBuilder: Linking package archive: "
            << Win32Process::ToNarrow(package_info.package_archive_path)
            << " (" << fs::file_size(package_info.package_archive_path) << " bytes)"
            << std::endl;
    }

    for (const auto& static_lib : package_info.static_libraries) {
        const fs::path sp(static_lib);
        const std::string fn = sp.filename().string();
        if (fn.starts_with("._") || fn.starts_with(".")) continue;
        if (fs::exists(sp)) {
            std::cout
                << "OPENFRUIT AppBuilder: Linking package static library: "
                << Win32Process::ToNarrow(sp.wstring())
                << " (" << fs::file_size(sp) << " bytes)"
                << std::endl;
        }
    }

    const auto link_start = std::chrono::steady_clock::now();
    std::string link_identity;
    {
        std::error_code identity_ec;
        const auto linker_time = fs::last_write_time(linker, identity_ec);
        const auto linker_size = identity_ec ? 0 : fs::file_size(linker, identity_ec);
        const auto command = ReadWholeFile(link_response);
        if (!identity_ec && !command.empty())
            link_identity = "link-stamp-v1\n" + Win32Process::ToNarrow(linker.wstring()) + "\n" +
                std::to_string(linker_size) + "\n" +
                std::to_string(linker_time.time_since_epoch().count()) + "\n" + command;
    }
    ProcessResult link_process;
    if (LinkOutputUpToDate(linked_output, link_dependency_info, link_stamp, link_identity)) {
        link_process.success = true;
        std::cout << "OPENFRUIT AppBuilder: Mach-O link is up to date; its linker was not started." << std::endl;
    } else {
        std::error_code stamp_ec;
        fs::remove(link_stamp, stamp_ec);
        std::cout
            << "OPENFRUIT AppBuilder: Invoking ld64.lld..."
            << std::endl;
        link_process =
            Win32Process::Run(
                linker.wstring(),
                run_link_args,
                L"",
                {},
                [](const std::string& out) {
                    std::cout << out << std::flush;
                },
                [](const std::string& err) {
                    std::cerr << err << std::flush;
                }
            );
        if (link_process.success && fs::is_regular_file(linked_output, stamp_ec) && !link_identity.empty()) {
            std::ofstream stamp(link_stamp, std::ios::binary | std::ios::trunc);
            stamp << link_identity;
        }
    }
    if (link_process.success) {
        if (!CopyFileW(linked_output.c_str(), fs::path(result.executable_path).c_str(), FALSE)) {
            std::cerr << "OPENFRUIT AppBuilder: cannot place the linked executable in the bundle (Win32 error "
                      << GetLastError() << ")." << std::endl;
            return result;
        }
    }

    if (!link_process.success || !fs::exists(result.executable_path)) {
        std::cerr
            << "OPENFRUIT AppBuilder: Linking failed (exit code "
            << link_process.exit_code << ") after "
            << FormatDuration(link_start) << "."
            << std::endl;
        if (!link_process.std_err.empty()) {
            std::cerr << link_process.std_err << std::endl;
        }
        return result;
    }

    std::cout
        << "OPENFRUIT AppBuilder: Mach-O executable linked successfully in "
        << FormatDuration(link_start)
        << " -> "
        << Win32Process::ToNarrow(result.executable_path)
        << " (" << fs::file_size(result.executable_path) << " bytes)"
        << std::endl;

    if (!package_info.package_archive_path.empty()) {
        const fs::path scratch = fs::path(package_info.package_archive_path).parent_path().parent_path().parent_path();
        if (fs::exists(scratch / "checkouts")) {
            std::error_code sp_ec;
            const fs::path build_root = fs::path(repo_root) / "build";
            const fs::path sp_build = build_root / "SourcePackages";
            const fs::path sp_products = products_root / "SourcePackages";
            if (!fs::exists(sp_build, sp_ec)) fs::create_directory_symlink(scratch, sp_build, sp_ec);
            sp_ec.clear();
            if (!fs::exists(sp_products, sp_ec)) fs::create_directory_symlink(scratch, sp_products, sp_ec);
        }
    }

    if (!RunShellScriptPhases(shell_spec, true, object_dir)) {
        return result;
    }
    {
        std::string cd_error;
        if (!CoreDataCompiler::CompileUncompiledInBundle(app_dir, cd_error)) {
            std::cerr << "OPENFRUIT AppBuilder: in-bundle Core Data compilation failed: "
                      << cd_error << std::endl;
            return result;
        }
    }
    if (is_extension || (!is_framework && !is_static_lib)) {
        std::string ib_error;
        if (!InterfaceBuilderCompiler::CompileUncompiledInBundle(app_dir, ib_error,
                Win32Process::ToNarrow(spec.module_name))) {
            std::cerr << "OPENFRUIT AppBuilder: in-bundle Interface Builder compilation failed: "
                      << ib_error << std::endl;
            return result;
        }
    }
    result.success = true;
    return result;
}

static bool BuildTargetDependenciesImpl(
    const std::wstring& repo_root,
    const DiscoveredProject& project,
    const SDKInfo& sdk_info,
    const std::wstring& configuration,
    unsigned int jobs,
    PackageBuildResult& pkg_res,
    bool execute_targets
) {
    const fs::path root(repo_root);
    const fs::path products_root =
        (project.build_products_root.empty() ? root / "build" / "Products" : project.build_products_root)
            / Win32Process::ToNarrow(configuration);
    auto fail = [](const std::string& reason) {
        std::cerr << "OPENFRUIT: Target dependency error: " << reason << std::endl;
        return false;
    };
    try {
    auto canonical_key = [](const fs::path& path) {
        const auto canonical = fs::canonical(path);
        const auto identity = [](const fs::path& entry) {
            HANDLE handle = CreateFileW(entry.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot identify target project.");
            BY_HANDLE_FILE_INFORMATION info{};
            const auto valid = GetFileInformationByHandle(handle, &info);
            CloseHandle(handle);
            if (!valid) throw std::runtime_error("Cannot inspect target project identity.");
            return std::to_wstring(info.dwVolumeSerialNumber) + L":" +
                std::to_wstring(info.nFileIndexHigh) + L":" + std::to_wstring(info.nFileIndexLow);
        };
        // Volume serials and file IDs are not global across cloned volumes or
        // remote shares. Scope them to the canonical drive or full UNC share.
        auto spelling = canonical.wstring();
        std::replace(spelling.begin(), spelling.end(), L'/', L'\\');
        auto prefix = spelling.substr(0, 8);
        std::transform(prefix.begin(), prefix.end(), prefix.begin(), [](wchar_t ch) {
            return ch >= L'A' && ch <= L'Z' ? static_cast<wchar_t>(ch + (L'a' - L'A')) : ch;
        });
        std::wstring root_namespace;
        if (prefix == LR"(\\?\unc\)") spelling = LR"(\\)" + spelling.substr(8);
        else if (spelling.starts_with(LR"(\\?\)")) {
            if (spelling.size() >= 7 && spelling[5] == L':' && spelling[6] == L'\\') spelling.erase(0, 4);
            else {
                // Preserve already-canonical volume GUID namespaces too.
                const auto volume_end = spelling.find(L'\\', 4);
                if (volume_end == std::wstring::npos || volume_end == 4)
                    throw std::runtime_error("Cannot identify target project volume namespace.");
                root_namespace = spelling.substr(0, volume_end);
            }
        }
        if (root_namespace.empty() && spelling.starts_with(LR"(\\)")) {
            const auto server_end = spelling.find(L'\\', 2);
            const auto share_end = server_end == std::wstring::npos ? server_end : spelling.find(L'\\', server_end + 1);
            if (server_end == std::wstring::npos || server_end == 2 ||
                server_end + 1 == spelling.size() || share_end == server_end + 1)
                throw std::runtime_error("Cannot identify target project UNC namespace.");
            root_namespace = spelling.substr(0, share_end);
        } else if (root_namespace.empty()) {
            root_namespace = fs::path(spelling).root_name().wstring();
            if (root_namespace.empty()) throw std::runtime_error("Cannot identify target project drive namespace.");
        }
        // Fold only the namespace, never case-sensitive path components. Alias
        // roots may conservatively remain distinct; different shares cannot merge.
        std::transform(root_namespace.begin(), root_namespace.end(), root_namespace.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        // Preserve distinct relative contexts even for hard-linked PBX files.
        return root_namespace + L"\n" + identity(canonical.parent_path()) + L"/" + identity(canonical);
    };
    struct PlannedTarget {
        XcodeProject project;
        XcodeTarget target;
        DiscoveredProject discovered;
    };
    BuildGraph graph;
    std::vector<PlannedTarget> planned;
    std::map<std::wstring, BuildNodeId> identities;
    std::vector<std::pair<BuildNodeId, BuildNodeId>> scheme_edges;
    const auto context_identity = L"\n" + configuration + L"\n" + sdk_info.target_triple;
    std::string resolution_error;
    const XcodeDependencyOptions dependency_options{!project.selection_frozen,
        project.build_implicit_dependencies.value_or(true), project.selection_frozen};

    // UUIDs are authoritative. Names are only a fallback for descriptors which
    // have no UUID, and must identify exactly one target in the selected scope.
    auto matching_targets = [](const XcodeProject& owner, const XcodeTargetDependency& dep) {
        std::vector<XcodeTarget> found;
        const auto name = ToLowerAscii(dep.target_name.empty() ? dep.name : dep.target_name);
        for (const auto& target : owner.Targets()) {
            if (!dep.target_id.empty() ? target.id == dep.target_id :
                    (!name.empty() && ToLowerAscii(target.name) == name)) found.push_back(target);
        }
        return found;
    };
    auto resolve = [&](const XcodeProject& owner, const XcodeTargetDependency& dep)
            -> std::optional<std::pair<XcodeProject, XcodeTarget>> {
        if (!dep.resolution_error.empty()) {
            resolution_error = dep.resolution_error;
            return std::nullopt;
        }
        const auto label = dep.target_name.empty() ? (dep.name.empty() ? dep.target_id : dep.name) : dep.target_name;
        if (dep.is_subproject && dep.project_path.empty()) {
            resolution_error = "missing project reference for '" + label + "'";
            return std::nullopt;
        }
        auto destination = owner.ProjectBundle();
        if (dep.is_subproject) destination = dep.project_path.is_absolute()
            ? dep.project_path : owner.SourceRoot() / dep.project_path;
        auto selected = XcodeProject::Load(destination, project.build_products_root);
        if (!selected) {
            resolution_error = "cannot load dependency project '" + destination.string() + "'";
            return std::nullopt;
        }
        auto matches = matching_targets(*selected, dep);
        if (matches.size() > 1) {
            resolution_error = "ambiguous target '" + label + "' in '" + destination.string() + "'";
            return std::nullopt;
        }
        if (matches.size() == 1) return std::make_pair(std::move(*selected), matches.front());

        // Only an unbound name may use the existing workspace search. A bound
        // project/UUID must never silently resolve to another same-name target.
        std::optional<std::pair<XcodeProject, XcodeTarget>> workspace_match;
        if (!dep.is_subproject && dep.target_id.empty()) {
            std::set<std::wstring> visited{canonical_key(selected->PbxprojPath())};
            for (const auto& path : owner.DiscoverWorkspaceProjects()) {
                auto other = XcodeProject::Load(path, project.build_products_root);
                if (!other || !visited.insert(canonical_key(other->PbxprojPath())).second) continue;
                for (const auto& target : matching_targets(*other, dep)) {
                    if (workspace_match) {
                        resolution_error = "ambiguous workspace target '" + label + "'";
                        return std::nullopt;
                    }
                    workspace_match = std::make_pair(*other, target);
                }
            }
        }
        if (!workspace_match) resolution_error = "target '" + label + "' (UUID '" + dep.target_id +
            "') not found in '" + destination.string() + "'";
        return workspace_match;
    };
    const auto root_path = project.pbxproj_path.empty() ? fs::path(project.project_dir) : fs::path(project.pbxproj_path);
    auto root_project = XcodeProject::Load(root_path, project.build_products_root);
    if (!root_project) return fail("cannot load root project '" + root_path.string() + "'");
    XcodeTargetDependency root_descriptor;
    root_descriptor.target_id = project.target_id;
    root_descriptor.target_name = Win32Process::ToNarrow(project.project_name);
    auto roots = matching_targets(*root_project, root_descriptor);
    if (roots.size() != 1) return fail("root target is missing or ambiguous");

    const auto root_target_key = canonical_key(root_project->PbxprojPath()) + L"\n" +
        Win32Process::ToWide(roots.front().id) + context_identity;
    XcodeDependencyOptions non_scheme_options = dependency_options;
    non_scheme_options.include_scheme = false;
    auto depends_on_root = [&](const XcodeProject& start_proj, const XcodeTarget& start_target) {
        const auto saved_error = resolution_error;
        std::vector<std::pair<XcodeProject, XcodeTarget>> stack{{start_proj, start_target}};
        std::set<std::wstring> visited{canonical_key(start_proj.PbxprojPath()) + L"\n" +
            Win32Process::ToWide(start_target.id) + context_identity};
        bool found_root = false;
        while (!stack.empty()) {
            const auto [cur_proj, cur_target] = std::move(stack.back());
            stack.pop_back();
            for (const auto& d : cur_proj.ResolveTargetDependencies(cur_target, non_scheme_options)) {
                if (d.scheme_entry || !d.resolution_error.empty()) continue;
                auto next = resolve(cur_proj, d);
                if (!next) continue;
                const auto next_key = canonical_key(next->first.PbxprojPath()) + L"\n" +
                    Win32Process::ToWide(next->second.id) + context_identity;
                if (next_key == root_target_key) {
                    found_root = true;
                    break;
                }
                if (visited.insert(next_key).second) {
                    stack.push_back(std::move(*next));
                }
            }
            if (found_root) break;
        }
        resolution_error = saved_error;
        return found_root;
    };

    std::function<std::optional<BuildNodeId>(const XcodeProject&, const XcodeTarget&)> visit;
    visit = [&](const XcodeProject& owner, const XcodeTarget& target) -> std::optional<BuildNodeId> {
        const auto identity = canonical_key(owner.PbxprojPath()) + L"\n" +
            Win32Process::ToWide(target.id) + context_identity;
        if (const auto found = identities.find(identity); found != identities.end()) return found->second;
        const auto id = graph.AddNode(owner.ProjectBundle().string() + "::" + target.name + " [" + target.id + "]");
        identities.emplace(identity, id);
        planned.push_back({owner, target, {}});
        // Register before descending so back-edges are retained for validation.
        const auto dependencies = project.selection_frozen && id == 0
            ? project.target_dependencies : owner.ResolveTargetDependencies(target, dependency_options);
        for (const auto& dep : dependencies) {
            // A scheme lists co-build entries, not dependencies of every target
            // reached from it. Only the selected root contributes its list.
            if (dep.scheme_entry && id != 0) continue;
            auto child = resolve(owner, dep);
            if (!child) return std::nullopt;
            if (dep.scheme_entry && depends_on_root(child->first, child->second)) continue;
            auto child_id = visit(child->first, child->second);
            if (!child_id) return std::nullopt;
            if (dep.scheme_entry && *child_id == id) continue;
            if (dep.scheme_entry) scheme_edges.emplace_back(id, *child_id);
            if (!graph.AddDependency(id, *child_id)) {
                resolution_error = "self dependency at '" + graph.Get(id)->name + "'";
                return std::nullopt;
            }
        }
        return id;
    };
    const auto root_id = visit(*root_project, roots.front());
    if (!root_id) return fail(resolution_error);
    const auto order = graph.TopologicalOrder();
    if (!order) {
        std::string cycle = "target dependency cycle:";
        for (const auto& component : graph.StronglyConnectedComponents()) {
            if (component.size() < 2) continue;
            for (const auto& [from, to] : scheme_edges) {
                if (std::find(component.begin(), component.end(), from) != component.end() &&
                    std::find(component.begin(), component.end(), to) != component.end())
                    return fail("unsupported scheme ordering: a co-build target requires the selected root first");
            }
            for (auto id : component) cycle += " " + graph.Get(id)->name;
        }
        return fail(cycle);
    }

    // Resolve every reachable target before executing any dependent build.
    for (auto id : *order) {
        if (id == *root_id) continue;
        auto& item = planned[id];
        std::string target_configuration = Win32Process::ToNarrow(configuration);
        if (project.selection_frozen) {
            std::string configuration_error;
            const auto canonical = item.project.ResolveConfigurationName(item.target,
                target_configuration, &configuration_error);
            if (!canonical) return fail(configuration_error);
            if (*canonical != target_configuration)
                return fail("dependency configuration spelling differs from the frozen build configuration: '" + *canonical + "'");
            target_configuration = *canonical;
        }
        item.discovered = UniversalProject::InspectTarget(item.project, item.target,
            target_configuration, dependency_options);
        if (item.target.kind == XcodeTargetKind::Legacy)
            return fail("unsupported PBXLegacyTarget external build tool: '" + graph.Get(id)->name + "'");
        if (!item.discovered.is_valid) return fail("cannot inspect dependency '" + graph.Get(id)->name +
            (item.target.kind == XcodeTargetKind::Aggregate ? "': aggregate phase is missing or unsupported" : "'"));
        std::string xcframework_error;
        if (!UniversalProject::ResolveXcframeworkSlices(item.discovered, sdk_info.target_triple, xcframework_error))
            return fail("XCFramework selection for '" + graph.Get(id)->name + "': " + xcframework_error);
    }
    if (!execute_targets) return true;
    if (!pkg_res.generated_source_lifetime)
        pkg_res.generated_source_lifetime = std::make_shared<GeneratedSourceLifetime>();
    for (const auto& lease : pkg_res.artifact_leases)
        pkg_res.generated_source_lifetime->Retain(lease);
    std::error_code ec;
    fs::create_directories(products_root, ec);
    if (ec) return fail("cannot create products directory: " + ec.message());
    NormalizeModuleMaps(products_root);
    NormalizeSwiftInterfaces(fs::path(repo_root));
    AddUnique(pkg_res.frameworks, products_root.wstring());
    AddUnique(pkg_res.module_include_dirs, products_root.wstring());
    for (auto id : *order) {
        if (id == *root_id) continue;
        const auto& item = planned[id];
        const auto& disc = item.discovered;

        AppBuildSpec spec = UniversalProject::ToAppBuildSpec(disc, jobs);
        if (project.selection_frozen)
            spec.intermediates_namespace = (project.build_products_root / "Intermediates").wstring();
        spec.configuration = project.selection_frozen ? disc.configuration : configuration;
        spec.jobs = jobs;
        spec.products_dir = products_root.wstring();
        AddUnique(spec.embedded_framework_dirs, products_root.wstring());
        AddUnique(spec.swift_include_paths, products_root.wstring());

        std::cout << "\n---------------------------------------------------------\n"
                  << "  OPENFRUIT: Building Target Dependency '" << item.target.name << "'\n"
                  << "  Product Type: " << disc.product_type << "\n"
                  << "---------------------------------------------------------" << std::endl;

        PackageBuildResult dep_pkg_res = pkg_res;
        AddUnique(dep_pkg_res.frameworks, products_root.wstring());
        AddUnique(dep_pkg_res.module_include_dirs, products_root.wstring());

        AppBuildResult res = AppBuilder::Build(repo_root, spec, sdk_info, dep_pkg_res);
        if (!res.success) {
            std::cerr << "OPENFRUIT: Target dependency build failed: " << item.target.name << std::endl;
            return false;
        }

        pkg_res.contains_swift_sources = pkg_res.contains_swift_sources || res.contains_swift_sources;

        if (spec.product_type == "com.apple.product-type.framework") {
            AddUnique(pkg_res.frameworks, products_root.wstring());
            AddUnique(pkg_res.linked_frameworks, res.product_path);
            pkg_res.signing_products.push_back(UniversalProject::ToSigningProduct(disc, res));
        } else if (spec.product_type == "com.apple.product-type.library.static") {
            if (!res.product_path.empty()) {
                AddUnique(pkg_res.static_libraries, res.product_path);
            }
        } else if (spec.product_type == "com.apple.product-type.bundle") {
            AddUnique(pkg_res.resource_bundles, res.product_path);
        } else if (spec.product_type.find("extension") != std::string::npos ||
                   spec.product_type == "com.apple.product-type.app-extension") {
            AddUnique(pkg_res.resource_bundles, res.product_path);
            pkg_res.signing_products.push_back(UniversalProject::ToSigningProduct(disc, res));
        }

        for (const auto& b : disc.resource_bundles) {
            AddUnique(pkg_res.resource_bundles, b);
        }

    }
    return true;
    } catch (const std::exception& failure) {
        return fail(failure.what());
    }
}

std::vector<std::wstring> AppBuilder::ResolveArchiveLinkInputs(
    const AppBuildSpec& spec,
    const std::wstring& products_dir,
    const PackageBuildResult& package_info
) {
    const bool is_framework =
        (spec.product_type == "com.apple.product-type.framework");
    const bool is_static_lib =
        (spec.product_type == "com.apple.product-type.library.static");
    const bool is_bundle =
        (spec.product_type == "com.apple.product-type.bundle");
    const bool is_extension =
        (spec.product_type.find("extension") != std::string::npos ||
         spec.product_type == "com.apple.product-type.app-extension");
    const bool is_app = !is_framework && !is_static_lib && !is_bundle && !is_extension;

    const fs::path products_root(products_dir);
    auto archive_identity = [](const fs::path& p) {
        std::error_code ec;
        const fs::path canonical = fs::weakly_canonical(p, ec);
        const fs::path norm = (!ec && !canonical.empty()) ? canonical.lexically_normal() : p.lexically_normal();
        return ToLowerAscii(Win32Process::ToNarrow(norm.wstring()));
    };

    std::vector<std::wstring> args;
    std::set<std::string> seen_archives;

    for (const auto& lib_name : spec.link_libraries) {
        if (lib_name.empty()) continue;
        fs::path direct_p(lib_name);
        fs::path resolved;
        if (direct_p.is_absolute() && fs::exists(direct_p)) {
            resolved = direct_p;
        } else {
            std::vector<fs::path> candidates = {
                products_root / lib_name,
                products_root / (L"lib" + lib_name),
                products_root / (lib_name + L".a"),
                products_root / (L"lib" + lib_name + L".a")
            };
            for (const auto& lib_dir : spec.library_search_paths) {
                candidates.push_back(fs::path(lib_dir) / lib_name);
                candidates.push_back(fs::path(lib_dir) / (L"lib" + lib_name));
                candidates.push_back(fs::path(lib_dir) / (lib_name + L".a"));
                candidates.push_back(fs::path(lib_dir) / (L"lib" + lib_name + L".a"));
            }
            for (const auto& candidate : candidates) {
                if (fs::exists(candidate)) {
                    resolved = candidate;
                    break;
                }
            }
            if (resolved.empty()) {
                const std::string base_lower = ToLowerAscii(Win32Process::ToNarrow(direct_p.filename().wstring()));
                const std::string lib_base_lower = "lib" + base_lower;
                const std::string base_a_lower = base_lower + ".a";
                const std::string lib_base_a_lower = lib_base_lower + ".a";
                for (const auto& static_library : package_info.static_libraries) {
                    const fs::path sp(static_library);
                    if (!fs::exists(sp)) continue;
                    const std::string fn_lower = ToLowerAscii(Win32Process::ToNarrow(sp.filename().wstring()));
                    if (fn_lower == base_lower || fn_lower == lib_base_lower ||
                        fn_lower == base_a_lower || fn_lower == lib_base_a_lower) {
                        resolved = sp;
                        break;
                    }
                }
            }
            if (resolved.empty()) {
                resolved = products_root / lib_name;
            }
        }
        if (seen_archives.insert(archive_identity(resolved)).second) {
            args.push_back(resolved.wstring());
        }
    }

    // Unified iOS SwiftPM archive.
    if (!package_info.package_archive_path.empty() &&
        fs::exists(package_info.package_archive_path)) {
        const fs::path pkg_archive(package_info.package_archive_path);
        seen_archives.insert(archive_identity(pkg_archive));
        if (is_app) {
            /*
             * The aggregate contains many independent SwiftPM static targets.
             * Like Xcode's -all_load/-force_load handling for package products,
             * load every member for the host application so archive index
             * ordering cannot discard Swift extensions or Objective-C categories
             * referenced indirectly. Non-app targets (.framework, .appex) link
             * the archive without -force_load so only referenced members are
             * pulled into the target binary.
             */
            args.push_back(L"-force_load");
        }
        args.push_back(package_info.package_archive_path);
    }

    // Static binary libraries required by packages or child static targets.
    for (const auto& static_library : package_info.static_libraries) {
        const fs::path sp(static_library);
        const std::string fn = sp.filename().string();
        if (fn.starts_with("._") || fn.starts_with(".")) continue;
        if (fs::exists(sp) && seen_archives.insert(archive_identity(sp)).second) {
            args.push_back(sp.wstring());
        }
    }

    return args;
}

bool AppBuilder::ValidateTargetDependencies(const DiscoveredProject& project,
    const SDKInfo& sdk_info, const std::wstring& configuration) {
    PackageBuildResult unused;
    return BuildTargetDependenciesImpl(L"", project, sdk_info, configuration, 0, unused, false);
}

bool AppBuilder::BuildTargetDependencies(const std::wstring& repo_root,
    const DiscoveredProject& project, const SDKInfo& sdk_info,
    const std::wstring& configuration, unsigned int jobs, PackageBuildResult& pkg_res) {
    return BuildTargetDependenciesImpl(repo_root, project, sdk_info, configuration, jobs, pkg_res, true);
}

} // namespace OpenFruit
