#include "universal_project.hpp"
#include "xcframework_resolver.hpp"

#include "win32_process.hpp"
#include "xcode_project.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

std::wstring GetSetting(
    const std::unordered_map<
        std::string,
        std::string
    >& settings,
    const std::string& key
) {
    const auto it =
        settings.find(key);

    if (it == settings.end()) {
        return {};
    }

    return Win32Process::ToWide(
        it->second
    );
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

} // namespace

static bool IsBundleOrExcludedDir(const fs::path& dir_path) {
    const auto ext = dir_path.extension().wstring();
    if (ext == L".framework" || ext == L".xcframework" ||
        ext == L".bundle" || ext == L".app" ||
        ext == L".appex" || ext == L".dSYM") {
        return true;
    }
    const auto filename = dir_path.filename().wstring();
    if (!filename.empty() && filename.front() == L'.') {
        return true;
    }
    return false;
}

std::vector<std::wstring> ParseSearchPathsSetting(
    const std::wstring& raw,
    const fs::path& base_dir
) {
    std::vector<std::wstring> paths;
    if (raw.empty()) {
        return paths;
    }

    std::wstring current;
    bool in_quote = false;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        wchar_t c = raw[i];
        if (c == L'"') {
            in_quote = !in_quote;
        } else if ((c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') && !in_quote) {
            if (!current.empty()) {
                if (current != L"$(inherited)" && current != L"${inherited}") {
                    paths.push_back(current);
                }
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty() && current != L"$(inherited)" && current != L"${inherited}") {
        paths.push_back(current);
    }

    std::vector<std::wstring> resolved;
    for (const auto& item : paths) {
        bool is_recursive = false;
        std::wstring clean_item = item;
        if (clean_item.size() >= 3 &&
            (clean_item.substr(clean_item.size() - 3) == L"/**" ||
             clean_item.substr(clean_item.size() - 3) == L"\\**")) {
            is_recursive = true;
            clean_item = clean_item.substr(0, clean_item.size() - 3);
        } else if (clean_item.size() >= 2 &&
                   (clean_item.substr(clean_item.size() - 2) == L"/*" ||
                    clean_item.substr(clean_item.size() - 2) == L"\\*")) {
            is_recursive = true;
            clean_item = clean_item.substr(0, clean_item.size() - 2);
        }

        fs::path p(clean_item);
        if (!p.is_absolute() && !base_dir.empty()) {
            p = base_dir / p;
        }
        std::error_code ec;
        std::string p_str = p.string();
        if (p_str.find("build") != std::string::npos ||
            p_str.find("Products") != std::string::npos ||
            p_str.find("DerivedSources") != std::string::npos) {
            const auto norm = p.lexically_normal().wstring();
            if (std::find(resolved.begin(), resolved.end(), norm) == resolved.end()) {
                resolved.push_back(norm);
            }
        } else if (fs::exists(p, ec)) {
            const auto norm = p.lexically_normal().wstring();
            if (std::find(resolved.begin(), resolved.end(), norm) == resolved.end()) {
                resolved.push_back(norm);
            }
            if (is_recursive && fs::is_directory(p, ec)) {
                std::vector<std::wstring> subdirs;
                for (fs::recursive_directory_iterator it(p, fs::directory_options::skip_permission_denied, ec), end;
                     !ec && it != end; it.increment(ec)) {
                    if (ec) {
                        ec.clear();
                        break;
                    }
                    if (it->is_directory(ec)) {
                        if (IsBundleOrExcludedDir(it->path())) {
                            it.disable_recursion_pending();
                        } else {
                            subdirs.push_back(it->path().lexically_normal().wstring());
                        }
                    }
                }
                std::sort(subdirs.begin(), subdirs.end());
                for (const auto& sub : subdirs) {
                    if (std::find(resolved.begin(), resolved.end(), sub) == resolved.end()) {
                        resolved.push_back(sub);
                    }
                }
            }
        }
    }
    return resolved;
}

namespace {

std::vector<std::wstring> TokenizeFlags(const std::wstring& raw) {
    std::vector<std::wstring> tokens;
    if (raw.empty()) {
        return tokens;
    }

    std::wstring current;
    bool in_single_quote = false;
    bool in_double_quote = false;
    std::size_t i = 0;

    while (i < raw.size()) {
        const wchar_t c = raw[i];
        if (in_single_quote) {
            if (c == L'\'') {
                in_single_quote = false;
            } else {
                current.push_back(c);
            }
            ++i;
        } else if (in_double_quote) {
            if (c == L'\"') {
                in_double_quote = false;
                ++i;
            } else if (c == L'\\' && i + 1 < raw.size()) {
                const wchar_t next = raw[i + 1];
                if (next == L'\"' || next == L'\\' || next == L'$' || next == L'`') {
                    current.push_back(next);
                    i += 2;
                } else {
                    current.push_back(c);
                    ++i;
                }
            } else {
                current.push_back(c);
                ++i;
            }
        } else {
            if (c == L'\\' && i + 1 < raw.size()) {
                const wchar_t next = raw[i + 1];
                if (next == L'\"' || next == L'\'' || next == L'\\' ||
                    next == L' ' || next == L'\t' || next == L'$') {
                    current.push_back(next);
                    i += 2;
                } else {
                    current.push_back(c);
                    ++i;
                }
            } else if (c == L'\'') {
                in_single_quote = true;
                ++i;
            } else if (c == L'\"') {
                in_double_quote = true;
                ++i;
            } else if (std::iswspace(c)) {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
                ++i;
            } else {
                current.push_back(c);
                ++i;
            }
        }
    }

    if (!current.empty()) {
        tokens.push_back(current);
    }

    return tokens;
}

bool ParseBool(
    std::string value,
    bool fallback
) {
    value = ToLowerAscii(value);

    if (value == "yes" ||
        value == "true" ||
        value == "1") {
        return true;
    }

    if (value == "no" ||
        value == "false" ||
        value == "0") {
        return false;
    }

    return fallback;
}

std::wstring NormalizeSwiftLanguageMode(
    const std::wstring& value
) {
    if (value.empty()) {
        return L"5";
    }

    try {
        const std::size_t dot =
            value.find(L'.');

        const int major =
            std::stoi(
                dot == std::wstring::npos
                    ? value
                    : value.substr(0, dot)
            );

        int minor = 0;

        if (dot != std::wstring::npos) {
            const std::size_t next =
                value.find(
                    L'.',
                    dot + 1
                );

            const std::wstring part =
                value.substr(
                    dot + 1,
                    next == std::wstring::npos
                        ? std::wstring::npos
                        : next - dot - 1
                );

            if (!part.empty()) {
                minor = std::stoi(part);
            }
        }

        if (major >= 6) {
            return L"6";
        }

        if (major == 5) {
            return L"5";
        }

        if (major == 4) {
            return minor >= 2
                ? L"4.2"
                : L"4";
        }
    } catch (...) {
    }

    return L"5";
}

std::wstring XcodeModuleIdentifier(const std::wstring& value) {
    std::wstring result;
    result.reserve(value.size() + 1);

    for (const wchar_t c : value) {
        const bool ascii_letter =
            (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z');
        const bool ascii_digit = c >= L'0' && c <= L'9';
        result.push_back(
            ascii_letter || ascii_digit || c == L'_'
                ? c
                : L'_'
        );
    }

    if (result.empty()) result = L"_";
    if (result.front() >= L'0' && result.front() <= L'9') {
        result.insert(result.begin(), L'_');
    }
    return result;
}

bool UsesTypedAssetSymbols(
    const std::vector<std::wstring>& sources
) {
    const std::regex image_resource(
        R"(\bImageResource\b)"
    );

    const std::regex color_resource(
        R"(\bColorResource\b)"
    );

    const std::regex image_literal(
        R"(\bImage\s*\(\s*\.[A-Za-z_])"
    );

    const std::regex color_literal(
        R"(\bColor\s*\(\s*\.[A-Za-z_])"
    );

    for (const auto& value :
         sources) {

        const std::string source =
            ReadFileText(fs::path(value));

        if (source.empty()) {
            continue;
        }

        if (std::regex_search(
                source,
                image_resource) ||
            std::regex_search(
                source,
                color_resource) ||
            std::regex_search(
                source,
                image_literal) ||
            std::regex_search(
                source,
                color_literal)) {
            return true;
        }
    }

    return false;
}

void AddFrameworkSearchPath(
    DiscoveredProject& project,
    const fs::path& path
) {
    if (path.empty()) {
        return;
    }

    const std::wstring value =
        path.lexically_normal()
            .wstring();

    if (std::find(
            project.embedded_framework_dirs.begin(),
            project.embedded_framework_dirs.end(),
            value) ==
        project.embedded_framework_dirs.end()) {

        project.embedded_framework_dirs
            .push_back(value);
    }
}

void DiscoverCarthageFrameworks(
    const fs::path& source_root,
    DiscoveredProject& project
) {
    const fs::path carthage =
        source_root /
        "Carthage" /
        "Build";

    if (!fs::exists(carthage)) {
        return;
    }

    std::error_code ec;

    for (fs::recursive_directory_iterator it(
             carthage,
             fs::directory_options::
                 skip_permission_denied,
             ec);
         it !=
             fs::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) {
            ec.clear();
            continue;
        }

        if (!it->is_directory(ec) ||
            ToLowerAscii(
                it->path()
                    .extension()
                    .string()) !=
                ".framework") {
            continue;
        }

        const std::string lower =
            ToLowerAscii(
                it->path()
                    .string()
            );

        if (lower.find("simulator") !=
                std::string::npos ||
            lower.find("maccatalyst") !=
                std::string::npos ||
            lower.find("tvos") !=
                std::string::npos ||
            lower.find("watchos") !=
                std::string::npos ||
            lower.find("visionos") !=
                std::string::npos ||
            lower.find("macos") !=
                std::string::npos) {
            it.disable_recursion_pending();
            continue;
        }

        project.embedded_frameworks
            .push_back(
                it->path()
                    .wstring()
            );

        AddFrameworkSearchPath(
            project,
            it->path()
                .parent_path()
        );

        it.disable_recursion_pending();
    }
}

std::wstring FindIcon(
    const std::vector<std::wstring>& catalogs,
    const std::wstring& preferred_icon_name = L""
) {
    std::wstring best_path;
    int best_score = -10000;

    const std::string preferred_narrow =
        ToLowerAscii(Win32Process::ToNarrow(preferred_icon_name));

    for (const auto& catalog_value : catalogs) {
        const fs::path catalog(catalog_value);
        if (!fs::exists(catalog)) {
            continue;
        }

        std::error_code ec;
        for (fs::recursive_directory_iterator it(
                 catalog,
                 fs::directory_options::skip_permission_denied,
                 ec);
             it != fs::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                ec.clear();
                continue;
            }

            if (!it->is_regular_file(ec) ||
                ToLowerAscii(it->path().extension().string()) != ".png") {
                continue;
            }

            const std::string full_path = ToLowerAscii(it->path().string());
            const std::string filename = ToLowerAscii(it->path().filename().string());

            int score = 0;

            if (!preferred_narrow.empty()) {
                if (full_path.find(preferred_narrow + ".appiconset") != std::string::npos) {
                    score += 500;
                } else if (full_path.find(preferred_narrow) != std::string::npos) {
                    score += 200;
                }
            }

            if (full_path.find(".appiconset") != std::string::npos) {
                score += 100;
            }

            if (filename.find("primary") != std::string::npos ||
                full_path.find("primary") != std::string::npos) {
                score += 50;
            }

            if (filename.find("1024") != std::string::npos ||
                full_path.find("1024") != std::string::npos) {
                score += 40;
            }

            if (filename.find("appicon") != std::string::npos) {
                score += 30;
            }

            if (filename.find("dark") != std::string::npos ||
                full_path.find("dark") != std::string::npos ||
                filename.find("inverted") != std::string::npos ||
                full_path.find("inverted") != std::string::npos ||
                filename.find("tinted") != std::string::npos) {
                score -= 60;
            }

            if (score > best_score) {
                best_score = score;
                best_path = it->path().wstring();
            }
        }
    }

    return best_path;
}

} // namespace

DiscoveredProject
UniversalProject::InspectTarget(
    const XcodeProject& project,
    const XcodeTarget& target,
    const std::string& configuration,
    const XcodeDependencyOptions& options
) {
    DiscoveredProject result;
    result.build_products_root = project.BuildProductsRoot();
    const auto resolved =
        project.ResolveTarget(
            target,
            configuration,
            options
        );

    if (!resolved) {
        return result;
    }

    result.target_kind = target.kind;
    result.product_type = target.product_type;
    result.target_id = target.id;
    result.target_dependencies = resolved->target_dependencies;
    result.shell_script_phases = resolved->shell_script_phases;
    for (const auto& [key, value] : resolved->build_settings) {
        result.build_settings.emplace_back(
            Win32Process::ToWide(key),
            Win32Process::ToWide(value)
        );
    }
    for (const auto& h : resolved->headers) {
        result.public_headers.push_back(h.wstring());
    }
    for (const auto& h : resolved->project_headers) {
        result.project_headers.push_back(h.wstring());
    }

    const auto& settings =
        resolved->build_settings;

    result.project_name =
        Win32Process::ToWide(
            target.name
        );

    result.product_name =
        GetSetting(
            settings,
            "PRODUCT_NAME"
        );
    if (result.product_name.empty() ||
        result.product_name.find(L"$(") != std::wstring::npos ||
        result.product_name.find(L"${") != std::wstring::npos) {
        result.product_name =
            Win32Process::ToWide(
                target.product_name
            );
    }
    if (result.product_name.empty() ||
        result.product_name.find(L"$(") != std::wstring::npos ||
        result.product_name.find(L"${") != std::wstring::npos) {
        result.product_name = result.project_name;
    }

    result.module_name =
        GetSetting(
            settings,
            "PRODUCT_MODULE_NAME"
        );
    if (result.module_name.empty() ||
        result.module_name.find(L"$(") != std::wstring::npos ||
        result.module_name.find(L"${") != std::wstring::npos) {
        result.module_name =
            XcodeModuleIdentifier(result.product_name);
    }

    result.project_dir =
        project.SourceRoot()
            .wstring();

    result.pbxproj_path =
        project.PbxprojPath()
            .wstring();

    const auto entitlements = GetSetting(settings, "CODE_SIGN_ENTITLEMENTS");
    if (!entitlements.empty()) {
        fs::path path(entitlements);
        if (!path.is_absolute()) path = project.SourceRoot() / path;
        // Preserve missing/unresolved paths: signing must report them, not
        // silently discard the project's requested capabilities.
        result.code_sign_entitlements_path = path.lexically_normal().wstring();
    }

    result.bundle_id =
        GetSetting(
            settings,
            "PRODUCT_BUNDLE_IDENTIFIER"
        );

    result.display_name =
        GetSetting(
            settings,
            "INFOPLIST_KEY_CFBundleDisplayName"
        );
    if (result.display_name.empty() ||
        result.display_name.find(L"$(") != std::wstring::npos ||
        result.display_name.find(L"${") != std::wstring::npos) {
        result.display_name =
            GetSetting(
                settings,
                "CFBundleDisplayName"
            );
    }
    if (result.display_name.empty() ||
        result.display_name.find(L"$(") != std::wstring::npos ||
        result.display_name.find(L"${") != std::wstring::npos) {
        result.display_name =
            result.product_name.empty()
                ? result.project_name
                : result.product_name;
    }

    result.minimum_os_version =
        GetSetting(
            settings,
            "IPHONEOS_DEPLOYMENT_TARGET"
        );

    result.sdk_root = GetSetting(settings, "SDKROOT");

    result.swift_version =
        GetSetting(
            settings,
            "SWIFT_VERSION"
        );

    result.default_actor_isolation =
        GetSetting(
            settings,
            "SWIFT_DEFAULT_ACTOR_ISOLATION"
        );

    result.strict_concurrency =
        GetSetting(
            settings,
            "SWIFT_STRICT_CONCURRENCY"
        );

    result.marketing_version =
        GetSetting(
            settings,
            "MARKETING_VERSION"
        );

    result.current_project_version =
        GetSetting(
            settings,
            "CURRENT_PROJECT_VERSION"
        );

    result.configuration =
        Win32Process::ToWide(configuration);

    const std::wstring conditions_raw =
        GetSetting(
            settings,
            "SWIFT_ACTIVE_COMPILATION_CONDITIONS"
        );
    if (!conditions_raw.empty()) {
        for (const auto& token : TokenizeFlags(conditions_raw)) {
            if (token == L"$(inherited)" || token == L"${inherited}") continue;
            AddUnique(result.swift_active_compilation_conditions, token);
        }
    }

    const std::wstring swift_flags_raw = GetSetting(settings, "OTHER_SWIFT_FLAGS");
    if (!swift_flags_raw.empty()) {
        for (const auto& token : TokenizeFlags(swift_flags_raw)) {
            if (token == L"$(inherited)" || token == L"${inherited}") continue;
            result.swift_flags.push_back(token);
        }
    }

    std::vector<std::wstring> c_extra_flags;
    const std::wstring cflags = GetSetting(settings, "OTHER_CFLAGS");
    if (!cflags.empty()) {
        for (const auto& token : TokenizeFlags(cflags)) {
            if (token == L"$(inherited)" || token == L"${inherited}") continue;
            c_extra_flags.push_back(token);
        }
    }

    std::vector<std::wstring> cxx_extra_flags;
    const std::wstring cxxflags = GetSetting(settings, "OTHER_CPLUSPLUSFLAGS");
    if (!cxxflags.empty()) {
        for (const auto& token : TokenizeFlags(cxxflags)) {
            if (token == L"$(inherited)" || token == L"${inherited}") continue;
            if (token == L"$(OTHER_CFLAGS)" || token == L"${OTHER_CFLAGS}") {
                for (const auto& f : c_extra_flags) {
                    cxx_extra_flags.push_back(f);
                }
                continue;
            }
            cxx_extra_flags.push_back(token);
        }
    } else {
        // In Xcode, OTHER_CPLUSPLUSFLAGS defaults to $(OTHER_CFLAGS)
        cxx_extra_flags = c_extra_flags;
    }

    const std::wstring c_standard = GetSetting(settings, "GCC_C_LANGUAGE_STANDARD");
    if (!c_standard.empty()) {
        result.c_flags.push_back(L"-std=" + c_standard);
    }

    const std::wstring cxx_standard = GetSetting(settings, "CLANG_CXX_LANGUAGE_STANDARD");
    if (!cxx_standard.empty()) {
        result.cxx_flags.push_back(L"-std=" + cxx_standard);
    }

    const std::wstring inhibit_warnings = GetSetting(settings, "GCC_WARN_INHIBIT_ALL_WARNINGS");
    if (inhibit_warnings == L"YES") {
        result.c_flags.push_back(L"-w");
        result.cxx_flags.push_back(L"-w");
    }

    const std::wstring defs = GetSetting(settings, "GCC_PREPROCESSOR_DEFINITIONS");
    if (!defs.empty()) {
        for (const auto& token : TokenizeFlags(defs)) {
            if (token == L"$(inherited)" || token == L"${inherited}") continue;
            result.c_flags.push_back(L"-D" + token);
            result.cxx_flags.push_back(L"-D" + token);
        }
    }

    for (const auto& f : c_extra_flags) {
        result.c_flags.push_back(f);
    }
    for (const auto& f : cxx_extra_flags) {
        result.cxx_flags.push_back(f);
    }

    const std::wstring prefix_header_setting = GetSetting(settings, "GCC_PREFIX_HEADER");
    if (!prefix_header_setting.empty()) {
        fs::path p(prefix_header_setting);
        if (!p.is_absolute()) {
            p = project.SourceRoot() / p;
        }
        std::error_code ec;
        if (fs::exists(p, ec)) {
            result.c_flags.push_back(L"-include");
            result.c_flags.push_back(p.lexically_normal().wstring());
            result.cxx_flags.push_back(L"-include");
            result.cxx_flags.push_back(p.lexically_normal().wstring());
        }
    }

    const std::wstring bridging_header =
        GetSetting(
            settings,
            "SWIFT_OBJC_BRIDGING_HEADER"
        );
    if (!bridging_header.empty()) {
        fs::path header_path(bridging_header);
        if (!header_path.is_absolute()) {
            header_path =
                project.SourceRoot() / header_path;
        }
        result.bridging_header =
            header_path.lexically_normal().wstring();
    }

    const auto hsp =
        ParseSearchPathsSetting(
            GetSetting(settings, "HEADER_SEARCH_PATHS"),
            project.SourceRoot()
        );
    for (const auto& p : hsp) {
        AddUnique(result.header_search_paths, p);
    }

    const auto uhsp =
        ParseSearchPathsSetting(
            GetSetting(settings, "USER_HEADER_SEARCH_PATHS"),
            project.SourceRoot()
        );
    for (const auto& p : uhsp) {
        AddUnique(result.header_search_paths, p);
    }

    const auto sip =
        ParseSearchPathsSetting(
            GetSetting(settings, "SWIFT_INCLUDE_PATHS"),
            project.SourceRoot()
        );
    for (const auto& p : sip) {
        AddUnique(result.swift_include_paths, p);
    }

    const auto fsp =
        ParseSearchPathsSetting(
            GetSetting(settings, "FRAMEWORK_SEARCH_PATHS"),
            project.SourceRoot()
        );
    for (const auto& p : fsp) {
        AddFrameworkSearchPath(result, p);
    }

    const auto lsp =
        ParseSearchPathsSetting(
            GetSetting(settings, "LIBRARY_SEARCH_PATHS"),
            project.SourceRoot()
        );
    for (const auto& p : lsp) {
        AddUnique(result.library_search_paths, p);
    }

    const std::wstring plist =
        GetSetting(
            settings,
            "INFOPLIST_FILE"
        );

    if (!plist.empty()) {
        fs::path plist_path(
            plist
        );

        if (!plist_path.is_absolute()) {
            plist_path =
                project.SourceRoot() /
                plist_path;
        }

        result.primary_info_plist =
            plist_path
                .lexically_normal()
                .wstring();
    }

    for (const auto& source :
         resolved->swift_sources) {
        result.swift_sources.push_back(
            source.wstring()
        );
    }

    for (const auto& source :
         resolved->c_family_sources) {
        result.c_sources.push_back(
            source.wstring()
        );
    }
    for (const auto& [source, flags] : resolved->source_compiler_flags)
        result.c_source_flags.emplace_back(source.wstring(),
            TokenizeFlags(Win32Process::ToWide(flags)));

    for (const auto& catalog :
         resolved->asset_catalogs) {
        result.xcassets_dirs.push_back(
            catalog.wstring()
        );
    }

    for (const auto& catalog :
         resolved->string_catalogs) {
        result.xcstrings_files.push_back(
            catalog.wstring()
        );
    }

    for (const auto& model : resolved->core_data_models) {
        result.core_data_models.emplace_back(
            model.path.wstring(),
            Win32Process::ToWide(model.current_version)
        );
    }

    for (const auto& intent_def : resolved->intent_definitions) {
        result.intent_definitions.push_back(
            intent_def.wstring()
        );
    }

    for (const auto& resource :
         resolved->resources) {

        const std::string ext = ToLowerAscii(
            resource
                .extension()
                .string()
        );

        if (ext == ".bundle") {
            result.resource_bundles
                .push_back(
                    resource.wstring()
                );
        } else if (ext != ".xcassets" && ext != ".xcstrings") {
            result.resource_files
                .push_back(
                    resource.wstring()
                );
        }
    }

    for (const auto& framework :
         resolved->frameworks) {

        if (fs::exists(framework)) {
            result.embedded_frameworks
                .push_back(
                    framework.wstring()
                );

            AddFrameworkSearchPath(
                result,
                framework.parent_path()
            );
        }
    }

    for (const auto& framework :
         resolved->system_frameworks) {
        result.system_frameworks
            .push_back(
                Win32Process::ToWide(
                    framework
                )
            );
    }

    for (const auto& lib :
         resolved->system_libraries) {
        AddUnique(
            result.system_libraries,
            Win32Process::ToWide(lib)
        );
    }

    for (const auto& lib :
         resolved->link_libraries) {
        AddUnique(
            result.link_libraries,
            Win32Process::ToWide(lib)
        );
    }

    const std::wstring ldflags = GetSetting(settings, "OTHER_LDFLAGS");
    if (!ldflags.empty()) {
        for (const auto& token : TokenizeFlags(ldflags)) {
            if (token == L"$(inherited)" || token == L"${inherited}") continue;
            // Linker flags are an ordered token stream.  Repeated option
            // tokens such as "-framework Name" must not be deduplicated
            // independently from their operands.
            result.linker_flags.push_back(token);
        }
    }

    const auto asset_setting =
        settings.find(
            "ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS"
        );

    if (asset_setting !=
        settings.end()) {

        result.generate_asset_symbols =
            ParseBool(
                asset_setting->second,
                true
            );
    } else {
        result.generate_asset_symbols =
            UsesTypedAssetSymbols(
                result.swift_sources
            );
    }

    DiscoverCarthageFrameworks(
        project.SourceRoot(),
        result
    );

    const std::wstring appicon_setting =
        GetSetting(
            settings,
            "ASSETCATALOG_COMPILER_APPICON_NAME"
        );

    result.app_icon_name =
        appicon_setting.empty()
            ? L"AppIcon"
            : appicon_setting;

    result.include_all_app_icons =
        GetSetting(
            settings,
            "ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS"
        ) == L"YES";

    result.alternate_app_icons =
        TokenizeFlags(
            GetSetting(
                settings,
                "ASSETCATALOG_COMPILER_ALTERNATE_APPICON_NAMES"
            )
        );

    result.app_icon_path =
        FindIcon(
            result.xcassets_dirs,
            result.app_icon_name
        );

    if (result.bundle_id.empty()) {
        result.bundle_id =
            L"dev.OPENFRUIT.hello";
    }

    if (result.display_name.empty()) {
        result.display_name =
            result.product_name.empty()
                ? result.project_name
                : result.product_name;
    }

    if (result.minimum_os_version.empty()) {
        result.minimum_os_version =
            L"18.0";
    }

    if (result.sdk_root.empty()) {
        result.sdk_root =
            L"iphoneos";
    }

    if (result.marketing_version.empty()) {
        result.marketing_version =
            L"1.0.0";
    }

    if (result.current_project_version.empty()) {
        result.current_project_version =
            L"1";
    }

    if (result.product_type.find("unit-test") != std::string::npos ||
        result.product_type.find("ui-testing") != std::string::npos) {
        result.is_valid = false;
        return result;
    }

    result.is_valid =
        target.kind == XcodeTargetKind::Aggregate ||
        !result.swift_sources.empty() ||
        !result.c_sources.empty() ||
        (result.product_type == "com.apple.product-type.bundle" &&
         (!result.resource_files.empty() || !result.xcassets_dirs.empty())) ||
        (result.product_type == "com.apple.product-type.library.static" &&
         (!result.public_headers.empty() || !result.project_headers.empty() ||
          !result.shell_script_phases.empty()));

    return result;
}

DiscoveredProject UniversalProject::InspectSelected(
    const XcodeProject& project, const XcodeTarget& target,
    const std::string& configuration, ProjectBuildAction action,
    const std::optional<XcodeSchemeSelection>& scheme) {
    XcodeDependencyOptions options;
    options.include_scheme = false;
    options.strict_build_settings = true;
    if (scheme) {
        if (!scheme->build_implicit_dependencies.has_value())
            throw std::runtime_error("OPENFRUIT selection: scheme implicit-dependency policy is unspecified.");
        options.infer_linked_products = *scheme->build_implicit_dependencies;
    }
    auto result = InspectTarget(project, target, configuration, options);
    result.selection_frozen = true;
    result.build_action = action;
    if (!scheme) return result;
    result.selected_scheme_file = scheme->scheme_file;
    result.selected_scheme_sha256 = scheme->content_sha256;
    result.build_implicit_dependencies = scheme->build_implicit_dependencies;
    result.parallelize_buildables = scheme->parallelize_buildables;
    result.selected_scheme_entries = scheme->build_entries;
    const auto bundle_key = [](const fs::path& p) {
        std::error_code ec;
        const auto canonical = fs::weakly_canonical(p, ec);
        const auto norm = (!ec && !canonical.empty()) ? canonical.lexically_normal() : p.lexically_normal();
        return ToLowerAscii(norm.string());
    };
    const auto root_bundle_key = bundle_key(project.ProjectBundle());
    std::map<std::string, std::optional<XcodeProject>> loaded_projects;
    loaded_projects.emplace(root_bundle_key, project);
    const auto get_project = [&](const fs::path& bundle_path) -> const XcodeProject* {
        const auto key = bundle_key(bundle_path);
        auto it = loaded_projects.find(key);
        if (it == loaded_projects.end()) {
            it = loaded_projects.emplace(key, XcodeProject::Load(bundle_path, project.BuildProductsRoot())).first;
        }
        return it->second ? &(*it->second) : nullptr;
    };
    const auto entry_depends_on_target = [&](const XcodeTargetDependency& entry) {
        const fs::path entry_owner = entry.project_path.empty() ? project.ProjectBundle() : entry.project_path;
        const auto* start_proj = get_project(entry_owner);
        if (!start_proj) return false;
        const auto start_target = !entry.target_id.empty()
            ? start_proj->FindTarget(entry.target_id)
            : start_proj->FindTarget(entry.target_name.empty() ? entry.name : entry.target_name);
        if (!start_target) return false;

        std::vector<std::pair<const XcodeProject*, XcodeTarget>> stack{{start_proj, *start_target}};
        std::set<std::pair<std::string, std::string>> visited{
            {bundle_key(start_proj->ProjectBundle()), start_target->id}};
        while (!stack.empty()) {
            const auto [cur_proj, cur_target] = stack.back();
            stack.pop_back();
            for (const auto& dep : cur_proj->ResolveTargetDependencies(cur_target, options)) {
                if (dep.scheme_entry || !dep.resolution_error.empty()) continue;
                fs::path dep_bundle = cur_proj->ProjectBundle();
                if (dep.is_subproject && !dep.project_path.empty()) {
                    dep_bundle = dep.project_path.is_absolute()
                        ? dep.project_path
                        : (cur_proj->SourceRoot() / dep.project_path);
                }
                const auto* next_proj = get_project(dep_bundle);
                if (!next_proj) continue;
                const auto next_target = !dep.target_id.empty()
                    ? next_proj->FindTarget(dep.target_id)
                    : next_proj->FindTarget(dep.target_name.empty() ? dep.name : dep.target_name);
                if (!next_target) continue;
                const auto next_owner_key = bundle_key(next_proj->ProjectBundle());
                if (next_owner_key == root_bundle_key && next_target->id == target.id) {
                    return true;
                }
                if (visited.emplace(next_owner_key, next_target->id).second) {
                    stack.emplace_back(next_proj, *next_target);
                }
            }
        }
        return false;
    };
    for (auto entry : scheme->build_entries) {
        const auto owner = entry.project_path.lexically_normal();
        if (bundle_key(owner) == root_bundle_key && entry.target_id == target.id) continue;
        const bool required = std::any_of(result.target_dependencies.begin(), result.target_dependencies.end(),
            [&](const auto& dep) {
                const auto existing_owner = dep.project_path.empty() ? project.ProjectBundle() : dep.project_path;
                return bundle_key(existing_owner) == bundle_key(owner) && dep.target_id == entry.target_id;
            });
        if (required || entry_depends_on_target(entry)) continue;
        result.target_dependencies.push_back(std::move(entry));
    }
    return result;
}

DiscoveredProject
UniversalProject::Inspect(
    const std::wstring& input_path,
    const std::string& configuration,
    const fs::path& build_products_root
) {
    DiscoveredProject result;

    const fs::path input =
        fs::absolute(
            fs::path(input_path)
        ).lexically_normal();

    /*
     * Preferred v4 path: parse the actual Xcode graph and resolve only the
     * main PBXNativeTarget's build phases.
     */
    if (const auto project =
            XcodeProject::Load(input, build_products_root)) {

        const auto target =
            project->MainApplicationTarget();

        if (target) {
            return InspectTarget(*project, *target, configuration);
        }
    }

    /*
     * Swift-package-only fallback.  Xcode projects intentionally do NOT fall
     * back to recursive source scanning anymore: doing so would reintroduce
     * extension/test target leakage.
     */
    fs::path root = input;

    if (fs::is_regular_file(root)) {
        root = root.parent_path();
    }

    if (fs::exists(
            root /
            "Package.swift")) {

        result.project_name =
            root.filename()
                .wstring();

        result.product_name =
            result.project_name;

        result.module_name =
            XcodeModuleIdentifier(result.product_name);

        result.project_dir =
            root.wstring();

        result.package_swift_path =
            (root / "Package.swift")
                .wstring();

        std::error_code ec;

        for (fs::recursive_directory_iterator it(
                 root /
                 "Sources",
                 fs::directory_options::
                     skip_permission_denied,
                 ec);
             it !=
                 fs::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                ec.clear();
                continue;
            }

            if (it->is_regular_file(ec) &&
                ToLowerAscii(
                    it->path()
                        .extension()
                        .string()) ==
                    ".swift") {

                result.swift_sources.push_back(
                    it->path()
                        .wstring()
                );
            }
        }

        result.bundle_id =
            L"dev.OPENFRUIT.package";

        result.display_name =
            result.project_name;

        result.minimum_os_version =
            L"18.0";

        result.sdk_root =
            L"iphoneos";

        result.is_valid =
            !result.swift_sources.empty();
    }

    return result;
}

AppBuildSpec
UniversalProject::ToAppBuildSpec(
    const DiscoveredProject& project,
    unsigned int jobs
) {
    AppBuildSpec spec;
    spec.target_kind = project.target_kind;
    spec.target_id = project.target_id;

    spec.app_name =
        project.project_name;

    spec.product_name =
        project.product_name.empty()
            ? project.project_name
            : project.product_name;

    spec.module_name =
        project.module_name.empty()
            ? XcodeModuleIdentifier(spec.product_name)
            : project.module_name;

    spec.bundle_id =
        project.bundle_id;

    spec.deployment_version =
        project.minimum_os_version;

    spec.info_plist_path =
        project.primary_info_plist;

    spec.project_path =
        project.project_dir;

    spec.bridging_header =
        project.bridging_header;

    spec.additional_sources =
        project.swift_sources;

    spec.native_sources =
        project.c_sources;

    spec.native_source_flags =
        project.c_source_flags;

    spec.asset_catalog_dirs =
        project.xcassets_dirs;

    spec.app_icon_name =
        project.app_icon_name;

    spec.include_all_app_icons =
        project.include_all_app_icons;

    spec.alternate_app_icons =
        project.alternate_app_icons;

    spec.generate_asset_symbols =
        project.generate_asset_symbols;

    spec.embedded_framework_dirs =
        project.embedded_framework_dirs;

    spec.header_search_paths =
        project.header_search_paths;

    spec.swift_include_paths =
        project.swift_include_paths;

    spec.product_type =
        project.product_type;

    spec.public_headers =
        project.public_headers;

    spec.project_headers =
        project.project_headers;

    spec.resource_files =
        project.resource_files;

    spec.core_data_models =
        project.core_data_models;

    spec.intent_definitions =
        project.intent_definitions;

    spec.build_settings = project.build_settings;
    for (const auto& [k, v] : project.build_settings) {
        if (k == L"EXECUTABLE_NAME" && !v.empty()) {
            spec.executable_name = v;
            break;
        }
    }
    for (const auto& phase : project.shell_script_phases) {
        AppShellScriptPhase app_phase;
        app_phase.name = Win32Process::ToWide(phase.name);
        app_phase.shell_path = Win32Process::ToWide(phase.shell_path);
        app_phase.script = phase.script;
        app_phase.order = phase.order;
        app_phase.after_sources = phase.after_sources;
        for (const auto& path : phase.input_paths) {
            app_phase.input_paths.push_back(Win32Process::ToWide(path));
        }
        for (const auto& path : phase.output_paths) {
            app_phase.output_paths.push_back(Win32Process::ToWide(path));
        }
        spec.shell_script_phases.push_back(std::move(app_phase));
    }

    spec.c_flags =
        project.c_flags;

    spec.cxx_flags =
        project.cxx_flags;

    if (fs::exists(fs::path(project.project_dir) / project.project_name)) {
        spec.source_root =
            (fs::path(project.project_dir) / project.project_name).wstring();
    } else if (!project.swift_sources.empty()) {
        spec.source_root =
            fs::path(project.swift_sources.front()).parent_path().wstring();
    }

    spec.jobs = jobs;

    for (const auto& framework :
         project.embedded_frameworks) {

        spec.frameworks.push_back(
            fs::path(framework)
                .stem()
                .wstring()
        );
    }

    for (const auto& framework :
         project.system_frameworks) {

        if (std::find(
                spec.frameworks.begin(),
                spec.frameworks.end(),
                framework) ==
            spec.frameworks.end()) {

            spec.frameworks.push_back(
                framework
            );
        }
    }

    spec.swift_flags.push_back(
        L"-swift-version"
    );

    spec.swift_flags.push_back(
        NormalizeSwiftLanguageMode(
            project.swift_version
        )
    );

    spec.swift_flags.push_back(
        L"-enable-bare-slash-regex"
    );

    if (!project.default_actor_isolation.empty()) {
        spec.swift_flags.push_back(
            L"-default-isolation"
        );

        spec.swift_flags.push_back(
            project.default_actor_isolation
        );
    }

    if (!project.strict_concurrency.empty()) {
        spec.swift_flags.push_back(
            L"-strict-concurrency=" +
            project.strict_concurrency
        );
    }

    spec.swift_flags.push_back(
        L"-Xfrontend"
    );

    spec.swift_flags.push_back(
        L"-enable-cross-import-overlays"
    );

    if (ToLowerAscii(Win32Process::ToNarrow(project.configuration)).find("debug") != std::string::npos) {
        spec.swift_flags.push_back(
            L"-D"
        );
        spec.swift_flags.push_back(
            L"DEBUG"
        );
    }

    for (const auto& cond : project.swift_active_compilation_conditions) {
        if (!cond.empty()) {
            spec.swift_flags.push_back(
                L"-D"
            );
            spec.swift_flags.push_back(
                cond
            );
        }
    }

    for (const auto& f : project.swift_flags) {
        spec.swift_flags.push_back(f);
    }

    spec.linker_flags = project.linker_flags;
    for (const auto& lib : project.system_libraries) {
        AddUnique(spec.linker_flags, L"-l" + lib);
    }
    spec.link_libraries = project.link_libraries;
    spec.library_search_paths = project.library_search_paths;

    return spec;
}

bool UniversalProject::ResolveXcframeworkSlices(
    DiscoveredProject& project,
    const std::wstring& target_triple,
    std::string& error
) {
    std::vector<fs::path> artifacts;
    artifacts.reserve(project.embedded_frameworks.size());
    for (const auto& framework : project.embedded_frameworks) {
        artifacts.emplace_back(framework);
    }

    auto resolved = OpenFruit::ResolveXcframeworkSlices(artifacts, target_triple);
    if (!resolved.success) {
        error = std::move(resolved.error);
        return false;
    }

    project.embedded_frameworks.clear();
    for (const auto& library : resolved.libraries) {
        AddUnique(project.embedded_frameworks, library.wstring());
        AddFrameworkSearchPath(project, library.parent_path());
    }
    return true;
}

PackagingSpec
UniversalProject::ToPackagingSpec(
    const DiscoveredProject& project
) {
    PackagingSpec spec;

    spec.target_name =
        project.project_name;

    spec.product_name =
        project.product_name.empty()
            ? project.project_name
            : project.product_name;

    spec.app_name =
        spec.product_name;

    spec.module_name =
        project.module_name.empty()
            ? XcodeModuleIdentifier(spec.product_name)
            : project.module_name;

    spec.bundle_id =
        project.bundle_id;

    spec.display_name =
        project.display_name.empty()
            ? spec.product_name
            : project.display_name;

    spec.version =
        project.marketing_version;

    spec.build_version =
        project.current_project_version;

    spec.minimum_os_version =
        project.minimum_os_version;

    spec.icon_path =
        project.app_icon_path;

    spec.app_icon_name =
        project.app_icon_name;

    spec.include_all_app_icons =
        project.include_all_app_icons;

    spec.alternate_app_icons =
        project.alternate_app_icons;

    spec.info_plist_path =
        project.primary_info_plist;

    spec.code_sign_entitlements_path = project.code_sign_entitlements_path;
    spec.build_settings = project.build_settings;
    for (const auto& [k, v] : project.build_settings) {
        if (k == L"EXECUTABLE_NAME" && !v.empty()) {
            spec.executable_name = v;
            break;
        }
    }

    spec.resource_bundles =
        project.resource_bundles;

    spec.resource_files =
        project.resource_files;

    spec.embedded_frameworks =
        project.embedded_frameworks;

    spec.asset_catalog_dirs =
        project.xcassets_dirs;

    return spec;
}

SigningProduct UniversalProject::ToSigningProduct(
    const DiscoveredProject& project, const AppBuildResult& product) {
    if (!product.success || product.product_path.empty()) return {};
    SigningProduct signing;
    signing.product_path = product.product_path;
    signing.bundle_id = project.bundle_id;
    signing.entitlements_path = project.code_sign_entitlements_path;
    signing.project_file = project.pbxproj_path;
    signing.target_id = project.target_id;
    signing.configuration = project.configuration;
    signing.build_settings = project.build_settings;
    return signing;
}

} // namespace OpenFruit
