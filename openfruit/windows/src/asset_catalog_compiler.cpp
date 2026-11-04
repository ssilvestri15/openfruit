#include "asset_catalog_compiler.hpp"

#include "content_hash.hpp"
#include "environment_manager.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "svg_runtime_provider.hpp"
#include "text_util.hpp"

#include <plist/plist.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {
void CheckActive() {
    if (const auto operation = CurrentOperationContext()) {
        if (operation->CancellationRequested()) throw std::runtime_error("asset catalog compilation cancelled");
        if (operation->DeadlineExceeded()) throw std::runtime_error("asset catalog compilation deadline exceeded");
    }
}
bool Escapes(const fs::path& relative) {
    const auto normal = relative.lexically_normal();
    return !normal.empty() && *normal.begin() == L"..";
}
void InspectDirectory(const fs::path& directory, const AppIconSelection& app_icons,
                      bool& requires_svg, bool& external_references, unsigned depth = 0) {
    CheckActive();
    if (depth > 64) throw std::runtime_error("asset catalog namespace nesting exceeds 64 levels: " + directory.string());
    if (fs::is_symlink(directory)) throw std::runtime_error("symbolic-link asset catalog directory is unsupported: " + directory.string());
    for (const auto& entry : fs::directory_iterator(directory)) {
        CheckActive();
        const auto name = entry.path().filename().wstring();
        if (!name.empty() && name.front() == L'.') continue;
        if (!entry.is_directory()) continue;
        const auto extension = ToLowerAscii(entry.path().extension().string());
        if (fs::is_symlink(entry.symlink_status())) throw std::runtime_error("symbolic-link asset directory is unsupported: " + entry.path().string());
        if (extension.empty()) { InspectDirectory(entry.path(), app_icons, requires_svg, external_references, depth + 1); continue; }
        // Other platforms' layered-image containers have no iOS rendition.
        if (extension == ".solidimagestack" || extension == ".imagestack" || extension == ".brandassets") continue;
        if (extension != ".imageset" && extension != ".appiconset" && extension != ".colorset" &&
            extension != ".symbolset" && extension != ".dataset")
            throw std::runtime_error("unsupported asset type: " + entry.path().string());
        if (extension == ".appiconset" && !app_icons.Selects(entry.path().stem().wstring())) continue;
        const auto metadata = entry.path() / "Contents.json";
        std::ifstream input(metadata, std::ios::binary);
        if (!input) throw std::runtime_error("asset metadata is missing or unreadable: " + metadata.string());
        constexpr std::size_t metadata_limit = 4 * 1024 * 1024;
        // Read one byte beyond the limit: a growing file cannot bypass a prior
        // file_size check or cause unbounded allocation.
        std::string text(metadata_limit + 1, '\0');
        input.read(text.data(), static_cast<std::streamsize>(text.size()));
        text.resize(static_cast<std::size_t>(input.gcount()));
        if (input.bad()) throw std::runtime_error("cannot read asset metadata: " + metadata.string());
        if (text.size() > metadata_limit) throw std::runtime_error("asset metadata exceeds 4 MiB limit: " + metadata.string());
        if (text.size() >= 3 && text.compare(0, 3, "\xEF\xBB\xBF") == 0) text.erase(0, 3);
        std::string parse_error;
        const auto contents = JsonValue::Parse(text, &parse_error);
        if (!contents || !contents->IsObject()) throw std::runtime_error("invalid asset metadata: " + metadata.string() + ": " + parse_error);
        if (extension == ".colorset") continue;
        if (extension == ".dataset") {
            const auto* data_items = contents->Get("data");
            if (data_items && data_items->IsArray()) {
                for (const auto& item : data_items->ArrayItems()) {
                    if (!item.IsObject()) continue;
                    const auto* filename = item.Get("filename");
                    if (filename && !filename->IsString()) throw std::runtime_error("invalid data filename: " + metadata.string());
                    if (!filename || filename->StringValue().empty()) continue;
                    const fs::path relative(Win32Process::ToWide(filename->StringValue()));
                    if (relative.is_absolute()) throw std::runtime_error("asset filename must be relative: " + metadata.string());
                    external_references = external_references || Escapes(relative);
                    const auto source = entry.path() / relative;
                    if (!fs::is_regular_file(source)) throw std::runtime_error("missing referenced asset: " + source.string());
                }
            }
            continue;
        }
        if (extension == ".symbolset") {
            const auto* symbols = contents->Get("symbols");
            if (symbols && symbols->IsArray()) {
                for (const auto& symbol : symbols->ArrayItems()) {
                    if (!symbol.IsObject()) continue;
                    const auto* filename = symbol.Get("filename");
                    if (filename && !filename->IsString()) throw std::runtime_error("invalid symbol filename: " + metadata.string());
                    if (!filename || filename->StringValue().empty()) continue;
                    const fs::path relative(Win32Process::ToWide(filename->StringValue()));
                    if (relative.is_absolute()) throw std::runtime_error("asset filename must be relative: " + metadata.string());
                    external_references = external_references || Escapes(relative);
                    const auto source = entry.path() / relative;
                    if (!fs::is_regular_file(source)) throw std::runtime_error("missing referenced asset: " + source.string());
                    if (ToLowerAscii(relative.extension().string()) == ".svg") requires_svg = true;
                }
            }
            continue;
        }
        const auto* images = contents->Get("images");
        if (!images || !images->IsArray()) throw std::runtime_error("asset metadata requires an images array: " + metadata.string());
        for (const auto& image : images->ArrayItems()) {
            if (!image.IsObject()) throw std::runtime_error("invalid image entry: " + metadata.string());
            const auto* filename = image.Get("filename");
            if (filename && !filename->IsString()) throw std::runtime_error("invalid image filename: " + metadata.string());
            if (!filename || filename->StringValue().empty()) continue;
            const fs::path relative(Win32Process::ToWide(filename->StringValue()));
            if (relative.is_absolute()) throw std::runtime_error("asset filename must be relative: " + metadata.string());
            external_references = external_references || Escapes(relative);
            const auto source = entry.path() / relative;
            if (!fs::is_regular_file(source)) throw std::runtime_error("missing referenced asset: " + source.string());
            if (ToLowerAscii(relative.extension().string()) == ".svg") requires_svg = true;
        }
    }
}
// Content identity of one compilation: the compiler and rasterizer binaries,
// every option, and the relative path and bytes of every catalog file. The
// compiler reads only its catalogs and writes only its output directory.
std::optional<std::string> CompilationKey(const fs::path& compiler, const fs::path& svg,
                                          const std::vector<std::wstring>& arguments,
                                          const AssetCatalogInputs& inputs) {
    if (inputs.external_references) return std::nullopt;
    std::string identity = "openfruit.asset-catalog.v1\n";
    for (const auto& tool : {compiler, svg}) {
        if (tool.empty()) { identity += "-\n"; continue; }
        const auto digest = Sha256File(tool);
        if (!digest) return std::nullopt;
        identity += *digest + "\n";
    }
    // Arguments 1-2 name the output directory, which is not an input.
    for (std::size_t index = 3; index < arguments.size(); ++index)
        identity += Win32Process::ToNarrow(arguments[index]) + "\n";
    for (const auto& catalog : inputs.catalogs) {
        std::vector<fs::path> files;
        for (const auto& entry : fs::recursive_directory_iterator(catalog)) {
            CheckActive();
            if (entry.is_symlink()) return std::nullopt;
            if (entry.is_regular_file()) files.push_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        identity += "catalog\n";
        for (const auto& file : files) {
            const auto digest = Sha256File(file);
            if (!digest) return std::nullopt;
            identity += Win32Process::ToNarrow(file.lexically_relative(catalog).generic_wstring()) + "\t" + *digest + "\n";
        }
    }
    return Sha256(identity);
}

std::optional<std::string> ReadFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

// Adds what destination does not declare; dictionaries merge key by key.
void MergeMissing(plist_t destination, plist_t source) {
    plist_dict_iter iterator = nullptr;
    plist_dict_new_iter(source, &iterator);
    const auto release = [](void* value) { std::free(value); };
    std::unique_ptr<void, decltype(release)> owner(iterator, release);
    for (;;) {
        char* raw_key = nullptr;
        plist_t value = nullptr;
        plist_dict_next_item(source, iterator, &raw_key, &value);
        const std::string key = raw_key ? raw_key : "";
        std::free(raw_key);
        if (!value) break;
        const plist_t existing = plist_dict_get_item(destination, key.c_str());
        if (!existing) plist_dict_set_item(destination, key.c_str(), plist_copy(value));
        else if (plist_get_node_type(existing) == PLIST_DICT && plist_get_node_type(value) == PLIST_DICT)
            MergeMissing(existing, value);
    }
}

bool ValidArchive(const fs::path& archive) {
    std::ifstream stream(archive, std::ios::binary);
    char magic[8]{};
    stream.read(magic, sizeof(magic));
    return stream.gcount() == sizeof(magic) && std::string(magic, sizeof(magic)) == "BOMStore";
}
}

bool AppIconSelection::Selects(const std::wstring& name) const {
    if (primary.empty() || name == primary || include_all) return true;
    return std::find(alternates.begin(), alternates.end(), name) != alternates.end();
}

bool AssetCatalogCompiler::MergePartialInfoPlist(const fs::path& info, const fs::path& partial,
                                                 std::string& error) {
    const auto info_bytes = ReadFile(info);
    const auto partial_bytes = ReadFile(partial);
    if (!info_bytes || !partial_bytes) { error = "cannot read Info.plist or asset catalog Info.plist additions"; return false; }
    plist_t info_root = nullptr;
    plist_t partial_root = nullptr;
    plist_format_t format = PLIST_FORMAT_XML;
    plist_from_memory(info_bytes->data(), static_cast<uint32_t>(info_bytes->size()), &info_root, &format);
    plist_from_memory(partial_bytes->data(), static_cast<uint32_t>(partial_bytes->size()), &partial_root, nullptr);
    const auto release = [](plist_t node) { if (node) plist_free(node); };
    std::unique_ptr<void, decltype(release)> info_owner(info_root, release), partial_owner(partial_root, release);
    if (!info_root || plist_get_node_type(info_root) != PLIST_DICT ||
        !partial_root || plist_get_node_type(partial_root) != PLIST_DICT) {
        error = "Info.plist and asset catalog Info.plist additions must be dictionaries";
        return false;
    }
    MergeMissing(info_root, partial_root);
    char* bytes = nullptr;
    uint32_t length = 0;
    if ((format == PLIST_FORMAT_BINARY ? plist_to_bin(info_root, &bytes, &length)
                                       : plist_to_xml(info_root, &bytes, &length)) != PLIST_ERR_SUCCESS || !bytes) {
        error = "cannot serialize Info.plist";
        return false;
    }
    std::unique_ptr<char, decltype(&plist_mem_free)> bytes_owner(bytes, plist_mem_free);
    std::ofstream output(info, std::ios::binary | std::ios::trunc);
    output.write(bytes, length);
    if (!output) { error = "cannot write Info.plist: " + info.string(); return false; }
    return true;
}

bool AssetCatalogCompiler::PrepareInputs(const std::vector<std::wstring>& catalogs,
                                        const AppIconSelection& app_icons,
                                        AssetCatalogInputs& inputs, std::string& error) {
    inputs = {};
    error.clear();
    try {
        for (const auto& catalog : catalogs) {
            CheckActive();
            const fs::path path(catalog);
            if (!fs::is_directory(path)) throw std::runtime_error("declared asset catalog is missing: " + path.string());
            inputs.catalogs.push_back(path);
            // An Icon Composer document is composed and rasterized as SVG.
            if (ToLowerAscii(path.extension().string()) == ".icon") {
                if (!fs::is_regular_file(path / "icon.json"))
                    throw std::runtime_error("Icon Composer document has no icon.json: " + path.string());
                inputs.requires_svg = true;
                continue;
            }
            InspectDirectory(path, app_icons, inputs.requires_svg, inputs.external_references);
        }
        std::sort(inputs.catalogs.begin(), inputs.catalogs.end());
        return true;
    } catch (const std::exception& exception) {
        inputs = {};
        error = exception.what();
        return false;
    }
}

bool AssetCatalogCompiler::Compile(
    const std::vector<std::wstring>& catalogs,
    const fs::path& product_bundle,
    const std::wstring& deployment_target,
    const AppIconSelection& app_icons,
    std::string& error
) {
    error.clear();
    if (catalogs.empty()) return true;
    OperationSpan span("resource.asset_catalog");

    std::error_code ec;
    if (!fs::is_directory(product_bundle, ec)) {
        error = "product bundle does not exist: " + product_bundle.string();
        return false;
    }

    AssetCatalogInputs inputs;
    if (!PrepareInputs(catalogs, app_icons, inputs, error)) return false;
    fs::path svg_executable;
    if (inputs.requires_svg) {
        const auto provider = EnsureNativeSvgProvider(ToolPaths::LocalHome());
        if (!provider.available) { error = "native SVG provider unavailable: " + provider.error; return false; }
        svg_executable = provider.executable;
        if (!svg_executable.is_absolute() || !fs::is_regular_file(svg_executable, ec)) {
            error = "native SVG provider returned an invalid executable";
            return false;
        }
    }

    const fs::path compiler =
        ToolPaths::LocalHome() / "toolchains" / "asset-compiler" /
        "bin" / "OPENFRUIT-asset-compiler.exe";
    if (!EnvironmentManager::EnsureAssetCompiler() || !fs::is_regular_file(compiler, ec)) {
        error = "verified asset catalog compiler unavailable: " + compiler.string();
        return false;
    }

    const fs::path output = product_bundle / "Assets.car";
    fs::remove(output, ec);
    if (ec) { error = "cannot remove stale asset archive: " + ec.message(); return false; }

    std::vector<std::wstring> arguments = {
        compiler.wstring(),
        L"--output-directory", product_bundle.wstring(),
        L"--deployment-target",
        deployment_target.empty() ? L"16.0" : deployment_target
    };
    if (!app_icons.primary.empty()) {
        arguments.push_back(L"--app-icon");
        arguments.push_back(app_icons.primary);
    }
    if (app_icons.include_all) arguments.push_back(L"--include-all-app-icons");
    for (const auto& alternate : app_icons.alternates) {
        arguments.push_back(L"--alternate-app-icon");
        arguments.push_back(alternate);
    }
    if (!svg_executable.empty()) {
        arguments.push_back(L"--svg-rasterizer");
        arguments.push_back(svg_executable.wstring());
    }
    for (const auto& input : inputs.catalogs) arguments.push_back(input.wstring());

    std::vector<std::pair<std::wstring, std::wstring>> env_vars;
    const DWORD path_len = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    std::wstring existing_path;
    if (path_len > 0) {
        existing_path.resize(path_len);
        GetEnvironmentVariableW(L"PATH", existing_path.data(), path_len);
        if (!existing_path.empty() && existing_path.back() == L'\0') existing_path.pop_back();
    }
    env_vars.push_back({L"PATH", compiler.parent_path().wstring() + (existing_path.empty() ? L"" : L";" + existing_path)});

    // Unchanged inputs reuse a previous compilation: its complete output
    // directory is copied into the bundle exactly as the compiler writes it.
    std::optional<std::string> key;
    try { key = CompilationKey(compiler, svg_executable, arguments, inputs); }
    catch (const std::exception&) { key.reset(); }
    const fs::path cache_root = ToolPaths::CacheRoot() / "asset-catalogs";
    const fs::path cached = key ? cache_root / *key : fs::path{};
    const auto publish = [&](const fs::path& directory) {
        for (const auto& entry : fs::directory_iterator(directory))
            fs::copy(entry.path(), product_bundle / entry.path().filename(),
                     fs::copy_options::recursive | fs::copy_options::overwrite_existing);
    };
    // The compiler's Info.plist additions are build input, not bundle content.
    const auto apply_additions = [&]() {
        const fs::path partial = product_bundle / "assetcatalog_generated_info.plist";
        const fs::path info = product_bundle / "Info.plist";
        if (!fs::is_regular_file(partial, ec) || !fs::is_regular_file(info, ec)) return true;
        if (!MergePartialInfoPlist(info, partial, error)) return false;
        fs::remove(partial, ec);
        return true;
    };
    if (key && fs::is_regular_file(cached / "Assets.car", ec) && ValidArchive(cached / "Assets.car")) {
        bool published = false;
        try {
            publish(cached);
            published = true;
        } catch (const std::exception&) {
            // Fall back to a fresh compilation.
        }
        if (published) {
            // The entry's time records its last use; `cache clean` prunes unused ones.
            fs::last_write_time(cached, fs::file_time_type::clock::now(), ec);
            if (!apply_additions()) return false;
            span.Succeed();
            return true;
        }
    }
    fs::path staging;
    if (key) {
        staging = cache_root / (*key + ".pending-" + std::to_string(GetCurrentProcessId()) + "-" +
                                std::to_string(GetTickCount64()));
        fs::create_directories(staging, ec);
        if (ec) { staging.clear(); ec.clear(); }
        else arguments[2] = staging.wstring();
    }
    const ProcessResult compiled = Win32Process::Run(
        compiler.wstring(), arguments, product_bundle.wstring(), env_vars);
    if (!staging.empty()) {
        if (compiled.success && ValidArchive(staging / "Assets.car")) {
            try { publish(staging); }
            catch (const std::exception& exception) {
                fs::remove_all(staging, ec);
                error = std::string("cannot publish compiled asset catalogs: ") + exception.what();
                return false;
            }
            // A concurrent identical compilation may have published first.
            fs::rename(staging, cached, ec);
        }
        fs::remove_all(staging, ec);
    }
    if (!compiled.success || !fs::is_regular_file(output, ec) ||
        fs::file_size(output, ec) < 8) {
        error = "failed to compile asset catalogs (exit " +
            std::to_string(compiled.exit_code) + "): " + compiled.std_err + compiled.std_out;
        if (compiled.cancelled) error = "asset catalog compilation cancelled: " + error;
        if (compiled.timed_out) error = "asset catalog compilation deadline exceeded: " + error;
        return false;
    }

    if (!ValidArchive(output)) {
        error = "asset compiler produced an invalid CoreUI archive: " +
            output.string();
        return false;
    }
    if (!apply_additions()) return false;
    span.Succeed();
    return true;
}

} // namespace OpenFruit
