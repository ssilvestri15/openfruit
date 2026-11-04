#include "xcode_project.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <map>
#include <stdexcept>
#include <tuple>
#include <plist/plist.h>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

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

void MergeBuildSetting(
    std::unordered_map<std::string, std::string>& settings,
    const std::string& key,
    std::string value
) {
    const auto previous = settings.find(key);
    if (previous != settings.end()) {
        ReplaceAll(value, "$(inherited)", previous->second);
        ReplaceAll(value, "${inherited}", previous->second);
    }
    settings.insert_or_assign(key, TrimWhitespace(std::move(value)));
}


std::string XcodeIdentifier(
    std::string value,
    bool rfc1034
) {
    for (char& c : value) {
        const unsigned char u =
            static_cast<unsigned char>(c);

        const bool allowed =
            std::isalnum(u) ||
            c == '-' ||
            (!rfc1034 && c == '_');

        if (!allowed) {
            c = '-';
        }
    }

    // Xcode's identifier modifiers collapse repeated separators in the common
    // product/bundle-name case, giving deterministic bundle-safe output.
    std::string normalized;
    normalized.reserve(value.size());

    bool previous_dash = false;

    for (const char c : value) {
        if (c == '-') {
            if (previous_dash) {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }

        normalized.push_back(c);
    }

    while (!normalized.empty() &&
           normalized.front() == '-') {
        normalized.erase(
            normalized.begin()
        );
    }

    while (!normalized.empty() &&
           normalized.back() == '-') {
        normalized.pop_back();
    }

    return normalized;
}

std::string ApplyXcodeBuildSettingModifier(
    std::string value,
    const std::string& modifier
) {
    if (modifier == "c99extidentifier") {
        for (char& c : value) {
            const unsigned char u = static_cast<unsigned char>(c);
            const bool ascii_letter =
                (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z');
            const bool ascii_digit = u >= '0' && u <= '9';
            if (!ascii_letter && !ascii_digit && c != '_') c = '_';
        }
        if (value.empty()) return "_";
        if (value.front() >= '0' && value.front() <= '9') {
            value.insert(value.begin(), '_');
        }
        return value;
    }

    if (modifier == "rfc1034identifier") {
        return XcodeIdentifier(
            std::move(value),
            true
        );
    }

    if (modifier == "identifier") {
        return XcodeIdentifier(
            std::move(value),
            false
        );
    }

    // Unknown modifiers are left semantically neutral instead of destroying
    // the underlying value. More modifiers can be added without changing the
    // parser or build-setting graph.
    return value;
}

bool EndsWithCaseInsensitive(
    const std::string& value,
    const std::string& suffix
) {
    if (suffix.size() > value.size()) {
        return false;
    }

    return ToLowerAscii(value.substr(value.size() - suffix.size())) ==
           ToLowerAscii(suffix);
}

std::string UrlIdentity(std::string url) {
    while (!url.empty() &&
           (url.back() == '/' || url.back() == '\\')) {
        url.pop_back();
    }

    const std::size_t slash = url.find_last_of("/\\");
    std::string name =
        slash == std::string::npos
            ? url
            : url.substr(slash + 1);

    if (EndsWithCaseInsensitive(name, ".git")) {
        name.resize(name.size() - 4);
    }

    return ToLowerAscii(name);
}

std::string UnquoteXcconfigValue(std::string value) {
    value = TrimWhitespace(std::move(value));

    if (value.size() >= 2 &&
        value.front() == '"' &&
        value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }

    return value;
}

/*
 * Lexer/parser for Apple's ASCII/OpenStep plist syntax used by
 * project.pbxproj.
 *
 * This is intentionally token based; comments such as
 *
 *   ABC123  [comment: MyFile.swift]
 *
 * are discarded by the lexer and never become part of the actual ID.
 */
class OpenStepParser {
public:
    explicit OpenStepParser(std::string text)
        : text_(std::move(text)) {}

    XcodeProject::Value Parse() {
        SkipTrivia();
        return ParseValue();
    }

private:
    std::string text_;
    std::size_t pos_ = 0;

    bool Eof() const noexcept {
        return pos_ >= text_.size();
    }

    char Peek() const noexcept {
        return Eof() ? '\0' : text_[pos_];
    }

    char Take() noexcept {
        return Eof() ? '\0' : text_[pos_++];
    }

    void SkipTrivia() {
        for (;;) {
            while (!Eof() &&
                   std::isspace(
                       static_cast<unsigned char>(Peek()))) {
                ++pos_;
            }

            if (pos_ + 1 >= text_.size()) {
                return;
            }

            if (text_[pos_] == '/' &&
                text_[pos_ + 1] == '*') {
                pos_ += 2;

                while (pos_ + 1 < text_.size() &&
                       !(text_[pos_] == '*' &&
                         text_[pos_ + 1] == '/')) {
                    ++pos_;
                }

                if (pos_ + 1 < text_.size()) {
                    pos_ += 2;
                }

                continue;
            }

            if (text_[pos_] == '/' &&
                text_[pos_ + 1] == '/') {
                pos_ += 2;

                while (!Eof() &&
                       Peek() != '\n' &&
                       Peek() != '\r') {
                    ++pos_;
                }

                continue;
            }

            return;
        }
    }

    bool Consume(char expected) {
        SkipTrivia();

        if (Peek() != expected) {
            return false;
        }

        ++pos_;
        return true;
    }

    std::string ParseQuotedString() {
        std::string result;

        if (Take() != '"') {
            return result;
        }

        bool escaped = false;

        while (!Eof()) {
            const char c = Take();

            if (escaped) {
                switch (c) {
                case 'n':
                    result.push_back('\n');
                    break;
                case 'r':
                    result.push_back('\r');
                    break;
                case 't':
                    result.push_back('\t');
                    break;
                default:
                    result.push_back(c);
                    break;
                }

                escaped = false;
                continue;
            }

            if (c == '\\') {
                escaped = true;
                continue;
            }

            if (c == '"') {
                break;
            }

            result.push_back(c);
        }

        return result;
    }

    std::string ParseBareString() {
        std::string result;

        while (!Eof()) {
            const char c = Peek();

            if (std::isspace(
                    static_cast<unsigned char>(c)) ||
                c == '{' ||
                c == '}' ||
                c == '(' ||
                c == ')' ||
                c == '=' ||
                c == ';' ||
                c == ',') {
                break;
            }

            // Start of a comment ends a bare token.
            if (c == '/' &&
                pos_ + 1 < text_.size() &&
                (text_[pos_ + 1] == '*' ||
                 text_[pos_ + 1] == '/')) {
                break;
            }

            result.push_back(c);
            ++pos_;
        }

        return result;
    }

    std::string ParseStringToken() {
        SkipTrivia();

        if (Peek() == '"') {
            return ParseQuotedString();
        }

        return ParseBareString();
    }

    XcodeProject::Value ParseDictionary() {
        XcodeProject::Value result;
        result.kind = XcodeProject::Value::Kind::Dictionary;

        Consume('{');

        for (;;) {
            SkipTrivia();

            if (Consume('}')) {
                break;
            }

            if (Eof()) {
                break;
            }

            std::string key = ParseStringToken();

            if (key.empty()) {
                ++pos_;
                continue;
            }

            if (!Consume('=')) {
                continue;
            }

            XcodeProject::Value value =
                ParseValue();

            result.dictionary.insert_or_assign(
                std::move(key),
                std::move(value)
            );

            Consume(';');
        }

        return result;
    }

    XcodeProject::Value ParseArray() {
        XcodeProject::Value result;
        result.kind = XcodeProject::Value::Kind::Array;

        Consume('(');

        for (;;) {
            SkipTrivia();

            if (Consume(')')) {
                break;
            }

            if (Eof()) {
                break;
            }

            result.array.push_back(
                ParseValue()
            );

            Consume(',');
        }

        return result;
    }

    XcodeProject::Value ParseValue() {
        SkipTrivia();

        if (Peek() == '{') {
            return ParseDictionary();
        }

        if (Peek() == '(') {
            return ParseArray();
        }

        XcodeProject::Value result;
        result.kind = XcodeProject::Value::Kind::String;
        result.string = ParseStringToken();
        return result;
    }
};

const XcodeProject::Value* DictGet(
    const XcodeProject::Value* value,
    std::string_view key
) {
    if (!value ||
        value->kind != XcodeProject::Value::Kind::Dictionary) {
        return nullptr;
    }

    const auto it =
        value->dictionary.find(
            std::string(key)
        );

    return it == value->dictionary.end()
        ? nullptr
        : &it->second;
}

std::string DictString(
    const XcodeProject::Value* value,
    std::string_view key
) {
    const auto* child = DictGet(value, key);

    if (!child ||
        child->kind != XcodeProject::Value::Kind::String) {
        return {};
    }

    return child->string;
}

std::vector<std::string> DictStringArray(
    const XcodeProject::Value* value,
    std::string_view key
) {
    std::vector<std::string> result;

    const auto* child = DictGet(value, key);

    if (!child ||
        child->kind != XcodeProject::Value::Kind::Array) {
        return result;
    }

    result.reserve(child->array.size());

    for (const auto& item : child->array) {
        if (item.kind ==
            XcodeProject::Value::Kind::String) {
            result.push_back(item.string);
        }
    }

    return result;
}

bool IsGroupIsa(const std::string& isa) {
    return isa == "PBXGroup" ||
           isa == "PBXVariantGroup" ||
           isa == "XCVersionGroup" ||
           isa == "PBXFileSystemSynchronizedRootGroup";
}

bool IsCFamilySourceExtension(const std::string& ext) {
    return ext == ".c" ||
           ext == ".cc" ||
           ext == ".cpp" ||
           ext == ".cxx" ||
           ext == ".m" ||
           ext == ".mm";
}

bool IsResourceExtension(const fs::path& path) {
    const std::string filename =
        ToLowerAscii(path.filename().string());

    if (filename == "info.plist") {
        return false;
    }

    const std::string ext =
        ToLowerAscii(path.extension().string());

    return ext == ".plist" ||
           ext == ".strings" ||
           ext == ".stringsdict" ||
           ext == ".storyboard" ||
           ext == ".xib" ||
           ext == ".nib" ||
           ext == ".json" ||
           ext == ".png" ||
           ext == ".jpg" ||
           ext == ".jpeg" ||
           ext == ".gif" ||
           ext == ".webp" ||
           ext == ".svg" ||
           ext == ".pdf" ||
           ext == ".mp3" ||
           ext == ".wav" ||
           ext == ".m4a" ||
           ext == ".mp4" ||
           ext == ".mov" ||
           ext == ".html" ||
           ext == ".css" ||
           ext == ".js" ||
           ext == ".ttf" ||
           ext == ".otf" ||
           ext == ".ttc" ||
           ext == ".woff" ||
           ext == ".woff2" ||
           ext == ".txt" ||
           ext == ".rtf" ||
           ext == ".xml";
}

XcodeProject::Value ConvertPlistToValue(plist_t node) {
    XcodeProject::Value result;
    if (!node) {
        return result;
    }

    plist_type type = plist_get_node_type(node);
    switch (type) {
    case PLIST_BOOLEAN: {
        uint8_t val = 0;
        plist_get_bool_val(node, &val);
        result.kind = XcodeProject::Value::Kind::String;
        result.string = val ? "YES" : "NO";
        break;
    }
    case PLIST_INT: {
        int64_t val = 0;
        plist_get_int_val(node, &val);
        result.kind = XcodeProject::Value::Kind::String;
        result.string = std::to_string(val);
        break;
    }
    case PLIST_REAL: {
        double val = 0;
        plist_get_real_val(node, &val);
        result.kind = XcodeProject::Value::Kind::String;
        result.string = std::to_string(val);
        break;
    }
    case PLIST_STRING: {
        uint64_t len = 0;
        const char* str = plist_get_string_ptr(node, &len);
        if (str) {
            result.kind = XcodeProject::Value::Kind::String;
            result.string.assign(str, static_cast<std::size_t>(len));
        }
        break;
    }
    case PLIST_KEY: {
        char* str = nullptr;
        plist_get_key_val(node, &str);
        if (str) {
            result.kind = XcodeProject::Value::Kind::String;
            result.string = str;
            plist_mem_free(str);
        }
        break;
    }
    case PLIST_ARRAY: {
        result.kind = XcodeProject::Value::Kind::Array;
        uint32_t size = plist_array_get_size(node);
        result.array.reserve(size);
        for (uint32_t i = 0; i < size; ++i) {
            plist_t item = plist_array_get_item(node, i);
            result.array.push_back(ConvertPlistToValue(item));
        }
        break;
    }
    case PLIST_DICT: {
        result.kind = XcodeProject::Value::Kind::Dictionary;
        plist_dict_iter it = nullptr;
        plist_dict_new_iter(node, &it);
        if (it) {
            char* key = nullptr;
            plist_t subnode = nullptr;
            while (true) {
                plist_dict_next_item(node, it, &key, &subnode);
                if (!key) break;
                result.dictionary.emplace(std::string(key), ConvertPlistToValue(subnode));
                plist_mem_free(key);
            }
            plist_dict_free_iter(it);
        }
        break;
    }
    case PLIST_DATA: {
        uint64_t length = 0;
        const char* ptr = plist_get_data_ptr(node, &length);
        if (ptr) {
            result.kind = XcodeProject::Value::Kind::String;
            result.string.assign(ptr, static_cast<std::size_t>(length));
        }
        break;
    }
    case PLIST_DATE: {
        int64_t sec = 0;
        plist_get_unix_date_val(node, &sec);
        result.kind = XcodeProject::Value::Kind::String;
        result.string = std::to_string(sec);
        break;
    }
    case PLIST_UID: {
        uint64_t val = 0;
        plist_get_uid_val(node, &val);
        result.kind = XcodeProject::Value::Kind::String;
        result.string = std::to_string(val);
        break;
    }
    default:
        result.kind = XcodeProject::Value::Kind::Null;
        break;
    }
    return result;
}

} // namespace

const XcodeProject::Value*
XcodeProject::Value::Get(
    std::string_view key
) const {
    return DictGet(this, key);
}

std::string
XcodeProject::Value::String(
    std::string_view key
) const {
    return DictString(this, key);
}

std::vector<std::string>
XcodeProject::Value::StringArray(
    std::string_view key
) const {
    return DictStringArray(this, key);
}

std::optional<XcodeProject>
XcodeProject::Load(
    const fs::path& project_or_directory,
    const fs::path& build_products_root
) {
    XcodeProject result;
    if (!build_products_root.empty())
        result.build_products_root_ = fs::absolute(build_products_root).lexically_normal();

    fs::path input =
        fs::absolute(project_or_directory)
            .lexically_normal();

    if (!fs::exists(input)) {
        return std::nullopt;
    }

    if (fs::is_regular_file(input) &&
        input.filename() == "project.pbxproj") {
        result.pbxproj_path_ = input;
        result.project_bundle_ =
            input.parent_path();
        result.source_root_ =
            result.project_bundle_.parent_path();
    } else if (
        fs::is_directory(input) &&
        ToLowerAscii(input.extension().string()) ==
            ".xcodeproj") {
        result.project_bundle_ = input;
        result.pbxproj_path_ =
            input / "project.pbxproj";
        result.source_root_ =
            input.parent_path();
    } else {
        result.source_root_ = input;

        fs::path preferred =
            input /
            (input.filename().wstring() +
             L".xcodeproj");

        if (fs::exists(
                preferred /
                "project.pbxproj")) {
            result.project_bundle_ =
                preferred;
            result.pbxproj_path_ =
                preferred /
                "project.pbxproj";
        } else {
            std::error_code ec;

            for (fs::directory_iterator it(
                     input,
                     fs::directory_options::
                         skip_permission_denied,
                     ec);
                 it != fs::directory_iterator();
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
                        ".xcodeproj") {
                    continue;
                }

                const fs::path pbx =
                    it->path() /
                    "project.pbxproj";

                if (fs::exists(pbx)) {
                    result.project_bundle_ =
                        it->path();
                    result.pbxproj_path_ =
                        pbx;
                    break;
                }
            }
        }
    }

    if (result.pbxproj_path_.empty() ||
        !fs::exists(result.pbxproj_path_)) {
        return std::nullopt;
    }

    return LoadMetadata(result.project_bundle_, ReadFileText(result.pbxproj_path_), build_products_root);
}

std::optional<XcodeProject> XcodeProject::LoadMetadata(
    const fs::path& logical_project_bundle, std::string_view pbx_bytes,
    const fs::path& build_products_root, XcodeMetadataReader reader) {
    if (logical_project_bundle.empty() || !logical_project_bundle.is_absolute() ||
        pbx_bytes.size() > UINT32_MAX) return std::nullopt;
    XcodeProject result;
    result.metadata_reader_ = std::move(reader);
    const auto logical = logical_project_bundle.lexically_normal();
    result.project_bundle_ = logical.filename() == "project.pbxproj" ? logical.parent_path() : logical;
    if (ToLowerAscii(result.project_bundle_.extension().string()) != ".xcodeproj") return std::nullopt;
    result.pbxproj_path_ = result.project_bundle_ / "project.pbxproj";
    result.source_root_ = result.project_bundle_.parent_path();
    result.project_name_ = result.project_bundle_.stem().string();
    if (!build_products_root.empty())
        result.build_products_root_ = fs::absolute(build_products_root).lexically_normal();
    std::string content(pbx_bytes);

    // A UTF-8 signature describes the text encoding, not an OpenStep token.
    // Decode it in memory without rewriting the original project bytes.
    if (content.size() >= 3 && content.compare(0, 3, "\xef\xbb\xbf") == 0) {
        content.erase(0, 3);
    }

    if (content.empty()) {
        return std::nullopt;
    }

    bool parsed_with_libplist = false;
    plist_t root = nullptr;
    plist_format_t format = PLIST_FORMAT_NONE;
    if (plist_from_memory(content.data(), static_cast<uint32_t>(content.size()), &root, &format) == PLIST_ERR_SUCCESS && root) {
        result.parsed_.root = ConvertPlistToValue(root);
        plist_free(root);
        result.parsed_.objects = result.parsed_.root.Get("objects");
        if (result.parsed_.objects && result.parsed_.objects->kind == Value::Kind::Dictionary) {
            parsed_with_libplist = true;
        }
    }

    if (!parsed_with_libplist) {
        OpenStepParser parser(content);
        result.parsed_.root = parser.Parse();
        result.parsed_.objects = result.parsed_.root.Get("objects");
    }

    if (!result.parsed_.objects ||
        result.parsed_.objects->kind !=
            Value::Kind::Dictionary) {
        return std::nullopt;
    }

    result.BuildParentGroupIndex();
    return result;
}

const XcodeProject::Value*
XcodeProject::Object(
    const XcodeObjectId& id
) const {
    const Value* objs = parsed_.Objects();
    if (!objs) {
        return nullptr;
    }

    const auto it =
        objs->dictionary.find(id);

    return it ==
        objs->dictionary.end()
        ? nullptr
        : &it->second;
}

void XcodeProject::BuildParentGroupIndex() {
    parent_group_.clear();

    const Value* objs = parsed_.Objects();
    if (!objs) {
        return;
    }

    for (const auto& [id, object] :
         objs->dictionary) {

        const std::string isa =
            object.String("isa");

        if (!IsGroupIsa(isa)) {
            continue;
        }

        for (const auto& child :
             object.StringArray("children")) {
            parent_group_.insert_or_assign(
                child,
                id
            );
        }
    }
}

std::vector<XcodeTarget>
XcodeProject::Targets() const {
    std::vector<XcodeTarget> result;

    const Value* objs = parsed_.Objects();
    if (!objs) {
        return result;
    }

    for (const auto& [id, object] :
         objs->dictionary) {

        const auto isa = object.String("isa");
        if (isa != "PBXNativeTarget" && isa != "PBXAggregateTarget" && isa != "PBXLegacyTarget") {
            continue;
        }

        XcodeTarget target;
        target.kind = isa == "PBXAggregateTarget" ? XcodeTargetKind::Aggregate :
            isa == "PBXLegacyTarget" ? XcodeTargetKind::Legacy : XcodeTargetKind::Native;
        target.id = id;
        target.name = object.String("name");

        if (target.name.empty()) {
            target.name =
                object.String("productName");
        }

        const std::string product_reference =
            object.String("productReference");
        if (!product_reference.empty()) {
            const Value* product = Object(product_reference);
            if (product) {
                std::string product_path = product->String("path");
                if (product_path.empty()) {
                    product_path = product->String("name");
                }
                if (product_path.empty()) {
                    product_path = product->String("_comment");
                }
                if (!product_path.empty()) {
                    target.product_name =
                        fs::path(product_path).stem().string();
                }
            }
        }

        if (target.product_name.empty()) {
            target.product_name = object.String("productName");
        }

        target.product_type =
            object.String("productType");

        target.build_configuration_list =
            object.String(
                "buildConfigurationList"
            );

        target.build_phases =
            object.StringArray(
                "buildPhases"
            );

        target.package_product_dependencies =
            object.StringArray(
                "packageProductDependencies"
            );
        // Xcode also links a package product referenced only by a build file
        // of the target's Frameworks phase; that reference is a dependency.
        for (const auto& phase_id : target.build_phases) {
            const Value* phase = Object(phase_id);
            if (!phase || phase->String("isa") != "PBXFrameworksBuildPhase") continue;
            for (const auto& file_id : phase->StringArray("files")) {
                const Value* build_file = Object(file_id);
                const auto product = build_file ? build_file->String("productRef") : std::string();
                const Value* reference = product.empty() ? nullptr : Object(product);
                if (reference && reference->String("isa") == "XCSwiftPackageProductDependency" &&
                    std::find(target.package_product_dependencies.begin(),
                              target.package_product_dependencies.end(), product) ==
                        target.package_product_dependencies.end())
                    target.package_product_dependencies.push_back(product);
            }
        }

        target.synchronized_groups =
            object.StringArray(
                "fileSystemSynchronizedGroups"
            );

        target.dependencies =
            object.StringArray(
                "dependencies"
            );

        result.push_back(
            std::move(target)
        );
    }

    std::sort(
        result.begin(),
        result.end(),
        [](const XcodeTarget& a,
           const XcodeTarget& b) {
            return a.name < b.name;
        }
    );

    return result;
}

std::optional<XcodeTarget>
XcodeProject::MainApplicationTarget() const {
    const auto targets = Targets();

    const std::string desired =
        ToLowerAscii(project_name_);

    for (const auto& target : targets) {
        if (target.product_type ==
                "com.apple.product-type.application" &&
            ToLowerAscii(target.name) == desired) {
            return target;
        }
    }

    for (const auto& target : targets) {
        if (target.product_type ==
            "com.apple.product-type.application") {
            return target;
        }
    }

    return std::nullopt;
}

std::optional<XcodeTarget>
XcodeProject::FindTarget(
    const std::string& name_or_id,
    std::string* error
) const {
    if (error) error->clear();
    const auto targets = Targets();
    for (const auto& target : targets)
        if (target.id == name_or_id) return target;
    const std::string desired = ToLowerAscii(name_or_id);
    std::optional<XcodeTarget> selected;
    for (const auto& target : targets) {
        if (ToLowerAscii(target.name) != desired) continue;
        if (selected) {
            if (error) *error = "Ambiguous target name '" + name_or_id + "' in " + project_bundle_.string();
            return std::nullopt;
        }
        selected = target;
    }
    if (!selected && error)
        *error = "Target '" + name_or_id + "' not found in " + project_bundle_.string();
    return selected;
}

std::vector<fs::path> XcodeProject::DiscoverWorkspaceProjects() const {
    std::vector<fs::path> projects;
    std::unordered_set<std::string> seen;

    auto add_proj = [&](const fs::path& p) {
        std::error_code ec;
        fs::path norm = fs::absolute(p, ec).lexically_normal();
        if (ec || !fs::exists(norm / "project.pbxproj", ec)) return;
        std::string s = norm.string();
        if (seen.insert(s).second) {
            projects.push_back(norm);
        }
    };

    add_proj(project_bundle_);

    fs::path search_dir = source_root_;
    for (int depth = 0; depth < 3 && !search_dir.empty(); ++depth) {
        std::error_code ec;
        for (fs::directory_iterator it(search_dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (it->is_directory(ec) && it->path().extension() == ".xcworkspace") {
                fs::path ws_dir = it->path();
                fs::path data_file = ws_dir / "contents.xcworkspacedata";
                if (fs::exists(data_file, ec)) {
                    std::string data = ReadFileText(data_file);
                    std::size_t pos = 0;
                    while ((pos = data.find("location", pos)) != std::string::npos) {
                        std::size_t eq = data.find('=', pos);
                        if (eq == std::string::npos) break;
                        std::size_t q1 = data.find('"', eq);
                        if (q1 == std::string::npos) break;
                        std::size_t q2 = data.find('"', q1 + 1);
                        if (q2 == std::string::npos) break;
                        std::string loc = data.substr(q1 + 1, q2 - q1 - 1);
                        pos = q2 + 1;

                        std::string rel = loc;
                        if (rel.rfind("group:", 0) == 0) rel = rel.substr(6);
                        else if (rel.rfind("container:", 0) == 0) rel = rel.substr(10);
                        else if (rel.rfind("file:", 0) == 0) rel = rel.substr(5);

                        if (rel.find(".xcodeproj") != std::string::npos) {
                            fs::path p = (ws_dir.parent_path() / rel).lexically_normal();
                            add_proj(p);
                        }
                    }
                }
            }
        }
        if (search_dir == search_dir.parent_path()) break;
        search_dir = search_dir.parent_path();
    }

    add_proj(source_root_ / "Pods" / "Pods.xcodeproj");
    add_proj(source_root_.parent_path() / "Pods" / "Pods.xcodeproj");

    return projects;
}

std::optional<std::string> XcodeProject::ResolveConfigurationName(
    const XcodeTarget& target, const std::optional<std::string>& requested,
    std::string* error) const {
    if (error) error->clear();
    const auto fail = [&](const std::string& message) -> std::optional<std::string> {
        if (error) *error = message;
        return std::nullopt;
    };
    struct Configurations {
        bool present = false;
        std::vector<std::string> names;
        std::string default_name;
    };
    const auto read = [&](const XcodeObjectId& id) -> std::optional<Configurations> {
        Configurations result;
        if (id.empty()) return result;
        const auto* list = Object(id);
        if (!list || list->String("isa") != "XCConfigurationList") return std::nullopt;
        result.present = true;
        result.default_name = list->String("defaultConfigurationName");
        for (const auto& config_id : list->StringArray("buildConfigurations")) {
            const auto* configuration = Object(config_id);
            if (!configuration || configuration->String("isa") != "XCBuildConfiguration" ||
                configuration->String("name").empty()) return std::nullopt;
            result.names.push_back(configuration->String("name"));
        }
        return result;
    };
    const auto target_configs = read(target.build_configuration_list);
    const auto* project = Object(parsed_.root.String("rootObject"));
    const auto project_configs = read(project ? project->String("buildConfigurationList") : "");
    if (!target_configs || !project_configs) return fail("Invalid authoritative build configuration list.");
    const auto& primary = target_configs->present ? *target_configs : *project_configs;
    if (!primary.present || primary.names.empty()) return fail("No authoritative build configuration is available.");
    const auto lookup = [&](const Configurations& list, const std::string& name) -> std::optional<std::string> {
        std::vector<std::string> matches;
        for (const auto& candidate : list.names) if (candidate == name) matches.push_back(candidate);
        if (matches.empty())
            for (const auto& candidate : list.names)
                if (ToLowerAscii(candidate) == ToLowerAscii(name)) matches.push_back(candidate);
        if (matches.size() != 1) return std::nullopt;
        return matches.front();
    };
    std::string desired;
    if (requested) {
        if (requested->empty()) return fail("Requested build configuration is empty.");
        desired = *requested;
    } else if (!project_configs->default_name.empty()) {
        desired = project_configs->default_name;
    } else if (!target_configs->default_name.empty()) {
        desired = target_configs->default_name;
    } else if (primary.names.size() == 1) {
        desired = primary.names.front();
    } else {
        return fail("Build configuration selection is ambiguous and has no authoritative default.");
    }
    const auto selected = lookup(primary, desired);
    if (!selected) return fail("Requested build configuration '" + desired + "' is absent or ambiguous.");
    for (const auto* configurations : {&*target_configs, &*project_configs}) {
        if (configurations->present && !lookup(*configurations, *selected))
            return fail("Build configuration '" + *selected + "' does not resolve uniquely in both project and target.");
    }
    return selected;
}

std::vector<XcodeTargetDependency>
XcodeProject::ResolveTargetDependencies(
    const XcodeTarget& target,
    const XcodeDependencyOptions& options
) const {
    std::vector<XcodeTargetDependency> result;
    const std::string root_obj_id = parsed_.root.String("rootObject");
    std::map<std::pair<fs::path, std::string>, std::size_t> seen_targets;

    auto add_dep = [&](XcodeTargetDependency dep) {
        std::error_code ec;
        auto owner = dep.project_path.empty() ? project_bundle_ : dep.project_path;
        if (owner.is_relative()) owner = source_root_ / owner;
        const auto canonical = fs::weakly_canonical(owner, ec);
        if (!ec) owner = canonical;
        const auto identity = !dep.target_id.empty() ? "id:" + dep.target_id :
            "name:" + dep.target_name + "\n" + dep.name + "\n" + dep.resolution_error;
        const auto [entry, inserted] = seen_targets.emplace(std::make_pair(owner.lexically_normal(), identity), result.size());
        if (inserted) result.push_back(std::move(dep));
        else if (result[entry->second].scheme_entry && !dep.scheme_entry)
            result[entry->second] = std::move(dep); // Required edge outranks co-build membership.
    };

    for (const auto& dep_id : target.dependencies) {
        XcodeTargetDependency dep;
        const Value* dep_obj = Object(dep_id);
        if (!dep_obj || dep_obj->String("isa") != "PBXTargetDependency") {
            dep.name = dep_id;
            dep.resolution_error = "Missing or invalid PBXTargetDependency object: " + dep_id;
            add_dep(std::move(dep));
            continue;
        }
        dep.name = dep_obj->String("name");
        const auto local_id = dep_obj->String("target");
        if (!local_id.empty()) {
            dep.target_id = local_id;
            const Value* local_target = Object(local_id);
            if (!local_target) {
                dep.resolution_error = "Missing local target object: " + local_id;
            } else {
                dep.target_name = local_target->String("name");
                if (dep.target_name.empty()) dep.target_name = local_target->String("productName");
                if (dep.name.empty()) dep.name = dep.target_name;
            }
            add_dep(std::move(dep));
            continue;
        }
        const auto proxy_id = dep_obj->String("targetProxy");
        const Value* proxy = Object(proxy_id);
        if (!proxy || proxy->String("isa") != "PBXContainerItemProxy") {
            dep.resolution_error = "Missing or invalid target proxy for dependency: " + dep_id;
        } else {
            const auto portal = proxy->String("containerPortal");
            dep.target_name = proxy->String("remoteInfo");
            dep.target_id = proxy->String("remoteGlobalIDString");
            if (dep.name.empty()) dep.name = dep.target_name;
            if (portal != root_obj_id && portal != "Project object" && !portal.empty()) {
                dep.is_subproject = true;
                dep.project_path = ResolveFileReference(portal);
                if (dep.project_path.empty()) dep.resolution_error = "Unresolved target proxy project: " + portal;
            }
            if (dep.target_name.empty() && dep.target_id.empty())
                dep.resolution_error = "Target proxy has no target identity: " + proxy_id;
        }
        add_dep(std::move(dep));
    }

    const std::vector<fs::path> workspace_projects = DiscoverWorkspaceProjects();

    if (options.include_scheme) {
    // Scheme BuildActionEntries resolution
    std::vector<fs::path> scheme_search_dirs;
    scheme_search_dirs.push_back(project_bundle_ / "xcshareddata" / "xcschemes");
    for (const auto& wp : workspace_projects) {
        scheme_search_dirs.push_back(wp / "xcshareddata" / "xcschemes");
    }
    fs::path cur_scan = source_root_;
    for (int d = 0; d < 3 && !cur_scan.empty(); ++d) {
        std::error_code ec;
        for (fs::directory_iterator it(cur_scan, ec); it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (it->is_directory(ec) && it->path().extension() == ".xcworkspace") {
                scheme_search_dirs.push_back(it->path() / "xcshareddata" / "xcschemes");
            }
        }
        if (cur_scan == cur_scan.parent_path()) break;
        cur_scan = cur_scan.parent_path();
    }

    std::map<fs::path, fs::path> scheme_candidates;
    for (const auto& sdir : scheme_search_dirs) {
        const auto file = sdir / (target.name + ".xcscheme");
        std::error_code error;
        const bool exists = fs::exists(file, error);
        if (!exists && !error) continue;
        const auto canonical = exists ? fs::canonical(file, error) : fs::path();
        if (error) {
            XcodeTargetDependency invalid;
            invalid.scheme_entry = true;
            invalid.resolution_error = "Cannot identify scheme: " + file.string() + ": " + error.message();
            add_dep(std::move(invalid));
            continue;
        }
        scheme_candidates.emplace(canonical, file);
    }
    if (scheme_candidates.size() > 1) {
        XcodeTargetDependency invalid;
        invalid.scheme_entry = true;
        invalid.resolution_error = "Ambiguous implicit scheme '" + target.name + "':";
        for (const auto& [canonical, file] : scheme_candidates)
            invalid.resolution_error += " " + file.string();
        add_dep(std::move(invalid));
        scheme_candidates.clear();
    }
    for (const auto& [canonical, scheme_file] : scheme_candidates) {
        std::error_code ec;
        // Shared schemes are owned by this .xcodeproj or .xcworkspace, not
        // necessarily by the target's source directory.
        const auto scheme_owner = scheme_file.parent_path().parent_path().parent_path();
        const auto scheme_container_root = scheme_owner.parent_path();
        std::string scheme_xml = ReadFileText(scheme_file);
        std::size_t ba_start = scheme_xml.find("<BuildActionEntries>");
        std::size_t ba_end = scheme_xml.find("</BuildActionEntries>");
        if (ba_start == std::string::npos || ba_end == std::string::npos || ba_end < ba_start) {
            XcodeTargetDependency invalid;
            invalid.scheme_entry = true;
            invalid.resolution_error = "Missing or malformed scheme BuildActionEntries: " + scheme_file.string();
            add_dep(std::move(invalid));
            continue;
        }

        const auto attribute = [](const std::string& tag, const std::string& name) -> std::string {
            std::size_t pos = 0;
            while ((pos = tag.find(name, pos)) != std::string::npos) {
                const auto start = pos;
                pos += name.size();
                if (start && !std::isspace(static_cast<unsigned char>(tag[start - 1]))) continue;
                auto equal = pos;
                while (equal < tag.size() && std::isspace(static_cast<unsigned char>(tag[equal]))) ++equal;
                if (equal == tag.size() || tag[equal++] != '=') continue;
                while (equal < tag.size() && std::isspace(static_cast<unsigned char>(tag[equal]))) ++equal;
                if (equal == tag.size() || (tag[equal] != '"' && tag[equal] != '\'')) continue;
                const auto end = tag.find(tag[equal], equal + 1);
                if (end == std::string::npos) return {};
                return tag.substr(equal + 1, end - equal - 1);
            }
            return {};
        };
        std::size_t pos = ba_start + std::string("<BuildActionEntries>").size();
        while ((pos = scheme_xml.find("<BuildActionEntry", pos)) != std::string::npos && pos < ba_end) {
            const auto entry_begin = pos;
            const auto entry_open_end = scheme_xml.find('>', entry_begin);
            const auto entry_end = entry_open_end == std::string::npos ? std::string::npos :
                scheme_xml.find("</BuildActionEntry>", entry_open_end);
            if (entry_open_end == std::string::npos || entry_end == std::string::npos || entry_end > ba_end) {
                XcodeTargetDependency invalid;
                invalid.scheme_entry = true;
                invalid.resolution_error = "Malformed scheme build entry: " + scheme_file.string();
                add_dep(std::move(invalid));
                break;
            }
            const auto entry_tag = scheme_xml.substr(entry_begin, entry_open_end - entry_begin);
            pos = entry_end + std::string("</BuildActionEntry>").size();
            // This API currently plans product builds, without a precise scheme
            // action. Omit only explicitly disabled entries for ALL product
            // actions. Missing/unknown flags stay conservative required entries.
            if (attribute(entry_tag, "buildForRunning") == "NO" &&
                attribute(entry_tag, "buildForProfiling") == "NO" &&
                attribute(entry_tag, "buildForArchiving") == "NO" &&
                attribute(entry_tag, "buildForAnalyzing") == "NO") continue;
            const auto ref_begin = scheme_xml.find("<BuildableReference", entry_open_end);
            const auto ref_end = ref_begin == std::string::npos ? std::string::npos : scheme_xml.find('>', ref_begin);
            if (ref_begin == std::string::npos || ref_begin >= entry_end ||
                ref_end == std::string::npos || ref_end >= entry_end) {
                XcodeTargetDependency invalid;
                invalid.scheme_entry = true;
                invalid.resolution_error = "Missing or malformed scheme build reference: " + scheme_file.string();
                add_dep(std::move(invalid));
                continue;
            }
            const auto ref_block = scheme_xml.substr(ref_begin, ref_end - ref_begin);
            const auto extract_attr = [&](const std::string& name) { return attribute(ref_block, name); };

            std::string bp_name = extract_attr("BlueprintName");
            std::string bp_id = extract_attr("BlueprintIdentifier");
            std::string container = extract_attr("ReferencedContainer");

            if (bp_name.empty() && bp_id.empty()) {
                XcodeTargetDependency invalid;
                invalid.scheme_entry = true;
                invalid.resolution_error = "Scheme build reference has no target identity: " + scheme_file.string();
                add_dep(std::move(invalid));
                continue;
            }

            if (!bp_name.empty() || !bp_id.empty()) {
                std::string rel_container = container;
                if (rel_container.rfind("container:", 0) == 0) rel_container = rel_container.substr(10);
                else if (!rel_container.empty()) {
                    XcodeTargetDependency invalid;
                    invalid.scheme_entry = true;
                    invalid.resolution_error = "Unsupported scheme container reference: " + container;
                    add_dep(std::move(invalid));
                    continue;
                }
                // An explicit container is authoritative. Never adopt a same-
                // filename project elsewhere after its requested path fails.
                fs::path container_proj = rel_container.empty() ? project_bundle_ :
                    (scheme_container_root / rel_container).lexically_normal();
                std::error_code canonical_error;
                const auto owner = fs::weakly_canonical(container_proj, canonical_error);
                const auto own_project = fs::weakly_canonical(project_bundle_, ec);
                const bool own_container = !canonical_error && !ec && owner == own_project;
                // The selected target appears in its own scheme co-build list.
                // A different same-name target in another project is not self.
                if (own_container && ((!bp_id.empty() && bp_id == target.id) ||
                    (bp_id.empty() && bp_name == target.name))) continue;
                auto sub_proj = LoadRelatedProject(container_proj);
                if (sub_proj) {
                    // BlueprintIdentifier is authoritative; names are labels.
                    std::optional<XcodeTarget> sub_target;
                    for (const auto& candidate : sub_proj->Targets()) {
                        if (!bp_id.empty() ? candidate.id == bp_id : candidate.name == bp_name) {
                            if (sub_target) { sub_target.reset(); break; }
                            sub_target = candidate;
                        }
                    }
                    if (sub_target && (sub_target->product_type.find("unit-test") != std::string::npos ||
                        sub_target->product_type.find("ui-testing") != std::string::npos)) continue;
                }
                XcodeTargetDependency dep;
                dep.name = bp_name;
                dep.target_name = bp_name;
                dep.target_id = bp_id;
                dep.project_path = container_proj;
                dep.is_subproject = !own_container;
                dep.scheme_entry = true;
                if (!sub_proj) dep.resolution_error = "Cannot load scheme build project: " + container_proj.string();
                add_dep(std::move(dep));
            }
        }
        break;
    }

    }

    if (options.infer_linked_products) {
    // Implicit dependencies from PBXFrameworksBuildPhase
    for (const auto& phase_id : target.build_phases) {
        const Value* phase_obj = Object(phase_id);
        if (!phase_obj || phase_obj->String("isa") != "PBXFrameworksBuildPhase") continue;
        const Value* files = phase_obj->Get("files");
        if (!files || files->kind != Value::Kind::Array) continue;

        for (const auto& file_val : files->array) {
            const Value* build_file = Object(file_val.string);
            if (!build_file) continue;
            std::string file_ref_id = build_file->String("fileRef");
            const Value* file_ref = Object(file_ref_id);
            if (!file_ref) continue;

            std::string source_tree = file_ref->String("sourceTree");
            std::string ref_path = file_ref->String("path");
            if (ref_path.empty()) ref_path = file_ref->String("name");

            if (source_tree == "BUILT_PRODUCTS_DIR" ||
                (ref_path.size() >= 2 && ref_path.rfind(".a") == ref_path.size() - 2) ||
                (ref_path.size() >= 10 && ref_path.rfind(".framework") == ref_path.size() - 10)) {

                std::string stem = fs::path(ref_path).stem().string();
                if (stem.rfind("lib", 0) == 0) stem = stem.substr(3);

                for (const auto& wp : workspace_projects) {
                    if (wp == project_bundle_) continue;
                    auto sub_proj = LoadRelatedProject(wp);
                    if (!sub_proj) continue;
                    for (const auto& sub_target : sub_proj->Targets()) {
                        if (sub_target.kind != XcodeTargetKind::Native) continue;
                        if (sub_target.name == stem || sub_target.name == ref_path) {
                            XcodeTargetDependency dep;
                            dep.name = sub_target.name;
                            dep.target_name = sub_target.name;
                            dep.target_id = sub_target.id;
                            dep.project_path = wp;
                            dep.is_subproject = true;
                            add_dep(std::move(dep));
                            break;
                        }
                    }
                }
            }
        }
    }

    }
    return result;
}

fs::path XcodeProject::ResolveGroupPath(
    const XcodeObjectId& id,
    std::unordered_set<XcodeObjectId>& recursion_guard
) const {
    if (!recursion_guard.insert(id).second) {
        return source_root_;
    }

    const Value* object =
        Object(id);

    if (!object) {
        return source_root_;
    }

    const std::string source_tree =
        object->String("sourceTree");

    /*
     * PBXGroup.name is a navigator label, not a filesystem component.
     * Xcode groups commonly use `name = Frameworks` with no `path`; children
     * of such a group remain relative to the parent group.  Treating the
     * display name as a path incorrectly turns references such as
     * Carthage/Build/Foo.xcframework into Frameworks/Carthage/Build/....
     * Only an explicit `path` contributes to group path resolution.
     */
    const std::string path =
        object->String("path");

    fs::path base;

    if (source_tree == "SOURCE_ROOT" ||
        source_tree == "PROJECT_DIR") {
        base = source_root_;
    } else if (
        source_tree == "<absolute>") {
        base.clear();
    } else {
        const auto parent =
            parent_group_.find(id);

        if (parent ==
            parent_group_.end()) {
            base = source_root_;
        } else {
            base = ResolveGroupPath(
                parent->second,
                recursion_guard
            );
        }
    }

    recursion_guard.erase(id);

    if (path.empty()) {
        return base;
    }

    fs::path p(path);

    if (p.is_absolute()) {
        return p.lexically_normal();
    }

    return (base / p)
        .lexically_normal();
}

fs::path XcodeProject::ResolveFileReference(
    const XcodeObjectId& id
) const {
    const auto cached =
        resolved_file_paths_.find(id);

    if (cached !=
        resolved_file_paths_.end()) {
        return cached->second;
    }

    const Value* object =
        Object(id);

    if (!object) {
        return {};
    }

    const std::string source_tree =
        object->String("sourceTree");

    std::string path =
        object->String("path");

    if (path.empty()) {
        path =
            object->String("name");
    }

    if (path.empty()) {
        return {};
    }

    fs::path resolved;

    if (source_tree == "SOURCE_ROOT" ||
        source_tree == "PROJECT_DIR") {
        resolved =
            source_root_ /
            fs::path(path);
    } else if (
        source_tree == "<absolute>") {
        resolved = fs::path(path);
    } else if (
        source_tree == "SDKROOT" ||
        source_tree == "BUILT_PRODUCTS_DIR" ||
        source_tree == "DEVELOPER_DIR") {
        return {};
    } else {
        const auto parent =
            parent_group_.find(id);

        if (parent ==
            parent_group_.end()) {
            resolved =
                source_root_ /
                fs::path(path);
        } else {
            std::unordered_set<XcodeObjectId>
                guard;

            resolved =
                ResolveGroupPath(
                    parent->second,
                    guard
                ) /
                fs::path(path);
        }
    }

    resolved =
        resolved.lexically_normal();

    resolved_file_paths_.insert_or_assign(
        id,
        resolved
    );

    return resolved;
}

std::optional<std::string> XcodeProject::ReadMetadata(const fs::path& path) const {
    if (metadata_reader_) return metadata_reader_(path);
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::optional<XcodeProject> XcodeProject::LoadRelatedProject(const fs::path& project_or_bundle) const {
    if (project_or_bundle.empty()) return std::nullopt;
    std::error_code ec;
    fs::path bundle = project_or_bundle.is_absolute()
        ? project_or_bundle.lexically_normal()
        : fs::absolute(source_root_ / project_or_bundle, ec).lexically_normal();
    if (bundle.filename() == "project.pbxproj") {
        bundle = bundle.parent_path();
    }
    if (metadata_reader_) {
        const fs::path pbx = bundle / "project.pbxproj";
        if (const auto bytes = metadata_reader_(pbx)) {
            return LoadMetadata(bundle, *bytes, build_products_root_, metadata_reader_);
        }
    }
    return Load(bundle, build_products_root_);
}

static bool MatchGlobPattern(std::string_view text, std::string_view pattern, bool case_sensitive = false);

struct XcodeBuildConditionContext {
    std::string configuration;
    std::string sdk = "iphoneos";
    std::string arch = "arm64";
    std::string variant = "normal";
};

struct EvaluatedXcodeBuildSettingKey {
    bool matched = true;
    bool invalid_syntax = false;
    std::string base_key;
    std::size_t condition_count = 0;
    std::size_t specificity = 0;
};

static bool WildcardMatchCaseInsensitive(std::string_view text, std::string_view pattern) {
    return MatchGlobPattern(text, pattern, false);
}

static EvaluatedXcodeBuildSettingKey EvaluateXcodeBuildSettingKey(
    std::string_view raw_key,
    const XcodeBuildConditionContext& ctx
) {
    EvaluatedXcodeBuildSettingKey result;
    const std::string trimmed_raw = TrimWhitespace(std::string(raw_key));
    if (trimmed_raw.empty()) {
        result.matched = false;
        result.invalid_syntax = true;
        return result;
    }

    const auto qualifier = trimmed_raw.find('[');
    if (qualifier == std::string::npos) {
        if (trimmed_raw.find(']') != std::string::npos) {
            result.matched = false;
            result.invalid_syntax = true;
            return result;
        }
        result.base_key = trimmed_raw;
        return result;
    }

    result.base_key = TrimWhitespace(trimmed_raw.substr(0, qualifier));
    if (result.base_key.empty() || result.base_key.find(']') != std::string::npos) {
        result.matched = false;
        result.invalid_syntax = true;
        return result;
    }

    bool unknown_parameter = false;
    std::size_t cursor = qualifier;
    while (cursor < trimmed_raw.size()) {
        while (cursor < trimmed_raw.size() &&
               std::isspace(static_cast<unsigned char>(trimmed_raw[cursor]))) {
            ++cursor;
        }
        if (cursor == trimmed_raw.size()) break;
        const auto end = trimmed_raw.find(']', cursor + 1);
        const auto condition = end == std::string::npos
            ? std::string()
            : trimmed_raw.substr(cursor + 1, end - cursor - 1);
        const auto condition_equal = condition.find('=');
        if (trimmed_raw[cursor] != '[' ||
            end == std::string::npos ||
            condition.find('[') != std::string::npos ||
            condition_equal == std::string::npos) {
            result.matched = false;
            result.invalid_syntax = true;
            return result;
        }
        const auto parameter = TrimWhitespace(condition.substr(0, condition_equal));
        const auto pattern = TrimWhitespace(condition.substr(condition_equal + 1));
        if (parameter.empty() || pattern.empty() ||
            pattern.find_first_of("[\\") != std::string::npos) {
            result.matched = false;
            result.invalid_syntax = true;
            return result;
        }

        bool clause_matches = false;
        if (parameter == "config") {
            // Swift Build uses fnmatch without case folding for configuration patterns.
            clause_matches = MatchGlobPattern(ctx.configuration, pattern, true);
        } else if (parameter == "sdk") {
            clause_matches = WildcardMatchCaseInsensitive(ctx.sdk, pattern);
        } else if (parameter == "arch") {
            clause_matches = WildcardMatchCaseInsensitive(ctx.arch, pattern);
        } else if (parameter == "variant") {
            clause_matches = WildcardMatchCaseInsensitive(ctx.variant, pattern);
        } else {
            unknown_parameter = true;
        }

        ++result.condition_count;
        std::size_t literal_chars = 0;
        for (char c : pattern) {
            if (c != '*' && c != '?') ++literal_chars;
        }
        result.specificity += literal_chars * 10 + (pattern.find_first_of("*?") == std::string::npos ? 5 : 0);
        if (!unknown_parameter) {
            result.matched = result.matched && clause_matches;
        }
        cursor = end + 1;
    }

    if (result.condition_count == 0) {
        result.matched = false;
        result.invalid_syntax = true;
        return result;
    }

    if (unknown_parameter) {
        if (result.matched) {
            result.invalid_syntax = true;
        }
        result.matched = false;
    }
    return result;
}

void XcodeProject::MergeXcconfig(
    const fs::path& xcconfig,
    std::unordered_map<
        std::string,
        std::string
    >& values,
    std::unordered_set<std::string>& visited,
    const std::string& configuration,
    bool strict_build_settings,
    bool optional
) const {
    const bool strict = strict_build_settings || static_cast<bool>(metadata_reader_);
    std::error_code ec;
    fs::path absolute =
        fs::absolute(xcconfig, ec)
            .lexically_normal();

    if (ec) {
        absolute = xcconfig;
    }

    const std::string key =
        ToLowerAscii(absolute.string());

    if (!visited.insert(key).second) return;
    auto bytes = ReadMetadata(absolute);
    if (!bytes) {
        if (strict && !optional)
            throw std::runtime_error("Cannot read required Xcode configuration metadata: " + absolute.string());
        return;
    }
    if (bytes->size() >= 3 && bytes->compare(0, 3, "\xef\xbb\xbf") == 0) bytes->erase(0, 3);
    std::istringstream input(*bytes);

    std::string line;

    while (std::getline(input, line)) {
        std::string trimmed =
            TrimWhitespace(line);

        if (trimmed.empty() ||
            trimmed.rfind("//", 0) == 0) {
            continue;
        }

        if (trimmed.rfind("#include", 0) ==
            0) {
            const std::size_t first =
                trimmed.find('"');

            const std::size_t last =
                trimmed.find_last_of('"');

            if (first != std::string::npos &&
                last != std::string::npos &&
                last > first) {

                MergeXcconfig(
                    absolute.parent_path() /
                    trimmed.substr(
                        first + 1,
                        last - first - 1
                    ),
                    values,
                    visited,
                    configuration,
                    strict,
                    trimmed.rfind("#include?", 0) == 0
                );
            } else if (strict) {
                throw std::runtime_error("Malformed Xcode configuration include: " + absolute.string());
            }

            continue;
        }

        const std::size_t comment =
            trimmed.find("//");

        if (comment != std::string::npos) {
            trimmed.resize(comment);
        }

        // Conditional expressions contain '=' before the assignment itself.
        std::size_t equal = std::string::npos;
        unsigned brackets = 0;
        for (std::size_t i = 0; i < trimmed.size(); ++i) {
            if (trimmed[i] == '[') ++brackets;
            else if (trimmed[i] == ']' && brackets) --brackets;
            else if (trimmed[i] == '=' && !brackets) { equal = i; break; }
        }

        if (equal == std::string::npos) {
            if (strict && brackets)
                throw std::runtime_error("Unterminated Xcode configuration condition: " + absolute.string());
            continue;
        }

        std::string name =
            TrimWhitespace(trimmed.substr(0, equal));

        std::string value =
            UnquoteXcconfigValue(
                trimmed.substr(equal + 1)
            );

        XcodeBuildConditionContext ctx;
        ctx.configuration = configuration;
        const auto evaluated = EvaluateXcodeBuildSettingKey(name, ctx);
        if (evaluated.invalid_syntax) {
            if (strict) {
                throw std::runtime_error("Unsupported or malformed xcconfig conditional key '" + name + "' in " + absolute.string());
            }
            continue;
        }
        if (!evaluated.matched) {
            continue;
        }

        if (!evaluated.base_key.empty()) {
            MergeBuildSetting(values, evaluated.base_key, std::move(value));
        }
    }
}

std::unordered_map<std::string, std::string>
XcodeProject::ConfigurationSettings(
    const XcodeObjectId& configuration_list,
    const std::string& configuration,
    std::string* selected_name,
    bool strict_build_settings
) const {
    const bool strict = strict_build_settings || static_cast<bool>(metadata_reader_);
    std::unordered_map<
        std::string,
        std::string
    > result;

    const Value* list =
        Object(configuration_list);

    if (!list) {
        if (strict && !configuration_list.empty())
            throw std::runtime_error("Missing Xcode configuration list: " + configuration_list);
        return result;
    }

    const auto config_ids =
        list->StringArray(
            "buildConfigurations"
        );

    const Value* selected = nullptr;

    for (const auto& id : config_ids) {
        const Value* config =
            Object(id);

        if (!config) {
            continue;
        }

        if (strict) continue;
        if (ToLowerAscii(config->String("name")) ==
            ToLowerAscii(configuration)) {
            selected = config;
            break;
        }

        if (!selected) {
            selected = config;
        }
    }

    if (strict) {
        for (const bool exact : {true, false}) {
            std::size_t matches = 0;
            for (const auto& id : config_ids) {
                const auto* candidate = Object(id);
                if (!candidate || candidate->String("isa") != "XCBuildConfiguration")
                    throw std::runtime_error("Invalid Xcode build configuration: " + id);
                const auto name = candidate->String("name");
                if (exact ? name == configuration : ToLowerAscii(name) == ToLowerAscii(configuration)) {
                    selected = candidate; ++matches;
                }
            }
            if (matches > 1) throw std::runtime_error("Ambiguous Xcode build configuration: " + configuration);
            if (matches == 1) break;
        }
        if (!selected) throw std::runtime_error("Missing Xcode build configuration: " + configuration);
    }

    if (!selected) {
        return result;
    }

    const std::string active_config_name =
        selected->String("name").empty() ? configuration : selected->String("name");

    if (selected_name) {
        *selected_name = selected->String("name");
    }

    fs::path base;
    const std::string base_ref =
        selected->String(
            "baseConfigurationReference"
        );

    if (!base_ref.empty()) {
        base = ResolveFileReference(
            base_ref
        );
    } else {
        /*
         * Xcode 16+ may represent an xcconfig without a PBXFileReference:
         * the configuration names a file-system-synchronized root group as
         * an anchor and stores the path relative to that group.  This is the
         * same base-configuration semantic as baseConfigurationReference,
         * only a different project-file representation.
         */
        const std::string anchor_ref =
            selected->String(
                "baseConfigurationReferenceAnchor"
            );
        const std::string relative_path =
            selected->String(
                "baseConfigurationReferenceRelativePath"
            );

        if (!anchor_ref.empty() &&
            !relative_path.empty()) {
            base = ResolveFileReference(
                       anchor_ref
                   ) /
                   fs::path(relative_path);
        }
    }

    if (!base.empty()) {

        std::unordered_set<std::string>
            visited;

        MergeXcconfig(
            base,
            result,
            visited,
            active_config_name,
            strict
        );
    }

    const Value* build_settings =
        selected->Get(
            "buildSettings"
        );

    if (build_settings &&
        build_settings->kind ==
            Value::Kind::Dictionary) {

        XcodeBuildConditionContext ctx;
        ctx.configuration = active_config_name;

        struct MatchedBuildSettingEntry {
            std::string base_key;
            std::string raw_key;
            std::string value;
            std::size_t condition_count = 0;
            std::size_t specificity = 0;
        };
        std::vector<MatchedBuildSettingEntry> matched_entries;
        matched_entries.reserve(build_settings->dictionary.size());

        for (const auto& [key, value] :
             build_settings->dictionary) {

            std::string string_value;
            bool has_value = false;
            if (value.kind == Value::Kind::String) {
                string_value = value.string;
                has_value = true;
            } else if (value.kind == Value::Kind::Array) {
                std::ostringstream joined;
                bool first = true;
                for (const auto& item : value.array) {
                    if (item.kind != Value::Kind::String) {
                        continue;
                    }
                    if (!first) {
                        joined << ' ';
                    }
                    first = false;
                    joined << item.string;
                }
                string_value = joined.str();
                has_value = true;
            }
            if (!has_value) continue;

            const auto evaluated = EvaluateXcodeBuildSettingKey(key, ctx);
            if (evaluated.invalid_syntax) {
                if (strict) {
                    throw std::runtime_error("Unsupported or malformed Xcode build setting condition: " + key);
                }
                continue;
            }
            if (!evaluated.matched || evaluated.base_key.empty()) {
                continue;
            }

            matched_entries.push_back(MatchedBuildSettingEntry{
                evaluated.base_key,
                key,
                std::move(string_value),
                evaluated.condition_count,
                evaluated.specificity
            });
        }

        std::sort(
            matched_entries.begin(),
            matched_entries.end(),
            [](const MatchedBuildSettingEntry& a, const MatchedBuildSettingEntry& b) {
                return std::tie(a.base_key, a.condition_count, a.specificity, a.raw_key) <
                       std::tie(b.base_key, b.condition_count, b.specificity, b.raw_key);
            }
        );

        for (auto& entry : matched_entries) {
            MergeBuildSetting(result, entry.base_key, std::move(entry.value));
        }
    }

    return result;
}

std::string XcodeProject::ExpandBuildSetting(
    std::string value,
    const std::unordered_map<
        std::string,
        std::string
    >& settings
) const {
    for (int pass = 0;
         pass < 16;
         ++pass) {

        bool changed = false;

        for (std::size_t pos = 0;
             pos < value.size();) {

            std::size_t begin =
                value.find("$(", pos);

            char close = ')';

            const std::size_t alt =
                value.find("${", pos);

            if (alt != std::string::npos &&
                (begin == std::string::npos ||
                 alt < begin)) {
                begin = alt;
                close = '}';
            }

            if (begin ==
                std::string::npos) {
                break;
            }

            const std::size_t end =
                value.find(
                    close,
                    begin + 2
                );

            if (end ==
                std::string::npos) {
                break;
            }

            const std::string expression =
                value.substr(
                    begin + 2,
                    end - begin - 2
                );

            const std::size_t colon =
                expression.find(':');

            const std::string key =
                colon == std::string::npos
                    ? expression
                    : expression.substr(
                          0,
                          colon
                      );

            const std::string modifier =
                colon == std::string::npos
                    ? std::string()
                    : expression.substr(
                          colon + 1
                      );

            const auto it =
                settings.find(key);

            if (it ==
                settings.end()) {
                pos = end + 1;
                continue;
            }

            std::string target_value = it->second;
            if (!modifier.empty()) {
                for (int mod_pass = 0; mod_pass < 8; ++mod_pass) {
                    if (target_value.find("$(") == std::string::npos &&
                        target_value.find("${") == std::string::npos) {
                        break;
                    }
                    std::string next_target = target_value;
                    for (std::size_t tpos = 0; tpos < next_target.size();) {
                        std::size_t tbegin = next_target.find("$(", tpos);
                        char tclose = ')';
                        const std::size_t talt = next_target.find("${", tpos);
                        if (talt != std::string::npos &&
                            (tbegin == std::string::npos || talt < tbegin)) {
                            tbegin = talt;
                            tclose = '}';
                        }
                        if (tbegin == std::string::npos) break;
                        const std::size_t tend = next_target.find(tclose, tbegin + 2);
                        if (tend == std::string::npos) break;
                        const std::string texpr =
                            next_target.substr(tbegin + 2, tend - tbegin - 2);
                        const std::size_t tcolon = texpr.find(':');
                        const std::string tkey =
                            tcolon == std::string::npos ? texpr : texpr.substr(0, tcolon);
                        const std::string tmod =
                            tcolon == std::string::npos ? std::string() : texpr.substr(tcolon + 1);
                        const auto tit = settings.find(tkey);
                        if (tit == settings.end() || tkey == key) {
                            tpos = tend + 1;
                            continue;
                        }
                        std::string trepl = tit->second;
                        if (!tmod.empty() &&
                            trepl.find("$(") == std::string::npos &&
                            trepl.find("${") == std::string::npos) {
                            std::size_t mstart = 0;
                            while (mstart <= tmod.size()) {
                                const std::size_t mend = tmod.find(':', mstart);
                                const std::string mpart =
                                    mend == std::string::npos
                                        ? tmod.substr(mstart)
                                        : tmod.substr(mstart, mend - mstart);
                                if (!mpart.empty()) {
                                    trepl = ApplyXcodeBuildSettingModifier(std::move(trepl), mpart);
                                }
                                if (mend == std::string::npos) break;
                                mstart = mend + 1;
                            }
                        }
                        next_target.replace(tbegin, tend - tbegin + 1, trepl);
                        tpos = tbegin + trepl.size();
                    }
                    if (next_target == target_value) break;
                    target_value = std::move(next_target);
                }
            }

            std::string replacement = target_value;
            if (!modifier.empty()) {
                std::size_t mstart = 0;
                while (mstart <= modifier.size()) {
                    const std::size_t mend = modifier.find(':', mstart);
                    const std::string mpart =
                        mend == std::string::npos
                            ? modifier.substr(mstart)
                            : modifier.substr(mstart, mend - mstart);
                    if (!mpart.empty()) {
                        replacement = ApplyXcodeBuildSettingModifier(
                            std::move(replacement),
                            mpart
                        );
                    }
                    if (mend == std::string::npos) break;
                    mstart = mend + 1;
                }
            }

            value.replace(
                begin,
                end - begin + 1,
                replacement
            );

            changed = true;
            pos =
                begin +
                replacement.size();
        }

        if (!changed) {
            break;
        }
    }

    return value;
}

std::unordered_map<std::string, std::string>
XcodeProject::ResolveBuildSettings(
    const XcodeTarget& target,
    const std::string& configuration,
    bool strict_build_settings
) const {
    std::unordered_map<
        std::string,
        std::string
    > settings;

    std::string selected_configuration;
    const auto target_settings =
        ConfigurationSettings(
            target.build_configuration_list,
            configuration,
            &selected_configuration,
            strict_build_settings
        );
    if (selected_configuration.empty()) {
        selected_configuration = configuration;
    }

    settings["SRCROOT"] =
        source_root_.string();

    settings["SOURCE_ROOT"] =
        source_root_.string();

    settings["PROJECT_DIR"] =
        source_root_.string();

    settings["PROJECT_NAME"] =
        project_name_;
    settings["PROJECT_FILE_PATH"] = project_bundle_.string();

    settings["TARGET_NAME"] =
        target.name;

    settings["PRODUCT_NAME"] =
        target.product_name.empty()
            ? "$(TARGET_NAME)"
            : target.product_name;

    settings["PRODUCT_MODULE_NAME"] =
        "$(PRODUCT_NAME:c99extidentifier)";

    settings["EXECUTABLE_PREFIX"] =
        "";

    settings["EXECUTABLE_SUFFIX"] =
        "";

    settings["EXECUTABLE_NAME"] =
        "$(EXECUTABLE_PREFIX)$(PRODUCT_NAME)$(EXECUTABLE_SUFFIX)";

    settings["CONFIGURATION"] =
        selected_configuration;

    settings["PLATFORM_NAME"] =
        "iphoneos";

    settings["EFFECTIVE_PLATFORM_NAME"] =
        "";

    // The build invocation supplies its managed product location before any
    // setting expansion. Inspection without a context uses a discovered source
    // marker, or the project source directory; never a filesystem drive root.
    fs::path repo_root = source_root_;
    if (build_products_root_.empty()) {
        for (auto candidate = source_root_;
             !candidate.empty() && candidate != candidate.parent_path();
             candidate = candidate.parent_path()) {
            std::error_code ec;
            bool marker = fs::exists(candidate / ".git", ec);
            if (!marker) {
                for (fs::directory_iterator it(candidate, ec);
                     !ec && it != fs::directory_iterator(); it.increment(ec)) {
                    if (it->is_directory(ec) && it->path().extension() == ".xcworkspace") {
                        marker = true;
                        break;
                    }
                }
            }
            if (marker) { repo_root = candidate; break; }
        }
    }
    const fs::path build_products = build_products_root_.empty()
        ? repo_root / "build" / "Products" : build_products_root_;
    settings["BUILD_DIR"] =
        build_products.string();

    settings["SYMROOT"] =
        build_products.string();

    settings["BUILT_PRODUCTS_DIR"] =
        "$(BUILD_DIR)/$(CONFIGURATION)";

    settings["CONFIGURATION_BUILD_DIR"] =
        "$(BUILD_DIR)/$(CONFIGURATION)";

    settings["TARGET_BUILD_DIR"] =
        "$(BUILD_DIR)/$(CONFIGURATION)";

    /*
     * Project-level configuration is the base, native target configuration
     * overrides it.
     */
    const std::string root_object_id =
        parsed_.root.String(
            "rootObject"
        );

    if (const Value* root_object =
            Object(root_object_id)) {

        const auto project_settings =
            ConfigurationSettings(
                root_object->String(
                    "buildConfigurationList"
                ),
                selected_configuration,
                nullptr,
                strict_build_settings
            );

        for (const auto& [key, value] : project_settings)
            MergeBuildSetting(settings, key, value);
    }

    for (const auto& [key, value] :
         target_settings) {
        MergeBuildSetting(settings, key, value);
    }

    if (settings.find("SDKROOT") == settings.end() || settings["SDKROOT"].empty()) {
        auto it_dep = settings.find("IPHONEOS_DEPLOYMENT_TARGET");
        auto it_plat = settings.find("PLATFORM_NAME");
        if ((it_dep != settings.end() && !it_dep->second.empty()) ||
            (it_plat != settings.end() && it_plat->second == "iphoneos")) {
            settings["SDKROOT"] = "iphoneos";
        }
    }

    // Resolve variables after both configuration layers are present.
    for (int pass = 0;
         pass < 8;
         ++pass) {

        bool any_change = false;

        for (auto& [key, value] :
             settings) {

            const std::string expanded =
                ExpandBuildSetting(
                    value,
                    settings
                );

            if (expanded != value) {
                value = expanded;
                any_change = true;
            }
        }

        if (!any_change) {
            break;
        }
    }

    /*
     * Xcode presents the selected target's configuration directory as its
     * built-products and target-build directory. CocoaPods commonly refines
     * CONFIGURATION_BUILD_DIR in the target xcconfig after the workspace-wide
     * BUILD_DIR has been established.
     */
    const auto configuration_dir = settings.find("CONFIGURATION_BUILD_DIR");
    if (configuration_dir != settings.end() && !configuration_dir->second.empty()) {
        settings["BUILT_PRODUCTS_DIR"] = configuration_dir->second;
        settings["TARGET_BUILD_DIR"] = configuration_dir->second;
    }

    for (const auto& [name, value] : CommandLineBuildSettings())
        settings[name] = value;

    return settings;
}

namespace {
std::unordered_map<std::string, std::string>& CommandLineBuildSettingsStore() {
    static std::unordered_map<std::string, std::string> settings;
    return settings;
}
}

void XcodeProject::SetCommandLineBuildSettings(std::unordered_map<std::string, std::string> settings) {
    CommandLineBuildSettingsStore() = std::move(settings);
}

const std::unordered_map<std::string, std::string>& XcodeProject::CommandLineBuildSettings() {
    return CommandLineBuildSettingsStore();
}

void XcodeProject::CollectBuildPhaseFiles(
    const XcodeTarget& target,
    XcodeResolvedTarget& result
) const {
    std::unordered_set<std::string>
        seen;
    bool encountered_sources = false;
    std::size_t phase_order = 0;

    for (const auto& phase_id :
         target.build_phases) {

        const Value* phase =
            Object(phase_id);

        if (!phase) {
            continue;
        }

        const std::size_t current_order = phase_order++;

        const std::string isa =
            phase->String("isa");

        if (isa == "PBXShellScriptBuildPhase") {
            XcodeShellScriptPhase shell_phase;
            shell_phase.id = phase_id;
            shell_phase.name = phase->String("name");
            shell_phase.shell_path = phase->String("shellPath");
            shell_phase.script = phase->String("shellScript");
            shell_phase.order = current_order;
            shell_phase.after_sources = encountered_sources;
            for (const auto& value : phase->StringArray("inputPaths")) {
                shell_phase.input_paths.push_back(
                    ExpandBuildSetting(value, result.build_settings)
                );
            }
            for (const auto& value : phase->StringArray("outputPaths")) {
                shell_phase.output_paths.push_back(
                    ExpandBuildSetting(value, result.build_settings)
                );
            }
            if (!shell_phase.script.empty() || target.kind == XcodeTargetKind::Aggregate) {
                result.shell_script_phases.push_back(std::move(shell_phase));
            }
            continue;
        }

        const bool is_sources =
            isa == "PBXSourcesBuildPhase";

        if (is_sources) {
            encountered_sources = true;
        }

        const bool is_resources =
            isa == "PBXResourcesBuildPhase";

        const bool is_frameworks =
            isa == "PBXFrameworksBuildPhase";

        const bool is_headers =
            isa == "PBXHeadersBuildPhase";

        const bool is_copy_files =
            isa == "PBXCopyFilesBuildPhase";

        std::string dst_subfolder_spec;
        if (is_copy_files) {
            dst_subfolder_spec = phase->String("dstSubfolderSpec");
        }

        if (!is_sources &&
            !is_resources &&
            !is_frameworks &&
            !is_headers &&
            !is_copy_files) {
            continue;
        }

        for (const auto& build_file_id :
             phase->StringArray("files")) {

            const Value* build_file =
                Object(build_file_id);

            if (!build_file) {
                continue;
            }

            std::string file_ref =
                build_file->String("fileRef");

            if (file_ref.empty()) {
                file_ref =
                    build_file->String(
                        "productRef"
                    );
            }

            if (file_ref.empty()) {
                continue;
            }

            // A PBXVariantGroup is a logical localized group. Its path can be a
            // containing directory, while its children are the actual Base.lproj/xx.lproj inputs.
            if (const Value* variant = Object(file_ref);
                variant && variant->String("isa") == "PBXVariantGroup") {
                bool is_intent = false;
                fs::path primary_intent_def;
                for (const auto& child_id : variant->StringArray("children")) {
                    const fs::path child = ResolveFileReference(child_id);
                    if (child.empty()) continue;
                    const std::string ext = ToLowerAscii(child.extension().string());
                    if (ext == ".intentdefinition") {
                        is_intent = true;
                        if (primary_intent_def.empty() || child.string().find("Base.lproj") != std::string::npos) {
                            primary_intent_def = child;
                        }
                    }
                    // Retain the declared compiler input even when it is missing.
                    // Otherwise a missing Base intent silently selects another locale.
                    if (!fs::exists(child)) continue;
                    const std::string canonical = ToLowerAscii(child.lexically_normal().string());
                    if (seen.insert(isa + ":" + canonical).second) {
                        result.resources.push_back(child);
                    }
                }
                if (is_intent && !primary_intent_def.empty()) {
                    result.intent_definitions.push_back(primary_intent_def);
                }
                continue;
            }

            if (is_frameworks || (is_copy_files && dst_subfolder_spec == "10")) {
                const Value* framework_ref =
                    Object(file_ref);

                if (framework_ref) {
                    std::string framework_name =
                        framework_ref->String("path");

                    if (framework_name.empty()) {
                        framework_name =
                            framework_ref->String("name");
                    }
                    if (framework_name.empty()) {
                        framework_name =
                            framework_ref->String("_comment");
                    }

                    const fs::path fp(framework_name);
                    const std::string ext = ToLowerAscii(fp.extension().string());

                    if (ext == ".framework") {
                        result.system_frameworks.push_back(
                            fp.stem().string()
                        );
                    } else if (ext == ".tbd" || ext == ".dylib") {
                        std::string stem = fp.stem().string();
                        if (stem.rfind("lib", 0) == 0 && stem.size() > 3) {
                            stem = stem.substr(3);
                        }
                        result.system_libraries.push_back(stem);
                    } else if (ext == ".a") {
                        result.link_libraries.push_back(fp.filename().string());
                    }
                }
            }

            fs::path path;
            // Generated sources/resources can be absent until a dependency's
            // script runs. Resolve their declared setting-based location now;
            // never replace their PBX identity with a filesystem scan.
            const auto* reference = Object(file_ref);
            const auto tree = reference ? reference->String("sourceTree") : std::string();
            auto declared = reference ? reference->String("path") : std::string();
            if (declared.empty() && reference) declared = reference->String("name");
            if (!declared.empty() && (is_sources || is_resources || is_headers || is_copy_files)) {
                const auto expanded = ExpandBuildSetting(declared, result.build_settings);
                if (expanded.find("$(") == std::string::npos && expanded.find("${") == std::string::npos) {
                    const fs::path expanded_path(expanded);
                    if (expanded_path.is_absolute()) path = expanded_path;
                    else if (const auto base = result.build_settings.find(tree);
                        base != result.build_settings.end() && fs::path(base->second).is_absolute())
                        path = fs::path(base->second) / expanded_path;
                }
            }
            if (path.empty()) path = ResolveFileReference(file_ref);
            path = path.lexically_normal();

            if (path.empty()) {
                continue;
            }

            const std::string canonical =
                ToLowerAscii(
                    path.lexically_normal()
                        .string()
                );

            if (!seen.insert(
                    isa + ":" +
                    canonical).second) {
                continue;
            }

            const std::string ext =
                ToLowerAscii(
                    path.extension()
                        .string()
                );

            /*
             * Xcode treats Core Data models as typed compiler inputs.  They
             * normally live in PBXSourcesBuildPhase (XCVersionGroup for a
             * versioned model), so they must not be copied as raw resources.
             */
            if (ext == ".xcdatamodeld" || ext == ".xcdatamodel") {
                XcodeCoreDataModel model;
                model.path = path;
                if (const Value* model_ref = Object(file_ref)) {
                    const std::string current_id = model_ref->String("currentVersion");
                    if (!current_id.empty()) {
                        if (const Value* current_ref = Object(current_id)) {
                            std::string current_name = current_ref->String("path");
                            if (current_name.empty()) {
                                current_name = current_ref->String("name");
                            }
                            model.current_version = fs::path(current_name).stem().string();
                        }
                    }
                }
                result.core_data_models.push_back(std::move(model));
                continue;
            }

            if (ext == ".intentdefinition") {
                // Missing declared inputs must reach the resource compiler's error path.
                result.intent_definitions.push_back(path);
                if (fs::exists(path)) {
                    result.resources.push_back(path);
                }
                continue;
            }

            if (is_sources) {
                if (ext == ".swift") {
                    result.swift_sources.push_back(path);
                } else if (
                    ext == ".c" ||
                    ext == ".cc" ||
                    ext == ".cpp" ||
                    ext == ".cxx" ||
                    ext == ".m" ||
                    ext == ".mm") {

                    result.c_family_sources.push_back(path);
                    if (const Value* settings = build_file->Get("settings")) {
                        const auto flags = settings->String("COMPILER_FLAGS");
                        if (!flags.empty())
                            result.source_compiler_flags.emplace_back(
                                path, ExpandBuildSetting(flags, result.build_settings));
                    }
                }
            } else if (
                is_resources) {

                if (ext == ".xcassets" || ext == ".icon") { // .icon: Icon Composer document, an actool input
                    result.asset_catalogs
                        .push_back(path);
                } else if (
                    ext == ".xcstrings") {
                    result.string_catalogs
                        .push_back(path);
                } else {
                    result.resources
                        .push_back(path);
                }
            } else if (
                (is_frameworks || (is_copy_files && dst_subfolder_spec == "10")) &&
                (ext == ".framework" ||
                 ext == ".xcframework")) {

                result.frameworks
                    .push_back(path);
            } else if (
                is_copy_files && dst_subfolder_spec == "7") {

                if (ext == ".xcassets" || ext == ".icon") { // .icon: Icon Composer document, an actool input
                    result.asset_catalogs
                        .push_back(path);
                } else if (
                    ext == ".xcstrings") {
                    result.string_catalogs
                        .push_back(path);
                } else {
                    result.resources
                        .push_back(path);
                }
            } else if (is_headers) {
                if (fs::exists(path)) {
                    result.headers.push_back(path);
                }
            }
        }
    }
}

void XcodeProject::CollectSynchronizedGroupFiles(
    const XcodeTarget& target,
    XcodeResolvedTarget& result
) const {
    /*
     * Xcode 16 file-system-synchronized groups do not necessarily enumerate
     * every source through PBXBuildFile.  They *are* target scoped however,
     * so walking only the target's synchronized root is safe and avoids the
     * v3 bug that compiled extension folders into the main application.
     */
    std::unordered_set<std::string>
        already;

    for (const auto& path :
         result.swift_sources) {
        already.insert(
            ToLowerAscii(
                path.lexically_normal()
                    .string()
            )
        );
    }

    for (const auto& path :
         result.c_family_sources) {
        already.insert(
            ToLowerAscii(
                path.lexically_normal()
                    .string()
            )
        );
    }

    for (const auto& group_id :
         target.synchronized_groups) {

        std::unordered_set<XcodeObjectId>
            guard;

        const fs::path root =
            ResolveGroupPath(
                group_id,
                guard
            );

        if (!fs::exists(root) ||
            !fs::is_directory(root)) {
            continue;
        }

        std::unordered_set<std::string> excluded;

        if (const Value* group = Object(group_id)) {
            for (const auto& exception_id : group->StringArray("exceptions")) {
                const Value* exception = Object(exception_id);
                if (!exception) {
                    continue;
                }

                const std::string exception_target =
                    exception->String("target");

                if (!exception_target.empty() &&
                    exception_target != target.id) {
                    continue;
                }

                for (const auto& member :
                     exception->StringArray("membershipExceptions")) {
                    std::string norm =
                        fs::path(member)
                            .lexically_normal()
                            .generic_string();
                    while (norm.size() > 1 &&
                           (norm.back() == '/' || norm.back() == '.')) {
                        norm.pop_back();
                    }
                    excluded.insert(ToLowerAscii(norm));
                }
            }
        }

        std::error_code ec;

        for (fs::recursive_directory_iterator it(
                 root,
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

            const fs::path path =
                it->path();

            const std::string relative =
                ToLowerAscii(
                    fs::relative(path, root, ec)
                        .lexically_normal()
                        .generic_string()
                );

            if (!ec &&
                excluded.find(relative) != excluded.end()) {
                if (it->is_directory(ec)) {
                    it.disable_recursion_pending();
                }
                continue;
            }

            ec.clear();

            if (it->is_directory(ec)) {
                const std::string ext =
                    ToLowerAscii(path.extension().string());

                if (ext == ".xcassets" || ext == ".icon") { // .icon: Icon Composer document, an actool input
                    result.asset_catalogs
                        .push_back(path);
                    it.disable_recursion_pending();
                } else if (
                    ext == ".bundle" ||
                    ext == ".lproj") {
                    result.resources
                        .push_back(path);
                    it.disable_recursion_pending();
                } else if (
                    ext == ".xcdatamodeld" ||
                    ext == ".xcdatamodel") {
                    result.core_data_models.push_back({path, {}});
                    it.disable_recursion_pending();
                } else if (
                    ext == ".framework" ||
                    ext == ".xcframework") {
                    result.frameworks
                        .push_back(path);
                    it.disable_recursion_pending();
                }
                continue;
            }

            if (!it->is_regular_file(ec)) {
                continue;
            }

            const std::string ext =
                ToLowerAscii(path.extension().string());

            if (ext == ".swift") {
                const std::string canonical =
                    ToLowerAscii(
                        path.lexically_normal()
                            .string()
                    );

                if (already.insert(
                        canonical).second) {
                    result.swift_sources
                        .push_back(path);
                }
            } else if (IsCFamilySourceExtension(ext)) {
                const std::string canonical =
                    ToLowerAscii(
                        path.lexically_normal()
                            .string()
                    );

                if (already.insert(
                        canonical).second) {
                    result.c_family_sources
                        .push_back(path);
                }
            } else if (ext == ".xcstrings") {
                result.string_catalogs
                    .push_back(path);
            } else if (IsResourceExtension(path)) {
                result.resources
                    .push_back(path);
            }
        }
    }
}

void XcodeProject::CollectPackageDependencies(
    const XcodeTarget& target,
    XcodeResolvedTarget& result
) const {
    const auto bundle_key = [](const fs::path& bundle) {
        std::error_code ec;
        const auto canonical = fs::weakly_canonical(bundle, ec);
        return ToLowerAscii((ec ? bundle.lexically_normal() : canonical.lexically_normal()).generic_string());
    };

    const auto find_dep_target = [](const XcodeProject& proj,
                                    const std::string& id,
                                    const std::string& name) -> std::optional<XcodeTarget> {
        const auto targets = proj.Targets();
        if (!id.empty()) {
            for (const auto& candidate : targets) {
                if (candidate.id == id) return candidate;
            }
            return std::nullopt;
        }
        if (!name.empty()) {
            return proj.FindTarget(name);
        }
        return std::nullopt;
    };

    std::unordered_set<std::string> visited_targets;
    std::unordered_map<std::string, std::string> package_dedup_to_id;
    std::unordered_set<std::string> used_ref_ids;
    std::unordered_set<std::string> seen_products;

    const fs::path root_source = source_root_.lexically_normal();

    const auto parse_requirement = [](const Value* object) {
        XcodePackageRequirement req;
        const Value* requirement = object ? object->Get("requirement") : nullptr;
        if (!requirement || requirement->kind != Value::Kind::Dictionary) {
            return req;
        }
        const std::string kind = requirement->String("kind");
        if (kind == "upToNextMajorVersion") {
            req.kind = XcodePackageRequirement::Kind::UpToNextMajor;
            req.value = requirement->String("minimumVersion");
        } else if (kind == "upToNextMinorVersion") {
            req.kind = XcodePackageRequirement::Kind::UpToNextMinor;
            req.value = requirement->String("minimumVersion");
        } else if (kind == "exactVersion") {
            req.kind = XcodePackageRequirement::Kind::Exact;
            req.value = requirement->String("version");
        } else if (kind == "branch") {
            req.kind = XcodePackageRequirement::Kind::Branch;
            req.value = requirement->String("branch");
        } else if (kind == "revision") {
            req.kind = XcodePackageRequirement::Kind::Revision;
            req.value = requirement->String("revision");
        } else if (kind == "versionRange") {
            req.kind = XcodePackageRequirement::Kind::Range;
            req.lower_bound = requirement->String("minimumVersion");
            req.upper_bound = requirement->String("maximumVersion");
        }
        return req;
    };

    std::function<void(const XcodeProject&, const XcodeTarget&)> visit =
        [&](const XcodeProject& cur_proj, const XcodeTarget& cur_target) {
            const std::string cur_bundle_key = bundle_key(cur_proj.ProjectBundle());
            if (!visited_targets.insert(cur_bundle_key + "#" + cur_target.id).second) {
                return;
            }

            for (const auto& dependency_id : cur_target.package_product_dependencies) {
                const Value* dependency = cur_proj.Object(dependency_id);
                if (!dependency) {
                    continue;
                }

                XcodeProductDependency product;
                product.id = dependency_id;
                product.product_name = dependency->String("productName");
                product.package_id = dependency->String("package");

                const Value* objs = cur_proj.parsed_.Objects();
                if (product.package_id.empty() && objs &&
                    objs->kind == Value::Kind::Dictionary) {
                    for (const auto& [obj_id, obj] : objs->dictionary) {
                        const std::string isa = obj.String("isa");
                        if (isa == "XCLocalSwiftPackageReference") {
                            const std::string rel = obj.String("relativePath");
                            const std::string name = fs::path(rel).filename().string();
                            if (name == product.product_name) {
                                product.package_id = obj_id;
                                break;
                            }
                        } else if (isa == "XCRemoteSwiftPackageReference") {
                            const std::string repo = obj.String("repositoryURL");
                            if (UrlIdentity(repo) == product.product_name) {
                                product.package_id = obj_id;
                                break;
                            }
                        }
                    }
                }

                if (product.product_name.empty()) {
                    continue;
                }

                if (!product.package_id.empty()) {
                    const std::string raw_package_id = product.package_id;
                    if (const Value* pkg_obj = cur_proj.Object(raw_package_id)) {
                        const std::string isa = pkg_obj->String("isa");
                        if (isa == "XCLocalSwiftPackageReference") {
                            const std::string raw_rel = pkg_obj->String("relativePath");
                            if (!raw_rel.empty()) {
                                const fs::path cur_source = cur_proj.SourceRoot().lexically_normal();
                                const fs::path abs_pkg = (cur_source / fs::path(raw_rel)).lexically_normal();
                                XcodePackageReference ref;
                                ref.is_local = true;
                                if (cur_source == root_source) {
                                    ref.relative_path = raw_rel;
                                } else {
                                    std::error_code rel_ec;
                                    fs::path rel_to_root = fs::relative(abs_pkg, root_source, rel_ec);
                                    if (rel_ec || rel_to_root.empty()) {
                                        rel_to_root = abs_pkg.lexically_relative(root_source);
                                    }
                                    ref.relative_path = (rel_to_root.empty() ? abs_pkg : rel_to_root).lexically_normal().generic_string();
                                }
                                ref.identity = fs::path(raw_rel).filename().string();
                                if (ref.identity.empty() || ref.identity == "." || ref.identity == "..") {
                                    ref.identity = abs_pkg.filename().string();
                                }
                                const std::string dedup_key = "local:" + ToLowerAscii(abs_pkg.generic_string());
                                const auto existing = package_dedup_to_id.find(dedup_key);
                                if (existing != package_dedup_to_id.end()) {
                                    product.package_id = existing->second;
                                } else {
                                    std::string assigned_id = raw_package_id;
                                    if (!used_ref_ids.insert(assigned_id).second) {
                                        assigned_id = cur_bundle_key + ":" + raw_package_id;
                                        used_ref_ids.insert(assigned_id);
                                    }
                                    ref.id = assigned_id;
                                    package_dedup_to_id.emplace(dedup_key, assigned_id);
                                    product.package_id = assigned_id;
                                    result.package_references.push_back(std::move(ref));
                                }
                            }
                        } else if (isa == "XCRemoteSwiftPackageReference") {
                            XcodePackageReference ref;
                            ref.repository_url = pkg_obj->String("repositoryURL");
                            ref.identity = UrlIdentity(ref.repository_url);
                            ref.requirement = parse_requirement(pkg_obj);
                            if (!ref.repository_url.empty()) {
                                const std::string dedup_key = "remote:" + ToLowerAscii(ref.identity.empty() ? ref.repository_url : ref.identity);
                                const auto existing = package_dedup_to_id.find(dedup_key);
                                if (existing != package_dedup_to_id.end()) {
                                    product.package_id = existing->second;
                                } else {
                                    std::string assigned_id = raw_package_id;
                                    if (!used_ref_ids.insert(assigned_id).second) {
                                        assigned_id = cur_bundle_key + ":" + raw_package_id;
                                        used_ref_ids.insert(assigned_id);
                                    }
                                    ref.id = assigned_id;
                                    package_dedup_to_id.emplace(dedup_key, assigned_id);
                                    product.package_id = assigned_id;
                                    result.package_references.push_back(std::move(ref));
                                }
                            }
                        }
                    }
                }

                const std::string prod_dedup_key = product.package_id + "\n" + product.product_name;
                if (seen_products.insert(prod_dedup_key).second) {
                    result.package_products.push_back(std::move(product));
                }
            }

            const std::string root_obj_id = cur_proj.parsed_.root.String("rootObject");
            for (const auto& dep_id : cur_target.dependencies) {
                const Value* dep_obj = cur_proj.Object(dep_id);
                if (!dep_obj || dep_obj->String("isa") != "PBXTargetDependency") {
                    continue;
                }
                const std::string local_id = dep_obj->String("target");
                if (!local_id.empty()) {
                    if (const auto dep_target = find_dep_target(cur_proj, local_id, {})) {
                        visit(cur_proj, *dep_target);
                    }
                    continue;
                }
                const std::string proxy_id = dep_obj->String("targetProxy");
                const Value* proxy = cur_proj.Object(proxy_id);
                if (!proxy || proxy->String("isa") != "PBXContainerItemProxy") {
                    continue;
                }
                const std::string portal = proxy->String("containerPortal");
                const std::string remote_id = proxy->String("remoteGlobalIDString");
                const std::string remote_name = proxy->String("remoteInfo");
                if (portal.empty() || portal == root_obj_id || portal == "Project object") {
                    if (const auto dep_target = find_dep_target(cur_proj, remote_id, remote_name)) {
                        visit(cur_proj, *dep_target);
                    }
                } else {
                    const fs::path sub_bundle = cur_proj.ResolveFileReference(portal);
                    if (!sub_bundle.empty()) {
                        if (const auto sub_proj = cur_proj.LoadRelatedProject(sub_bundle)) {
                            if (const auto dep_target = find_dep_target(*sub_proj, remote_id, remote_name)) {
                                visit(*sub_proj, *dep_target);
                            }
                        }
                    }
                }
            }
        };

    visit(*this, target);
}

static bool MatchGlobPattern(std::string_view text, std::string_view pattern, bool case_sensitive) {
    std::size_t t = 0, p = 0;
    std::size_t star_p = std::string_view::npos, star_t = 0;
    while (t < text.size()) {
        if (p < pattern.size() && ((case_sensitive ? text[t] == pattern[p] :
            std::tolower(static_cast<unsigned char>(text[t])) == std::tolower(static_cast<unsigned char>(pattern[p]))) || pattern[p] == '?')) {
            ++t;
            ++p;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star_p = p++;
            star_t = t;
        } else if (star_p != std::string_view::npos) {
            p = star_p + 1;
            t = ++star_t;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') {
        ++p;
    }
    return p == pattern.size();
}

static bool IsPathExcluded(
    const fs::path& path,
    const fs::path& source_root,
    const std::vector<std::string>& excluded_patterns
) {
    if (excluded_patterns.empty() || path.empty()) {
        return false;
    }

    std::error_code ec;
    std::string rel = fs::relative(path, source_root, ec).generic_string();
    if (ec || rel.empty()) {
        rel = path.filename().generic_string();
    }
    std::string filename = path.filename().generic_string();
    std::string full = path.generic_string();

    for (const auto& pat : excluded_patterns) {
        if (pat.empty()) continue;
        if (pat.find('/') != std::string::npos) {
            if (MatchGlobPattern(rel, pat) ||
                MatchGlobPattern(rel, "*" + pat) ||
                MatchGlobPattern(full, "*" + pat)) {
                return true;
            }
        } else {
            if (MatchGlobPattern(filename, pat) ||
                MatchGlobPattern(rel, pat)) {
                return true;
            }
        }
    }
    return false;
}

std::vector<fs::path>
XcodeProject::CollectProjectHeaders(
    const XcodeTarget& target,
    const std::string& configuration
) const {
    std::vector<fs::path> result;
    const Value* objs = parsed_.Objects();
    if (!objs) {
        return result;
    }

    std::vector<std::string> excluded_patterns;
    const auto target_settings =
        ConfigurationSettings(target.build_configuration_list, configuration);
    auto it_excl = target_settings.find("EXCLUDED_SOURCE_FILE_NAMES");
    if (it_excl != target_settings.end() && !it_excl->second.empty()) {
        std::istringstream iss(it_excl->second);
        std::string token;
        while (iss >> token) {
            if (token.size() >= 2 &&
                ((token.front() == '"' && token.back() == '"') ||
                 (token.front() == '\'' && token.back() == '\''))) {
                token = token.substr(1, token.size() - 2);
            }
            if (!token.empty() && token != "$(inherited)" && token != "${inherited}") {
                excluded_patterns.push_back(token);
            }
        }
    }

    std::unordered_set<std::string> seen;

    for (const auto& [id, object] : objs->dictionary) {
        if (object.String("isa") != "PBXFileReference") {
            continue;
        }

        const fs::path path = ResolveFileReference(id);
        if (path.empty()) {
            continue;
        }

        const std::string ext = ToLowerAscii(path.extension().string());
        if (ext == ".h" || ext == ".hpp" || ext == ".hh" || ext == ".hxx") {
            if (!fs::exists(path)) {
                continue;
            }
            if (!excluded_patterns.empty() &&
                IsPathExcluded(path, source_root_, excluded_patterns)) {
                continue;
            }
            const fs::path norm = path.lexically_normal();
            if (seen.insert(ToLowerAscii(norm.string())).second) {
                result.push_back(norm);
            }
        }
    }

    std::sort(
        result.begin(),
        result.end(),
        [](const fs::path& a, const fs::path& b) {
            return a.string() < b.string();
        }
    );

    return result;
}

std::optional<XcodeResolvedTarget>
XcodeProject::ResolveTarget(
    const XcodeTarget& target,
    std::string configuration,
    const XcodeDependencyOptions& options
) const {
    if (target.kind == XcodeTargetKind::Legacy) return std::nullopt;
    if (target.kind == XcodeTargetKind::Aggregate) {
        // Aggregate execution currently implements shell phases, not native
        // compilation/link/copy phases. Preserve unsupported cases as failure.
        for (const auto& phase_id : target.build_phases) {
            const auto* phase = Object(phase_id);
            if (!phase || phase->String("isa") != "PBXShellScriptBuildPhase") return std::nullopt;
        }
    }
    XcodeResolvedTarget result;
    result.target = target;

    if (options.strict_build_settings || metadata_reader_) {
        std::string error;
        const auto canonical = ResolveConfigurationName(target,
            configuration.empty() ? std::nullopt : std::optional(configuration), &error);
        if (!canonical) throw std::runtime_error(error);
        configuration = *canonical;
    } else if (configuration.empty()) {
        configuration = "Debug";
    }

    result.build_settings =
        ResolveBuildSettings(
            target,
            configuration,
            options.strict_build_settings
        );

    auto it_excl = result.build_settings.find("EXCLUDED_SOURCE_FILE_NAMES");
    if (it_excl != result.build_settings.end() && !it_excl->second.empty()) {
        std::istringstream iss(it_excl->second);
        std::string token;
        while (iss >> token) {
            if (token.size() >= 2 &&
                ((token.front() == '"' && token.back() == '"') ||
                 (token.front() == '\'' && token.back() == '\''))) {
                token = token.substr(1, token.size() - 2);
            }
            if (!token.empty() && token != "$(inherited)" && token != "${inherited}") {
                result.excluded_source_file_names.push_back(token);
            }
        }
    }

    CollectBuildPhaseFiles(
        target,
        result
    );

    CollectSynchronizedGroupFiles(
        target,
        result
    );

    CollectPackageDependencies(
        target,
        result
    );

    result.target_dependencies =
        ResolveTargetDependencies(
            target,
            options
        );

    if (!result.excluded_source_file_names.empty()) {
        auto filter_excluded = [&](std::vector<fs::path>& paths) {
            paths.erase(
                std::remove_if(
                    paths.begin(),
                    paths.end(),
                    [&](const fs::path& p) {
                        return IsPathExcluded(p, source_root_, result.excluded_source_file_names);
                    }
                ),
                paths.end()
            );
        };
        filter_excluded(result.swift_sources);
        filter_excluded(result.c_family_sources);
        filter_excluded(result.headers);
    }

    result.project_headers = CollectProjectHeaders(target, configuration);

    const auto sort_paths =
        [](auto& values) {
            std::sort(
                values.begin(),
                values.end(),
                [](const fs::path& a,
                   const fs::path& b) {
                    return a.string() <
                           b.string();
                }
            );

            values.erase(
                std::unique(
                    values.begin(),
                    values.end()
                ),
                values.end()
            );
        };

    sort_paths(result.swift_sources);
    sort_paths(result.c_family_sources);
    sort_paths(result.headers);
    sort_paths(result.resources);
    sort_paths(result.asset_catalogs);
    sort_paths(result.string_catalogs);
    sort_paths(result.frameworks);

    std::sort(
        result.system_frameworks.begin(),
        result.system_frameworks.end()
    );

    result.system_frameworks.erase(
        std::unique(
            result.system_frameworks.begin(),
            result.system_frameworks.end()
        ),
        result.system_frameworks.end()
    );

    return result;
}

} // namespace OpenFruit
