#include "utf8_path.hpp"
#include "string_catalog_compiler.hpp"
#include "json_value.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <optional>
#include <regex>
#include <sstream>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

// A key's compiled form in one language: a plain string, or a format whose
// %#@name@ tokens are resolved by plural rules in the .stringsdict table.
struct PluralRule {
    std::string value_type;
    std::map<std::string, std::string> forms;
};
struct Entry {
    std::string format;
    std::map<std::string, PluralRule> rules;
};
using Table = std::map<std::string, Entry>;
using Languages = std::map<std::string, Table>;

std::string XmlEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        default:
            // XML 1.0 admits no other C0 controls, even escaped.
            if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') out += static_cast<char>(c);
        }
    }
    return out;
}

const JsonValue* Child(const JsonValue* value, const char* key) {
    return value && value->IsObject() ? value->Get(key) : nullptr;
}

std::optional<std::string> UnitValue(const JsonValue* localization) {
    const auto* value = Child(Child(localization, "stringUnit"), "value");
    if (!value || !value->IsString()) return std::nullopt;
    return value->StringValue();
}

// The length modifier and conversion of the first printf-style specifier,
// which is the argument type Foundation's plural rule selects on.
std::string ValueType(const std::map<std::string, std::string>& forms) {
    static const std::regex specifier(R"(%(?:\d+\$)?[-+ #0']*\d*(?:\.\d+)?((?:hh|h|ll|l|q|L|z|t|j)?[@dDiuUxXoOfFeEgGcCsSaAp]))");
    for (const auto& [category, text] : forms) {
        std::smatch match;
        if (std::regex_search(text, match, specifier)) return match[1].str();
    }
    return "lld";
}

std::map<std::string, std::string> PluralForms(const JsonValue* variations) {
    std::map<std::string, std::string> forms;
    const auto* plural = Child(variations, "plural");
    if (!plural || !plural->IsObject()) return forms;
    for (const auto& [category, form] : plural->ObjectItems())
        if (const auto value = UnitValue(&form)) forms[category] = *value;
    return forms;
}

// Device variations have no run-time selector in a .strings table; an iOS
// build takes the iPhone form, then the generic one.
std::optional<std::string> DeviceValue(const JsonValue* variations) {
    const auto* device = Child(variations, "device");
    for (const char* name : {"iphone", "other"})
        if (const auto value = UnitValue(Child(device, name))) return value;
    return std::nullopt;
}

std::optional<Entry> CompileLocalization(const JsonValue& localization) {
    Entry entry;
    const auto* variations = Child(&localization, "variations");
    if (auto forms = PluralForms(variations); !forms.empty()) {
        entry.format = "%#@value@";
        entry.rules["value"] = PluralRule{ValueType(forms), std::move(forms)};
    } else if (const auto device = DeviceValue(variations)) {
        entry.format = *device;
    } else if (const auto value = UnitValue(&localization)) {
        entry.format = *value;
    } else {
        return std::nullopt;
    }
    const auto* substitutions = Child(&localization, "substitutions");
    if (substitutions && substitutions->IsObject()) {
        for (const auto& [name, substitution] : substitutions->ObjectItems()) {
            auto forms = PluralForms(Child(&substitution, "variations"));
            if (forms.empty()) continue;
            const auto specifier = substitution.GetString("formatSpecifier", "lld");
            const auto* position = Child(&substitution, "argNum");
            const std::string argument = "%" + (position && position->IsNumber() ? position->StringValue() + "$" : "") + specifier;
            // A substitution's forms name their own argument as %arg.
            for (auto& [category, text] : forms)
                for (std::size_t at = text.find("%arg"); at != std::string::npos; at = text.find("%arg", at + argument.size()))
                    text.replace(at, 4, argument);
            entry.rules[name] = PluralRule{specifier, std::move(forms)};
        }
    }
    return entry;
}

bool ReadCatalog(const fs::path& path, Languages& languages, std::string& source_language, std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) { error = "cannot read string catalog " + path.string(); return false; }
    std::stringstream text;
    text << input.rdbuf();
    std::string parse_error;
    const auto catalog = JsonValue::Parse(text.str(), &parse_error);
    if (!catalog || !catalog->IsObject()) {
        error = "invalid string catalog " + path.string() + (parse_error.empty() ? "" : ": " + parse_error);
        return false;
    }
    const auto source = catalog->GetString("sourceLanguage", "en");
    if (source_language.empty()) source_language = source;
    const auto* strings = catalog->Get("strings");
    if (!strings || !strings->IsObject()) return true;
    const auto table = path.stem().string();
    for (const auto& [key, definition] : strings->ObjectItems()) {
        bool has_source = false;
        if (const auto* localizations = Child(&definition, "localizations"); localizations && localizations->IsObject()) {
            for (const auto& [language, localization] : localizations->ObjectItems()) {
                if (auto entry = CompileLocalization(localization)) {
                    languages[language + "\n" + table][key] = std::move(*entry);
                    has_source = has_source || language == source;
                }
            }
        }
        // A key without its own source-language string is its own value.
        if (!has_source) languages[source + "\n" + table][key] = Entry{key, {}};
    }
    return true;
}

bool WriteText(const fs::path& path, const std::string& text, std::string& error) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
    if (!output) { error = "cannot write " + path.string(); return false; }
    return true;
}

constexpr const char* kPlistHeader =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n<dict>\n";

bool WriteTable(const fs::path& directory, const std::string& table, const Table& entries, std::string& error) {
    std::ostringstream strings, plurals;
    strings << kPlistHeader;
    plurals << kPlistHeader;
    bool has_plurals = false;
    for (const auto& [key, entry] : entries) {
        if (entry.rules.empty()) {
            strings << "\t<key>" << XmlEscape(key) << "</key>\n\t<string>" << XmlEscape(entry.format) << "</string>\n";
            continue;
        }
        has_plurals = true;
        plurals << "\t<key>" << XmlEscape(key) << "</key>\n\t<dict>\n"
                << "\t\t<key>NSStringLocalizedFormatKey</key>\n\t\t<string>" << XmlEscape(entry.format) << "</string>\n";
        for (const auto& [name, rule] : entry.rules) {
            plurals << "\t\t<key>" << XmlEscape(name) << "</key>\n\t\t<dict>\n"
                    << "\t\t\t<key>NSStringFormatSpecTypeKey</key>\n\t\t\t<string>NSStringPluralRuleType</string>\n"
                    << "\t\t\t<key>NSStringFormatValueTypeKey</key>\n\t\t\t<string>" << XmlEscape(rule.value_type) << "</string>\n";
            for (const auto& [category, text] : rule.forms)
                plurals << "\t\t\t<key>" << XmlEscape(category) << "</key>\n\t\t\t<string>" << XmlEscape(text) << "</string>\n";
            plurals << "\t\t</dict>\n";
        }
        plurals << "\t</dict>\n";
    }
    strings << "</dict>\n</plist>\n";
    plurals << "</dict>\n</plist>\n";
    if (!WriteText(directory / (table + ".strings"), strings.str(), error)) return false;
    return !has_plurals || WriteText(directory / (table + ".stringsdict"), plurals.str(), error);
}

} // namespace

bool StringCatalogCompiler::Compile(
    const std::vector<fs::path>& catalogs,
    const fs::path& bundle_dir,
    std::string& development_region,
    std::string& error
) {
    error.clear();
    development_region.clear();
    Languages languages;
    for (const auto& catalog : catalogs)
        if (!ReadCatalog(catalog, languages, development_region, error)) return false;
    if (development_region.empty()) development_region = "en";
    for (const auto& [scope, entries] : languages) {
        const auto split = scope.find('\n');
        const auto language = scope.substr(0, split), table = scope.substr(split + 1);
        // Language codes come from the catalog: refuse anything that would
        // leave the bundle.
        if (language.empty() || language.find_first_of("/\\:.") != std::string::npos) {
            error = "invalid language code in string catalog: " + language;
            return false;
        }
        const auto directory = bundle_dir / Utf8Path(language + ".lproj");
        std::error_code ec;
        fs::create_directories(directory, ec);
        if (ec) { error = "cannot create " + directory.string() + ": " + ec.message(); return false; }
        if (!WriteTable(directory, table, entries, error)) return false;
    }
    return true;
}

} // namespace OpenFruit
