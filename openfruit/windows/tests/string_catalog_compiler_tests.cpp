#include "string_catalog_compiler.hpp"
#include "operation_events.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    stream << text;
    Require(static_cast<bool>(stream), "fixture write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::stringstream text;
    text << stream.rdbuf();
    return text.str();
}
bool Contains(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }
}

int main() {
    const auto root = fs::temp_directory_path() / ("of-xcstrings-" + NewOperationId());
    try {
        Write(root / "Localizable.xcstrings", R"({
  "sourceLanguage" : "en",
  "version" : "1.0",
  "strings" : {
    "Only key" : { },
    "Greeting" : { "localizations" : {
      "en" : { "stringUnit" : { "state" : "translated", "value" : "Hello & <welcome>" } },
      "it" : { "stringUnit" : { "state" : "translated", "value" : "Ciao" } } } },
    "%lld files" : { "localizations" : {
      "it" : { "variations" : { "plural" : {
        "one" : { "stringUnit" : { "state" : "translated", "value" : "%lld file" } },
        "other" : { "stringUnit" : { "state" : "translated", "value" : "%lld file" } } } } } } },
    "Device" : { "localizations" : {
      "en" : { "variations" : { "device" : {
        "iphone" : { "stringUnit" : { "state" : "translated", "value" : "Tap" } },
        "other" : { "stringUnit" : { "state" : "translated", "value" : "Click" } } } } } } },
    "Shared %#@items@" : { "localizations" : {
      "en" : { "stringUnit" : { "state" : "translated", "value" : "Shared %#@items@" },
        "substitutions" : { "items" : { "argNum" : 1, "formatSpecifier" : "lld", "variations" : { "plural" : {
          "one" : { "stringUnit" : { "state" : "translated", "value" : "%arg item" } },
          "other" : { "stringUnit" : { "state" : "translated", "value" : "%arg items" } } } } } } } } }
  }
})");
        const auto bundle = root / "Package_Target.bundle";
        std::string region, error;
        Require(StringCatalogCompiler::Compile({root / "Localizable.xcstrings"}, bundle, region, error), "valid catalog rejected");
        Require(region == "en", "source language is not the development region");

        const auto en = Read(bundle / "en.lproj" / "Localizable.strings");
        Require(Contains(en, "<key>Greeting</key>\n\t<string>Hello &amp; &lt;welcome&gt;</string>"), "source string or XML escaping lost");
        Require(Contains(en, "<key>Only key</key>\n\t<string>Only key</string>"), "key without localization must be its own value");
        Require(Contains(en, "<key>%lld files</key>\n\t<string>%lld files</string>"), "untranslated source key must be its own value");
        Require(Contains(en, "<key>Device</key>\n\t<string>Tap</string>"), "iOS build must take the iPhone device variation");

        const auto en_plurals = Read(bundle / "en.lproj" / "Localizable.stringsdict");
        Require(Contains(en_plurals, "<string>Shared %#@items@</string>"), "substitution format lost");
        Require(Contains(en_plurals, "<string>%1$lld item</string>") && Contains(en_plurals, "<string>%1$lld items</string>"),
            "substitution argument was not resolved to its specifier");

        const auto it = Read(bundle / "it.lproj" / "Localizable.strings");
        Require(Contains(it, "<key>Greeting</key>\n\t<string>Ciao</string>"), "translation lost");
        Require(!Contains(it, "files"), "plural key must not be a plain string");
        const auto it_plurals = Read(bundle / "it.lproj" / "Localizable.stringsdict");
        Require(Contains(it_plurals, "<string>%#@value@</string>") && Contains(it_plurals, "<string>NSStringPluralRuleType</string>") &&
            Contains(it_plurals, "<key>NSStringFormatValueTypeKey</key>\n\t\t\t<string>lld</string>") &&
            Contains(it_plurals, "<key>one</key>\n\t\t\t<string>%lld file</string>"), "plural variation not compiled to stringsdict");

        Write(root / "Bad.xcstrings", R"({"sourceLanguage":"en","strings":{"x":{"localizations":{"../evil":{"stringUnit":{"value":"x"}}}}}})");
        Require(!StringCatalogCompiler::Compile({root / "Bad.xcstrings"}, root / "Bad.bundle", region, error), "escaping language code accepted");
        Require(!fs::exists(root / "evil.lproj"), "language code escaped the bundle");
        Require(!StringCatalogCompiler::Compile({root / "Missing.xcstrings"}, root / "Missing.bundle", region, error), "missing catalog accepted");
        Require(!error.empty(), "missing catalog diagnostic lost");

        fs::remove_all(root);
        std::cout << "string catalog compiler tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::error_code ignored;
        fs::remove_all(root, ignored);
        std::cerr << "FAIL: " << failure.what() << '\n';
        return 1;
    }
}
