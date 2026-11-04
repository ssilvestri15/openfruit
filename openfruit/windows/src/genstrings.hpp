#pragma once

#include <map>
#include <string>
#include <vector>

// Xcode genstrings semantics: extraction of localizable strings from Swift,
// Objective-C and C sources, and rendering of .strings tables.
namespace OpenFruit::Genstrings {

enum class Language { Swift, ObjectiveC };

struct Options {
    // Routine base names; each also matches its FromTable, FromTableInBundle
    // and WithDefaultValue variants (genstrings -s).
    std::vector<std::string> routines = {"NSLocalizedString", "CFCopyLocalizedString"};
    bool positional_parameters = true;
};

struct Entry {
    std::string key;     // As written in source (escapes preserved).
    std::string value;   // Defaults to the key.
    std::vector<std::string> comments;
};

// table name -> key -> entry
using Tables = std::map<std::string, std::map<std::string, Entry>>;

// Extracts into tables, appending warnings formatted like genstrings'.
void Extract(const std::string& source_text, Language language, const std::string& file_name,
             const Options& options, Tables& tables, std::vector<std::string>& warnings);

// Rewrites multiple non-positional format specifiers as positional (%1$@).
std::string PositionalFormat(const std::string& text);

// One table's text in genstrings' layout, sorted by key.
std::string Render(const std::map<std::string, Entry>& table);

} // namespace OpenFruit::Genstrings
