#include "genstrings.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <regex>

namespace OpenFruit::Genstrings {
namespace {

constexpr const char* kNoComment = "No comment provided by engineer.";

bool IdentifierChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$';
}

struct Argument {
    std::string label;                 // Swift argument label, if any.
    std::optional<std::string> text;   // Literal content when the value is a string literal.
    bool null = false;                 // nil / NULL / empty.
};

class Scanner {
public:
    Scanner(const std::string& text, Language language) : text_(text), language_(language) {}

    // Skips a comment or string/character literal at the cursor. Returns false
    // when the cursor is on ordinary code.
    bool SkipNonCode() {
        if (Starts("//")) { while (pos_ < text_.size() && text_[pos_] != '\n') ++pos_; return true; }
        if (Starts("/*")) {
            int depth = 0;
            do {
                if (Starts("/*")) { ++depth; pos_ += 2; }
                else if (Starts("*/")) { pos_ += 2; if (language_ == Language::ObjectiveC || --depth == 0) break; }
                else ++pos_;
            } while (pos_ < text_.size());
            return true;
        }
        if (text_[pos_] == '"' || (text_[pos_] == '\'' && language_ == Language::ObjectiveC)) {
            ReadQuoted(); return true;
        }
        return false;
    }

    // Reads a quoted literal at the cursor, returning its raw content.
    std::string ReadQuoted() {
        if (language_ == Language::Swift && Starts("\"\"\"")) {
            pos_ += 3;
            const auto end = text_.find("\"\"\"", pos_);
            const auto content = text_.substr(pos_, end == std::string::npos ? std::string::npos : end - pos_);
            pos_ = end == std::string::npos ? text_.size() : end + 3;
            return content;
        }
        const char quote = text_[pos_++];
        std::string content;
        while (pos_ < text_.size() && text_[pos_] != quote && text_[pos_] != '\n') {
            if (text_[pos_] == '\\' && pos_ + 1 < text_.size()) content += text_[pos_++];
            content += text_[pos_++];
        }
        if (pos_ < text_.size() && text_[pos_] == quote) ++pos_;
        return content;
    }

    void SkipSpace() {
        while (pos_ < text_.size()) {
            if (std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_;
            else if (Starts("//") || Starts("/*")) SkipNonCode();
            else break;
        }
    }

    bool Starts(const char* prefix) const { return text_.compare(pos_, std::char_traits<char>::length(prefix), prefix) == 0; }
    std::size_t Line() const { return static_cast<std::size_t>(std::count(text_.begin(), text_.begin() + pos_, '\n')) + 1; }

    // Parses one argument up to a top-level ',' or ')'.
    Argument ParseArgument() {
        Argument argument;
        SkipSpace();
        if (language_ == Language::Swift) {
            const auto start = pos_;
            while (pos_ < text_.size() && IdentifierChar(text_[pos_])) ++pos_;
            const auto name = text_.substr(start, pos_ - start);
            SkipSpace();
            if (!name.empty() && pos_ < text_.size() && text_[pos_] == ':' && !Starts("::")) {
                argument.label = name; ++pos_; SkipSpace();
            } else pos_ = start;
        }
        std::string literal;
        bool literal_only = true, saw_literal = false;
        int depth = 0;
        const auto value_start = pos_;
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (depth == 0 && (c == ',' || c == ')')) break;
            if (c == '"') {
                const auto content = ReadQuoted();
                if (language_ == Language::Swift && content.find("\\(") != std::string::npos) literal_only = false;
                literal += content; saw_literal = true; continue;
            }
            if (Starts("//") || Starts("/*")) { SkipNonCode(); continue; }
            if (c == '\'' && language_ == Language::ObjectiveC) { ReadQuoted(); literal_only = false; continue; }
            if (c == '(' || c == '[' || c == '{') ++depth;
            else if (c == ')' || c == ']' || c == '}') --depth;
            if (!(c == '@' && language_ == Language::ObjectiveC) && !std::isspace(static_cast<unsigned char>(c)))
                literal_only = false;
            ++pos_;
        }
        auto raw = text_.substr(value_start, pos_ - value_start);
        raw.erase(std::remove_if(raw.begin(), raw.end(), [](unsigned char c) { return std::isspace(c); }), raw.end());
        if (saw_literal && literal_only) argument.text = literal;
        else if (raw == "nil" || raw == "NULL" || raw == "0" || raw.empty()) argument.null = true;
        return argument;
    }

    const std::string& text_;
    Language language_;
    std::size_t pos_ = 0;
};

struct Routine { std::string table_variant; };

void Add(Tables& tables, const std::string& table, const std::string& key, const std::string& value,
         const std::string& comment, const std::string& location, std::vector<std::string>& warnings) {
    auto& entries = tables[table];
    auto [found, inserted] = entries.try_emplace(key, Entry{key, value, {}});
    auto& entry = found->second;
    if (!inserted && entry.value != value)
        warnings.push_back("Key \"" + key + "\" used with multiple values. Value \"" + entry.value +
                           "\" kept. Value \"" + value + "\" ignored." + location);
    if (std::find(entry.comments.begin(), entry.comments.end(), comment) == entry.comments.end()) {
        if (!entry.comments.empty())
            warnings.push_back("Key \"" + key + "\" used with multiple comments \"" + entry.comments.front() +
                               "\" & \"" + comment + "\"" + location);
        entry.comments.push_back(comment);
    }
}

} // namespace

std::string PositionalFormat(const std::string& text) {
    static const std::regex specifier(
        R"(%(?:(\d+)\$)?[-+ #0']*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|q|L|z|t|j)?([@dDiuUxXoOfFeEgGcCsSpaA%]))");
    std::vector<std::smatch> matches;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), specifier); it != std::sregex_iterator(); ++it)
        if ((*it)[2] != "%") matches.push_back(*it);
    if (matches.size() < 2 ||
        std::any_of(matches.begin(), matches.end(), [](const auto& m) { return m[1].matched; }))
        return text;
    std::string result;
    std::size_t last = 0, index = 0;
    for (auto it = std::sregex_iterator(text.begin(), text.end(), specifier); it != std::sregex_iterator(); ++it) {
        const auto& match = *it;
        const auto offset = static_cast<std::size_t>(match.position(0));
        result += text.substr(last, offset - last);
        auto spelled = match.str(0);
        if (match[2] != "%") spelled.insert(1, std::to_string(++index) + "$");
        result += spelled;
        last = offset + static_cast<std::size_t>(match.length(0));
    }
    return result + text.substr(last);
}

void Extract(const std::string& source_text, Language language, const std::string& file_name,
             const Options& options, Tables& tables, std::vector<std::string>& warnings) {
    Scanner scanner(source_text, language);
    auto& pos = scanner.pos_;
    while (pos < source_text.size()) {
        if (scanner.SkipNonCode()) continue;
        if (!IdentifierChar(source_text[pos]) || (pos > 0 && (IdentifierChar(source_text[pos - 1]) ||
                                                             source_text[pos - 1] == '.'))) {
            ++pos; continue;
        }
        const auto start = pos;
        while (pos < source_text.size() && IdentifierChar(source_text[pos])) ++pos;
        const auto name = source_text.substr(start, pos - start);
        std::string variant;
        const auto routine = std::find_if(options.routines.begin(), options.routines.end(), [&](const auto& base) {
            if (name.rfind(base, 0) != 0) return false;
            variant = name.substr(base.size());
            return variant.empty() || variant == "FromTable" || variant == "FromTableInBundle" ||
                   variant == "WithDefaultValue";
        });
        if (routine == options.routines.end()) continue;
        const auto line = scanner.Line();
        scanner.SkipSpace();
        if (pos >= source_text.size() || source_text[pos] != '(') continue;
        ++pos;
        std::vector<Argument> arguments;
        while (pos < source_text.size()) {
            arguments.push_back(scanner.ParseArgument());
            if (pos < source_text.size() && source_text[pos] == ',') { ++pos; continue; }
            if (pos < source_text.size()) ++pos; // ')'
            break;
        }
        const auto location = " (" + file_name + ":" + std::to_string(line) + ")";
        const auto labeled = [&](const char* label) -> const Argument* {
            for (const auto& argument : arguments) if (argument.label == label) return &argument;
            return nullptr;
        };
        const Argument *key = nullptr, *table = nullptr, *value = nullptr, *comment = nullptr;
        if (language == Language::Swift && std::any_of(arguments.begin(), arguments.end(),
                [](const auto& a) { return !a.label.empty(); })) {
            for (const auto& argument : arguments) if (argument.label.empty()) { key = &argument; break; }
            table = labeled("tableName"); value = labeled("value"); comment = labeled("comment");
        } else {
            // Positional C/Objective-C macro parameters.
            const auto at = [&](std::size_t i) { return i < arguments.size() ? &arguments[i] : nullptr; };
            key = at(0);
            if (variant.empty()) comment = at(1);
            else if (variant == "FromTable") { table = at(1); comment = at(2); }
            else if (variant == "FromTableInBundle") { table = at(1); comment = at(3); }
            else { table = at(1); value = at(3); comment = at(4); }
        }
        const auto literal = [](const Argument* argument) { return argument && argument->text; };
        if (!literal(key)) {
            warnings.push_back("Bad entry in file " + file_name + " (line = " + std::to_string(line) +
                               "): Argument is not a literal string.");
            continue;
        }
        if ((table && !table->null && !literal(table)) || (value && !value->null && !literal(value)) ||
            (comment && !comment->null && !literal(comment))) {
            warnings.push_back("Bad entry in file " + file_name + " (line = " + std::to_string(line) +
                               "): Argument is not a literal string.");
            continue;
        }
        const auto table_name = literal(table) && !table->text->empty() ? *table->text : std::string("Localizable");
        auto text = literal(value) ? *value->text : *key->text;
        if (options.positional_parameters) text = PositionalFormat(text);
        const auto note = literal(comment) && !comment->text->empty() ? *comment->text : std::string(kNoComment);
        Add(tables, table_name, *key->text, text, note, location, warnings);
    }
}

std::string Render(const std::map<std::string, Entry>& table) {
    std::string out;
    for (const auto& [key, entry] : table) {
        out += "/* ";
        for (std::size_t i = 0; i < entry.comments.size(); ++i) {
            if (i) out += "\n   ";
            out += entry.comments[i];
        }
        out += " */\n\"" + key + "\" = \"" + entry.value + "\";\n\n";
    }
    return out;
}

} // namespace OpenFruit::Genstrings
