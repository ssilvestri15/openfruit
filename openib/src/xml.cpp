#include "openib/xml.hpp"

#include <charconv>
#include <fstream>
#include <sstream>

namespace openib::xml {

std::optional<std::string_view> Node::attr(std::string_view key) const {
    for (const auto& a : attributes) {
        if (a.name == key) return a.value;
    }
    return std::nullopt;
}

std::string Node::attr_or(std::string_view key, std::string fallback) const {
    auto value = attr(key);
    return value ? std::string(*value) : std::move(fallback);
}

bool Node::attr_is_yes(std::string_view key) const {
    auto value = attr(key);
    return value && (*value == "YES" || *value == "true" || *value == "1");
}

const Node* Node::first_child(std::string_view child_name) const {
    for (const auto& child : children) {
        if (child->name == child_name) return child.get();
    }
    return nullptr;
}

Node* Node::first_child(std::string_view child_name) {
    for (auto& child : children) {
        if (child->name == child_name) return child.get();
    }
    return nullptr;
}

std::vector<const Node*> Node::children_named(std::string_view child_name) const {
    std::vector<const Node*> result;
    for (const auto& child : children) {
        if (child->name == child_name) result.push_back(child.get());
    }
    return result;
}

static void collect_descendants(const Node& node, std::string_view name,
                                std::vector<const Node*>& out) {
    for (const auto& child : node.children) {
        if (child->name == name) out.push_back(child.get());
        collect_descendants(*child, name, out);
    }
}

std::vector<const Node*> Node::descendants_named(std::string_view child_name) const {
    std::vector<const Node*> result;
    collect_descendants(*this, child_name, result);
    return result;
}

Document Parser::parse_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw OpenIBError("Unable to open XML file: " + path.string());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return parse_string(buffer.str(), path.string());
}

Document Parser::parse_string(std::string_view input, std::string source_name) {
    // XML processors normalize CRLF and bare CR to LF before parsing.
    normalized_input_.clear();normalized_input_.reserve(input.size());
    for(std::size_t i=0;i<input.size();++i){if(input[i]=='\r'){normalized_input_.push_back('\n');if(i+1<input.size()&&input[i+1]=='\n')++i;}else normalized_input_.push_back(input[i]);}
    input_ = normalized_input_;
    source_ = std::move(source_name);
    pos_ = 0;
    line_ = 1;

    if (input_.size() >= 3 && static_cast<unsigned char>(input_[0]) == 0xEF &&
        static_cast<unsigned char>(input_[1]) == 0xBB &&
        static_cast<unsigned char>(input_[2]) == 0xBF) {
        pos_ = 3;
    }

    skip_prolog_and_misc();
    auto root = parse_node();
    skip_prolog_and_misc();
    skip_ws();
    if (!eof()) fail("Unexpected trailing content after root element");
    return {std::move(root), source_};
}

bool Parser::eof() const { return pos_ >= input_.size(); }

char Parser::peek(std::size_t offset) const {
    if (pos_ + offset >= input_.size()) return '\0';
    return input_[pos_ + offset];
}

char Parser::take() {
    if (eof()) fail("Unexpected end of file");
    char c = input_[pos_++];
    if (c == '\n') ++line_;
    return c;
}

void Parser::skip_ws() {
    while (!eof()) {
        char c = peek();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') take();
        else break;
    }
}

bool Parser::starts_with(std::string_view s) const {
    return input_.substr(pos_, s.size()) == s;
}

void Parser::expect(char c) {
    if (take() != c) fail(std::string("Expected '") + c + "'");
}

void Parser::skip_until(std::string_view marker) {
    auto found = input_.find(marker, pos_);
    if (found == std::string_view::npos) fail("Unterminated XML construct");
    while (pos_ < found + marker.size()) take();
}

void Parser::skip_prolog_and_misc() {
    while (true) {
        skip_ws();
        if (starts_with("<?")) {
            skip_until("?>");
        } else if (starts_with("<!--")) {
            skip_until("-->");
        } else if (starts_with("<!DOCTYPE")) {
            // Xcode storyboards use a simple doctype at most. Track [] nesting defensively.
            int bracket_depth = 0;
            while (!eof()) {
                char c = take();
                if (c == '[') ++bracket_depth;
                if (c == ']') --bracket_depth;
                if (c == '>' && bracket_depth <= 0) break;
            }
        } else {
            break;
        }
    }
}

std::string Parser::parse_name() {
    std::size_t start = pos_;
    while (!eof()) {
        char c = peek();
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' ||
                        c == ':' || c == '.';
        if (!ok) break;
        take();
    }
    if (pos_ == start) fail("Expected XML name");
    return std::string(input_.substr(start, pos_ - start));
}

std::string Parser::parse_quoted() {
    char quote = take();
    if (quote != '\'' && quote != '"') fail("Expected quoted attribute value");
    std::size_t start = pos_;
    while (!eof() && peek() != quote) take();
    if (eof()) fail("Unterminated attribute value");
    auto raw = input_.substr(start, pos_ - start);
    take();
    return decode_entities(raw);
}

std::unique_ptr<Node> Parser::parse_node() {
    skip_ws();
    if (!starts_with("<")) fail("Expected element");
    const auto node_line = line_;
    expect('<');
    if (peek() == '/') fail("Unexpected closing tag");

    auto node = std::make_unique<Node>();
    node->line = node_line;
    node->name = parse_name();

    while (true) {
        skip_ws();
        if (starts_with("/>")) {
            take(); take();
            return node;
        }
        if (peek() == '>') {
            take();
            break;
        }
        Attribute attribute;
        attribute.name = parse_name();
        skip_ws();
        expect('=');
        skip_ws();
        attribute.value = parse_quoted();
        node->attributes.push_back(std::move(attribute));
    }

    std::string text_accumulator;
    while (true) {
        if (eof()) fail("Unterminated element <" + node->name + ">");
        if (starts_with("</")) {
            take(); take();
            auto closing = parse_name();
            if (closing != node->name) {
                fail("Mismatched closing tag </" + closing + "> for <" + node->name + ">");
            }
            skip_ws();
            expect('>');
            node->text = decode_entities(text_accumulator);
            return node;
        }
        if (starts_with("<!--")) {
            skip_until("-->");
            continue;
        }
        if (starts_with("<![CDATA[")) {
            for (int i = 0; i < 9; ++i) take();
            auto end = input_.find("]]>", pos_);
            if (end == std::string_view::npos) fail("Unterminated CDATA section");
            while (pos_ < end) text_accumulator.push_back(take());
            take(); take(); take();
            continue;
        }
        if (peek() == '<') {
            node->children.push_back(parse_node());
            continue;
        }
        text_accumulator.push_back(take());
    }
}

std::string Parser::decode_entities(std::string_view s) const {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') {
            out.push_back(s[i]);
            continue;
        }
        auto semicolon = s.find(';', i + 1);
        if (semicolon == std::string_view::npos) {
            out.push_back('&');
            continue;
        }
        auto entity = s.substr(i + 1, semicolon - i - 1);
        if (entity == "amp") out.push_back('&');
        else if (entity == "lt") out.push_back('<');
        else if (entity == "gt") out.push_back('>');
        else if (entity == "quot") out.push_back('"');
        else if (entity == "apos") out.push_back('\'');
        else if (!entity.empty() && entity[0] == '#') {
            unsigned int cp = 0;
            bool ok = false;
            if (entity.size() > 2 && (entity[1] == 'x' || entity[1] == 'X')) {
                auto first = entity.data() + 2;
                auto last = entity.data() + entity.size();
                ok = std::from_chars(first, last, cp, 16).ec == std::errc{};
            } else {
                auto first = entity.data() + 1;
                auto last = entity.data() + entity.size();
                ok = std::from_chars(first, last, cp, 10).ec == std::errc{};
            }
            if (ok && cp <= 0x7F) out.push_back(static_cast<char>(cp));
            else out.append(s.substr(i, semicolon - i + 1));
        } else {
            out.append(s.substr(i, semicolon - i + 1));
        }
        i = semicolon;
    }
    return out;
}

[[noreturn]] void Parser::fail(const std::string& message) const {
    throw OpenIBError(source_ + ":" + std::to_string(line_) + ": " + message);
}

std::string escape(std::string_view value) {
    std::string out;
    for (char c : value) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += c; break;
        }
    }
    return out;
}

} // namespace openib::xml
