#pragma once

#include "openib/diagnostics.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace openib::xml {

struct Attribute {
    std::string name;
    std::string value;
};

struct Node {
    std::string name;
    std::vector<Attribute> attributes;
    std::vector<std::unique_ptr<Node>> children;
    std::string text;
    std::size_t line{1};

    [[nodiscard]] std::optional<std::string_view> attr(std::string_view key) const;
    [[nodiscard]] std::string attr_or(std::string_view key, std::string fallback = {}) const;
    [[nodiscard]] bool attr_is_yes(std::string_view key) const;
    [[nodiscard]] const Node* first_child(std::string_view child_name) const;
    [[nodiscard]] Node* first_child(std::string_view child_name);
    [[nodiscard]] std::vector<const Node*> children_named(std::string_view child_name) const;
    [[nodiscard]] std::vector<const Node*> descendants_named(std::string_view child_name) const;
};

struct Document {
    std::unique_ptr<Node> root;
    std::string source_path;
};

class Parser {
public:
    Document parse_file(const std::filesystem::path& path);
    Document parse_string(std::string_view input, std::string source_name = "<memory>");

private:
    std::string normalized_input_;
    std::string_view input_;
    std::string source_;
    std::size_t pos_{0};
    std::size_t line_{1};

    [[nodiscard]] bool eof() const;
    [[nodiscard]] char peek(std::size_t offset = 0) const;
    char take();
    void skip_ws();
    bool starts_with(std::string_view s) const;
    void expect(char c);
    void skip_until(std::string_view marker);
    void skip_prolog_and_misc();
    std::string parse_name();
    std::string parse_quoted();
    std::unique_ptr<Node> parse_node();
    std::string decode_entities(std::string_view s) const;
    [[noreturn]] void fail(const std::string& message) const;
};

std::string escape(std::string_view value);

} // namespace openib::xml
