#pragma once

#include "openib/diagnostics.hpp"
#include "openib/xml.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace openib {

struct IBScene {
    std::string scene_id;
    const xml::Node* scene_node{nullptr};
    const xml::Node* objects_node{nullptr};
    const xml::Node* controller_node{nullptr};
};

struct IBDocument {
    xml::Document xml_document;
    std::string type;
    std::string format_version;
    std::string tools_version;
    std::string target_runtime;
    std::string initial_view_controller;
    bool is_storyboard{false};
    bool is_xib{false};
    std::vector<IBScene> scenes;
};

class IBParser {
public:
    IBDocument parse(const std::filesystem::path& path, Diagnostics& diagnostics) const;

private:
    static bool is_controller_tag(std::string_view tag);
};

struct CoverageReport {
    std::unordered_map<std::string, std::size_t> tag_counts;
    std::unordered_map<std::string, std::size_t> unsupported_tag_counts;
    std::size_t scene_count{0};
    std::size_t outlet_count{0};
    std::size_t action_count{0};
    std::size_t segue_count{0};
    std::size_t constraint_count{0};
};

CoverageReport analyze_document(const IBDocument& document);
bool compiler_knows_tag(std::string_view tag);

} // namespace openib
