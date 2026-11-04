#pragma once

#include "openib/diagnostics.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace openib::nib {

enum class ValueType : std::uint8_t {
    Int8 = 0x00,
    Int16 = 0x01,
    Int32 = 0x02,
    Int64 = 0x03,
    False = 0x04,
    True = 0x05,
    Float = 0x06,
    Double = 0x07,
    Bytes = 0x08,
    Nil = 0x09,
    Reference = 0x0A
};

struct Reference { std::uint32_t index{0}; };
struct Bytes { std::vector<std::uint8_t> data; };

using Payload = std::variant<std::monostate, std::int8_t, std::int16_t, std::int32_t,
                             std::int64_t, float, double, Bytes, Reference>;

struct ObjectEntry {
    std::uint32_t class_index{0};
    std::uint32_t value_start{0};
    std::uint32_t value_count{0};
};

struct ValueEntry {
    std::uint32_t key_index{0};
    ValueType type{ValueType::Nil};
    Payload payload{};
};

struct ClassEntry {
    std::string name;
    std::vector<std::uint32_t> fallback_class_indices;
};

struct Archive {
    std::uint32_t format_version{1};
    std::uint32_t coder_version{10};
    std::vector<ObjectEntry> objects;
    std::vector<std::string> keys;
    std::vector<ValueEntry> values;
    std::vector<ClassEntry> classes;
};

class Reader {
public:
    Archive read_file(const std::filesystem::path& path) const;
    Archive read_bytes(const std::vector<std::uint8_t>& bytes) const;
};

class Writer {
public:
    std::vector<std::uint8_t> write_bytes(const Archive& archive) const;
    void write_file(const Archive& archive, const std::filesystem::path& path) const;
};

std::string dump_text(const Archive& archive, bool show_types = true);
std::string canonical_text(const Archive& archive);

// High-level graph used by the Interface Builder compiler before flattening.
struct GraphObject;
using GraphRef = std::shared_ptr<GraphObject>;
struct RawBytes { std::vector<std::uint8_t> data; };
struct RawFloat { float value{0}; };
struct RawInt32 { std::int32_t value{0}; };
struct RawInt64 { std::int64_t value{0}; };

using GraphValue = std::variant<std::monostate, bool, std::int64_t, double, RawFloat,
                                RawInt32, RawInt64, RawBytes, GraphRef>;

struct GraphObject {
    std::string class_name;
    std::vector<std::pair<std::string, GraphValue>> properties;
    std::uint64_t serial{0};

    GraphObject& set(std::string key, GraphValue value);
    [[nodiscard]] std::optional<GraphValue> get(const std::string& key) const;
    void erase(const std::string& key);
};

class GraphBuilder {
public:
    GraphBuilder();
    GraphRef object(std::string class_name);
    GraphRef string(std::string value);
    GraphRef array(const std::vector<GraphRef>& items);
    GraphRef mutable_array(const std::vector<GraphRef>& items);
    GraphRef dictionary(const std::vector<std::pair<GraphRef, GraphRef>>& items);
    GraphRef mutable_dictionary(const std::vector<std::pair<GraphRef, GraphRef>>& items);
    GraphRef proxy(std::string identifier);
    Archive flatten(const std::vector<GraphRef>& roots, std::uint32_t coder_version = 10) const;

private:
    mutable std::uint64_t next_serial_{1};
    std::unordered_map<std::string, std::weak_ptr<GraphObject>> strings_;
    std::weak_ptr<GraphObject> empty_array_;
};

} // namespace openib::nib
