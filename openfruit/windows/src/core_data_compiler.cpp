#include "core_data_compiler.hpp"

#include "win32_process.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <unordered_map>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

struct XmlNode {
    std::string name;
    std::map<std::string, std::string> attributes;
    std::vector<XmlNode> children;

    std::string Attribute(const std::string& key) const {
        const auto it = attributes.find(key);
        return it == attributes.end() ? std::string() : it->second;
    }
};

std::string XmlEscape(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
        case '&': result += "&amp;"; break;
        case '<': result += "&lt;"; break;
        case '>': result += "&gt;"; break;
        case '\"': result += "&quot;"; break;
        case '\'': result += "&apos;"; break;
        default: result += ch; break;
        }
    }
    return result;
}

std::string DecodeXml(std::string value) {
    const std::pair<const char*, const char*> entities[] = {
        {"&quot;", "\""}, {"&apos;", "'"}, {"&lt;", "<"},
        {"&gt;", ">"}, {"&amp;", "&"}
    };
    for (const auto& [encoded, decoded] : entities) {
        std::size_t pos = 0;
        while ((pos = value.find(encoded, pos)) != std::string::npos) {
            value.replace(pos, std::char_traits<char>::length(encoded), decoded);
            pos += std::char_traits<char>::length(decoded);
        }
    }
    return value;
}

class XmlParser {
public:
    explicit XmlParser(std::string input) : input_(std::move(input)) {}

    bool Parse(XmlNode& root, std::string& error) {
        SkipMisc();
        if (!ParseNode(root, error)) return false;
        SkipMisc();
        return true;
    }

private:
    std::string input_;
    std::size_t position_ = 0;

    bool Starts(const std::string& value) const {
        return input_.compare(position_, value.size(), value) == 0;
    }
    void Space() {
        while (position_ < input_.size() &&
               std::isspace(static_cast<unsigned char>(input_[position_]))) ++position_;
    }
    void SkipMisc() {
        for (;;) {
            Space();
            if (Starts("<?")) {
                const auto end = input_.find("?>", position_ + 2);
                position_ = end == std::string::npos ? input_.size() : end + 2;
            } else if (Starts("<!--")) {
                const auto end = input_.find("-->", position_ + 4);
                position_ = end == std::string::npos ? input_.size() : end + 3;
            } else if (Starts("<!DOCTYPE")) {
                const auto end = input_.find('>', position_ + 9);
                position_ = end == std::string::npos ? input_.size() : end + 1;
            } else break;
        }
    }
    std::string Name() {
        const std::size_t start = position_;
        while (position_ < input_.size()) {
            const char ch = input_[position_];
            if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
                  ch == '-' || ch == ':' || ch == '.')) break;
            ++position_;
        }
        return input_.substr(start, position_ - start);
    }
    bool ParseNode(XmlNode& node, std::string& error) {
        SkipMisc();
        if (position_ >= input_.size() || input_[position_] != '<' || Starts("</")) {
            error = "expected XML element";
            return false;
        }
        ++position_;
        node.name = Name();
        if (node.name.empty()) { error = "empty XML element name"; return false; }
        for (;;) {
            Space();
            if (Starts("/>")) { position_ += 2; return true; }
            if (position_ < input_.size() && input_[position_] == '>') { ++position_; break; }
            const std::string key = Name();
            Space();
            if (key.empty() || position_ >= input_.size() || input_[position_++] != '=') {
                error = "invalid XML attribute in " + node.name;
                return false;
            }
            Space();
            if (position_ >= input_.size() ||
                (input_[position_] != '\"' && input_[position_] != '\'')) {
                error = "unquoted XML attribute in " + node.name;
                return false;
            }
            const char quote = input_[position_++];
            const auto end = input_.find(quote, position_);
            if (end == std::string::npos) { error = "unterminated XML attribute"; return false; }
            node.attributes[key] = DecodeXml(input_.substr(position_, end - position_));
            position_ = end + 1;
        }
        for (;;) {
            SkipMisc();
            if (Starts("</")) {
                position_ += 2;
                const std::string closing = Name();
                Space();
                if (closing != node.name || position_ >= input_.size() || input_[position_++] != '>') {
                    error = "mismatched XML closing element for " + node.name;
                    return false;
                }
                return true;
            }
            if (position_ >= input_.size()) { error = "unterminated XML element " + node.name; return false; }
            if (input_[position_] == '<') {
                XmlNode child;
                if (!ParseNode(child, error)) return false;
                node.children.push_back(std::move(child));
            } else {
                const auto next = input_.find('<', position_);
                position_ = next == std::string::npos ? input_.size() : next;
            }
        }
    }
};

struct PlistValue {
    enum class Kind { String, Integer, Real, Boolean, Data, Uid, Array, Dictionary };
    Kind kind = Kind::String;
    std::string text;
    long long integer = 0;
    double real = 0.0;
    bool boolean = false;
    std::vector<PlistValue> array;
    std::vector<std::pair<std::string, PlistValue>> dictionary;

    static PlistValue String(std::string v) { PlistValue p; p.text = std::move(v); return p; }
    static PlistValue Integer(long long v) { PlistValue p; p.kind = Kind::Integer; p.integer = v; return p; }
    static PlistValue Real(double v) { PlistValue p; p.kind = Kind::Real; p.real = v; return p; }
    static PlistValue Boolean(bool v) { PlistValue p; p.kind = Kind::Boolean; p.boolean = v; return p; }
    static PlistValue Uid(std::size_t v) { PlistValue p; p.kind = Kind::Uid; p.integer = static_cast<long long>(v); return p; }
    static PlistValue Array(std::vector<PlistValue> v) { PlistValue p; p.kind = Kind::Array; p.array = std::move(v); return p; }
    static PlistValue Dictionary(std::vector<std::pair<std::string, PlistValue>> v) { PlistValue p; p.kind = Kind::Dictionary; p.dictionary = std::move(v); return p; }
};

void WritePlistValue(std::ostream& out, const PlistValue& value, int depth) {
    const std::string pad(static_cast<std::size_t>(depth) * 2, ' ');
    switch (value.kind) {
    case PlistValue::Kind::String: out << pad << "<string>" << XmlEscape(value.text) << "</string>\n"; break;
    case PlistValue::Kind::Integer: out << pad << "<integer>" << value.integer << "</integer>\n"; break;
    case PlistValue::Kind::Real: out << pad << "<real>" << value.real << "</real>\n"; break;
    case PlistValue::Kind::Boolean: out << pad << (value.boolean ? "<true/>\n" : "<false/>\n"); break;
    case PlistValue::Kind::Data: out << pad << "<data>" << value.text << "</data>\n"; break;
    case PlistValue::Kind::Uid:
        out << pad << "<dict>\n" << pad << "  <key>CF$UID</key>\n" << pad << "  <integer>" << value.integer << "</integer>\n" << pad << "</dict>\n";
        break;
    case PlistValue::Kind::Array:
        out << pad << "<array>\n";
        for (const auto& item : value.array) WritePlistValue(out, item, depth + 1);
        out << pad << "</array>\n";
        break;
    case PlistValue::Kind::Dictionary:
        out << pad << "<dict>\n";
        for (const auto& [key, item] : value.dictionary) {
            out << pad << "  <key>" << XmlEscape(key) << "</key>\n";
            WritePlistValue(out, item, depth + 1);
        }
        out << pad << "</dict>\n";
        break;
    }
}

bool IsYes(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower == "yes" || lower == "true" || lower == "1";
}

const XmlNode* Child(const XmlNode& node, const std::string& name) {
    for (const auto& child : node.children) if (child.name == name) return &child;
    return nullptr;
}

std::map<std::string, std::string> UserInfo(const XmlNode& node) {
    std::map<std::string, std::string> result;
    if (const XmlNode* info = Child(node, "userInfo")) {
        for (const auto& entry : info->children) {
            if (entry.name == "entry" && !entry.Attribute("key").empty())
                result[entry.Attribute("key")] = entry.Attribute("value");
        }
    }
    return result;
}

struct PropertyModel {
    const XmlNode* node = nullptr;
    std::size_t object = 0;
};
struct EntityModel {
    const XmlNode* node = nullptr;
    std::size_t object = 0;
    std::vector<PropertyModel> properties;
};

class ArchiveBuilder {
public:
    ArchiveBuilder() {
        objects_.push_back(PlistValue::String("$null"));
        objects_.push_back(PlistValue::Dictionary({}));
        strings_["$null"] = 0;
    }

    std::size_t Add(PlistValue value) { objects_.push_back(std::move(value)); return objects_.size() - 1; }
    std::size_t String(const std::string& value) {
        const auto found = strings_.find(value);
        if (found != strings_.end()) return found->second;
        const auto index = Add(PlistValue::String(value));
        strings_[value] = index;
        return index;
    }
    std::size_t Class(const std::string& name, std::vector<std::string> hierarchy) {
        const auto found = classes_.find(name);
        if (found != classes_.end()) return found->second;
        std::vector<PlistValue> classes;
        for (auto& item : hierarchy) classes.push_back(PlistValue::String(std::move(item)));
        const auto index = Add(PlistValue::Dictionary({
            {"$classname", PlistValue::String(name)},
            {"$classes", PlistValue::Array(std::move(classes))}
        }));
        classes_[name] = index;
        return index;
    }
    std::size_t Collection(const std::map<std::string, std::size_t>& values, bool mutable_value = false) {
        std::vector<PlistValue> keys, objects;
        for (const auto& [key, value] : values) {
            keys.push_back(PlistValue::Uid(String(key)));
            objects.push_back(PlistValue::Uid(value));
        }
        return Add(PlistValue::Dictionary({
            {"NS.keys", PlistValue::Array(std::move(keys))},
            {"NS.objects", PlistValue::Array(std::move(objects))},
            {"$class", PlistValue::Uid(Class(mutable_value ? "NSMutableDictionary" : "NSDictionary",
                mutable_value ? std::vector<std::string>{"NSMutableDictionary", "NSDictionary", "NSObject"}
                              : std::vector<std::string>{"NSDictionary", "NSObject"}))}
        }));
    }
    std::size_t Array(const std::vector<std::size_t>& values, bool set = false) {
        std::vector<PlistValue> objects;
        for (const auto value : values) objects.push_back(PlistValue::Uid(value));
        const std::string name = set ? "NSSet" : "NSMutableArray";
        const std::vector<std::string> hierarchy = set
            ? std::vector<std::string>{"NSSet", "NSObject"}
            : std::vector<std::string>{"NSMutableArray", "NSArray", "NSObject"};
        return Add(PlistValue::Dictionary({
            {"NS.objects", PlistValue::Array(std::move(objects))},
            {"$class", PlistValue::Uid(Class(name, hierarchy))}
        }));
    }
    void Set(std::size_t index, PlistValue value) { objects_.at(index) = std::move(value); }
    bool Write(const fs::path& path, std::string& error) const {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) { error = "cannot write " + path.string(); return false; }
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
               "<plist version=\"1.0\">\n<dict>\n"
               "  <key>$version</key>\n  <integer>100000</integer>\n"
               "  <key>$archiver</key>\n  <string>NSKeyedArchiver</string>\n"
               "  <key>$top</key>\n  <dict>\n    <key>root</key>\n";
        WritePlistValue(out, PlistValue::Uid(1), 2);
        out << "  </dict>\n  <key>$objects</key>\n  <array>\n";
        for (const auto& object : objects_) WritePlistValue(out, object, 2);
        out << "  </array>\n</dict>\n</plist>\n";
        if (!out.good()) { error = "failed while writing " + path.string(); return false; }
        return true;
    }

private:
    std::vector<PlistValue> objects_;
    std::unordered_map<std::string, std::size_t> strings_;
    std::unordered_map<std::string, std::size_t> classes_;
};

std::pair<long long, std::string> AttributeType(const std::string& name) {
    if (name == "Integer 16") return {100, "NSNumber"};
    if (name == "Integer 32") return {200, "NSNumber"};
    if (name == "Integer 64") return {300, "NSNumber"};
    if (name == "Decimal") return {400, "NSDecimalNumber"};
    if (name == "Double") return {500, "NSNumber"};
    if (name == "Float") return {600, "NSNumber"};
    if (name == "String") return {700, "NSString"};
    if (name == "Boolean") return {800, "NSNumber"};
    if (name == "Date") return {900, "NSDate"};
    if (name == "Binary") return {1000, "NSData"};
    if (name == "UUID") return {1100, "NSUUID"};
    if (name == "URI") return {1200, "NSURL"};
    if (name == "Transformable") return {1800, {}};
    return {-1, {}};
}

std::size_t UserInfoObject(ArchiveBuilder& archive, const XmlNode& node) {
    std::map<std::string, std::size_t> values;
    for (const auto& [key, value] : UserInfo(node)) values[key] = archive.String(value);
    return archive.Collection(values);
}

std::size_t DefaultObject(ArchiveBuilder& archive, const XmlNode& node, long long type, std::string& error) {
    const std::string value = node.Attribute("defaultValueString");
    if (value.empty()) return 0;
    if (type == 800) return archive.Add(PlistValue::Boolean(IsYes(value)));
    if (type >= 100 && type <= 300) {
        long long number = 0;
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
        if (parsed.ec != std::errc()) { error = "invalid integer Core Data default: " + value; return 0; }
        return archive.Add(PlistValue::Integer(number));
    }
    if (type == 400 || type == 500 || type == 600) {
        try { return archive.Add(PlistValue::Real(std::stod(value))); }
        catch (...) { error = "invalid floating-point Core Data default: " + value; return 0; }
    }
    if (type == 700) return archive.String(value);
    error = "unsupported Core Data default value for attribute type " + node.Attribute("attributeType");
    return 0;
}

bool CompileModel(const fs::path& contents, const fs::path& output, std::string& error) {
    std::ifstream input(contents, std::ios::binary);
    if (!input) { error = "cannot read Core Data model " + contents.string(); return false; }
    std::ostringstream buffer; buffer << input.rdbuf();
    XmlNode model;
    if (!XmlParser(buffer.str()).Parse(model, error) || model.name != "model") {
        if (error.empty()) error = "Core Data contents root is not <model>";
        return false;
    }

    ArchiveBuilder archive;
    std::vector<EntityModel> entities;
    std::unordered_map<std::string, std::size_t> entity_by_name;
    std::map<std::string, std::size_t> entity_dictionary;

    for (const auto& child : model.children) {
        if (child.name != "entity") continue;
        EntityModel entity;
        entity.node = &child;
        entity.object = archive.Add(PlistValue::Dictionary({}));
        entities.push_back(entity);
        entity_by_name[child.Attribute("name")] = entity.object;
        entity_dictionary[child.Attribute("name")] = entity.object;
    }
    for (auto& entity : entities) {
        for (const auto& child : entity.node->children) {
            if (child.name == "attribute" || child.name == "relationship") {
                entity.properties.push_back({&child, archive.Add(PlistValue::Dictionary({}))});
            } else if (child.name == "fetchedProperty" || child.name == "derivedAttribute") {
                error = "unsupported Core Data property kind <" + child.name + "> in " + contents.string();
                return false;
            }
        }
    }

    std::unordered_map<std::string, std::size_t> property_by_identity;
    for (const auto& entity : entities) for (const auto& property : entity.properties)
        property_by_identity[entity.node->Attribute("name") + "\n" + property.node->Attribute("name")] = property.object;

    const auto attribute_class = archive.Class("NSAttributeDescription", {"NSAttributeDescription", "NSPropertyDescription", "NSObject"});
    const auto relationship_class = archive.Class("NSRelationshipDescription", {"NSRelationshipDescription", "NSPropertyDescription", "NSObject"});
    const auto entity_class = archive.Class("NSEntityDescription", {"NSEntityDescription", "NSObject"});
    const auto model_class = archive.Class("NSManagedObjectModel", {"NSManagedObjectModel", "NSObject"});

    for (auto& entity : entities) {
        std::map<std::string, std::size_t> properties;
        for (auto& property : entity.properties) {
            const XmlNode& node = *property.node;
            const std::string name = node.Attribute("name");
            properties[name] = property.object;
            const bool optional = IsYes(node.Attribute("optional"));
            const bool has_user_info = !UserInfo(node).empty();
            std::vector<std::pair<std::string, PlistValue>> fields;
            fields.push_back({"_P", PlistValue::Integer(241 - (has_user_info ? 64 : 0) + (optional ? 2 : 0))});
            fields.push_back({"NSEntity", PlistValue::Uid(entity.object)});
            fields.push_back({"NSPropertyName", PlistValue::Uid(archive.String(name))});
            fields.push_back({"NSRenamingIdentifier", PlistValue::Uid(archive.String(node.Attribute("renamingIdentifier").empty() ? name : node.Attribute("renamingIdentifier")))});
            if (optional) fields.push_back({"NSIsOptional", PlistValue::Boolean(true)});
            if (IsYes(node.Attribute("transient"))) fields.push_back({"NSIsTransient", PlistValue::Boolean(true)});
            if (has_user_info) fields.push_back({"NSUserInfo", PlistValue::Uid(UserInfoObject(archive, node))});

            if (node.name == "attribute") {
                auto [type, value_class] = AttributeType(node.Attribute("attributeType"));
                if (type < 0) { error = "unsupported Core Data attribute type: " + node.Attribute("attributeType"); return false; }
                const std::string custom_class = node.Attribute("customClassName");
                if (!custom_class.empty()) value_class = custom_class;
                const auto default_object = DefaultObject(archive, node, type, error);
                if (!error.empty()) return false;
                fields.push_back({"NSAttributeType", PlistValue::Integer(type)});
                fields.push_back({"NSAttributeValueClassName", PlistValue::Uid(value_class.empty() ? 0 : archive.String(value_class))});
                fields.push_back({"NSDefaultValue", PlistValue::Uid(default_object)});
                const std::string transformer = node.Attribute("valueTransformerName");
                fields.push_back({"NSValueTransformerName", PlistValue::Uid(transformer.empty() ? 0 : archive.String(transformer))});
                fields.push_back({"NSFlagsKey", PlistValue::Integer(0)});
                if (IsYes(node.Attribute("indexed"))) fields.push_back({"NSIsIndexed", PlistValue::Boolean(true)});
                if (IsYes(node.Attribute("allowsExternalBinaryDataStorage"))) fields.push_back({"NSAllowsExternalBinaryDataStorage", PlistValue::Boolean(true)});
                fields.push_back({"$class", PlistValue::Uid(attribute_class)});
            } else {
                const std::string destination_name = node.Attribute("destinationEntity");
                const auto destination = entity_by_name.find(destination_name);
                if (destination == entity_by_name.end()) { error = "unknown Core Data relationship destination " + destination_name; return false; }
                const std::string inverse_name = node.Attribute("inverseName");
                const std::string inverse_entity = node.Attribute("inverseEntity").empty() ? destination_name : node.Attribute("inverseEntity");
                std::size_t inverse = 0;
                const auto inverse_it = property_by_identity.find(inverse_entity + "\n" + inverse_name);
                if (!inverse_name.empty() && inverse_it != property_by_identity.end()) inverse = inverse_it->second;
                const std::map<std::string, long long> rules = {{"No Action", 0}, {"Nullify", 1}, {"Cascade", 2}, {"Deny", 3}};
                const auto rule_it = rules.find(node.Attribute("deletionRule"));
                const long long rule = rule_it == rules.end() ? 0 : rule_it->second;
                long long min_count = 0, max_count = IsYes(node.Attribute("toMany")) ? 0 : 1;
                if (!node.Attribute("minCount").empty()) std::from_chars(node.Attribute("minCount").data(), node.Attribute("minCount").data() + node.Attribute("minCount").size(), min_count);
                if (!node.Attribute("maxCount").empty()) std::from_chars(node.Attribute("maxCount").data(), node.Attribute("maxCount").data() + node.Attribute("maxCount").size(), max_count);
                fields.push_back({"NSDestinationEntity", PlistValue::Uid(destination->second)});
                fields.push_back({"NSDeleteRule", PlistValue::Integer(rule)});
                fields.push_back({"NSInverseRelationship", PlistValue::Uid(inverse)});
                fields.push_back({"_NSInverseRelationshipName", PlistValue::Uid(inverse_name.empty() ? 0 : archive.String(inverse_name))});
                fields.push_back({"_NSDestinationEntityName", PlistValue::Uid(archive.String(destination_name))});
                fields.push_back({"NSMinCount", PlistValue::Integer(min_count)});
                fields.push_back({"NSMaxCount", PlistValue::Integer(max_count)});
                if (IsYes(node.Attribute("ordered"))) fields.push_back({"NSIsOrdered", PlistValue::Boolean(true)});
                fields.push_back({"$class", PlistValue::Uid(relationship_class)});
            }
            archive.Set(property.object, PlistValue::Dictionary(std::move(fields)));
        }

        std::map<std::string, std::size_t> subentities;
        for (const auto& candidate : entities) {
            if (candidate.node->Attribute("parentEntity") == entity.node->Attribute("name"))
                subentities[candidate.node->Attribute("name")] = candidate.object;
        }
        std::vector<std::size_t> unique_tuples;
        if (const XmlNode* constraints = Child(*entity.node, "uniquenessConstraints")) {
            for (const auto& tuple : constraints->children) {
                std::vector<std::size_t> names;
                for (const auto& constraint : tuple.children) if (constraint.name == "constraint") names.push_back(archive.String(constraint.Attribute("value")));
                if (!names.empty()) unique_tuples.push_back(archive.Array(names));
            }
        }
        const std::string name = entity.node->Attribute("name");
        const std::string represented = entity.node->Attribute("representedClassName").empty() ? name : entity.node->Attribute("representedClassName");
        const std::string renamed = entity.node->Attribute("renamingIdentifier").empty() ? name : entity.node->Attribute("renamingIdentifier");
        const auto super_it = entity_by_name.find(entity.node->Attribute("parentEntity"));
        archive.Set(entity.object, PlistValue::Dictionary({
            {"NSEntityName", PlistValue::Uid(archive.String(name))},
            {"NSClassNameForEntity", PlistValue::Uid(archive.String(represented))},
            {"NSUniqueTuples", PlistValue::Uid(archive.Array(unique_tuples))},
            {"NSUserInfo", PlistValue::Uid(UserInfoObject(archive, *entity.node))},
            {"NSSubentities", PlistValue::Uid(archive.Collection(subentities, true))},
            {"NSVersionHashModifier", PlistValue::Uid(entity.node->Attribute("versionHashModifier").empty() ? 0 : archive.String(entity.node->Attribute("versionHashModifier")))},
            {"NSProperties", PlistValue::Uid(archive.Collection(properties, true))},
            {"NSRenamingIdentifier", PlistValue::Uid(archive.String(renamed))},
            {"NSManagedObjectModel", PlistValue::Uid(1)},
            {"NSSuperentity", PlistValue::Uid(super_it == entity_by_name.end() ? 0 : super_it->second)},
            {"$class", PlistValue::Uid(entity_class)}
        }));
    }

    std::vector<std::size_t> identifiers;
    if (!model.Attribute("userDefinedModelVersionIdentifier").empty())
        identifiers.push_back(archive.String(model.Attribute("userDefinedModelVersionIdentifier")));
    long long tool_version = 0;
    std::from_chars(model.Attribute("lastSavedToolsVersion").data(), model.Attribute("lastSavedToolsVersion").data() + model.Attribute("lastSavedToolsVersion").size(), tool_version);
    archive.Set(1, PlistValue::Dictionary({
        {"NSEntities", PlistValue::Uid(archive.Collection(entity_dictionary, true))},
        {"CDMCompilerToolVersion", PlistValue::Real(static_cast<double>(tool_version))},
        {"NSFetchRequestTemplates", PlistValue::Uid(0)},
        {"NSVersionIdentifiers", PlistValue::Uid(archive.Array(identifiers, true))},
        {"$class", PlistValue::Uid(model_class)}
    }));
    return archive.Write(output, error);
}

std::string CurrentVersionFromFile(const fs::path& model) {
    std::ifstream input(model / ".xccurrentversion", std::ios::binary);
    if (!input) return {};
    std::ostringstream buffer; buffer << input.rdbuf();
    const std::string contents = buffer.str();
    const auto key = contents.find("_XCCurrentVersionName");
    if (key == std::string::npos) return {};
    const auto begin = contents.find("<string>", key);
    const auto end = begin == std::string::npos ? std::string::npos : contents.find("</string>", begin);
    if (begin == std::string::npos || end == std::string::npos) return {};
    return DecodeXml(contents.substr(begin + 8, end - begin - 8));
}

bool CompileOne(const fs::path& source, std::string current, const fs::path& bundle, std::string& error) {
    const std::string extension = source.extension().string();
    if (extension == ".xcdatamodel") {
        fs::create_directories(bundle);
        return CompileModel(source / "contents", bundle / (source.stem().string() + ".mom"), error);
    }
    if (extension != ".xcdatamodeld") { error = "unsupported Core Data input " + source.string(); return false; }

    const fs::path destination = bundle / (source.stem().string() + ".momd");
    std::error_code ec;
    fs::remove_all(destination, ec);
    ec.clear();
    fs::create_directories(destination, ec);
    if (ec) { error = "cannot create " + destination.string() + ": " + ec.message(); return false; }

    std::vector<fs::path> versions;
    for (const auto& entry : fs::directory_iterator(source, ec))
        if (entry.is_directory() && entry.path().extension() == ".xcdatamodel") versions.push_back(entry.path());
    std::sort(versions.begin(), versions.end());
    if (versions.empty()) { error = "versioned Core Data model has no versions: " + source.string(); return false; }
    for (const auto& version : versions)
        if (!CompileModel(version / "contents", destination / (version.stem().string() + ".mom"), error)) return false;

    if (current.empty()) current = CurrentVersionFromFile(source);
    if (current.size() > std::string(".xcdatamodel").size() && current.ends_with(".xcdatamodel"))
        current.resize(current.size() - std::string(".xcdatamodel").size());
    if (current.empty() && versions.size() == 1) current = versions.front().stem().string();
    if (current.empty()) { error = "XCVersionGroup has no current Core Data model: " + source.string(); return false; }
    if (!fs::exists(destination / (current + ".mom"))) { error = "selected Core Data model version does not exist: " + current; return false; }

    std::ofstream info(destination / "VersionInfo.plist", std::ios::binary | std::ios::trunc);
    info << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><dict>\n"
            "<key>NSManagedObjectModel_CurrentVersionName</key><string>" << XmlEscape(current) << "</string>\n"
            "</dict></plist>\n";
    if (!info.good()) { error = "cannot write Core Data VersionInfo.plist"; return false; }
    return true;
}

} // namespace

bool CoreDataCompiler::Compile(
    const std::vector<std::pair<std::wstring, std::wstring>>& models,
    const fs::path& product_bundle,
    std::string& error
) {
    for (const auto& [path, current] : models) {
        const fs::path source(path);
        if (!fs::exists(source)) { error = "Core Data model is missing: " + source.string(); return false; }
        if (!CompileOne(source, Win32Process::ToNarrow(current), product_bundle, error)) return false;
        std::cout << "OPENFRUIT: Core Data model compiled: " << source.string() << std::endl;
    }
    return true;
}

bool CoreDataCompiler::CompileUncompiledInBundle(
    const fs::path& bundle_dir,
    std::string& error
) {
    std::error_code ec;
    if (!fs::exists(bundle_dir, ec) || !fs::is_directory(bundle_dir, ec))
        return true;

    // Collect .momd directories that contain raw .xcdatamodel subdirectories
    // instead of compiled .mom files.  These arrive when a build script (e.g.
    // CocoaPods [CP] Copy Pods Resources, or xcrun momc shimmed as cp)
    // copies the source .xcdatamodeld into the bundle under a .momd name
    // without actually running the model compiler.
    std::vector<fs::path> uncompiled;
    for (fs::recursive_directory_iterator it(
             bundle_dir,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (!it->is_directory(ec)) continue;
        if (it->path().extension() != ".momd") continue;

        // A compiled .momd contains .mom files and VersionInfo.plist.
        // An uncompiled one contains .xcdatamodel subdirectories and
        // a .xccurrentversion plist.  Detect by looking for .xcdatamodel
        // children.
        bool has_xcdatamodel = false;
        for (fs::directory_iterator child(it->path(), ec);
             child != fs::directory_iterator(); child.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (child->is_directory(ec) &&
                child->path().extension() == ".xcdatamodel") {
                has_xcdatamodel = true;
                break;
            }
        }
        if (has_xcdatamodel) {
            uncompiled.push_back(it->path());
            // Don't recurse into this .momd — we'll handle it as a whole.
            it.disable_recursion_pending();
        }
    }

    if (uncompiled.empty()) return true;

    for (const auto& momd : uncompiled) {
        // The .momd directory IS the source — it was copied verbatim from a
        // .xcdatamodeld.  We compile each .xcdatamodel/contents inside it
        // into a .mom, write VersionInfo.plist, and remove the now-superfluous
        // .xcdatamodel subdirectories.

        // 1. Find all .xcdatamodel version subdirectories.
        std::vector<fs::path> versions;
        for (fs::directory_iterator child(momd, ec);
             child != fs::directory_iterator(); child.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (child->is_directory(ec) &&
                child->path().extension() == ".xcdatamodel") {
                versions.push_back(child->path());
            }
        }
        std::sort(versions.begin(), versions.end());
        if (versions.empty()) continue;

        // 2. Determine the current version from .xccurrentversion.
        std::string current = CurrentVersionFromFile(momd);
        if (current.size() > std::string(".xcdatamodel").size() &&
            current.ends_with(".xcdatamodel"))
            current.resize(current.size() - std::string(".xcdatamodel").size());
        if (current.empty() && versions.size() == 1)
            current = versions.front().stem().string();
        if (current.empty()) {
            error = "uncompiled Core Data model in bundle has no current "
                    "version: " + momd.string();
            return false;
        }

        // 3. Compile each version.
        for (const auto& version : versions) {
            const fs::path contents = version / "contents";
            if (!fs::exists(contents, ec)) continue;
            const fs::path mom = momd / (version.stem().string() + ".mom");
            if (!CompileModel(contents, mom, error)) return false;
        }

        // 4. Verify the current version was compiled.
        if (!fs::exists(momd / (current + ".mom"), ec)) {
            error = "selected Core Data model version does not exist after "
                    "in-bundle compilation: " + current;
            return false;
        }

        // 5. Write VersionInfo.plist.
        {
            std::ofstream info(
                momd / "VersionInfo.plist",
                std::ios::binary | std::ios::trunc);
            info << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                    "<plist version=\"1.0\"><dict>\n"
                    "<key>NSManagedObjectModel_CurrentVersionName</key>"
                    "<string>" << XmlEscape(current) << "</string>\n"
                    "</dict></plist>\n";
            if (!info.good()) {
                error = "cannot write Core Data VersionInfo.plist for " +
                        momd.string();
                return false;
            }
        }

        // 6. Remove the raw .xcdatamodel subdirectories and
        //    .xccurrentversion now that compiled .mom files exist.
        for (const auto& version : versions)
            fs::remove_all(version, ec);
        fs::remove(momd / ".xccurrentversion", ec);

        std::cout << "OPENFRUIT: Core Data model compiled in-bundle: "
                  << momd.string() << std::endl;
    }

    return true;
}

} // namespace OpenFruit
