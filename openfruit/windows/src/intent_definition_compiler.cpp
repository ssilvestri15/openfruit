#include "intent_definition_compiler.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

struct XmlNode {
    std::string name;
    std::string text;
    std::map<std::string, std::string> attributes;
    std::vector<XmlNode> children;
};

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
               std::isspace(static_cast<unsigned char>(input_[position_]))) {
            ++position_;
        }
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
            } else {
                break;
            }
        }
    }

    std::string Name() {
        const std::size_t start = position_;
        while (position_ < input_.size()) {
            const char ch = input_[position_];
            if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
                  ch == '-' || ch == ':' || ch == '.')) {
                break;
            }
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
        if (node.name.empty()) {
            error = "empty XML element name";
            return false;
        }
        for (;;) {
            Space();
            if (Starts("/>")) {
                position_ += 2;
                return true;
            }
            if (position_ < input_.size() && input_[position_] == '>') {
                ++position_;
                break;
            }
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
            if (end == std::string::npos) {
                error = "unterminated XML attribute";
                return false;
            }
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
            if (position_ >= input_.size()) {
                error = "unterminated XML element " + node.name;
                return false;
            }
            if (input_[position_] == '<') {
                XmlNode child;
                if (!ParseNode(child, error)) return false;
                node.children.push_back(std::move(child));
            } else {
                const auto next = input_.find('<', position_);
                std::string t = input_.substr(position_, next - position_);
                node.text += DecodeXml(std::move(t));
                position_ = next == std::string::npos ? input_.size() : next;
            }
        }
    }
};

struct PlistValue {
    enum class Kind { None, String, Integer, Real, Boolean, Array, Dict } kind = Kind::None;
    std::string string_val;
    int64_t int_val = 0;
    bool bool_val = false;
    std::vector<PlistValue> array_val;
    std::map<std::string, PlistValue> dict_val;

    bool IsDict() const { return kind == Kind::Dict; }
    bool IsArray() const { return kind == Kind::Array; }
    bool IsString() const { return kind == Kind::String; }
    bool IsBool() const { return kind == Kind::Boolean; }

    std::string String(const std::string& key) const {
        if (kind != Kind::Dict) return {};
        auto it = dict_val.find(key);
        if (it != dict_val.end() && it->second.kind == Kind::String) return it->second.string_val;
        return {};
    }

    bool Bool(const std::string& key, bool default_val = false) const {
        if (kind != Kind::Dict) return default_val;
        auto it = dict_val.find(key);
        if (it != dict_val.end() && it->second.kind == Kind::Boolean) return it->second.bool_val;
        return default_val;
    }

    int64_t Integer(const std::string& key, int64_t default_val = 0) const {
        if (kind != Kind::Dict) return default_val;
        auto it = dict_val.find(key);
        if (it != dict_val.end() && it->second.kind == Kind::Integer) return it->second.int_val;
        return default_val;
    }

    const PlistValue* Child(const std::string& key) const {
        if (kind != Kind::Dict) return nullptr;
        auto it = dict_val.find(key);
        if (it != dict_val.end()) return &it->second;
        return nullptr;
    }
};

PlistValue NodeToPlistValue(const XmlNode& node);

PlistValue ParseDictNode(const XmlNode& dict_node) {
    PlistValue val;
    val.kind = PlistValue::Kind::Dict;
    std::string current_key;
    for (const auto& child : dict_node.children) {
        if (child.name == "key") {
            current_key = child.text;
        } else if (!current_key.empty()) {
            val.dict_val[current_key] = NodeToPlistValue(child);
            current_key.clear();
        }
    }
    return val;
}

PlistValue ParseArrayNode(const XmlNode& array_node) {
    PlistValue val;
    val.kind = PlistValue::Kind::Array;
    for (const auto& child : array_node.children) {
        val.array_val.push_back(NodeToPlistValue(child));
    }
    return val;
}

PlistValue NodeToPlistValue(const XmlNode& node) {
    if (node.name == "dict") {
        return ParseDictNode(node);
    }
    if (node.name == "array") {
        return ParseArrayNode(node);
    }
    if (node.name == "string") {
        PlistValue val;
        val.kind = PlistValue::Kind::String;
        val.string_val = node.text;
        return val;
    }
    if (node.name == "true") {
        PlistValue val;
        val.kind = PlistValue::Kind::Boolean;
        val.bool_val = true;
        return val;
    }
    if (node.name == "false") {
        PlistValue val;
        val.kind = PlistValue::Kind::Boolean;
        val.bool_val = false;
        return val;
    }
    if (node.name == "integer") {
        PlistValue val;
        val.kind = PlistValue::Kind::Integer;
        val.int_val = std::strtoll(node.text.c_str(), nullptr, 10);
        return val;
    }
    if (node.name == "real") {
        PlistValue val;
        val.kind = PlistValue::Kind::Real;
        return val;
    }
    PlistValue val;
    return val;
}

std::string CapFirst(std::string s) {
    if (!s.empty()) {
        s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
    }
    return s;
}

std::string MapTypeToSwift(const std::string& type_name, const std::string& object_type, const std::string& enum_type) {
    if (type_name == "Object") {
        return object_type.empty() ? "INObject" : object_type;
    }
    if (type_name == "Enum") {
        return enum_type.empty() ? "Int" : enum_type;
    }
    if (type_name == "String") {
        return "String";
    }
    if (type_name == "Integer" || type_name == "Decimal" || type_name == "Boolean") {
        return "NSNumber";
    }
    if (type_name == "DateComponents") {
        return "DateComponents";
    }
    if (type_name == "Location") {
        return "CLPlacemark";
    }
    if (type_name == "File") {
        return "INFile";
    }
    if (type_name == "SpeakableString") {
        return "INSpeakableString";
    }
    return object_type.empty() ? "AnyObject" : object_type;
}

} // namespace

std::filesystem::path IntentDefinitionCompiler::Compile(
    const std::filesystem::path& intent_definition_path,
    const std::filesystem::path& output_dir,
    std::string& error
) {
    std::ifstream file(intent_definition_path, std::ios::binary);
    if (!file) {
        error = "cannot open intent definition: " + intent_definition_path.string();
        return {};
    }

    std::string content(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    XmlParser parser(std::move(content));
    XmlNode root_node;
    if (!parser.Parse(root_node, error)) {
        error = "failed to parse intent definition XML: " + error;
        return {};
    }

    PlistValue root_dict;
    if (root_node.name == "plist" && !root_node.children.empty()) {
        root_dict = NodeToPlistValue(root_node.children.front());
    } else if (root_node.name == "dict") {
        root_dict = NodeToPlistValue(root_node);
    }

    if (!root_dict.IsDict()) {
        error = "root element is not a plist dict";
        return {};
    }

    std::ostringstream out;
    out << "//\n"
        << "// Generated by OPENFRUIT IntentDefinitionCompiler\n"
        << "// Do not edit.\n"
        << "//\n\n"
        << "import Foundation\n"
        << "import Intents\n\n"
        << "#if canImport(CoreLocation)\n"
        << "import CoreLocation\n"
        << "#endif\n\n";

    // 1. Enums
    const PlistValue* enums_array = root_dict.Child("INEnums");
    if (enums_array && enums_array->IsArray()) {
        for (const auto& enum_elem : enums_array->array_val) {
            const std::string enum_name = enum_elem.String("INEnumName");
            if (enum_name.empty()) continue;

            out << "@available(iOS 12.0, macOS 10.16, watchOS 5.0, tvOS 14.0, *)\n"
                << "@objc public enum " << enum_name << ": Int {\n";

            const PlistValue* cases = enum_elem.Child("INEnumCases");
            if (cases && cases->IsArray()) {
                for (const auto& case_elem : cases->array_val) {
                    const std::string case_name = case_elem.String("INEnumCaseName");
                    const int64_t case_val = case_elem.Integer("INEnumCaseValue", 0);
                    if (!case_name.empty()) {
                        out << "    case " << case_name << " = " << case_val << "\n";
                    }
                }
            }
            out << "}\n\n";
        }
    }

    // 2. Custom Types (INTypes)
    const PlistValue* types_array = root_dict.Child("INTypes");
    if (types_array && types_array->IsArray()) {
        for (const auto& type_elem : types_array->array_val) {
            const std::string type_name = type_elem.String("INTypeName");
            if (type_name.empty()) continue;

            out << "@available(iOS 12.0, macOS 10.16, watchOS 5.0, tvOS 14.0, *)\n"
                << "@objc(" << type_name << ")\n"
                << "open class " << type_name << ": INObject {\n"
                << "    @objc(initWithIdentifier:displayString:pronunciationHint:)\n"
                << "    public override init(identifier: String?, display displayString: String, pronunciationHint: String?) {\n"
                << "        super.init(identifier: identifier, display: displayString, pronunciationHint: pronunciationHint)\n"
                << "    }\n\n"
                << "    public convenience init(identifier: String?, display displayString: String) {\n"
                << "        self.init(identifier: identifier, display: displayString, pronunciationHint: nil)\n"
                << "    }\n\n"
                << "    public required init?(coder: NSCoder) {\n"
                << "        super.init(coder: coder)\n"
                << "    }\n";

            const PlistValue* props = type_elem.Child("INTypeProperties");
            if (props && props->IsArray()) {
                for (const auto& prop_elem : props->array_val) {
                    const std::string prop_name = prop_elem.String("INTypePropertyName");
                    if (prop_name.empty()) continue;
                    // Standard properties already handled by INObject
                    if (prop_name == "identifier" || prop_name == "displayString" ||
                        prop_name == "pronunciationHint" || prop_name == "subtitle" ||
                        prop_name == "subtitleString" || prop_name == "image" ||
                        prop_name == "alternativeSpeakableMatches") {
                        continue;
                    }
                    const std::string prop_type = prop_elem.String("INTypePropertyType");
                    const std::string object_type = prop_elem.String("INTypePropertyObjectType");
                    const bool multiple = prop_elem.Bool("INTypePropertySupportsMultipleValues", false);

                    std::string item_type = MapTypeToSwift(prop_type, object_type, "");
                    std::string swift_type = multiple ? ("[" + item_type + "]") : item_type;

                    out << "    @NSManaged public var " << prop_name << ": " << swift_type << "?\n";
                }
            }

            out << "}\n\n";
        }
    }

    // 3. Intents (INIntents)
    const PlistValue* intents_array = root_dict.Child("INIntents");
    if (intents_array && intents_array->IsArray()) {
        for (const auto& intent_elem : intents_array->array_val) {
            const std::string intent_name = intent_elem.String("INIntentName");
            if (intent_name.empty()) continue;

            const std::string class_name = intent_name + "Intent";
            const std::string response_name = intent_name + "IntentResponse";
            const std::string response_code_name = intent_name + "IntentResponseCode";
            const std::string protocol_name = intent_name + "IntentHandling";

            struct ParamInfo {
                std::string name;
                std::string item_type;
                std::string swift_type;
                bool supports_dynamic_enumeration = false;
            };

            std::vector<ParamInfo> params;
            const PlistValue* params_array = intent_elem.Child("INIntentParameters");
            if (params_array && params_array->IsArray()) {
                for (const auto& p_elem : params_array->array_val) {
                    ParamInfo pi;
                    pi.name = p_elem.String("INIntentParameterName");
                    if (pi.name.empty()) continue;

                    const std::string p_type = p_elem.String("INIntentParameterType");
                    const std::string obj_type = p_elem.String("INIntentParameterObjectType");
                    const std::string enum_type = p_elem.String("INIntentParameterEnumType");
                    const bool multiple = p_elem.Bool("INIntentParameterSupportsMultipleValues", false);
                    pi.supports_dynamic_enumeration = p_elem.Bool("INIntentParameterSupportsDynamicEnumeration", false);

                    pi.item_type = MapTypeToSwift(p_type, obj_type, enum_type);
                    pi.swift_type = multiple ? ("[" + pi.item_type + "]") : pi.item_type;
                    params.push_back(std::move(pi));
                }
            }

            // Intent Class
            out << "@available(iOS 12.0, macOS 10.16, watchOS 5.0, tvOS 14.0, *)\n"
                << "@objc(" << class_name << ")\n"
                << "open class " << class_name << ": INIntent {\n";

            for (const auto& p : params) {
                out << "    @NSManaged public var " << p.name << ": " << p.swift_type << "?\n";
            }

            out << "\n    public override init() {\n"
                << "        super.init()\n"
                << "    }\n\n"
                << "    public required init?(coder: NSCoder) {\n"
                << "        super.init(coder: coder)\n"
                << "    }\n";

            if (!params.empty()) {
                out << "\n    public convenience init(";
                for (std::size_t i = 0; i < params.size(); ++i) {
                    if (i > 0) out << ", ";
                    out << params[i].name << ": " << params[i].swift_type << "? = nil";
                }
                out << ") {\n"
                    << "        self.init()\n";
                for (const auto& p : params) {
                    out << "        self." << p.name << " = " << p.name << "\n";
                }
                out << "    }\n";
            }

            out << "}\n\n";

            // Response Code Enum
            out << "@available(iOS 12.0, macOS 10.16, watchOS 5.0, tvOS 14.0, *)\n"
                << "@objc public enum " << response_code_name << ": Int {\n"
                << "    case unspecified = 0\n"
                << "    case ready = 1\n"
                << "    case continueInApp = 2\n"
                << "    case userConfirmationRequired = 3\n"
                << "    case failure = 4\n"
                << "    case failureRequiringAppLaunch = 5\n"
                << "    case success = 6\n"
                << "}\n\n";

            // Response Class
            out << "@available(iOS 12.0, macOS 10.16, watchOS 5.0, tvOS 14.0, *)\n"
                << "@objc(" << response_name << ")\n"
                << "open class " << response_name << ": INIntentResponse {\n"
                << "    @objc public var code: " << response_code_name << " = .unspecified\n\n"
                << "    public init(code: " << response_code_name << ", userActivity: NSUserActivity?) {\n"
                << "        self.code = code\n"
                << "        super.init()\n"
                << "    }\n\n"
                << "    public required init?(coder: NSCoder) {\n"
                << "        super.init(coder: coder)\n"
                << "    }\n\n"
                << "    public convenience init(code: " << response_code_name << ") {\n"
                << "        self.init(code: code, userActivity: nil)\n"
                << "    }\n"
                << "}\n\n";

            // Handling Protocol
            out << "@available(iOS 12.0, macOS 10.16, watchOS 5.0, tvOS 14.0, *)\n"
                << "@objc(" << protocol_name << ")\n"
                << "public protocol " << protocol_name << ": NSObjectProtocol {\n"
                << "    @objc(handle" << intent_name << ":completion:)\n"
                << "    optional func handle(intent: " << class_name << ", completion: @escaping (" << response_name << ") -> Void)\n\n"
                << "    @objc(confirm" << intent_name << ":completion:)\n"
                << "    optional func confirm(intent: " << class_name << ", completion: @escaping (" << response_name << ") -> Void)\n";

            for (const auto& p : params) {
                const std::string cap = CapFirst(p.name);
                if (p.supports_dynamic_enumeration) {
                    out << "\n    @objc(provide" << cap << "OptionsCollectionFor" << intent_name << ":withCompletion:)\n"
                        << "    optional func provide" << cap << "OptionsCollection(for intent: "
                        << class_name << ", with completion: @escaping (INObjectCollection<" << p.item_type << ">?, Error?) -> Void)\n\n"
                        << "    @objc(default" << cap << "For" << intent_name << ":)\n"
                        << "    optional func default" << cap << "(for intent: " << class_name
                        << ") -> " << p.item_type << "?\n";
                }
            }

            out << "}\n\n";
        }
    }

    std::error_code ec;
    fs::create_directories(output_dir, ec);

    std::string stem = intent_definition_path.stem().string();
    if (stem.empty()) stem = "Intent";
    const fs::path output_path = output_dir / (stem + ".swift");

    const std::string generated = out.str();
    bool content_changed = true;
    if (fs::exists(output_path, ec)) {
        std::ifstream existing(output_path, std::ios::binary);
        if (existing) {
            std::string existing_str(
                (std::istreambuf_iterator<char>(existing)),
                std::istreambuf_iterator<char>()
            );
            if (existing_str == generated) {
                content_changed = false;
            }
        }
    }

    if (content_changed) {
        std::ofstream outfile(output_path, std::ios::binary | std::ios::trunc);
        if (!outfile) {
            error = "cannot write generated intent code to " + output_path.string();
            return {};
        }
        outfile.write(generated.data(), static_cast<std::streamsize>(generated.size()));
    }

    return output_path;
}

} // namespace OpenFruit
