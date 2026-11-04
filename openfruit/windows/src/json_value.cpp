#include "json_value.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace OpenFruit {
namespace {

void AppendUtf8(std::string& output, unsigned int codepoint) {
    if (codepoint <= 0x7F) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7FF) {
        output.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    } else if (codepoint <= 0xFFFF) {
        output.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    } else {
        output.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    }
}

int HexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

class Parser {
public:
    Parser(const std::string& text, std::string* error)
        : text_(text), error_(error) {}

    std::optional<JsonValue> ParseDocument() {
        SkipWhitespace();
        auto value = ParseValue();
        if (!value) return std::nullopt;
        SkipWhitespace();
        if (position_ != text_.size()) {
            Fail("unexpected trailing JSON content");
            return std::nullopt;
        }
        return value;
    }

private:
    const std::string& text_;
    std::size_t position_ = 0;
    std::string* error_ = nullptr;

    void Fail(const std::string& message) {
        if (error_ && error_->empty()) {
            *error_ = message + " at byte " + std::to_string(position_);
        }
    }

    void SkipWhitespace() {
        while (position_ < text_.size() &&
               std::isspace(static_cast<unsigned char>(text_[position_]))) {
            ++position_;
        }
    }

    bool Consume(char expected) {
        SkipWhitespace();
        if (position_ >= text_.size() || text_[position_] != expected) {
            return false;
        }
        ++position_;
        return true;
    }

    std::optional<JsonValue> ParseValue() {
        SkipWhitespace();
        if (position_ >= text_.size()) {
            Fail("unexpected end of JSON");
            return std::nullopt;
        }

        switch (text_[position_]) {
        case 'n': return ParseLiteral("null", JsonValue::Null());
        case 't': return ParseLiteral("true", JsonValue::Boolean(true));
        case 'f': return ParseLiteral("false", JsonValue::Boolean(false));
        case '"': {
            auto s = ParseString();
            if (!s) return std::nullopt;
            return JsonValue::String(std::move(*s));
        }
        case '[': return ParseArray();
        case '{': return ParseObject();
        default:
            if (text_[position_] == '-' ||
                std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                return ParseNumber();
            }
            Fail("unexpected JSON token");
            return std::nullopt;
        }
    }

    std::optional<JsonValue> ParseLiteral(
        const char* literal,
        JsonValue value
    ) {
        const std::size_t length = std::char_traits<char>::length(literal);
        if (text_.compare(position_, length, literal) != 0) {
            Fail("invalid JSON literal");
            return std::nullopt;
        }
        position_ += length;
        return value;
    }

    std::optional<std::string> ParseString() {
        if (!Consume('"')) {
            Fail("expected JSON string");
            return std::nullopt;
        }

        std::string result;
        while (position_ < text_.size()) {
            const char c = text_[position_++];
            if (c == '"') return result;

            if (static_cast<unsigned char>(c) < 0x20) {
                Fail("control character in JSON string");
                return std::nullopt;
            }

            if (c != '\\') {
                result.push_back(c);
                continue;
            }

            if (position_ >= text_.size()) {
                Fail("unterminated JSON escape");
                return std::nullopt;
            }

            const char escape = text_[position_++];
            switch (escape) {
            case '"': result.push_back('"'); break;
            case '\\': result.push_back('\\'); break;
            case '/': result.push_back('/'); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                if (position_ + 4 > text_.size()) {
                    Fail("short JSON unicode escape");
                    return std::nullopt;
                }

                unsigned int codepoint = 0;
                for (int i = 0; i < 4; ++i) {
                    const int digit = HexValue(text_[position_++]);
                    if (digit < 0) {
                        Fail("invalid JSON unicode escape");
                        return std::nullopt;
                    }
                    codepoint = (codepoint << 4) | static_cast<unsigned int>(digit);
                }

                if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                    if (position_ + 6 <= text_.size() &&
                        text_[position_] == '\\' && text_[position_ + 1] == 'u') {
                        position_ += 2;
                        unsigned int low = 0;
                        for (int i = 0; i < 4; ++i) {
                            const int digit = HexValue(text_[position_++]);
                            if (digit < 0) {
                                Fail("invalid JSON surrogate pair");
                                return std::nullopt;
                            }
                            low = (low << 4) | static_cast<unsigned int>(digit);
                        }
                        if (low >= 0xDC00 && low <= 0xDFFF) {
                            codepoint = 0x10000 +
                                ((codepoint - 0xD800) << 10) +
                                (low - 0xDC00);
                        } else {
                            Fail("invalid JSON low surrogate");
                            return std::nullopt;
                        }
                    } else {
                        Fail("missing JSON low surrogate");
                        return std::nullopt;
                    }
                }

                AppendUtf8(result, codepoint);
                break;
            }
            default:
                Fail("invalid JSON escape");
                return std::nullopt;
            }
        }

        Fail("unterminated JSON string");
        return std::nullopt;
    }

    std::optional<JsonValue> ParseNumber() {
        const std::size_t begin = position_;

        if (text_[position_] == '-') ++position_;
        if (position_ >= text_.size()) {
            Fail("invalid JSON number");
            return std::nullopt;
        }

        if (text_[position_] == '0') {
            ++position_;
        } else {
            if (!std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                Fail("invalid JSON number");
                return std::nullopt;
            }
            while (position_ < text_.size() &&
                   std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
        }

        if (position_ < text_.size() && text_[position_] == '.') {
            ++position_;
            if (position_ >= text_.size() ||
                !std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                Fail("invalid JSON fraction");
                return std::nullopt;
            }
            while (position_ < text_.size() &&
                   std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
        }

        if (position_ < text_.size() &&
            (text_[position_] == 'e' || text_[position_] == 'E')) {
            ++position_;
            if (position_ < text_.size() &&
                (text_[position_] == '+' || text_[position_] == '-')) {
                ++position_;
            }
            if (position_ >= text_.size() ||
                !std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                Fail("invalid JSON exponent");
                return std::nullopt;
            }
            while (position_ < text_.size() &&
                   std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
        }

        return JsonValue::Number(text_.substr(begin, position_ - begin));
    }

    std::optional<JsonValue> ParseArray() {
        if (!Consume('[')) return std::nullopt;
        JsonValue::Array values;
        SkipWhitespace();
        if (Consume(']')) return JsonValue::ArrayValue(std::move(values));

        for (;;) {
            auto value = ParseValue();
            if (!value) return std::nullopt;
            values.push_back(std::move(*value));
            SkipWhitespace();
            if (Consume(']')) break;
            if (!Consume(',')) {
                Fail("expected ',' in JSON array");
                return std::nullopt;
            }
        }

        return JsonValue::ArrayValue(std::move(values));
    }

    std::optional<JsonValue> ParseObject() {
        if (!Consume('{')) return std::nullopt;
        JsonValue::Object values;
        SkipWhitespace();
        if (Consume('}')) return JsonValue::ObjectValue(std::move(values));

        for (;;) {
            auto key = ParseString();
            if (!key) return std::nullopt;
            if (!Consume(':')) {
                Fail("expected ':' in JSON object");
                return std::nullopt;
            }
            auto value = ParseValue();
            if (!value) return std::nullopt;
            values.insert_or_assign(std::move(*key), std::move(*value));
            SkipWhitespace();
            if (Consume('}')) break;
            if (!Consume(',')) {
                Fail("expected ',' in JSON object");
                return std::nullopt;
            }
        }

        return JsonValue::ObjectValue(std::move(values));
    }
};

std::string EscapeJson(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char c : value) {
        switch (c) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20) {
                output << "\\u"
                       << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<unsigned int>(c)
                       << std::dec;
            } else {
                output << static_cast<char>(c);
            }
        }
    }
    return output.str();
}

void SerializeValue(
    const JsonValue& value,
    std::ostringstream& output,
    bool pretty,
    int depth
) {
    const auto indent = [&](int d) {
        if (pretty) output << std::string(static_cast<std::size_t>(d * 2), ' ');
    };

    switch (value.type()) {
    case JsonValue::Type::Null:
        output << "null";
        break;
    case JsonValue::Type::Boolean:
        output << (value.Bool() ? "true" : "false");
        break;
    case JsonValue::Type::Number:
        output << value.StringValue();
        break;
    case JsonValue::Type::String:
        output << '"' << EscapeJson(value.StringValue()) << '"';
        break;
    case JsonValue::Type::Array: {
        output << '[';
        const auto& items = value.ArrayItems();
        if (!items.empty()) {
            if (pretty) output << '\n';
            for (std::size_t i = 0; i < items.size(); ++i) {
                indent(depth + 1);
                SerializeValue(items[i], output, pretty, depth + 1);
                if (i + 1 != items.size()) output << ',';
                if (pretty) output << '\n';
            }
            indent(depth);
        }
        output << ']';
        break;
    }
    case JsonValue::Type::Object: {
        output << '{';
        const auto& items = value.ObjectItems();
        if (!items.empty()) {
            std::vector<std::string> keys;
            keys.reserve(items.size());
            for (const auto& [key, _] : items) keys.push_back(key);
            std::sort(keys.begin(), keys.end());

            if (pretty) output << '\n';
            for (std::size_t i = 0; i < keys.size(); ++i) {
                const auto it = items.find(keys[i]);
                indent(depth + 1);
                output << '"' << EscapeJson(keys[i]) << '"' << ':';
                if (pretty) output << ' ';
                SerializeValue(it->second, output, pretty, depth + 1);
                if (i + 1 != keys.size()) output << ',';
                if (pretty) output << '\n';
            }
            indent(depth);
        }
        output << '}';
        break;
    }
    }
}

const std::string kEmptyString;
const JsonValue::Array kEmptyArray;
const JsonValue::Object kEmptyObject;

} // namespace

JsonValue::JsonValue() = default;

JsonValue JsonValue::Null() { return JsonValue(); }

JsonValue JsonValue::Boolean(bool value) {
    JsonValue result;
    result.type_ = Type::Boolean;
    result.boolean_ = value;
    return result;
}

JsonValue JsonValue::Number(std::string value) {
    JsonValue result;
    result.type_ = Type::Number;
    result.scalar_ = std::move(value);
    return result;
}

JsonValue JsonValue::String(std::string value) {
    JsonValue result;
    result.type_ = Type::String;
    result.scalar_ = std::move(value);
    return result;
}

JsonValue JsonValue::ArrayValue(Array value) {
    JsonValue result;
    result.type_ = Type::Array;
    result.array_ = std::move(value);
    return result;
}

JsonValue JsonValue::ObjectValue(Object value) {
    JsonValue result;
    result.type_ = Type::Object;
    result.object_ = std::move(value);
    return result;
}

std::optional<JsonValue> JsonValue::Parse(
    const std::string& text,
    std::string* error
) {
    if (error) error->clear();
    return Parser(text, error).ParseDocument();
}

std::string JsonValue::Serialize(bool pretty) const {
    std::ostringstream output;
    SerializeValue(*this, output, pretty, 0);
    if (pretty) output << '\n';
    return output.str();
}

bool JsonValue::Bool(bool fallback) const noexcept {
    return IsBoolean() ? boolean_ : fallback;
}

int JsonValue::Int(int fallback) const noexcept {
    if (!IsNumber()) return fallback;
    try {
        return std::stoi(scalar_);
    } catch (...) {
        return fallback;
    }
}

const std::string& JsonValue::StringValue() const noexcept {
    return (IsString() || IsNumber()) ? scalar_ : kEmptyString;
}

const JsonValue::Array& JsonValue::ArrayItems() const noexcept {
    return IsArray() ? array_ : kEmptyArray;
}

JsonValue::Array& JsonValue::ArrayItems() {
    if (!IsArray()) {
        type_ = Type::Array;
        scalar_.clear();
        object_.clear();
        array_.clear();
    }
    return array_;
}

const JsonValue::Object& JsonValue::ObjectItems() const noexcept {
    return IsObject() ? object_ : kEmptyObject;
}

JsonValue::Object& JsonValue::ObjectItems() {
    if (!IsObject()) {
        type_ = Type::Object;
        scalar_.clear();
        array_.clear();
        object_.clear();
    }
    return object_;
}

const JsonValue* JsonValue::Get(const std::string& key) const {
    if (!IsObject()) return nullptr;
    const auto it = object_.find(key);
    return it == object_.end() ? nullptr : &it->second;
}

JsonValue* JsonValue::Get(const std::string& key) {
    if (!IsObject()) return nullptr;
    const auto it = object_.find(key);
    return it == object_.end() ? nullptr : &it->second;
}

std::string JsonValue::GetString(
    const std::string& key,
    const std::string& fallback
) const {
    const JsonValue* value = Get(key);
    return value && value->IsString() ? value->StringValue() : fallback;
}

JsonValue& JsonValue::Set(const std::string& key, JsonValue value) {
    auto& object = ObjectItems();
    auto [it, inserted] = object.insert_or_assign(key, std::move(value));
    (void)inserted;
    return it->second;
}

} // namespace OpenFruit
