#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace OpenFruit {

class JsonValue {
public:
    enum class Type {
        Null,
        Boolean,
        Number,
        String,
        Array,
        Object
    };

    using Array = std::vector<JsonValue>;
    using Object = std::unordered_map<std::string, JsonValue>;

    JsonValue();

    static JsonValue Null();
    static JsonValue Boolean(bool value);
    static JsonValue Number(std::string value);
    static JsonValue String(std::string value);
    static JsonValue ArrayValue(Array value = {});
    static JsonValue ObjectValue(Object value = {});

    static std::optional<JsonValue> Parse(
        const std::string& text,
        std::string* error = nullptr
    );

    std::string Serialize(bool pretty = false) const;

    Type type() const noexcept { return type_; }

    bool IsNull() const noexcept { return type_ == Type::Null; }
    bool IsBoolean() const noexcept { return type_ == Type::Boolean; }
    bool IsNumber() const noexcept { return type_ == Type::Number; }
    bool IsString() const noexcept { return type_ == Type::String; }
    bool IsArray() const noexcept { return type_ == Type::Array; }
    bool IsObject() const noexcept { return type_ == Type::Object; }

    bool Bool(bool fallback = false) const noexcept;
    int Int(int fallback = 0) const noexcept;
    const std::string& StringValue() const noexcept;

    const Array& ArrayItems() const noexcept;
    Array& ArrayItems();

    const Object& ObjectItems() const noexcept;
    Object& ObjectItems();

    const JsonValue* Get(const std::string& key) const;
    JsonValue* Get(const std::string& key);

    std::string GetString(
        const std::string& key,
        const std::string& fallback = {}
    ) const;

    JsonValue& Set(const std::string& key, JsonValue value);

private:
    Type type_ = Type::Null;
    bool boolean_ = false;
    std::string scalar_;
    Array array_;
    Object object_;
};

} // namespace OpenFruit
