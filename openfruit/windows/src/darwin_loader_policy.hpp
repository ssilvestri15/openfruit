#pragma once
#include <cstdint>
#include "json_value.hpp"
namespace OpenFruit {
// Native launch authorization within the owned mounted namespace. This is not
// Apple signature/platform authority, environment injection or kernel AMFI.
class DarwinLoaderPolicy {
public:
    DarwinLoaderPolicy(bool mounted_namespace=false,bool at_paths_authorized=false)
        : mounted_namespace_(mounted_namespace),at_paths_authorized_(at_paths_authorized){}
    int Query(std::uint64_t input,std::uint64_t& output) const noexcept {
        // Only the ordinary native process request is implemented. Simulator,
        // restricted-process and other input modes need their actual semantics.
        if(input)return 45;
        output=mounted_namespace_&&at_paths_authorized_?1:0;return 0;
    }
    JsonValue ToJson() const {
        auto value=JsonValue::ObjectValue();value.Set("source",JsonValue::String("native-task-loader-path-policy"));
        value.Set("mounted_namespace",JsonValue::Boolean(mounted_namespace_));
        value.Set("at_paths_authorized",JsonValue::Boolean(at_paths_authorized_));
        value.Set("flags",JsonValue::Number(mounted_namespace_&&at_paths_authorized_?"1":"0"));
        value.Set("signature_authority",JsonValue::Boolean(false));return value;
    }
private:
    bool mounted_namespace_,at_paths_authorized_;
};
}
