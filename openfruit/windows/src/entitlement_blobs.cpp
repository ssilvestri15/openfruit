#include "entitlement_blobs.hpp"
#include "provisioning_identity.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <plist/plist.h>
#include <bit>
#include <cstdlib>
#include <limits>
#include <map>
#include <array>
namespace OpenFruit {
namespace {
constexpr std::size_t limit = 16 * 1024 * 1024;
constexpr std::size_t maximum_nodes = 100000;
bool Active(std::string& error) {
    const auto context = CurrentOperationContext();
    if (context && (context->CancellationRequested() || context->DeadlineExceeded())) {
        error = "Entitlement conversion cancelled or deadline exceeded."; return false;
    }
    return true;
}
struct Plist {
    plist_t value = nullptr;
    ~Plist() { if (value) plist_free(value); }
    bool Parse(std::string_view bytes) {
        return !bytes.empty() && bytes.size() <= limit &&
            plist_from_memory(bytes.data(), static_cast<uint32_t>(bytes.size()), &value, nullptr) == PLIST_ERR_SUCCESS &&
            plist_get_node_type(value) == PLIST_DICT;
    }
};
bool Utf8(std::string_view bytes) {
    return bytes.find('\0') == std::string_view::npos && (bytes.empty() ||
        (bytes.size() <= limit && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            bytes.data(), static_cast<int>(bytes.size()), nullptr, 0) > 0));
}
bool Append(std::string& target, std::string_view bytes) {
    if (bytes.size() > limit - target.size()) return false;
    target.append(bytes); return true;
}
bool Tlv(unsigned char tag, std::string_view body, std::string& out) {
    if (body.size() > limit - 6) return false;
    out.assign(1, static_cast<char>(tag));
    if (body.size() < 128) out += static_cast<char>(body.size());
    else {
        std::string length;
        for (auto size = body.size(); size; size >>= 8) length.insert(length.begin(), static_cast<char>(size & 255));
        out += static_cast<char>(128 | length.size()); out += length;
    }
    return Append(out, body);
}
std::string_view Text(plist_t node) {
    uint64_t size = 0; const auto bytes = plist_get_string_ptr(node, &size);
    return bytes ? std::string_view(bytes, static_cast<std::size_t>(size)) : std::string_view{};
}
bool SignedInteger(plist_t node, int64_t& value) {
    // libplist stores unsigned values above INT64_MAX with the same value bits
    // as negative integers. Its signed getter/comparator alone cannot detect
    // that range violation; preserve the node's signedness distinction.
    if (plist_get_node_type(node) != PLIST_INT) return false;
    uint64_t bits = 0; plist_get_uint_val(node, &bits);
    if (bits > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) && !plist_int_val_is_negative(node)) return false;
    plist_get_int_val(node, &value); return true;
}
struct DictionaryIterator {
    plist_dict_iter iterator = nullptr;
    explicit DictionaryIterator(plist_t node) { plist_dict_new_iter(node, &iterator); }
    ~DictionaryIterator() { std::free(iterator); }
};
struct Encoder {
    std::size_t nodes = 0;
    std::string& error;
    bool Value(plist_t node, std::string& result, unsigned depth = 0) {
        if (!Active(error) || depth > 64 || ++nodes > maximum_nodes || !node) return false;
        switch (plist_get_node_type(node)) {
        case PLIST_BOOLEAN: {
            uint8_t value = 0; plist_get_bool_val(node, &value);
            return Tlv(1, std::string(1, value ? '\xff' : '\0'), result);
        }
        case PLIST_INT: {
            int64_t value = 0; if (!SignedInteger(node, value)) return false;
            uint64_t bits = static_cast<uint64_t>(value); std::string bytes(8, '\0');
            for (int i = 7; i >= 0; --i) { bytes[i] = static_cast<char>(bits & 255); bits >>= 8; }
            std::size_t first = 0;
            while (first < 7 && ((bytes[first] == 0 && !(static_cast<unsigned char>(bytes[first + 1]) & 128)) ||
                (static_cast<unsigned char>(bytes[first]) == 255 && (static_cast<unsigned char>(bytes[first + 1]) & 128)))) ++first;
            return Tlv(2, std::string_view(bytes).substr(first), result);
        }
        case PLIST_STRING: return Utf8(Text(node)) && Tlv(12, Text(node), result);
        case PLIST_ARRAY: {
            std::string body;
            for (uint32_t i = 0; i < plist_array_get_size(node); ++i) {
                std::string value;
                if (!Value(plist_array_get_item(node, i), value, depth + 1) || !Append(body, value)) return false;
            }
            return Tlv(0x30, body, result);
        }
        case PLIST_DICT: {
            if (plist_dict_get_size(node) > maximum_nodes - nodes) return false;
            std::map<std::string, plist_t> entries;
            DictionaryIterator iterator(node);
            for (;;) {
                char* key = nullptr; plist_t value = nullptr;
                plist_dict_next_item(node, iterator.iterator, &key, &value);
                if (!value) { std::free(key); break; }
                std::string name = key ? key : ""; std::free(key);
                if (!Utf8(name) || !entries.emplace(std::move(name), value).second) return false;
            }
            std::string body;
            for (const auto& [key, value] : entries) {
                std::string encoded_key, encoded_value, pair, entry;
                if (!Tlv(12, key, encoded_key) || !Value(value, encoded_value, depth + 1) ||
                    !Append(pair, encoded_key) || !Append(pair, encoded_value) || !Tlv(0x30, pair, entry) || !Append(body, entry)) return false;
            }
            return Tlv(0xb0, body, result);
        }
        default: return false;
        }
    }
};
// Independent bounded TLV reader: no encoder is called during verification.
struct Cursor {
    std::string_view remaining;
    bool Read(unsigned char& tag, std::string_view& body) {
        if (remaining.size() < 2) return false;
        tag = static_cast<unsigned char>(remaining[0]);
        std::size_t offset = 2, length = static_cast<unsigned char>(remaining[1]);
        if ((tag & 31) == 31) return false;
        if (length & 128) {
            const auto count = length & 127;
            if (!count || count > 4 || count > remaining.size() - offset || remaining[offset] == 0) return false;
            length = 0;
            for (std::size_t i = 0; i < count; ++i) length = (length << 8) | static_cast<unsigned char>(remaining[offset++]);
            if (length < 128) return false;
        }
        if (length > remaining.size() - offset) return false;
        body = remaining.substr(offset, length); remaining.remove_prefix(offset + length); return true;
    }
    bool ReadTag(unsigned char expected, std::string_view& body) {
        unsigned char tag = 0; return Read(tag, body) && tag == expected;
    }
};
struct Verifier {
    std::size_t nodes = 0;
    std::string& error;
    bool Value(Cursor& cursor, plist_t expected, unsigned depth = 0) {
        if (!Active(error) || depth > 64 || ++nodes > maximum_nodes || !expected) return false;
        unsigned char tag = 0; std::string_view body;
        if (!cursor.Read(tag, body)) return false;
        switch (tag) {
        case 1: {
            if (plist_get_node_type(expected) != PLIST_BOOLEAN || body.size() != 1 ||
                (body[0] != 0 && static_cast<unsigned char>(body[0]) != 255)) return false;
            uint8_t value = 0; plist_get_bool_val(expected, &value); return (body[0] != 0) == (value != 0);
        }
        case 2: {
            int64_t value = 0;
            if (!SignedInteger(expected, value) || body.empty() || body.size() > 8) return false;
            if (body.size() > 1 && ((body[0] == 0 && !(static_cast<unsigned char>(body[1]) & 128)) ||
                (static_cast<unsigned char>(body[0]) == 255 && (static_cast<unsigned char>(body[1]) & 128)))) return false;
            uint64_t bits = static_cast<unsigned char>(body[0]) & 128 ? UINT64_MAX : 0;
            for (unsigned char byte : body) bits = (bits << 8) | byte;
            return value == std::bit_cast<int64_t>(bits);
        }
        case 12: return plist_get_node_type(expected) == PLIST_STRING && Utf8(body) && body == Text(expected);
        case 0x30: {
            if (plist_get_node_type(expected) != PLIST_ARRAY) return false;
            Cursor values{body};
            for (uint32_t i = 0; i < plist_array_get_size(expected); ++i)
                if (!Value(values, plist_array_get_item(expected, i), depth + 1)) return false;
            return values.remaining.empty();
        }
        case 0xb0: {
            if (plist_get_node_type(expected) != PLIST_DICT) return false;
            Cursor entries{body}; std::string previous; bool first = true; uint32_t count = 0;
            while (!entries.remaining.empty()) {
                std::string_view pair, key;
                if (!entries.ReadTag(0x30, pair)) return false;
                Cursor entry{pair};
                if (!entry.ReadTag(12, key) || !Utf8(key) || (!first && key <= previous)) return false;
                previous.assign(key); first = false; ++count;
                if (!Value(entry, plist_dict_get_item(expected, previous.c_str()), depth + 1) || !entry.remaining.empty()) return false;
            }
            return count == plist_dict_get_size(expected);
        }
        default: return false;
        }
    }
};
uint32_t Word(std::string_view bytes, std::size_t offset) {
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) value = (value << 8) | static_cast<unsigned char>(bytes[offset + i]);
    return value;
}
std::string Blob(uint32_t magic, std::string_view payload) {
    if (payload.size() > limit - 8) return {};
    std::string result(8, '\0');
    for (int i = 3; i >= 0; --i) { result[i] = static_cast<char>(magic & 255); magic >>= 8; }
    auto length = static_cast<uint32_t>(payload.size() + 8);
    for (int i = 7; i >= 4; --i) { result[i] = static_cast<char>(length & 255); length >>= 8; }
    result.append(payload); return result;
}
bool Framed(std::string_view blob, uint32_t magic) {
    return blob.size() >= 8 && blob.size() <= limit && Word(blob, 0) == magic && Word(blob, 4) == blob.size();
}
}
bool EncodeEntitlementsDer(std::string_view xml, std::string& der, std::string& error) {
    // Snapshot possible output alias before withholding all partial bytes.
    if (xml.empty() || xml.size() > limit) {
        der.clear(); error = "Entitlement XML input exceeds the supported bounds."; return false;
    }
    std::string input(xml); der.clear(); error.clear();
    Plist plist; std::string dictionary, body, encoded;
    Encoder encoder{0, error};
    if (!Active(error) || !plist.Parse(input) || !encoder.Value(plist.value, dictionary) ||
        !Append(body, std::string_view("\x02\x01\x01", 3)) || !Append(body, dictionary) || !Tlv(0x70, body, encoded)) {
        if (error.empty()) error = "Entitlement DER requires a bounded dictionary of bool/int64/UTF-8/array/dictionary values.";
        return false;
    }
    if (!VerifyEntitlementsDer(input, encoded, error)) return false;
    der = std::move(encoded); return true;
}
bool VerifyEntitlementsDer(std::string_view xml, std::string_view der, std::string& error) {
    error.clear(); Plist plist;
    Cursor root{der}; std::string_view body, version;
    bool valid = Active(error) && der.size() <= limit && plist.Parse(xml) && root.ReadTag(0x70, body) && root.remaining.empty();
    Cursor content{body}; Verifier verifier{0, error};
    valid = valid && content.ReadTag(2, version) && version == std::string_view("\x01", 1) &&
        verifier.Value(content, plist.value) && content.remaining.empty();
    if (!valid && error.empty()) error = "Entitlement DER is noncanonical, unsupported or differs from the typed XML input.";
    return valid;
}
bool DeriveEntitlementExecutionFlags(std::string_view xml, uint64_t& flags, std::string& error) {
    flags = 0; error.clear(); Plist plist;
    if (!Active(error)) return false;
    if (!plist.Parse(xml)) { error = "Execution flags require a bounded entitlement dictionary."; return false; }
    constexpr std::array<std::pair<const char*, uint64_t>, 7> bits{{
        {"get-task-allow", 0x10}, {"run-unsigned-code", 0x10},
        {"com.apple.private.cs.debugger", 0x20}, {"dynamic-codesigning", 0x40},
        {"com.apple.private.skip-library-validation", 0x80},
        {"com.apple.private.amfi.can-load-cdhash", 0x100},
        {"com.apple.private.amfi.can-execute-cdhash", 0x200}
    }};
    uint64_t result = 0;
    for (const auto& [key, bit] : bits) {
        const auto node = plist_dict_get_item(plist.value, key);
        if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) continue;
        uint8_t enabled = 0; plist_get_bool_val(node, &enabled);
        if (enabled) result |= bit;
    }
    flags = result; return true;
}
bool BuildProvisioningEntitlementBlobs(const PreparedEntitlementRequest& binding, CodeDirectorySpecialSlots& blobs, std::string& error) {
    blobs.clear(); error.clear();
    if (!ValidateProvisioningSignatureEntitlements(binding, error)) return false;
    std::string der;
    if (!EncodeEntitlementsDer(binding.profile_signature_entitlements_xml, der, error)) return false;
    CodeDirectorySpecialSlots result{{5, Blob(0xfade7171, binding.profile_signature_entitlements_xml)}, {7, Blob(0xfade7172, der)}};
    if (!ValidateProvisioningEntitlementBlobs(binding, result, error)) return false;
    blobs = std::move(result); return true;
}
bool ValidateProvisioningEntitlementBlobs(const PreparedEntitlementRequest& binding, const CodeDirectorySpecialSlots& blobs, std::string& error) {
    if (!ValidateProvisioningSignatureEntitlements(binding, error)) return false;
    const auto xml = blobs.find(5), der = blobs.find(7);
    if (xml == blobs.end() || der == blobs.end() || !Framed(xml->second, 0xfade7171) || !Framed(der->second, 0xfade7172) ||
        xml->second.size() > limit - der->second.size() ||
        std::string_view(xml->second).substr(8) != binding.profile_signature_entitlements_xml) {
        error = "Native provisioned signature requires checked, complete XML and DER entitlement blobs."; return false;
    }
    return VerifyEntitlementsDer(std::string_view(xml->second).substr(8), std::string_view(der->second).substr(8), error);
}
}
