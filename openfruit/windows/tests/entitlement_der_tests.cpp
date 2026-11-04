#include "entitlement_blobs.hpp"
#include "operation_events.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
std::string Xml(std::string_view body) { return "<plist version=\"1.0\"><dict>" + std::string(body) + "</dict></plist>"; }
std::string Hex(std::string_view hex) {
    std::string bytes;
    auto Digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i < hex.size(); i += 2) bytes += static_cast<char>((Digit(hex[i]) << 4) | Digit(hex[i + 1]));
    return bytes;
}
}
int main() {
    try {
        std::string error, encoded;
        // Explicit ASN.1 byte vectors. No length, integer, offset or expected
        // hash is injected into the production converter.
        const std::vector<std::pair<std::string, std::string>> vectors{
            {"", "7005020101b000"},
            {"<key>key</key><false/>", "700f020101b00a30080c036b6579010100"},
            {"<key>key</key><true/>", "700f020101b00a30080c036b65790101ff"},
            {"<key>key</key><integer>0</integer>", "700f020101b00a30080c036b6579020100"},
            {"<key>key</key><integer>-1</integer>", "700f020101b00a30080c036b65790201ff"},
            {"<key>key</key><integer>127</integer>", "700f020101b00a30080c036b657902017f"},
            {"<key>key</key><integer>128</integer>", "7010020101b00b30090c036b657902020080"},
            {"<key>key</key><integer>255</integer>", "7010020101b00b30090c036b6579020200ff"},
            {"<key>key</key><integer>256</integer>", "7010020101b00b30090c036b657902020100"},
            {"<key>key</key><integer>-128</integer>", "700f020101b00a30080c036b6579020180"},
            {"<key>key</key><integer>-129</integer>", "7010020101b00b30090c036b65790202ff7f"},
            {"<key>key</key><integer>9223372036854775807</integer>", "7016020101b011300f0c036b657902087fffffffffffffff"},
            {"<key>key</key><integer>-9223372036854775808</integer>", "7016020101b011300f0c036b657902088000000000000000"},
            {"<key>key</key><string/>", "700e020101b00930070c036b65790c00"},
            {"<key>key</key><array/>", "700e020101b00930070c036b65793000"},
            {"<key>key</key><dict/>", "700e020101b00930070c036b6579b000"},
            {"<key>key</key><array><true/><string>foo</string></array>", "7016020101b011300f0c036b657930080101ff0c03666f6f"},
            {"<key>key</key><dict><key>inner</key><false/></dict>", "701a020101b01530130c036b6579b00c300a0c05696e6e6572010100"}
        };
        for (const auto& [body, bytes] : vectors) {
            const auto xml = Xml(body), expected = Hex(bytes);
            Require(EncodeEntitlementsDer(xml, encoded, error), error.c_str());
            Require(encoded == expected, "native DER differs from explicit ASN.1 vector");
            Require(VerifyEntitlementsDer(xml, expected, error), error.c_str());
            for (std::size_t size = 0; size < expected.size(); ++size)
                Require(!VerifyEntitlementsDer(xml, std::string_view(expected).substr(0, size), error), "truncated DER accepted");
            Require(!VerifyEntitlementsDer(xml, expected + "trailing", error), "trailing DER bytes accepted");
        }
        const auto bool_xml = Xml("<key>key</key><true/>"), bool_der = Hex(vectors[2].second);
        const std::vector<std::pair<std::string, uint64_t>> execution_bits{
            {"get-task-allow", 0x10}, {"run-unsigned-code", 0x10},
            {"com.apple.private.cs.debugger", 0x20}, {"dynamic-codesigning", 0x40},
            {"com.apple.private.skip-library-validation", 0x80},
            {"com.apple.private.amfi.can-load-cdhash", 0x100}, {"com.apple.private.amfi.can-execute-cdhash", 0x200}
        };
        std::string all_execution_rights;
        uint64_t flags = UINT64_MAX;
        Require(DeriveEntitlementExecutionFlags(Xml(""), flags, error) && flags == 0, "empty entitlement dictionary enables execution bits");
        for (const auto& [key, bit] : execution_bits) {
            const auto enabled = "<key>" + key + "</key><true/>";
            Require(DeriveEntitlementExecutionFlags(Xml(enabled), flags, error) && flags == bit, "boolean entitlement maps to wrong execution bit");
            all_execution_rights += enabled;
            for (const auto value : {"<false/>", "<integer>1</integer>", "<string>true</string>", "<array><true/></array>"})
                Require(DeriveEntitlementExecutionFlags(Xml("<key>" + key + "</key>" + value), flags, error) && flags == 0,
                    "false or nonboolean entitlement enables execution bit");
        }
        Require(DeriveEntitlementExecutionFlags(Xml(all_execution_rights), flags, error) && flags == 0x3f0,
            "combined execution bits are incomplete or include the main-binary bit");
        flags = UINT64_MAX;
        Require(!DeriveEntitlementExecutionFlags("malformed XML", flags, error) && flags == 0, "invalid XML retains stale execution flags");
        Require(!VerifyEntitlementsDer(Xml("<key>key</key><integer>1</integer>"), bool_der, error), "DER bool equals XML integer");
        const std::vector<std::string> malformed{
            "70810f020101b00a30080c036b65790101ff", // overlong length
            "7080020101b00a30080c036b65790101ff0000", // indefinite length
            "700f020102b00a30080c036b65790101ff", // unsupported version
            "700f020101310a30080c036b65790101ff", // old dictionary representation
            "700f020101b00a30080c036b6579010101", // noncanonical true
            "700f020101b00a30080c036b00790101ff", // embedded NUL key
            "700f020101b00a30080c03ff65790101ff", // invalid UTF-8 key
            "700f020101b00a300813036b65790101ff", // wrong string tag
            "7010020101b00b30090c036b657902020000", // padded integer zero
            "7010020101b00b30090c036b65790202ffff", // padded integer minus one
            "7019020101b01430080c036b65790101ff30080c036b65790101ff" // duplicate keys
        };
        for (const auto& bytes : malformed) Require(!VerifyEntitlementsDer(bool_xml, Hex(bytes), error), "noncanonical DER accepted");
        Require(!VerifyEntitlementsDer(Xml("<key>key</key><integer>0</integer>"), Hex("7010020101b00b30090c036b657902020000"), error),
            "integer verifier accepts unnecessary positive sign padding");
        Require(!VerifyEntitlementsDer(Xml("<key>key</key><integer>-1</integer>"), Hex("7010020101b00b30090c036b65790202ffff"), error),
            "integer verifier accepts unnecessary negative sign padding");
        Require(!VerifyEntitlementsDer(Xml("<key>key</key><integer>9223372036854775808</integer>"), Hex(vectors[12].second), error),
            "unsigned XML overflow compares equal to signed DER minimum");
        const auto ordered = Xml("<key>a</key><false/><key>z</key><true/>");
        std::string ordered_der;
        Require(EncodeEntitlementsDer(ordered, ordered_der, error), error.c_str());
        Require(EncodeEntitlementsDer(Xml("<key>z</key><true/><key>a</key><false/>"), encoded, error) && encoded == ordered_der,
            "dictionary insertion order changed canonical DER");
        auto unordered_der = ordered_der;
        // Both one-letter entries have the same byte size; swap the actual
        // encoded entries without invoking the converter to generate this fault.
        unordered_der.replace(7, 8, ordered_der.substr(15, 8)); unordered_der.replace(15, 8, ordered_der.substr(7, 8));
        Require(!VerifyEntitlementsDer(ordered, unordered_der, error), "unsorted DER dictionary accepted");
        Require(EncodeEntitlementsDer(Xml("<key>key</key><array><true/><false/></array>"), encoded, error), error.c_str());
        Require(!VerifyEntitlementsDer(Xml("<key>key</key><array><false/><true/></array>"), encoded, error), "array ordering ignored");
        for (const auto size : {127u, 128u, 255u, 256u, 65536u}) {
            const auto xml = Xml("<key>key</key><string>" + std::string(size, 'x') + "</string>");
            Require(EncodeEntitlementsDer(xml, encoded, error) && VerifyEntitlementsDer(xml, encoded, error), error.c_str());
        }
        Require(EncodeEntitlementsDer(Xml("<key>key</key><string>\xc3\xa8 &amp; &lt;</string>"), encoded, error), error.c_str());
        for (const auto body : {"<key>key</key><real>1.25</real>", "<key>key</key><data>AA==</data>",
            "<key>key</key><date>2026-10-04T00:00:00Z</date>", "<key>key</key><integer>9223372036854775808</integer>",
            "<key>key</key><integer>18446744073709551615</integer>", "<key>key</key><integer>-9223372036854775809</integer>"}) {
            encoded = "stale DER";
            Require(!EncodeEntitlementsDer(Xml(body), encoded, error) && encoded.empty() && !error.empty(), "unsupported type/range produced partial DER");
        }
        std::string nested = "<true/>";
        for (int i = 0; i < 66; ++i) nested = "<array>" + nested + "</array>";
        Require(!EncodeEntitlementsDer(Xml("<key>key</key>" + nested), encoded, error) && encoded.empty(), "DER recursion bound ignored");
        const std::string oversized(16 * 1024 * 1024 + 1, 'x');
        encoded = "stale oversized DER";
        Require(!EncodeEntitlementsDer(oversized, encoded, error) && encoded.empty(), "XML size bound ignored");
        Require(!VerifyEntitlementsDer(bool_xml, oversized, error), "DER size bound ignored");
        std::string many_values = "<key>key</key><array>";
        for (int i = 0; i < 100001; ++i) many_values += "<true/>";
        many_values += "</array>";
        Require(!EncodeEntitlementsDer(Xml(many_values), encoded, error) && encoded.empty(), "DER node budget ignored");
        Require(!EncodeEntitlementsDer(Xml("<key>key</key><string>\xff</string>"), encoded, error) && encoded.empty(), "invalid UTF-8 string accepted");
        auto alias = bool_xml;
        Require(EncodeEntitlementsDer(alias, alias, error) && alias == bool_der, "output alias invalidated XML input");
        for (const bool deadline : {false, true}) {
            auto context = std::make_shared<OperationContext>();
            if (deadline) context->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() - std::chrono::seconds(1));
            else context->RequestCancellation();
            OperationBinding binding(context); encoded = "stale cancelled DER";
            Require(!EncodeEntitlementsDer(bool_xml, encoded, error) && encoded.empty() && error.find("cancelled or deadline") != std::string::npos,
                "cancelled DER conversion continued");
            Require(!VerifyEntitlementsDer(bool_xml, bool_der, error), "cancelled DER verification continued");
            flags = UINT64_MAX;
            Require(!DeriveEntitlementExecutionFlags(Xml(all_execution_rights), flags, error) && flags == 0,
                "cancelled execution flag derivation continued or retained stale flags");
        }
        std::cout << "Canonical entitlement DER vectors, strict independent XML comparison and negative controls: PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
