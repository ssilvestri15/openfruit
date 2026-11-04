#pragma once
#include "http_transfer.hpp"
#include "aea_fcs_key.hpp"
#include "aea_root.hpp"
#include "json_value.hpp"
#include <memory>
#include <optional>
namespace OpenFruit {
class AeaInput {
public:
    ~AeaInput();
    AeaInput(const AeaInput&) = delete;
    AeaInput& operator=(const AeaInput&) = delete;
    static std::unique_ptr<AeaInput> Open(const std::filesystem::path&,const std::string& expected_sha256,
        std::string& error,CancellationToken = {},
        std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max());
    // The read lease denies writes/replacement for the entire session lifetime.
    std::optional<std::string> Read(std::uint64_t offset,std::uint64_t count,std::string& error) const;
    const std::string* Metadata(const std::string& key) const;
    std::unique_ptr<AeaFcsKey> AcquireFcsKey(std::string& error) const;
    std::unique_ptr<SecretBytes> UnwrapFcsKey(std::string& error) const;
    std::unique_ptr<AeaRoot> InspectRoot(std::string& error) const;
    AeaDecodeResult Decode(const AeaSink&,std::string& error) const;
    JsonValue ToJson() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit AeaInput(std::unique_ptr<Impl>);
};
// Accept only the observed Apple HTTPS FCS redirect, preserving the original key path.
std::optional<std::wstring> ResolveAeaFcsRedirect(const std::wstring& source, const std::wstring& location);
JsonValue InspectAeaStage(const std::filesystem::path& stage_report, bool acquire_key = false, bool unwrap_key = false, bool inspect_root = false);
JsonValue DecodeAeaStage(const std::filesystem::path& stage_report,const std::filesystem::path& new_quarantine_directory);
}
