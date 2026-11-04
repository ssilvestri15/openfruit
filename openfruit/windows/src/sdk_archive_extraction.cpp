#include "sdk_archive_extraction.hpp"
#include "archive_tree_extraction.hpp"
#include "win32_process.hpp"
namespace OpenFruit {
namespace {
SDKExtractionStatus SDKStatus(ArchiveExtractionStatus status) {
    switch (status) {
    case ArchiveExtractionStatus::Succeeded: return SDKExtractionStatus::Succeeded;
    case ArchiveExtractionStatus::InvalidDestination: return SDKExtractionStatus::InvalidDestination;
    case ArchiveExtractionStatus::DestinationExists: return SDKExtractionStatus::DestinationExists;
    case ArchiveExtractionStatus::ArchiveFailure: return SDKExtractionStatus::ArchiveFailure;
    case ArchiveExtractionStatus::UnsafePath: return SDKExtractionStatus::UnsafePath;
    case ArchiveExtractionStatus::UnresolvedLink: return SDKExtractionStatus::UnresolvedLink;
    case ArchiveExtractionStatus::UnsupportedEntry: return SDKExtractionStatus::UnsupportedEntry;
    case ArchiveExtractionStatus::SymbolicLinksUnavailable: return SDKExtractionStatus::SymbolicLinksUnavailable;
    case ArchiveExtractionStatus::IoFailure: return SDKExtractionStatus::IoFailure;
    case ArchiveExtractionStatus::ResourceLimit: return SDKExtractionStatus::ResourceLimit;
    case ArchiveExtractionStatus::Cancelled: return SDKExtractionStatus::Cancelled;
    case ArchiveExtractionStatus::TimedOut: return SDKExtractionStatus::TimedOut;
    case ArchiveExtractionStatus::MissingSelection: return SDKExtractionStatus::MissingSdk;
    }
    return SDKExtractionStatus::IoFailure;
}
}
SDKExtractionResult SDKArchiveExtraction::ExtractIos(const std::filesystem::path& archive,
    const std::filesystem::path& destination, const SDKExtractionOptions& options) {
    SDKExtractionResult result;
    ArchiveExtractionOptions common;
    common.read = options.read; common.max_plan_entries = options.max_plan_entries;
    common.max_plan_string_bytes = options.max_plan_string_bytes; common.max_written_bytes = options.max_written_bytes;
    const auto extracted = ArchiveTreeExtraction::Extract(archive, destination,
        [&result](const std::filesystem::path& source, const XipReadOptions& read_options) {
            ArchiveTreeSelection selection;
            const auto metadata = SDKArchiveMetadata::DiscoverIos(source, read_options);
            if (metadata.read.status != XipStatus::Completed && metadata.read.status != XipStatus::Stopped) {
                selection.status = metadata.read.status == XipStatus::Cancelled ? ArchiveExtractionStatus::Cancelled :
                    metadata.read.status == XipStatus::TimedOut ? ArchiveExtractionStatus::TimedOut :
                    metadata.read.status == XipStatus::ResourceLimit ? ArchiveExtractionStatus::ResourceLimit : ArchiveExtractionStatus::ArchiveFailure;
                selection.diagnostic_code = metadata.read.error.empty() ? "archive.extraction.archive_read_failed" : metadata.read.error;
            } else if (!metadata.Found()) {
                selection.status = ArchiveExtractionStatus::MissingSelection;
                selection.diagnostic_code = "archive.extraction.iphoneos_metadata_missing";
            } else {
                result.version = metadata.version; selection.member_paths.push_back(metadata.sdk_root);
            }
            return selection;
        }, common);
    result.status = SDKStatus(extracted.status); result.diagnostic_code = extracted.diagnostic_code;
    if (result.diagnostic_code.starts_with("archive.extraction.")) result.diagnostic_code.replace(0, 19, "sdk.extraction.");
    result.native_error = extracted.native_error; result.files = extracted.files;
    result.selected_entries = extracted.selected_entries; result.hardlinks = extracted.hardlinks;
    result.symlinks = extracted.symlinks; result.written_bytes = extracted.written_bytes;
    result.staging_present = extracted.staging_present; result.toc_checksum_verified = extracted.toc_checksum_verified;
    result.content_checksum_verified = extracted.content_checksum_verified; result.xar_signature_valid = extracted.xar_signature_valid;
    result.apple_signing_chain_valid = extracted.apple_signing_chain_valid; result.apple_revocation_valid = extracted.apple_revocation_valid;
    if (extracted.Succeeded()) result.sdk_path = destination / std::filesystem::path(Win32Process::ToWide(extracted.member_paths.front()));
    return result;
}
const char* SDKExtractionStatusName(SDKExtractionStatus status) noexcept {
    switch (status) {
    case SDKExtractionStatus::Succeeded: return "succeeded";
    case SDKExtractionStatus::InvalidDestination: return "invalid_destination";
    case SDKExtractionStatus::DestinationExists: return "destination_exists";
    case SDKExtractionStatus::ArchiveFailure: return "archive_failure";
    case SDKExtractionStatus::MissingSdk: return "missing_sdk";
    case SDKExtractionStatus::UnsafePath: return "unsafe_path";
    case SDKExtractionStatus::UnresolvedLink: return "unresolved_link";
    case SDKExtractionStatus::UnsupportedEntry: return "unsupported_entry";
    case SDKExtractionStatus::SymbolicLinksUnavailable: return "symbolic_links_unavailable";
    case SDKExtractionStatus::IoFailure: return "io_failure";
    case SDKExtractionStatus::ResourceLimit: return "resource_limit";
    case SDKExtractionStatus::Cancelled: return "cancelled";
    case SDKExtractionStatus::TimedOut: return "timed_out";
    }
    return "io_failure";
}
JsonValue SDKExtractionResult::ToJson() const {
    auto data = JsonValue::ObjectValue();
    data.Set("schema_version", JsonValue::Number("1")); data.Set("status", JsonValue::String(SDKExtractionStatusName(status)));
    data.Set("version", JsonValue::String(version)); data.Set("sdk_path", JsonValue::String(Win32Process::ToNarrow(sdk_path.wstring())));
    data.Set("diagnostic_code", JsonValue::String(diagnostic_code)); data.Set("native_error", JsonValue::Number(std::to_string(native_error)));
    data.Set("files", JsonValue::Number(std::to_string(files))); data.Set("hardlinks", JsonValue::Number(std::to_string(hardlinks)));
    data.Set("selected_entries", JsonValue::Number(std::to_string(selected_entries)));
    data.Set("symlinks", JsonValue::Number(std::to_string(symlinks))); data.Set("written_bytes", JsonValue::Number(std::to_string(written_bytes)));
    data.Set("staging_present", JsonValue::Boolean(staging_present)); data.Set("publisher_verified", JsonValue::Boolean(false));
    data.Set("toc_checksum_verified", JsonValue::Boolean(toc_checksum_verified));
    data.Set("content_checksum_verified", JsonValue::Boolean(content_checksum_verified));
    data.Set("xar_signature_valid", JsonValue::Boolean(xar_signature_valid));
    data.Set("apple_signing_chain_valid", JsonValue::Boolean(apple_signing_chain_valid));
    data.Set("apple_revocation_valid", JsonValue::Boolean(apple_revocation_valid));
    data.Set("published", JsonValue::Boolean(false));
    if (status == SDKExtractionStatus::SymbolicLinksUnavailable) data.Set("required_capability", JsonValue::String("windows.symbolic_links"));
    return data;
}
}
