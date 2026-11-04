#pragma once
#include "config.hpp"
#include <filesystem>
#include <string>
namespace OpenFruit {
enum class SDKSelectionStatus { Succeeded, NotRegistered, InvalidPath, IncompleteLayout, PublicationFailed };
struct SDKSelectionResult {
    SDKSelectionStatus status = SDKSelectionStatus::NotRegistered;
    std::string message;
    bool Succeeded() const noexcept { return status == SDKSelectionStatus::Succeeded; }
};
enum class SDKRemovalStatus { Succeeded, NotRegistered, InUse, PublicationFailed, InvalidPath, RemovalFailed, Cancelled };
struct SDKRemovalResult {
    SDKRemovalStatus status = SDKRemovalStatus::NotRegistered;
    std::string message;
    bool cleanup_pending = false;
    std::filesystem::path retained_directory;
    std::filesystem::path retained_receipt;
    bool Succeeded() const noexcept { return status == SDKRemovalStatus::Succeeded; }
};
// Application operation combines SDK inspection with configuration persistence.
// The caller owns the snapshot. SDK safety fields must match persisted state;
// successful mutation uses that persisted base, retaining unrelated settings.
// Conditional publication rejects changed bytes under the cooperative Config
// writer lease; external writers ignoring that lease are not covered.
// Select/Remove retry a uniquely owned v2/v3 prepared quarantine only against the
// exact persisted configuration before-image. Legacy, modified or committed
// transactions stay retained. Selection pins SDKUsage through publication.
class SDKSelection {
public:
    static SDKSelectionResult Select(Config& snapshot, const std::wstring& registered_version,
        const std::filesystem::path& configuration_path);
};

// Explicit registered SDK removal. Existing external registrations remain supported;
// strict path/layout checks prevent broad or aliased deletion. SDKUsage handles
// block detachment. Configuration failure restores the original directory before
// deleting any contents. A committed removal can report deferred cleanup.
class SDKRemoval {
public:
    static SDKRemovalResult Remove(Config& snapshot, const std::wstring& registered_version,
        const std::filesystem::path& configuration_path, bool remove_directory = true);
    // Explicit v3 transaction cleanup; no global discovery or legacy adoption.
    static SDKRemovalResult Cleanup(const std::filesystem::path& receipt_path,
        const std::filesystem::path& configuration_path);
};
}
