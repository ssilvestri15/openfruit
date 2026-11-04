#pragma once
#include "win32_process.hpp"
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
namespace OpenFruit {
// Cooperating readers/writers and retention use the same exclusive, crash-safe
// destination.import-lock. Keep a lease alive for the whole mutable operation.
// Acquire records last use on that lock; TryAcquire does not refresh last use.
class ArtifactLease {
public:
    static std::shared_ptr<ArtifactLease> Acquire(const std::filesystem::path& destination,
        const ProcessRunOptions& control = {});
    // Null means another owner holds the lease; other failures throw.
    static std::shared_ptr<ArtifactLease> TryAcquire(const std::filesystem::path& destination);
    // Shared consumers require an existing ordinary publisher lock. They may
    // coexist but exclude publishers/pruners using the exclusive methods.
    static std::shared_ptr<ArtifactLease> AcquireSharedRead(const std::filesystem::path& destination,
        const ProcessRunOptions& control = {});
    static std::shared_ptr<ArtifactLease> TryAcquireSharedRead(const std::filesystem::path& destination);
    ~ArtifactLease();
    ArtifactLease(const ArtifactLease&) = delete;
    ArtifactLease& operator=(const ArtifactLease&) = delete;
private:
    friend class NativeArtifactStore;
    void TouchLastUse();
    static std::shared_ptr<ArtifactLease> TryAcquireMode(const std::filesystem::path& destination, bool shared_read);
    explicit ArtifactLease(void* handle) noexcept : handle_(handle) {}
    void* handle_ = nullptr;
};

struct CachePruneOptions {
    std::optional<std::uint64_t> max_bytes_quota;
    std::uint64_t max_age_seconds = 0;
    bool require_existing_consumer_lease = false;
    std::function<bool(const std::filesystem::path&)> eligible_entry;
    std::size_t max_entries_scanned = 4096; // 0 means unbounded
    std::size_t max_entries_deleted = 0;    // 0 means unbounded
    ProcessRunOptions control{};
};

struct CachePruneReport {
    std::size_t entries_removed = 0;
    std::size_t entries_skipped_in_use = 0;
    std::size_t entries_skipped_unmanaged = 0;
    // Logical lengths of deleted files; hard links/compression prevent this
    // from being a measurement of physical disk space recovered.
    std::uint64_t bytes_reclaimed = 0;
    std::size_t entries_scanned = 0;
    std::size_t entries_eligible = 0;
    std::size_t entries_deferred_budget = 0;
    bool partial = false;
    bool cancelled = false;
    bool timed_out = false;
    bool success = true;
    std::string error_message;
};

class NativeArtifactStore {
public:
    static bool ImportFile(const std::filesystem::path& source, const std::filesystem::path& destination);
    // Synchronize an independently copied metadata file (at most 64 MiB).
    // Caller owns the destination/receipt scope lease. An empty source removes
    // only a previously receipted import; unreceipted solver output is preserved.
    // Receipt phases record ownership before mutation and allow crash recovery.
    static bool SynchronizeImportedFile(const std::filesystem::path& source_or_empty,
        const std::filesystem::path& destination, const std::filesystem::path& receipt);
    static bool ImportTree(const std::filesystem::path& source, const std::filesystem::path& destination, std::size_t* imported_files = nullptr);
    static bool ImportTreeTransactional(const std::filesystem::path& source,
        const std::filesystem::path& destination,
        const std::function<bool(const std::filesystem::path&)>& validator,
        std::size_t* imported_files = nullptr);

    // Creates an NTFS directory junction or directory symlink pointing link -> target without admin rights.
    static bool CreateDirectoryJunction(const std::filesystem::path& link, const std::filesystem::path& target);

    // Creates an NTFS hard link pointing destination -> source (same volume, 0 byte duplication, 0 ms).
    static bool CreateNtfsHardLink(const std::filesystem::path& source, const std::filesystem::path& destination);

    // Prunes immediate owned children by max(content modification, lease last
    // use) age/quota. Consumers must
    // lease that same child for its whole lifetime; deeper leases do not cover
    // an ancestor entry. Root/top-level reparse entries are never traversed.
    // A nullopt quota disables byte-based retention; zero is an actual quota.
    // Use require_existing_consumer_lease only in namespaces whose consumers
    // use ArtifactLease. It preserves legacy/unowned entries without creating
    // locks for them; it does not make arbitrary managed cache roots safe.
    static CachePruneReport PruneCache(
        const std::filesystem::path& cache_root,
        const CachePruneOptions& options
    );

    static CachePruneReport PruneCache(
        const std::filesystem::path& cache_root,
        std::optional<std::uint64_t> max_bytes_quota,
        std::uint64_t max_age_seconds = 0,
        bool require_existing_consumer_lease = false,
        const std::function<bool(const std::filesystem::path&)>& eligible_entry = {}
    );
};
}

