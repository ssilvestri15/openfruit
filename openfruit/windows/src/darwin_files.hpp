#pragma once
#include "darwin_closure.hpp"
#include "darwin_file_metadata.hpp"
#include "darwin_file_mapping.hpp"
#include "darwin_file_signature.hpp"
#include <span>
#include <optional>

namespace OpenFruit {
// pending is a host readiness result, never a completed guest read/EOF/errno.
struct DarwinFileResult {std::uint64_t value=0;int error=0;bool pending=false;};
// Task-owned descriptors for immutable original-tree files. These are not
// Windows handles, cached Mach-O reconstructions, or synthesized providers.
class DarwinFiles {
public:
    // Retains an admitted open description while a guest read is suspended.
    // It does not allocate a descriptor or follow subsequent fd replacement.
    class ReadLease {
    public:
        ReadLease()=default;
    private:
        friend class DarwinFiles;
        std::shared_ptr<void> description_;
        std::weak_ptr<void> owner_;
    };
    explicit DarwinFiles(const DarwinClosure&,const DarwinClosureOptions& = {},const std::string& initial_directory = "/");
    ~DarwinFiles();
    DarwinFiles(const DarwinFiles&)=delete;
    DarwinFiles& operator=(const DarwinFiles&)=delete;
    DarwinFileResult Open(const std::string& path,std::uint32_t flags);
    DarwinFileResult OpenAt(std::int32_t directory,const std::string& path,std::uint32_t flags);
    DarwinFileResult Stat(const std::string& path,DarwinFileMetadata&);
    DarwinFileResult Access(const std::string& path,std::uint32_t mode);
    DarwinFileResult Fstat(std::int32_t fd,DarwinFileMetadata&) const;
    std::shared_ptr<DarwinPrivateFileMapping> PrivateMapping(std::int32_t fd,std::uint64_t offset,std::uint64_t length,std::uint64_t page_size,int& error) const;
    DarwinFileResult BindOutput(std::int32_t fd,void* native_handle);
    // PIPE read endpoint only. Caller transfers exclusive reader ownership;
    // after binding it must not read through any retained native alias.
    DarwinFileResult BindInput(std::int32_t fd,void* native_handle);
    DarwinFileResult Dup(std::int32_t fd);
    DarwinFileResult Dup2(std::int32_t fd,std::int32_t target);
    DarwinFileResult WriteCapacity(std::int32_t fd,std::uint64_t requested) const;
    DarwinFileResult Write(std::int32_t fd,std::span<const char> bytes);
    DarwinFileResult Close(std::int32_t fd);
    DarwinFileResult ReadCapacity(std::int32_t fd,std::uint64_t requested,std::optional<std::uint64_t> offset = {}) const;
    DarwinFileResult Read(std::int32_t fd,std::span<char> bytes,std::optional<std::uint64_t> offset = {});
    DarwinFileResult AcquireRead(std::int32_t fd,std::uint64_t requested,std::optional<std::uint64_t> offset,ReadLease&) const;
    DarwinFileResult ReadCapacity(const ReadLease&,std::uint64_t requested,std::optional<std::uint64_t> offset = {}) const;
    DarwinFileResult Read(const ReadLease&,std::span<char> bytes,std::optional<std::uint64_t> offset = {});
    DarwinFileResult Seek(std::int32_t fd,std::int64_t offset,std::uint32_t whence);
    DarwinFileResult Fcntl(std::int32_t fd,std::uint32_t command,std::uint64_t argument);
    DarwinFileResult SignatureDescriptor(std::int32_t fd) const;
    DarwinFileResult RegisterSignature(std::int32_t fd,std::uint64_t slice_offset,
        std::uint64_t blob_offset,std::uint64_t blob_size,DarwinFileSignature&);
    DarwinFileResult CheckLibrary(std::int32_t fd,std::uint64_t slice_offset,
        std::uint32_t task_status,JsonValue& evidence,std::string& reason) const;
    DarwinFileResult Path(std::int32_t fd,std::string& path) const;
    bool Contains(std::int32_t fd) const noexcept;
    // Exclusive upper bound for new descriptor numbers, capped at the native
    // table capacity (4096). Lowering it does not revoke existing descriptors.
    void SetMaxDescriptors(std::uint64_t max_descriptors) noexcept;
    std::uint64_t MaxDescriptors() const noexcept;
    std::uint64_t TotalReads() const noexcept;
    std::uint64_t TotalOutputCalls() const noexcept;
    JsonValue ToJson() const;
private:
    struct State;
    std::unique_ptr<State> state_;
    DarwinFileResult ReadCapacityDescription(const std::shared_ptr<void>&,std::uint64_t,std::optional<std::uint64_t>) const;
};
}
