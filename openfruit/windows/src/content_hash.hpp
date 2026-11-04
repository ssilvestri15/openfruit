#pragma once
#include "cancellation.hpp"
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <memory>
namespace OpenFruit {
class Sha256Stream {
    struct Impl;
    std::unique_ptr<Impl> state_;
public:
    Sha256Stream();
    ~Sha256Stream();
    Sha256Stream(const Sha256Stream&) = delete;
    Sha256Stream& operator=(const Sha256Stream&) = delete;
    bool Update(std::string_view);
    std::optional<std::string> Finish();
};
std::optional<std::string> Sha256(std::string_view);
// Borrow an already held native Windows file handle; hash that exact object from
// offset zero, leaving its position at EOF. Caller owns handle/lifetime/access.
std::optional<std::string> Sha256FileHandle(void* native_handle,CancellationToken cancellation = {},
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max());
// Hash a stable handle; concurrent mutation/replacement is denied during reading.
std::optional<std::string> Sha256File(const std::filesystem::path&, CancellationToken cancellation = {},
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max());
// Sha256File for large inputs that rarely change (toolchain binaries): the
// digest recorded in `cache_file` is reused while the file keeps its size,
// write time, NTFS change time and file identity, which any content edit or
// replacement alters. The file is held open, denying writes, while checked.
std::optional<std::string> Sha256FileStatCached(const std::filesystem::path&, const std::filesystem::path& cache_file,
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max());
// The same for an already held handle, named in the cache by file identity.
std::optional<std::string> Sha256FileHandleStatCached(void* native_handle, const std::filesystem::path& cache_file,
    CancellationToken cancellation = {}, std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max());
}
