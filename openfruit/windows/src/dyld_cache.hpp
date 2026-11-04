#pragma once
#include "cancellation.hpp"
#include "json_value.hpp"
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <cstdint>
#include <vector>
#include <memory>
namespace OpenFruit {
struct DarwinImage;
using DyldCacheRead=std::function<std::string(std::uint64_t,std::uint64_t)>;
JsonValue InspectDyldCache(const DyldCacheRead&,std::uint64_t,const std::string& virtual_path);
JsonValue InspectDyldCacheStage(const std::filesystem::path&,CancellationToken={},
    std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());
JsonValue InspectDyldSubcache(const DyldCacheRead& parent,std::uint64_t parent_bytes,const std::string& parent_virtual_path,
    const DyldCacheRead& child,std::uint64_t child_bytes,const std::string& child_virtual_path);
JsonValue InspectDyldSubcacheStage(const std::filesystem::path& parent_file_report,
    const std::filesystem::path& child_file_report,CancellationToken={},
    std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());
JsonValue InspectDyldCacheSetStage(const std::filesystem::path& parent_file_report,
    const std::vector<std::filesystem::path>& child_file_reports,CancellationToken={},
    std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());
struct DyldCacheMemoryRange {
    std::uint64_t address=0,size=0;
    std::uint32_t protection=0;
    void* bytes=nullptr;
    std::uint32_t initial_protection=0,maximum_protection=0;
    std::uint64_t mapping_flags=0;
};
// Private Windows views associated with original guest VM addresses.
// Host pointers are separate; guest mapping, fixups and execution are not implied.
class DyldCacheMemory {
public:
    ~DyldCacheMemory();
    DyldCacheMemory(const DyldCacheMemory&)=delete;
    DyldCacheMemory& operator=(const DyldCacheMemory&)=delete;
    const std::vector<DyldCacheMemoryRange>& Ranges() const;
    // Runtime-generated anonymous state, never an original-file range/read.
    const DyldCacheMemoryRange& DynamicRange() const;
    JsonValue DynamicData() const;
    // Resolve only identities published from this owner's held original file.
    int FilePathByIdentity(std::uint32_t filesystem,std::uint64_t object,std::string& path) const;
private:
    friend class DyldCacheView;
    DyldCacheMemory();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
struct DyldCacheSlideFixup {
    std::uint64_t address=0,raw=0,target=0;
    std::uint16_t diversity=0;
    std::uint8_t high8=0;
    bool authenticated=false,address_diversity=false,key_is_data=false;
};
// Visitor runs under the source lease/lock; it must not reenter this view.
using DyldCacheSlideVisitor=std::function<void(const DyldCacheSlideFixup&)>;
// Native original-address reads. Input leases remain held for the view lifetime.
class DyldCacheView {
public:
    ~DyldCacheView();
    DyldCacheView(const DyldCacheView&)=delete;
    DyldCacheView& operator=(const DyldCacheView&)=delete;
    static std::unique_ptr<DyldCacheView> Open(const std::filesystem::path& parent_report,
        const std::vector<std::filesystem::path>& child_reports,std::string& error,
        CancellationToken={},std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());
    bool Read(std::uint64_t address,std::uint64_t size,std::string& bytes,std::string& error);
    const JsonValue& Layout() const;
    std::unique_ptr<DyldCacheMemory> MapMemory(std::string& error);
    JsonValue WalkSlideFixups(const DyldCacheSlideVisitor&);
    bool ContainsImage(const std::string& original_virtual_path,std::string& error);
    bool InspectImage(const std::string& original_virtual_path,DarwinImage&,std::string& error);
private:
    DyldCacheView();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
JsonValue InspectDyldCacheImagesStage(const std::filesystem::path& parent_file_report,
    const std::vector<std::filesystem::path>& child_file_reports,CancellationToken={},
    std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());

JsonValue InspectDyldCacheImageExportsStage(const std::string& original_virtual_image,
    const std::filesystem::path& parent_file_report,const std::vector<std::filesystem::path>& child_file_reports,
    CancellationToken={},std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());

JsonValue InspectDyldCacheSlideFixupsStage(const std::filesystem::path& parent_file_report,
    const std::vector<std::filesystem::path>& child_file_reports,CancellationToken={},
    std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());

JsonValue MapDyldCacheMemoryStage(const std::filesystem::path& parent_file_report,
    const std::vector<std::filesystem::path>& child_file_reports,CancellationToken={},
    std::chrono::steady_clock::time_point=std::chrono::steady_clock::time_point::max());

}
