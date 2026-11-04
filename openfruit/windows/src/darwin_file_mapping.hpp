#pragma once
#include "json_value.hpp"
#include <memory>
#include <cstdint>
#include <string>
namespace OpenFruit {
// Private bytes from an immutable held file; retained native lease excludes
// source writes/deletion after the guest descriptor closes. No Apple trust.
class DarwinPrivateFileMapping {
public:
    ~DarwinPrivateFileMapping();
    DarwinPrivateFileMapping(const DarwinPrivateFileMapping&)=delete;
    DarwinPrivateFileMapping& operator=(const DarwinPrivateFileMapping&)=delete;
    static std::shared_ptr<DarwinPrivateFileMapping> Capture(void* handle,std::uint64_t file_size,
        const std::string& path,const std::string& sha256,std::uint64_t offset,
        std::uint64_t length,std::uint64_t page_size,int& error);
    void* Bytes() const noexcept;
    std::uint64_t Size() const noexcept;
    std::uint64_t Delta() const noexcept;
    JsonValue ToJson() const;
private:
    DarwinPrivateFileMapping();
    struct State;std::unique_ptr<State> state_;
};
}
