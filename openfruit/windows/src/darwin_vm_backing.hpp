#pragma once
#include <cstdint>
#include <memory>
namespace OpenFruit {
// Shared native ownership for anonymous guest regions. Guest permissions remain
// enforced by the CPU backend; this backing stays writable for kernel copyout.
// Pages are demand-zero: reserved on allocation, committed on first access.
class DarwinVmBacking {
public:
    ~DarwinVmBacking();
    DarwinVmBacking(const DarwinVmBacking&)=delete;
    DarwinVmBacking& operator=(const DarwinVmBacking&)=delete;
    static std::shared_ptr<DarwinVmBacking> Allocate(std::uint64_t size) noexcept;
    void* Bytes() const noexcept{return bytes_;}
    std::uint64_t Size() const noexcept{return size_;}
private:
    DarwinVmBacking()=default;
    void* bytes_=nullptr;
    std::uint64_t size_=0;
};
}
