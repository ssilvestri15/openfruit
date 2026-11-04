#include "darwin_vm_backing.hpp"
#include <windows.h>
#include <algorithm>
#include <limits>
#include <map>
#include <mutex>
namespace OpenFruit {
namespace {
// Guest anonymous memory is demand-zero, as in XNU: a region only reserves
// address space, and each page is committed (zero-filled) on first native
// access, whether from the CPU backend or from kernel copyin/copyout. Guest
// reservations far larger than their use (allocator arenas) then charge only
// the pages actually touched.
SRWLOCK reservations_lock=SRWLOCK_INIT;
std::map<std::uintptr_t,std::uint64_t>& Reservations(){static auto* reservations=new std::map<std::uintptr_t,std::uint64_t>;return *reservations;}
constexpr std::uintptr_t commit_window=64*1024;
LONG CALLBACK CommitOnAccess(EXCEPTION_POINTERS* exception){
    const auto* record=exception->ExceptionRecord;
    if(record->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION||record->NumberParameters<2)return EXCEPTION_CONTINUE_SEARCH;
    const auto address=static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
    std::uintptr_t base=0,end=0;
    AcquireSRWLockShared(&reservations_lock);
    auto& reservations=Reservations();auto owner=reservations.upper_bound(address);
    if(owner!=reservations.begin()){--owner;if(address-owner->first<owner->second){base=owner->first;end=owner->first+static_cast<std::uintptr_t>(owner->second);}}
    ReleaseSRWLockShared(&reservations_lock);
    if(!end)return EXCEPTION_CONTINUE_SEARCH;
    // Only reserved pages are demand-committed; a fault on committed backing
    // is a genuine native error and keeps its normal handling.
    MEMORY_BASIC_INFORMATION page{};
    if(!VirtualQuery(reinterpret_cast<void*>(address),&page,sizeof(page))||page.State!=MEM_RESERVE)return EXCEPTION_CONTINUE_SEARCH;
    const auto first=std::max(base,address&~(commit_window-1));
    const auto limit=std::min({end,first+commit_window,
        reinterpret_cast<std::uintptr_t>(page.BaseAddress)+static_cast<std::uintptr_t>(page.RegionSize)});
    return VirtualAlloc(reinterpret_cast<void*>(first),limit-first,MEM_COMMIT,PAGE_READWRITE)
        ?EXCEPTION_CONTINUE_EXECUTION:EXCEPTION_CONTINUE_SEARCH;
}
}
DarwinVmBacking::~DarwinVmBacking(){
    if(!bytes_)return;
    AcquireSRWLockExclusive(&reservations_lock);Reservations().erase(reinterpret_cast<std::uintptr_t>(bytes_));ReleaseSRWLockExclusive(&reservations_lock);
    VirtualFree(bytes_,0,MEM_RELEASE);
}
std::shared_ptr<DarwinVmBacking> DarwinVmBacking::Allocate(std::uint64_t size) noexcept{
    if(!size||size>std::numeric_limits<SIZE_T>::max())return {};
    try{
        static std::once_flag handler;
        std::call_once(handler,[]{AddVectoredExceptionHandler(1,CommitOnAccess);});
        auto allocation=std::shared_ptr<DarwinVmBacking>(new DarwinVmBacking);
        void* bytes=VirtualAlloc(nullptr,static_cast<SIZE_T>(size),MEM_RESERVE,PAGE_READWRITE);
        if(!bytes)return {};
        AcquireSRWLockExclusive(&reservations_lock);
        try{Reservations().emplace(reinterpret_cast<std::uintptr_t>(bytes),size);}
        catch(...){ReleaseSRWLockExclusive(&reservations_lock);VirtualFree(bytes,0,MEM_RELEASE);return {};}
        ReleaseSRWLockExclusive(&reservations_lock);
        allocation->bytes_=bytes;allocation->size_=size;return allocation;
    }catch(...){return {};}
}
}
