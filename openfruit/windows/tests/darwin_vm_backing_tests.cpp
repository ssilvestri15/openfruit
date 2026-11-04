#include "darwin_vm_backing.hpp"
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>
using namespace OpenFruit;
void Require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
int main(){try{
    Require(!DarwinVmBacking::Allocate(0),"Empty backing allocation admitted");
    auto backing=DarwinVmBacking::Allocate(65536);Require(bool(backing),"Native backing unavailable");
    auto* bytes=static_cast<unsigned char*>(backing->Bytes());Require(backing->Size()==65536&&bytes[0]==0&&bytes[65535]==0,"Native anonymous bytes not zero initialized");
    MEMORY_BASIC_INFORMATION info{};Require(VirtualQuery(bytes,&info,sizeof(info))&&info.State==MEM_COMMIT&&info.Type==MEM_PRIVATE,"Backing is not real Windows private memory");
    std::weak_ptr<DarwinVmBacking> lease=backing;auto remaining=backing;backing.reset();
    Require(!lease.expired(),"Removing one region freed shared backing");bytes[32768]=42;Require(static_cast<unsigned char*>(remaining->Bytes())[32768]==42,"Retained region lost original backing bytes");
    remaining.reset();Require(lease.expired(),"Last region failed to release native lease");
    Require(VirtualQuery(bytes,&info,sizeof(info))&&info.State==MEM_FREE,"Last lease failed to free Windows backing");
    // Demand-zero: a guest reservation larger than its use charges only touched pages.
    const auto committed=[]{PROCESS_MEMORY_COUNTERS_EX counters{};counters.cb=sizeof(counters);
        Require(GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),sizeof(counters)),"Process commit unavailable");
        return static_cast<std::uint64_t>(counters.PrivateUsage);};
    const auto before=committed();
    auto arena=DarwinVmBacking::Allocate(32ULL<<30);Require(bool(arena),"Large guest reservation unavailable");
    Require(committed()-before<(1ULL<<20),"Guest reservation charged commit before access");
    auto* distant=static_cast<unsigned char*>(arena->Bytes())+(16ULL<<30)+123;
    Require(*distant==0,"Demand-committed page is not zero filled");*distant=7;Require(*distant==7,"Demand-committed page is not writable");
    Require(committed()-before<(1ULL<<20),"First access committed more than its page window");
    Require(VirtualQuery(static_cast<unsigned char*>(arena->Bytes())+(8ULL<<30),&info,sizeof(info))&&info.State==MEM_RESERVE,"Untouched guest pages were committed");
    arena.reset();
    std::cout<<"Native anonymous backing ownership/zeroing/shared lifetime PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
