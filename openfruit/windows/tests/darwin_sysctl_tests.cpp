#include "darwin_sysctl.hpp"
#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <stdexcept>
using namespace OpenFruit;
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
int main(){try{
    for(auto geometry:{4096ULL,16384ULL}){
        DarwinSysctl registry(geometry);
        const auto oid=registry.NameToOid("hw.pagesize");Require(!oid.error&&oid.bytes.size()==8,"name2oid size failed");
        std::array<std::int32_t,2> mib{};std::memcpy(mib.data(),oid.bytes.data(),8);
        const auto value=registry.Read(mib);std::uint32_t bytes=0;Require(!value.error&&value.bytes.size()==4,"typed sysctl size failed");
        std::memcpy(&bytes,value.bytes.data(),4);Require(bytes==geometry,"guest geometry did not propagate");
        Require(registry.NameToOid("hw.pagesize.").bytes==oid.bytes,"trailing-dot lookup differs from XNU");
        Require(registry.NameToOid(std::string_view("hw.pagesize\0ignored",19)).bytes==oid.bytes,"C-string lookup differs from XNU");
        Require(registry.NameToOid("security.mac.lockdown_mode_state").error==2,"missing MAC node fabricated");
        Require(registry.NameToOid("hw.PAGESIZE").error==2,"case-sensitive namespace lost");
        Require(registry.NameToOid("").error==2&&registry.NameToOid(std::string(1024,'a')).error==63,"name bound lost");
        Require(registry.Read(std::array<std::int32_t,1>{6}).error==22,"short MIB accepted");
        Require(registry.Read(std::array<std::int32_t,13>{}).error==22,"oversized MIB accepted");
        Require(registry.Read(std::array<std::int32_t,2>{6,999}).error==2,"missing numeric node fabricated");
    }
    for(auto invalid:{0ULL,3ULL,0x100000000ULL}){bool rejected=false;try{DarwinSysctl registry(invalid);}catch(const std::invalid_argument&){rejected=true;}
        Require(rejected,"invalid native geometry accepted");}
    std::cout<<"Native-owned sysctl registry/name2oid/page geometry contract PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
