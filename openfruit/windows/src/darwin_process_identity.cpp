#include "darwin_process_identity.hpp"
#include "darwin_file_metadata.hpp"
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <limits>
#include <stdexcept>

namespace OpenFruit {
int CaptureDarwinProcessCredentials(DarwinProcessCredentials& output){
    output={};DarwinProcessCredentials value;
    struct Token {HANDLE value=nullptr;~Token(){if(value)CloseHandle(value);}} token;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token.value)){
        if(GetLastError()!=ERROR_NO_TOKEN||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value))return 5;
    }
    const auto info=[&](TOKEN_INFORMATION_CLASS kind,std::vector<unsigned char>& bytes){
        DWORD size=0;GetTokenInformation(token.value,kind,nullptr,0,&size);
        if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||!size||size>1024*1024)return false;
        bytes.resize(size);return GetTokenInformation(token.value,kind,bytes.data(),size,&size)!=FALSE;
    };
    const auto principal=[](PSID sid,std::uint32_t& id){
        if(!sid||!IsValidSid(sid))return 22;
        return DarwinPrincipalFromSid({static_cast<const unsigned char*>(sid),GetLengthSid(sid)},id);
    };
    std::vector<unsigned char> bytes;int error=0;
    if(!info(TokenUser,bytes))return 5;
    if((error=principal(reinterpret_cast<const TOKEN_USER*>(bytes.data())->User.Sid,value.uid)))return error;
    if(!info(TokenPrimaryGroup,bytes))return 5;
    if((error=principal(reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(bytes.data())->PrimaryGroup,value.gid)))return error;
    value.groups.push_back(value.gid);
    if(!info(TokenGroups,bytes))return 5;
    const auto* native=reinterpret_cast<const TOKEN_GROUPS*>(bytes.data());
    for(DWORD n=0;n<native->GroupCount;++n){
        const auto& group=native->Groups[n];
        if(!(group.Attributes&SE_GROUP_ENABLED)||(group.Attributes&SE_GROUP_USE_FOR_DENY_ONLY))continue;
        std::uint32_t id=0;if((error=principal(group.Sid,id)))return error;
        if(std::find(value.groups.begin(),value.groups.end(),id)==value.groups.end())value.groups.push_back(id);
    }
    output=std::move(value);return 0;
}
std::uint32_t AllocateDarwinProcessId(){
    static std::atomic<std::uint32_t> next{2};
    auto id=next.load(std::memory_order_relaxed);
    do {
        if(id<2||id>=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw std::runtime_error("Guest process identity namespace exhausted.");
    }while(!next.compare_exchange_weak(id,id+1,std::memory_order_relaxed));
    return id;
}
std::uint32_t AllocateDarwinProcessGeneration(){
    static std::atomic<std::uint32_t> next{1};
    auto generation=next.load(std::memory_order_relaxed);
    do {
        if(!generation)throw std::runtime_error("Guest process generation namespace exhausted.");
        // Zero is a permanent exhausted sentinel, never an allocated identity.
        // Explicit handling also avoids recycling 1 after uint32_t wraparound.
        const auto successor=generation==std::numeric_limits<std::uint32_t>::max()?0:generation+1;
        if(next.compare_exchange_weak(generation,successor,std::memory_order_relaxed))return generation;
    }while(true);
}
DarwinSecurityToken BuildDarwinSecurityToken(const DarwinProcessCredentials& credentials) noexcept{
    return {credentials.uid,credentials.gid};
}
DarwinAuditToken BuildDarwinAuditToken(const DarwinProcessCredentials& credentials,
    std::uint32_t pid,std::uint32_t generation,const DarwinProcessAuditSession& session) noexcept{
    return {session.auid,credentials.uid,credentials.gid,credentials.uid,
        credentials.gid,pid,session.asid,generation};
}
}
