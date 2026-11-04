#include "darwin_process_identity.hpp"
#include "darwin_file_metadata.hpp"
#include <windows.h>
#include <algorithm>
#include <array>
#include <exception>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace OpenFruit;
namespace {
struct NativeToken {
    HANDLE value=nullptr;
    ~NativeToken(){if(value)CloseHandle(value);}
};
std::vector<unsigned char> NativeTokenInfo(HANDLE token,TOKEN_INFORMATION_CLASS kind){
    DWORD bytes=0;GetTokenInformation(token,kind,nullptr,0,&bytes);
    if(!bytes||GetLastError()!=ERROR_INSUFFICIENT_BUFFER)throw std::runtime_error("Independent token size query failed.");
    std::vector<unsigned char> result(bytes);
    if(!GetTokenInformation(token,kind,result.data(),bytes,&bytes))throw std::runtime_error("Independent token query failed.");
    return result;
}
std::uint32_t NativePrincipal(PSID sid){
    std::uint32_t id=0;
    if(!IsValidSid(sid)||DarwinPrincipalFromSid({static_cast<const unsigned char*>(sid),GetLengthSid(sid)},id))
        throw std::runtime_error("Independent native SID mapping failed.");
    return id;
}
}
int main(){try{
    DarwinProcessCredentials credentials;
    if(CaptureDarwinProcessCredentials(credentials)||credentials.uid<0x40000000U||credentials.gid<0x40000000U
        ||credentials.groups.empty()||credentials.groups.front()!=credentials.gid)
        throw std::runtime_error("Native credentials fabricated root or discarded primary group.");
    NativeToken token;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token.value)){
        if(GetLastError()!=ERROR_NO_TOKEN||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value))
            throw std::runtime_error("Independent effective token query failed.");
    }
    const auto user=NativeTokenInfo(token.value,TokenUser);
    const auto primary=NativeTokenInfo(token.value,TokenPrimaryGroup);
    const auto native_groups=NativeTokenInfo(token.value,TokenGroups);
    const auto uid=NativePrincipal(reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid);
    const auto gid=NativePrincipal(reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(primary.data())->PrimaryGroup);
    if(uid!=credentials.uid||gid!=credentials.gid)
        throw std::runtime_error("Process credential differs from existing stat64 native SID realm.");
    const std::set<std::uint32_t> groups(credentials.groups.begin(),credentials.groups.end());
    if(groups.size()!=credentials.groups.size())throw std::runtime_error("Supplementary group projection duplicated native principal.");
    std::set<std::uint32_t> expected_groups{gid};
    const auto* native=reinterpret_cast<const TOKEN_GROUPS*>(native_groups.data());
    for(DWORD n=0;n<native->GroupCount;++n){
        const auto& group=native->Groups[n];
        if((group.Attributes&SE_GROUP_ENABLED)&&!(group.Attributes&SE_GROUP_USE_FOR_DENY_ONLY))
            expected_groups.insert(NativePrincipal(group.Sid));
    }
    if(groups!=expected_groups)throw std::runtime_error("Credential groups differ from enabled effective Windows SID membership.");
    // A fresh native process is the important negative control: integration
    // tests may have already allocated many guest tasks before checking IDs.
    if(AllocateDarwinProcessId()!=2||AllocateDarwinProcessId()!=3)
        throw std::runtime_error("First ordinary task acquired kernel/init identity.");
    std::array<std::vector<std::uint32_t>,8> ids;
    std::vector<std::thread> workers;
    for(auto& group:ids)workers.emplace_back([&group]{for(unsigned i=0;i<128;++i)group.push_back(AllocateDarwinProcessId());});
    for(auto& worker:workers)worker.join();
    std::set<std::uint32_t> unique;
    for(const auto& group:ids)for(auto id:group)
        if(id<4||id>1027||!unique.insert(id).second)
            throw std::runtime_error("Concurrent native engines acquired invalid/duplicate PID.");
    if(unique.size()!=1024||AllocateDarwinProcessId()!=1028)
        throw std::runtime_error("Guest identity namespace lost an allocation.");

    // Generation is a process-creation counter, not a token-query count or an
    // alias for PID. Tasks preserve these owned snapshots after other tasks die.
    struct TaskLifetime {
        const std::uint32_t pid=AllocateDarwinProcessId();
        const std::uint32_t generation=AllocateDarwinProcessGeneration();
        const DarwinProcessCredentials credentials;
        const DarwinProcessAuditSession session{};
        explicit TaskLifetime(const DarwinProcessCredentials& launch):credentials(launch){}
        DarwinAuditToken Audit() const{return BuildDarwinAuditToken(credentials,pid,generation,session);}
        DarwinSecurityToken Security() const{return BuildDarwinSecurityToken(credentials);}
    };
    const TaskLifetime first(credentials);
    if(first.generation!=1||first.pid!=1029||first.generation==first.pid)
        throw std::runtime_error("Task generation did not begin with an independent nonzero lifetime identity.");
    const auto first_audit=first.Audit();const auto first_security=first.Security();
    static_assert(sizeof(DarwinSecurityToken)==8&&sizeof(DarwinAuditToken)==32);
    if(first_audit[0]!=std::numeric_limits<std::uint32_t>::max()||first_audit[6]!=0)
        throw std::runtime_error("Non-login guest task fabricated an audit login session.");
    if(first_audit[1]!=uid||first_audit[3]!=uid||first_audit[2]!=gid||first_audit[4]!=gid
        ||first_audit[5]!=first.pid||first_audit[7]!=first.generation
        ||first_security[0]!=uid||first_security[1]!=gid)
        throw std::runtime_error("Task token ABI fields differ from native credentials or lifetime identity.");
    std::array<std::vector<DarwinAuditToken>,8> audits;
    std::array<std::exception_ptr,8> worker_errors{};
    workers.clear();
    for(std::size_t slot=0;slot<audits.size();++slot)workers.emplace_back([&,slot]{try{
        for(unsigned n=0;n<128;++n){
            const TaskLifetime task(credentials);
            const auto audit=task.Audit();
            if(task.Audit()!=audit||task.Security()!=BuildDarwinSecurityToken(credentials))
                throw std::runtime_error("A token query changed process-lifetime identity.");
            audits[slot].push_back(audit);
        }
    }catch(...){worker_errors[slot]=std::current_exception();}});
    for(auto& worker:workers)worker.join();
    for(const auto& error:worker_errors)if(error)std::rethrow_exception(error);
    std::set<std::uint32_t> generations,pids;
    std::set<DarwinAuditToken> distinct_tokens;
    for(const auto& list:audits){
        std::uint32_t last_generation=first.generation;
        for(const auto& audit:list){
            if(audit[7]<=last_generation||audit[7]<2||audit[7]>1025
                ||!generations.insert(audit[7]).second||!pids.insert(audit[5]).second
                ||!distinct_tokens.insert(audit).second)
                throw std::runtime_error("Concurrent task creation reused, lost or reordered a lifetime identity.");
            last_generation=audit[7];
            if(audit[0]!=first_audit[0]||audit[1]!=uid||audit[2]!=gid
                ||audit[3]!=uid||audit[4]!=gid||audit[6]!=0)
                throw std::runtime_error("Concurrent task token changed launch credentials or non-login session.");
        }
    }
    if(generations.size()!=1024||AllocateDarwinProcessGeneration()!=1026)
        throw std::runtime_error("Concurrent generation allocator lost an allocation.");
    if(first.Audit()!=first_audit||first.Security()!=first_security)
        throw std::runtime_error("Other task lifetimes modified a live task token.");
    // Builders return independent snapshots. Mutating caller-owned input here
    // is a value-lifetime test, not implementation of guest credential mutation.
    credentials.uid=0;credentials.gid=0;credentials.groups.clear();
    if(first.Audit()!=first_audit||first.Security()!=first_security)
        throw std::runtime_error("Captured task credentials alias a mutable launcher value.");
    DarwinProcessCredentials recaptured;
    if(CaptureDarwinProcessCredentials(recaptured)||recaptured.uid!=uid||recaptured.gid!=gid
        ||std::set<std::uint32_t>(recaptured.groups.begin(),recaptured.groups.end())!=expected_groups)
        throw std::runtime_error("Credential snapshot mutation leaked into the native Windows provider.");
    std::cout<<"Native SID credentials, non-login token ABI, stable task snapshots and concurrent PID/generation allocation PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
