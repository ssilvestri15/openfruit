#include "darwin_file_metadata.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <aclapi.h>
#include <authz.h>
#include <charconv>
#include <map>
#include <mutex>
#include <limits>
namespace OpenFruit {
namespace {
struct Security {PSECURITY_DESCRIPTOR value=nullptr;~Security(){if(value)LocalFree(value);}};
struct Manager {AUTHZ_RESOURCE_MANAGER_HANDLE value=nullptr;~Manager(){if(value)AuthzFreeResourceManager(value);}};
struct Context {AUTHZ_CLIENT_CONTEXT_HANDLE value=nullptr;~Context(){if(value)AuthzFreeContext(value);}};
int Error(DWORD value){return value==ERROR_ACCESS_DENIED?13:value==ERROR_NOT_SUPPORTED?45:5;}
int Rights(AUTHZ_RESOURCE_MANAGER_HANDLE manager,PSECURITY_DESCRIPTOR descriptor,PSID sid,DWORD& rights){
    Context context;LUID id{};
    // SID-only ACL projection avoids invented Windows group memberships or
    // domain/logon tokens. Actual native opens still enforce the full host ACL.
    if(!AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS,sid,manager,nullptr,id,nullptr,&context.value))return Error(GetLastError());
    AUTHZ_ACCESS_REQUEST request{};request.DesiredAccess=MAXIMUM_ALLOWED;
    DWORD error=0;AUTHZ_ACCESS_REPLY reply{};reply.ResultListLength=1;reply.GrantedAccessMask=&rights;reply.Error=&error;
    if(!AuthzAccessCheck(0,context.value,&request,nullptr,descriptor,nullptr,0,&reply,nullptr))return Error(GetLastError());
    if(error==ERROR_ACCESS_DENIED){rights=0;return 0;}return error?Error(error):0;
}
unsigned Mode(DWORD rights){return ((rights&FILE_READ_DATA)?4:0)|((rights&FILE_EXECUTE)?1:0);}
}
DarwinFileTime DarwinTimeFromWindowsTicks(std::int64_t ticks) noexcept {
    auto seconds=ticks/10000000-11644473600LL;auto remainder=ticks%10000000;
    if(remainder<0){--seconds;remainder+=10000000;}
    return {seconds,static_cast<std::uint32_t>(remainder*100)};
}
int DarwinPrincipalFromSid(std::span<const unsigned char> sid,std::uint32_t& id){
    id=0;
    // Check bounds before Windows SID validation can inspect its subauthorities.
    if(sid.size()<8||sid[0]!=SID_REVISION||sid[1]>SID_MAX_SUB_AUTHORITIES||sid.size()!=8+std::size_t(sid[1])*4)return 22;
    if(!IsValidSid(const_cast<unsigned char*>(sid.data())))return 22;
    const std::string key(reinterpret_cast<const char*>(sid.data()),sid.size());
    auto hash=Sha256(std::string("OPENFRUIT-native-principal-v1:")+key);if(!hash)return 5;
    std::uint32_t digest=0;const auto parsed=std::from_chars(hash->data(),hash->data()+8,digest,16);if(parsed.ec!=std::errc{})return 5;
    const auto candidate=0x40000000U|(digest&0x3fffffffU);
    static std::mutex mutex;static std::map<std::uint32_t,std::string> assigned;
    std::lock_guard lock(mutex);const auto found=assigned.find(candidate);
    if(found!=assigned.end()&&found->second!=key)return 84;
    assigned.emplace(candidate,key);id=candidate;return 0;
}
int QueryDarwinReadonlyFileMetadata(void* handle,DarwinFileMetadata& result){
    result={};DarwinFileMetadata value;
    BY_HANDLE_FILE_INFORMATION identity{};FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{};FILE_STORAGE_INFO storage{};
    if(!GetFileInformationByHandle(handle,&identity)||!GetFileInformationByHandleEx(handle,FileBasicInfo,&basic,sizeof(basic))
        ||!GetFileInformationByHandleEx(handle,FileStandardInfo,&standard,sizeof(standard))
        ||!GetFileInformationByHandleEx(handle,FileStorageInfo,&storage,sizeof(storage)))return Error(GetLastError());
    if(standard.Directory||identity.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)return 45;
    if(standard.DeletePending||standard.EndOfFile.QuadPart<0||standard.AllocationSize.QuadPart<0)return 5;
    if(standard.NumberOfLinks>UINT16_MAX)return 84;
    if(!identity.dwVolumeSerialNumber||!storage.PhysicalBytesPerSectorForPerformance
        ||storage.PhysicalBytesPerSectorForPerformance>INT32_MAX)return 5;
    value.device=identity.dwVolumeSerialNumber;value.inode=(std::uint64_t(identity.nFileIndexHigh)<<32)|identity.nFileIndexLow;
    if(!value.inode)return 5;
    value.links=static_cast<std::uint16_t>(standard.NumberOfLinks);value.size=standard.EndOfFile.QuadPart;
    value.blocks=standard.AllocationSize.QuadPart/512+(standard.AllocationSize.QuadPart%512!=0);
    value.io_blocksize=storage.PhysicalBytesPerSectorForPerformance;
    value.times={DarwinTimeFromWindowsTicks(basic.LastAccessTime.QuadPart),DarwinTimeFromWindowsTicks(basic.LastWriteTime.QuadPart),
        DarwinTimeFromWindowsTicks(basic.ChangeTime.QuadPart),DarwinTimeFromWindowsTicks(basic.CreationTime.QuadPart)};
    // Hidden is an actual source attribute; no immutable flag is inferred from
    // a read-only mount, and unsupported file generations remain unexposed.
    value.flags=(identity.dwFileAttributes&FILE_ATTRIBUTE_HIDDEN)?0x8000U:0;
    Security security;PSID owner=nullptr,group=nullptr;PACL dacl=nullptr;
    const auto query=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,&group,&dacl,nullptr,&security.value);if(query)return Error(query);
    if(!owner||!group)return 5;
    const auto principal=[&](PSID sid,std::uint32_t& output){const auto length=GetLengthSid(sid);
        return DarwinPrincipalFromSid({static_cast<const unsigned char*>(sid),length},output);};
    if(const auto error=principal(owner,value.uid))return error;if(const auto error=principal(group,value.gid))return error;
    Manager manager;if(!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT,nullptr,nullptr,nullptr,nullptr,&manager.value))return Error(GetLastError());
    std::array<unsigned char,SECURITY_MAX_SID_SIZE> world{};DWORD length=static_cast<DWORD>(world.size());
    if(!CreateWellKnownSid(WinWorldSid,nullptr,world.data(),&length))return Error(GetLastError());
    DWORD owner_rights=0,group_rights=0,world_rights=0;
    if(const auto error=Rights(manager.value,security.value,owner,owner_rights))return error;
    if(const auto error=Rights(manager.value,security.value,group,group_rights))return error;
    if(const auto error=Rights(manager.value,security.value,world.data(),world_rights))return error;
    value.mode=static_cast<std::uint16_t>(0100000|(Mode(owner_rights)<<6)|(Mode(group_rights)<<3)|Mode(world_rights));
    result=value;return 0;
}
std::array<unsigned char,144> DarwinFileMetadata::EncodeStat64() const {
    std::array<unsigned char,144> bytes{};const auto put=[&](std::size_t offset,std::uint64_t value,unsigned count){
        for(unsigned i=0;i<count;++i)bytes[offset+i]=static_cast<unsigned char>(value>>(8*i));};
    put(0,device,4);put(4,mode,2);put(6,links,2);put(8,inode,8);put(16,uid,4);put(20,gid,4);
    for(unsigned i=0;i<times.size();++i){put(32+i*16,static_cast<std::uint64_t>(times[i].seconds),8);put(40+i*16,times[i].nanoseconds,8);}
    put(96,static_cast<std::uint64_t>(size),8);put(104,static_cast<std::uint64_t>(blocks),8);put(112,io_blocksize,4);put(116,flags,4);
    return bytes;
}
JsonValue DarwinFileMetadata::ToJson() const {
    auto out=JsonValue::ObjectValue();
    for(auto [key,value]:std::initializer_list<std::pair<const char*,std::uint64_t>>{{"device",device},{"inode",inode},{"uid",uid},{"gid",gid},{"mode",mode},{"links",links},{"io_blocksize",io_blocksize},{"flags",flags}})
        out.Set(key,JsonValue::Number(std::to_string(value)));
    out.Set("size",JsonValue::Number(std::to_string(size)));out.Set("blocks",JsonValue::Number(std::to_string(blocks)));
    auto dates=JsonValue::ArrayValue();for(auto time:times){auto item=JsonValue::ObjectValue();item.Set("seconds",JsonValue::Number(std::to_string(time.seconds)));
        item.Set("nanoseconds",JsonValue::Number(std::to_string(time.nanoseconds)));dates.ArrayItems().push_back(std::move(item));}
    out.Set("times",std::move(dates));out.Set("source",JsonValue::String("held-Windows-file-information-and-SID-security-descriptor"));
    out.Set("mode_policy",JsonValue::String("readonly-SID-only-ACL-projection-host-ACL-enforced"));return out;
}
}
