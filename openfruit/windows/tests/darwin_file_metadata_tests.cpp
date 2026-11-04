#include "darwin_file_metadata.hpp"
#include <windows.h>
#include <aclapi.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace OpenFruit;
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Fixture {
    std::filesystem::path path;HANDLE handle=INVALID_HANDLE_VALUE;PSECURITY_DESCRIPTOR security=nullptr;PACL original=nullptr;
    ~Fixture(){if(handle!=INVALID_HANDLE_VALUE){if(security)SetSecurityInfo(handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION, nullptr,nullptr,original,nullptr);CloseHandle(handle);}if(security)LocalFree(security);if(!path.empty())DeleteFileW(path.c_str());}
};
std::uint64_t Read(const std::array<unsigned char,144>& bytes,unsigned offset,unsigned count){std::uint64_t result=0;for(unsigned i=0;i<count;++i)result|=std::uint64_t(bytes[offset+i])<<(8*i);return result;}
int main(){try{
    Fixture f;wchar_t directory[MAX_PATH]{},name[MAX_PATH]{};
    Require(GetTempPathW(MAX_PATH,directory)&&GetTempFileNameW(directory,L"ofm",0,name),"temporary fixture creation failed");f.path=name;
    f.handle=CreateFileW(name,GENERIC_READ|GENERIC_WRITE|READ_CONTROL|WRITE_DAC,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    Require(f.handle!=INVALID_HANDLE_VALUE,"fixture open failed");
    const std::vector<char> contents(12345,'x');DWORD written=0;Require(WriteFile(f.handle,contents.data(),DWORD(contents.size()),&written,nullptr)&&written==contents.size(),"fixture write failed");
    PSID owner=nullptr,group=nullptr;
    Require(GetSecurityInfo(f.handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,&group,&f.original,nullptr,&f.security)==ERROR_SUCCESS,"fixture security query failed");
    std::array<unsigned char,SECURITY_MAX_SID_SIZE> world{};DWORD length=DWORD(world.size());Require(CreateWellKnownSid(WinWorldSid,nullptr,world.data(),&length),"world SID failed");
    auto acl=[&](bool deny_owner_execute){
        std::array<EXPLICIT_ACCESS_W,4> entries{};unsigned count=0;
        auto add=[&](PSID sid,DWORD rights,ACCESS_MODE mode){auto& entry=entries[count++];entry.grfAccessPermissions=rights;entry.grfAccessMode=mode;entry.Trustee.TrusteeForm=TRUSTEE_IS_SID;entry.Trustee.ptstrName=static_cast<LPWSTR>(sid);};
        if(deny_owner_execute)add(owner,FILE_EXECUTE,DENY_ACCESS);
        add(owner,FILE_READ_DATA|FILE_EXECUTE|FILE_WRITE_DATA|READ_CONTROL|WRITE_DAC,GRANT_ACCESS);
        add(group,FILE_READ_DATA,GRANT_ACCESS);add(world.data(),FILE_READ_DATA,GRANT_ACCESS);
        PACL value=nullptr;Require(SetEntriesInAclW(count,entries.data(),nullptr,&value)==ERROR_SUCCESS,"controlled ACL build failed");
        const auto error=SetSecurityInfo(f.handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,value,nullptr);LocalFree(value);Require(!error,"controlled ACL installation failed");
    };
    acl(false);DarwinFileMetadata m;Require(!QueryDarwinReadonlyFileMetadata(f.handle,m),"metadata query failed");
    BY_HANDLE_FILE_INFORMATION identity{};FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{};FILE_STORAGE_INFO storage{};
    Require(GetFileInformationByHandle(f.handle,&identity)&&GetFileInformationByHandleEx(f.handle,FileBasicInfo,&basic,sizeof(basic))&&GetFileInformationByHandleEx(f.handle,FileStandardInfo,&standard,sizeof(standard))&&GetFileInformationByHandleEx(f.handle,FileStorageInfo,&storage,sizeof(storage)),"independent native query failed");
    Require(m.device==identity.dwVolumeSerialNumber&&m.inode==((std::uint64_t(identity.nFileIndexHigh)<<32)|identity.nFileIndexLow),"held source identity changed");
    Require(m.size==12345&&m.size==standard.EndOfFile.QuadPart&&m.blocks==(standard.AllocationSize.QuadPart+511)/512&&m.links==standard.NumberOfLinks&&m.io_blocksize==storage.PhysicalBytesPerSectorForPerformance,"native size/allocation/geometry changed");
    std::array<LONGLONG,4> ticks{basic.LastAccessTime.QuadPart,basic.LastWriteTime.QuadPart,basic.ChangeTime.QuadPart,basic.CreationTime.QuadPart};
    for(unsigned i=0;i<4;++i)Require((m.times[i].seconds+11644473600LL)*10000000+m.times[i].nanoseconds/100==ticks[i],"native timestamp precision lost");
    Require(m.mode==(0100000|0500|(EqualSid(owner,group)?050:040)|04),"SID ACL rights not projected or writable mount fabricated");
    std::uint32_t uid=0,gid=0;Require(!DarwinPrincipalFromSid({static_cast<const unsigned char*>(owner),GetLengthSid(owner)},uid)&&!DarwinPrincipalFromSid({static_cast<const unsigned char*>(group),GetLengthSid(group)},gid)&&m.uid==uid&&m.gid==gid&&uid>=0x40000000&&gid>=0x40000000,"owner/group identity lost or guest root invented");
    const auto bytes=m.EncodeStat64();Require(Read(bytes,0,4)==m.device&&Read(bytes,4,2)==m.mode&&Read(bytes,6,2)==m.links&&Read(bytes,8,8)==m.inode&&Read(bytes,16,4)==uid&&Read(bytes,20,4)==gid&&Read(bytes,96,8)==12345&&Read(bytes,104,8)==std::uint64_t(m.blocks)&&Read(bytes,112,4)==m.io_blocksize,"Darwin stat64 field layout changed");
    for(unsigned i=0;i<4;++i)Require(Read(bytes,32+i*16,8)==std::uint64_t(m.times[i].seconds)&&Read(bytes,40+i*16,8)==m.times[i].nanoseconds,"Darwin timespec layout changed");
    for(unsigned i: {24U,28U,120U,124U,128U,132U,136U,140U})Require(!Read(bytes,i,4),"unsupported device/generation/spare data fabricated");
    LARGE_INTEGER zero{},before{},after{};Require(SetFilePointerEx(f.handle,zero,&before,FILE_CURRENT),"position query failed");
    acl(true);Require(!QueryDarwinReadonlyFileMetadata(f.handle,m)&&m.mode==(0100000|0444),"explicit ACL deny ignored");
    Require(SetFilePointerEx(f.handle,zero,&after,FILE_CURRENT)&&before.QuadPart==after.QuadPart,"metadata altered native position");
    auto invalid=std::array<unsigned char,8>{1,15};Require(DarwinPrincipalFromSid(invalid,uid)==22&&uid==0,"truncated SID accepted");
    const auto epoch=DarwinTimeFromWindowsTicks(116444736000000000LL),negative=DarwinTimeFromWindowsTicks(116444735999999999LL);
    Require(!epoch.seconds&&!epoch.nanoseconds&&negative.seconds==-1&&negative.nanoseconds==999999900,"pre-epoch timestamp normalization failed");
    Require(QueryDarwinReadonlyFileMetadata(INVALID_HANDLE_VALUE,m)==5&&!m.inode&&!m.size,"invalid handle fabricated metadata");
    std::cout<<"Held native identity/time/allocation, SID ownership, real ACL grant/deny, read-only policy and Darwin stat64 layout PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
