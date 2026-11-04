#include "darwin_file_mapping.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace OpenFruit;
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Fixture {std::filesystem::path path;HANDLE file=INVALID_HANDLE_VALUE;~Fixture(){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(!path.empty())DeleteFileW(path.c_str());}};
int main(){try{
    Fixture fixture;wchar_t root[MAX_PATH]{},name[MAX_PATH]{};
    Require(GetTempPathW(MAX_PATH,root)&&GetTempFileNameW(root,L"ofv",0,name),"fixture creation failed");fixture.path=name;
    std::vector<unsigned char> original(200123);for(std::size_t i=0;i<original.size();++i)original[i]=static_cast<unsigned char>((i*31+i/8192)%251);
    {std::ofstream file(fixture.path,std::ios::binary);file.write(reinterpret_cast<const char*>(original.data()),original.size());Require(bool(file),"fixture write failed");}
    fixture.file=CreateFileW(name,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);Require(fixture.file!=INVALID_HANDLE_VALUE,"lease failed");
    const auto sha=Sha256FileHandle(fixture.file);Require(bool(sha),"source hash failed");int error=0;
    LARGE_INTEGER zero{},before{},after{};Require(SetFilePointerEx(fixture.file,zero,&before,FILE_CURRENT),"position query failed");
    for(auto page: {4096ULL,16384ULL})for(auto offset: {0ULL,65536ULL,65537ULL,199999ULL}){
        const auto length=std::min<std::uint64_t>(123,original.size()-offset);
        auto mapping=DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,offset,length,page,error);
        Require(mapping&&!error&&mapping->Size()%page==0&&mapping->Delta()==offset%page,"page or source-window geometry lost");
        const auto source_offset=offset-offset%page;const auto source_bytes=std::min<std::uint64_t>(mapping->Size(),original.size()-source_offset);
        const auto* bytes=static_cast<const unsigned char*>(mapping->Bytes());
        for(std::uint64_t i=0;i<source_bytes;++i)Require(bytes[i]==original[source_offset+i],"mapped byte differed from actual source including bytes after requested length");
        for(auto i=source_bytes;i<mapping->Size();++i)Require(bytes[i]==0,"final partial EOF page not zero filled");
        auto* writable=static_cast<unsigned char*>(mapping->Bytes());writable[mapping->Delta()]^=0xff;
        Require(*Sha256FileHandle(fixture.file)==*sha,"private write modified original file");
    }
    // Explicit lengths reaching the final page boundary have the same bytes
    // and COW semantics as a shorter request, not an unimplemented EOF pager.
    for(auto page: {4096ULL,16384ULL}){
        const auto end=(original.size()+page-1)&~(page-1);
        const auto offset=original.size()-1;
        auto tail=DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,offset,end-offset,page,error);
        Require(tail&&!error&&tail->Size()==page,"request within final partial EOF page rejected");
        auto* bytes=static_cast<unsigned char*>(tail->Bytes());
        Require(bytes[tail->Delta()]==original.back(),"final actual source byte lost");
        for(auto i=tail->Delta()+1;i<tail->Size();++i)Require(bytes[i]==0,"requested partial EOF tail was not zeroed");
        auto peer=DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,offset,end-offset,page,error);
        Require(peer&&!error,"independent COW view failed");
        bytes[tail->Delta()]^=0xff;bytes[tail->Size()-1]=0x7e;
        const auto* peer_bytes=static_cast<const unsigned char*>(peer->Bytes());
        Require(peer_bytes[peer->Delta()]==original.back()&&peer_bytes[peer->Size()-1]==0,"private source/tail write leaked to independent mapping");
        Require(*Sha256FileHandle(fixture.file)==*sha,"private EOF tail write changed original file");
        Require(!DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,offset,end-offset+1,page,error)&&error==45,"complete beyond-EOF page fabricated");
    }
    // Restore the hash helper's deliberate position change before comparing
    // capture alone; capture must never perform a descriptor read or seek.
    Require(SetFilePointerEx(fixture.file,before,nullptr,FILE_BEGIN),"position restore failed");
    auto retained=DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,0,original.size(),16384,error);
    Require(retained&&!error&&SetFilePointerEx(fixture.file,zero,&after,FILE_CURRENT)&&after.QuadPart==before.QuadPart,"capture consumed descriptor position");
    for(auto invalid: {0ULL,UINT64_MAX})Require(!DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,0,invalid,16384,error)&&error==22,"invalid length accepted");
    Require(!DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,original.size(),1,16384,error)&&error==45,"beyond EOF page fabricated");
    for(auto page: {0ULL,8192ULL,32768ULL})Require(!DarwinPrivateFileMapping::Capture(fixture.file,original.size(),"/fixture/source",*sha,0,1,page,error)&&error==22,"unsupported page size admitted");
    Require(!DarwinPrivateFileMapping::Capture(fixture.file,512ULL*1024*1024,"/fixture/source",*sha,0,256ULL*1024*1024+1,16384,error)&&error==12,"snapshot budget not enforced before source mapping");
    Require(!DarwinPrivateFileMapping::Capture(fixture.file,original.size()+1,"/fixture/source",*sha,0,1,16384,error)&&error==5,"source-size mismatch ignored");
    CloseHandle(fixture.file);fixture.file=INVALID_HANDLE_VALUE;
    auto writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Require(writer==INVALID_HANDLE_VALUE,"closed source descriptor dropped mapping lease");
    Require(static_cast<unsigned char*>(retained->Bytes())[100001]==original[100001],"close invalidated mapped bytes");retained.reset();
    writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Require(writer!=INVALID_HANDLE_VALUE,"mapping destruction retained stale lease");CloseHandle(writer);
    std::cout<<"Private source bytes, offset/window/page/EOF, unchanged source/position and closed-descriptor lease lifetime PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
