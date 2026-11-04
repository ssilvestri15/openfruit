#include "darwin_files.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
using namespace OpenFruit;
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Fixture {std::filesystem::path path;HANDLE file=INVALID_HANDLE_VALUE,read=nullptr,write=nullptr;~Fixture(){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(read)CloseHandle(read);if(write)CloseHandle(write);if(!path.empty())DeleteFileW(path.c_str());}};
int main(){try{
    Fixture fixture;wchar_t root[MAX_PATH]{},name[MAX_PATH]{};
    Require(GetTempPathW(MAX_PATH,root)&&GetTempFileNameW(root,L"ofw",0,name),"temporary sink failed");fixture.path=name;
    fixture.file=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Require(fixture.file!=INVALID_HANDLE_VALUE,"native sink failed");
    DarwinClosure closure;closure.original_directories.insert("/");DarwinFiles files(closure);
    Require(files.WriteCapacity(2,1).error==9&&files.BindOutput(-1,fixture.file).error==22&&files.BindOutput(2,nullptr).error==9,"invalid binding accepted");
    Require(!files.BindOutput(2,fixture.file).error&&files.BindOutput(2,fixture.file).error==22,"native sink binding failed or replaced live descriptor");
    CloseHandle(fixture.file);fixture.file=INVALID_HANDLE_VALUE;
    const std::array<char,8> payload{'o','u','t','\0',char(0xff),'\r','\n','!'};
    const auto written=files.Write(2,payload);Require(!written.error&&written.value==payload.size(),"actual native write count failed");
    Require(!files.Write(2,{}).error&&files.WriteCapacity(2,UINT64_MAX).error==22&&files.WriteCapacity(999,UINT64_MAX).error==22&&files.WriteCapacity(2,std::uint64_t(INT32_MAX)+1).error==22&&files.WriteCapacity(2,32ULL*1024*1024).value==16ULL*1024*1024,"zero/overflow/bounded write failed");
    std::array<char,1> byte{'Q'};DarwinFileMetadata metadata;std::string path;int error=0;
    Require(files.ReadCapacity(2,1).error==9&&files.Read(2,byte).error==9&&byte[0]=='Q'&&files.Seek(2,0,0).error==29&&files.Path(2,path).error==45&&files.Fstat(2,metadata).error==45&&!metadata.inode&&!files.PrivateMapping(2,0,1,16384,error)&&error==9,"output masqueraded as regular source/readable/seekable metadata");
    Require(files.Fcntl(2,3,0).value==1&&files.Fcntl(2,1,0).value==0,"output status/descriptor flags wrong");
    Require(!files.Close(2).error&&files.Write(2,payload).error==9&&files.Close(2).error==9,"closed output stayed writable");
    std::ifstream source(fixture.path,std::ios::binary);std::string actual((std::istreambuf_iterator<char>(source)),{});Require(actual==std::string(payload.data(),payload.size()),"binary output bytes changed on native disk");
    const auto report=files.ToJson();const auto& first=report.Get("output_descriptors")->ArrayItems()[0];
    Require(first.GetString("prefix_hex")=="6f757400ff0d0a21"&&first.Get("closed")->Bool()&&first.Get("bytes")->Serialize()=="8"&&report.Get("bytes_written")->Serialize()=="8","actual binary sink diagnostics changed");
    Require(CreatePipe(&fixture.read,&fixture.write,nullptr,0),"native pipe failed");Require(!files.BindOutput(7,fixture.write).error,"pipe binding failed");
    const auto output_alias=files.Dup(7);Require(!output_alias.error&&output_alias.value==0,"output alias allocation failed");
    Require(!files.Close(7).error&&!files.ToJson().Get("output_descriptors")->ArrayItems()[1].Get("closed")->Bool(),"closing one alias marked shared output closed");
    Require(files.Write(output_alias.value,payload).value==payload.size(),"output alias did not retain native endpoint");
    std::array<char,8> consumed{};DWORD transferred=0;Require(ReadFile(fixture.read,consumed.data(),DWORD(consumed.size()),&transferred,nullptr)&&transferred==payload.size()&&consumed==payload,"alias changed real native pipe bytes");
    Require(!files.Fcntl(output_alias.value,2,1).error&&!files.Dup2(output_alias.value,1).error&&files.Fcntl(1,1,0).value==0&&files.Fcntl(output_alias.value,1,0).value==1,"output alias FD flags leaked");
    CloseHandle(fixture.read);fixture.read=nullptr;Require(files.Write(output_alias.value,payload).error==32,"native broken pipe acknowledged as successful write");
    Require(!files.Close(output_alias.value).error&&!files.ToJson().Get("output_descriptors")->ArrayItems()[1].Get("closed")->Bool()
        &&!files.Close(1).error&&files.ToJson().Get("output_descriptors")->ArrayItems()[1].Get("closed")->Bool(),"shared output last-close state is inaccurate");
    CloseHandle(fixture.write);fixture.write=nullptr;
    Require(CreatePipe(&fixture.read,&fixture.write,nullptr,0),"native input pipe failed");
    Require(files.BindInput(-1,fixture.read).error==22&&files.BindInput(0,nullptr).error==9&&files.BindInput(6,fixture.write).error!=0,"invalid input endpoint admitted");
    Require(!files.BindInput(0,fixture.read).error&&files.BindInput(0,fixture.read).error==22,"native input binding failed/replaced live fd");
    CloseHandle(fixture.read);fixture.read=nullptr;
    const auto input_alias=files.Dup(0);Require(!input_alias.error&&input_alias.value==1,"input alias allocation failed");
    byte[0]='Q';const auto empty=files.Read(0,byte);
    Require(empty.pending&&!empty.error&&!empty.value&&byte[0]=='Q'&&files.ReadCapacity(1,1).pending,"empty live pipe fabricated EOF/errno or changed buffer");
    Require(!files.Read(0,{}).pending&&!files.Read(0,{}).error&&files.ReadCapacity(0,UINT64_MAX).error==22,"input zero/count semantics changed");
    Require(files.ReadCapacity(0,1,0).error==29&&files.Read(0,byte,0).error==29&&files.Seek(0,0,0).error==29&&files.Write(0,payload).error==9,"pipe became seekable/writable");
    Require(files.Path(0,path).error==45&&files.Fstat(0,metadata).error==45&&!files.PrivateMapping(0,0,1,16384,error)&&error==9,"input masqueraded as original file metadata/mapping");
    Require(WriteFile(fixture.write,payload.data(),DWORD(payload.size()),&transferred,nullptr)&&transferred==payload.size(),"native input producer failed");
    std::array<char,3> head{};const auto read_head=files.Read(1,head);
    Require(!read_head.pending&&!read_head.error&&read_head.value==head.size()&&std::equal(head.begin(),head.end(),payload.begin()),"input alias lost native leading bytes");
    Require(files.ReadCapacity(0,100).value==5&&!files.Close(0).error,"input aliases did not share native pipe stream");
    std::array<char,5> tail{};const auto read_tail=files.Read(1,tail);
    Require(!read_tail.pending&&!read_tail.error&&read_tail.value==tail.size()&&std::equal(tail.begin(),tail.end(),payload.begin()+3),"closing input original lost endpoint/remaining bytes");
    Require(files.ReadCapacity(1,1).pending,"drained live input fabricated EOF");
    const char final_byte='Z';Require(WriteFile(fixture.write,&final_byte,1,&transferred,nullptr)&&transferred==1,"final input producer failed");
    CloseHandle(fixture.write);fixture.write=nullptr;
    const auto buffered=files.Read(1,byte);Require(!buffered.pending&&!buffered.error&&buffered.value==1&&byte[0]=='Z',"writer close discarded buffered native input");
    byte[0]='Q';const auto eof=files.Read(1,byte);
    Require(!eof.pending&&!eof.error&&!eof.value&&byte[0]=='Q'&&!files.Close(1).error&&files.Read(1,byte).error==9,"real writer close/last reader close contract failed");
    Require(report.Get("descriptors")->ArrayItems().empty(),"output fabricated an original-file record");
    std::cout<<"Real native disk/pipe binary output, counts/errors, duplicate/close lifetime and descriptor type contract PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
