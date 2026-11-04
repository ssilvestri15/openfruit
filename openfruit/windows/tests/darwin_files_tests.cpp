#include "darwin_files.hpp"
#include <windows.h>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Fixture {std::filesystem::path path;~Fixture(){if(!path.empty())DeleteFileW(path.c_str());}};
struct NativePipe {
    HANDLE input=nullptr,output=nullptr;
    NativePipe(){Require(CreatePipe(&input,&output,nullptr,0)!=FALSE,"native read lease pipe creation failed");}
    ~NativePipe(){if(input)CloseHandle(input);if(output)CloseHandle(output);}
};
}
int main(){try{
    Fixture fixture;wchar_t directory[MAX_PATH]{},name[MAX_PATH]{};
    Require(GetTempPathW(MAX_PATH,directory)&&GetTempFileNameW(directory,L"ofv",0,name),"native fixture creation failed");fixture.path=name;
    const std::string original="original-owned-source";
    {std::ofstream stream(fixture.path,std::ios::binary);stream.write(original.data(),original.size());Require(bool(stream),"fixture producer failed");}
    DarwinClosure closure;closure.original_directories.insert("/");
    closure.original_files["/source"]=std::filesystem::canonical(fixture.path);closure.original_real_paths["/source"]="/source";
    DarwinFiles files(closure);
    Require(!files.Access("/source",0).error&&!files.Access("/source",4).error,"bounded native read/existence access failed");
    Require(files.Access("/source",1).error==45&&files.Access("/source",5).error==45&&files.Access("/",1).error==45,"read admission fabricated execute/search authority");
    Require(files.Access("/source",2).error==30&&files.Access("/source",7).error==30,"immutable mount granted write access");
    Require(files.Access("/missing",1).error==2&&files.Access("/missing",2).error==2&&files.Access("/source",8).error==22,"access lookup/mode validation changed");
    Require(files.ToJson().Get("opens")->Int()==0&&files.ToJson().Get("descriptors")->ArrayItems().empty(),"access created persistent descriptors");
    const auto opened=files.Open("/source",0x01000000);Require(!opened.error&&opened.value==0,"original source did not use lowest free fd");const auto fd=static_cast<std::int32_t>(opened.value);
    const auto duplicate=files.Dup(fd);Require(!duplicate.error&&duplicate.value==1,"dup did not choose lowest free fd");const auto alias=static_cast<std::int32_t>(duplicate.value);
    Require(files.Fcntl(fd,1,0).value==1&&files.Fcntl(alias,1,0).value==0&&files.Fcntl(alias,3,0).value==files.Fcntl(fd,3,0).value,"dup inherited descriptor flags or lost shared access status");
    Require(!files.Fcntl(alias,2,1).error&&files.Fcntl(fd,1,0).value==1&&!files.Fcntl(fd,2,0).error&&files.Fcntl(alias,1,0).value==1,"FD_CLOEXEC is not descriptor-local");
    Require(!files.Dup2(alias,alias).error&&files.Fcntl(alias,1,0).value==1&&files.Dup2(999,999).error==9&&files.Dup2(fd,-1).error==9&&files.Dup2(fd,4096).error==9,"dup2 same-fd/bounds validation lost");
    const auto second=files.Open("/source",0);Require(!second.error&&second.value==2,"independent open descriptor failed");
    Require(!files.Seek(second.value,9,0).error&&!files.Dup2(fd,second.value).error&&files.Fcntl(second.value,1,0).value==0&&files.Seek(second.value,0,1).value==0,"dup2 failed atomic replacement/shared cursor");
    constexpr std::uint64_t oversized=std::uint64_t(INT32_MAX)+1;
    Require(files.ReadCapacity(fd,oversized).error==22&&files.ReadCapacity(-1,oversized).error==22&&files.ReadCapacity(-1,UINT64_MAX).error==22,"XNU count validation/errno precedence missing");
    const auto folder=files.Open("/",0x100000);Require(!folder.error&&files.ReadCapacity(folder.value,oversized).error==22&&files.ReadCapacity(folder.value,1).error==21,"read count/directory precedence changed");
    Require(files.ReadCapacity(fd,INT32_MAX).value==original.size()&&!files.ReadCapacity(fd,INT32_MAX).error,"admitted boundary count was rejected");
    Require(files.ReadCapacity(fd,1,UINT64_MAX).error==22&&files.ReadCapacity(fd,1,original.size()).value==0,"position range/EOF contract changed");
    std::array<char,4> bytes{};
    Require(!files.Seek(fd,2,0).error&&files.Read(fd,bytes,5).value==bytes.size()&&std::string(bytes.data(),bytes.size())==original.substr(5,4)&&files.Seek(fd,0,1).value==2,"positioned read lost bytes or altered cursor");
    Require(files.Read(fd,bytes).value==bytes.size()&&std::string(bytes.data(),bytes.size())==original.substr(2,4)&&files.Seek(fd,0,1).value==6,"sequential read failed source/cursor consumption");
    Require(files.Seek(alias,0,1).value==6&&files.Seek(second.value,0,1).value==6,"aliased descriptors did not observe shared open-file offset");
    bytes.fill('Q');Require(files.Read(fd,bytes,UINT64_MAX).error==22&&bytes==std::array<char,4>{'Q','Q','Q','Q'}&&files.Seek(fd,0,1).value==6,"failed read mutated destination or cursor");
    const auto reads=files.ToJson().Get("reads")->Int();Require(!files.ReadCapacity(fd,oversized).value&&files.ToJson().Get("reads")->Int()==reads,"rejected preflight performed IO");
    auto writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Require(writer==INVALID_HANDLE_VALUE,"original descriptor did not hold immutable source lease");
    Require(!files.Close(fd).error&&files.ReadCapacity(fd,1).error==9&&files.Read(fd,bytes).error==9,"closed source remained readable");
    Require(files.Read(alias,bytes).value==bytes.size()&&std::string(bytes.data(),bytes.size())==original.substr(6,4)&&files.Seek(second.value,0,1).value==10,"closing original discarded shared alias/cursor");
    writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Require(writer==INVALID_HANDLE_VALUE,"alias did not retain original immutable source lease");
    const auto reused=files.Open("/source",0);Require(!reused.error&&reused.value==0&&!files.Close(reused.value).error,"open did not reuse lowest free standard fd");
    Require(!files.Close(alias).error&&!files.Close(second.value).error,"source alias close failed");
    writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Require(writer!=INVALID_HANDLE_VALUE,"source descriptor leaked immutable lease");CloseHandle(writer);
    {
        DarwinFiles bounded(closure);const auto first=bounded.Open("/source",0);Require(!first.error&&first.value==0,"bounded source admission failed");
        for(int target=1;target<4096;++target){const auto copy=bounded.Dup(0);Require(!copy.error&&copy.value==std::uint64_t(target),"descriptor limit allocation skipped a free slot");}
        Require(bounded.Dup(0).error==24&&bounded.Dup2(0,4095).value==4095&&!bounded.Dup2(0,4095).error,"descriptor limit rejected valid replacement or missed EMFILE");
        Require(bounded.Dup2(-1,4095).error==9&&bounded.Contains(4095)&&bounded.ReadCapacity(4095,1).value==1,"failed dup2 destroyed target");
        Require(!bounded.Close(4).error&&bounded.Dup(0).value==4,"dup failed to reuse lowest available descriptor");
    }
    {
        DarwinFiles limited(closure);
        Require(limited.Open("/source",0).value==0&&!limited.Dup2(0,100).error,"high descriptor fixture failed");
        limited.SetMaxDescriptors(1);
        Require(limited.MaxDescriptors()==1&&limited.Contains(100)&&limited.ReadCapacity(100,1).value==1,"lowering NOFILE revoked existing high descriptor");
        Require(limited.Dup(100).error==24&&limited.Dup(-1).error==9,"full table lost dup source validation precedence");
        Require(limited.Open("/missing",0).error==24&&limited.Open("/source",3).error==22,"open access-mode/allocation/lookup precedence changed");
        Require(limited.Dup2(100,100).error==9&&limited.Dup2(0,1).error==9&&limited.Contains(100),"dup2 admitted target outside lowered limit");
        Require(!limited.Close(0).error,"low descriptor close failed");
        const auto copied=limited.Dup(100);
        Require(!copied.error&&copied.value==0,"high live descriptor population blocked free low dup slot");
        Require(!limited.Seek(100,2,0).error&&limited.Seek(0,0,1).value==2,"lowered-limit alias lost shared cursor");
        Require(!limited.Close(0).error&&!limited.Dup2(100,0).error,"high live descriptor population blocked low dup2 target");
        Require(!limited.Close(0).error,"low replacement close failed");
        const auto reopened=limited.Open("/source",0);
        Require(!reopened.error&&reopened.value==0,"high live descriptor population blocked free low open slot");
        limited.SetMaxDescriptors(0);
        Require(limited.Dup(100).error==24&&limited.Open("/source",0).error==24&&limited.Dup2(100,0).error==9,"zero NOFILE admitted new descriptor");
        Require(limited.ReadCapacity(100,1).value==1&&limited.ReadCapacity(0,1).value==1&&!limited.Close(0).error,"zero NOFILE broke existing descriptors");
        limited.SetMaxDescriptors(UINT64_MAX);
        Require(limited.MaxDescriptors()==4096&&limited.Dup2(100,4096).error==9,"NOFILE update exceeded native capacity");
        Require(limited.Open("/missing",0).error==2&&limited.Open("/source",3).error==22&&limited.Dup(-1).error==9,"available capacity lost original failure semantics");
    }
    {
        NativePipe pipe;DarwinFiles limited(closure);
        Require(!limited.Open("/source",0).error&&!limited.Dup2(0,100).error&&!limited.Close(0).error,"native binding limit fixture failed");
        limited.SetMaxDescriptors(1);
        Require(!limited.BindInput(0,pipe.input).error&&limited.ReadCapacity(0,1).pending,"high fd population blocked low input binding");
        Require(!limited.Dup2(100,0).error&&!limited.Close(0).error&&!limited.BindOutput(0,pipe.output).error,"high fd population blocked low output binding");
        const char byte='L';Require(limited.Write(0,std::span<const char>(&byte,1)).value==1,"bounded output binding lost native IO");
        DWORD read=0;char received=0;Require(ReadFile(pipe.input,&received,1,&read,nullptr)&&read==1&&received==byte,"bounded output did not reach original pipe");
    }
    {
        DarwinFiles retained(closure),other(closure);DarwinFiles::ReadLease lease;
        const auto source=retained.Open("/source",0);
        Require(!source.error&&!retained.Seek(source.value,2,0).error&&!retained.AcquireRead(source.value,4,{},lease).error,"source read lease admission failed");
        auto copied=lease;
        Require(other.ReadCapacity(lease,1).error==9&&other.ReadCapacity(lease,oversized).error==22,"read lease owner/count validation missing");
        Require(!retained.Close(source.value).error,"retained source close failed");
        const auto replacement=retained.Open("/source",0);
        Require(!replacement.error&&replacement.value==source.value,"retained source fixture did not reuse fd");
        bytes.fill('Q');Require(retained.Read(copied,bytes).value==4&&std::string(bytes.data(),bytes.size())==original.substr(2,4),"read lease followed reused fd");
        Require(retained.Read(lease,bytes).value==4&&std::string(bytes.data(),bytes.size())==original.substr(6,4)&&retained.Seek(replacement.value,0,1).value==0,"copied leases lost shared original cursor or changed replacement");
        Require(retained.Read(lease,bytes,1).value==4&&std::string(bytes.data(),bytes.size())==original.substr(1,4)&&retained.ReadCapacity(copied,INT32_MAX).value==original.size()-10,"positioned lease read changed shared cursor");
        Require(retained.TotalReads()==3,"lease read counters did not match native IO");
        Require(retained.AcquireRead(-1,1,{},lease).error==9&&retained.ReadCapacity(lease,1).error==9,"failed lease acquisition retained prior file");
        Require(retained.ReadCapacity(copied,1).value==1,"failed lease acquisition revoked independent copy");
    }
    {
        NativePipe pipe;DarwinFiles pending(closure);DarwinFiles::ReadLease lease;
        Require(!pending.BindInput(0,pipe.input).error,"pending lease pipe bind failed");
        CloseHandle(pipe.input);pipe.input=nullptr;
        const auto acquired=pending.AcquireRead(0,4,{},lease);
        Require(!acquired.error&&acquired.pending&&pending.ReadCapacity(lease,4).pending&&pending.TotalReads()==0,"pending pipe admission did not retain lease or performed IO");
        Require(pending.ReadCapacity(lease,1,0).error==29,"positioned pipe lease read did not reject ESPIPE");
        auto copied=lease;const auto replacement=pending.Open("/source",0);
        Require(!replacement.error&&!pending.Dup2(replacement.value,0).error&&!pending.Close(replacement.value).error,"pipe fd replacement failed");
        Require(pending.ReadCapacity(lease,4).pending&&pending.ReadCapacity(0,1).value==1,"pending lease followed descriptor replacement");
        DWORD written=0;Require(WriteFile(pipe.output,"AB",2,&written,nullptr)&&written==2,"lease input producer failed");
        Require(pending.Read(copied,bytes).value==2&&std::string(bytes.data(),2)=="AB"&&pending.Seek(0,0,1).value==0,"retained pipe read consumed replacement file");
        Require(pending.Read(lease,bytes).pending&&pending.TotalReads()==1,"empty live pipe lease fabricated read/EOF");
        Require(!pending.Close(0).error,"replacement close failed");
        Require(WriteFile(pipe.output,"C",1,&written,nullptr)&&written==1&&pending.Read(lease,bytes).value==1&&bytes[0]=='C',"closing replacement invalidated retained pipe");
        CloseHandle(pipe.output);pipe.output=nullptr;
        const auto eof=pending.Read(lease,bytes);
        Require(!eof.error&&!eof.pending&&eof.value==0&&pending.TotalReads()==3,"retained pipe lost true writer-close EOF/counters");
    }
    std::cout<<"Native immutable source access boundary, XNU read count precedence, positioned/sequential cursor and source lease PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
