#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "darwin_arm64.hpp"
#include "darwin_image.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "content_hash.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>

using namespace OpenFruit;
namespace fs=std::filesystem;
namespace {
void Require(bool value,const std::string& why){if(!value)throw std::runtime_error(why);}
void Write(const fs::path& path,const std::string& bytes){std::ofstream out(path,std::ios::binary);out<<bytes;Require(bool(out),"Fixture write failed");}
std::string Read(const fs::path& path){std::ifstream in(path,std::ios::binary);Require(bool(in),"Fixture read failed");return {std::istreambuf_iterator<char>(in),{}};}
std::uint32_t U32(const std::string& bytes,std::size_t offset){Require(offset+4<=bytes.size(),"Fixture header truncated");std::uint32_t value;std::memcpy(&value,bytes.data()+offset,4);return value;}
void U32(std::string& bytes,std::size_t offset,std::uint32_t value){Require(offset+4<=bytes.size(),"Fixture patch outside owned header");std::memcpy(bytes.data()+offset,&value,4);}
void Run(const fs::path& tool,std::vector<std::wstring> arguments){arguments.insert(arguments.begin(),tool.wstring());const auto result=Win32Process::Run(tool.wstring(),arguments);Require(result.success,"Owned fixture compiler/linker failed: "+result.std_out+result.std_err);}
const JsonValue& Field(const JsonValue& value,const char* name){const auto* field=value.Get(name);Require(field!=nullptr,std::string("Missing report field ")+name);return *field;}
std::uint64_t Number(const JsonValue& value,const char* name){return std::stoull(Field(value,name).Serialize());}

// The runtime's existing inherited-stderr binding duplicates this real pipe.
// The guest must write bytes to its peer; diagnostic counters alone are not
// sufficient evidence. No host bytes are injected into the output stream.
struct StderrPipe {
    HANDLE reader=nullptr,writer=nullptr,previous=INVALID_HANDLE_VALUE;
    bool installed=false;
    StderrPipe(){
        Require(CreatePipe(&reader,&writer,nullptr,0)!=FALSE,"Native output pipe creation failed");
        previous=GetStdHandle(STD_ERROR_HANDLE);
        if(!SetStdHandle(STD_ERROR_HANDLE,writer)){
            CloseHandle(reader);CloseHandle(writer);reader=writer=nullptr;
            throw std::runtime_error("Native stderr binding failed");
        }
        installed=true;
    }
    void Restore(){if(installed){SetStdHandle(STD_ERROR_HANDLE,previous);installed=false;}}
    ~StderrPipe(){Restore();if(writer)CloseHandle(writer);if(reader)CloseHandle(reader);}
    std::string Drain(){
        Restore();CloseHandle(writer);writer=nullptr;
        std::string bytes;std::array<char,128> buffer{};
        for(;;){DWORD count=0;
            if(!ReadFile(reader,buffer.data(),static_cast<DWORD>(buffer.size()),&count,nullptr)){
                Require(GetLastError()==ERROR_BROKEN_PIPE,"Native output pipe read failed");break;
            }
            if(!count)break;bytes.append(buffer.data(),count);
        }
        return bytes;
    }
};

// Pinned XNU f6217f89 forwards ordinary read/write/open/close/fcntl/pread/openat
// to these same nocancel providers after its cancellation check. This suite
// verifies the existing immutable-VFS operations and ABI aliases only; it does
// not claim guest pthread cancellation or scheduler-backed pipe waits.
const char* assembly=R"(
.text
.p2align 2
.globl _main
_main: ret
.macro START mode
sub sp,sp,#512
mov x28,#\mode
.endmacro
.macro SC selector,value,error
mov x20,#\selector
mov x22,#\value
mov x23,#\error
bl Lcall
.endmacro
.macro PAIR value
mov x25,#\value
bl Lpair
.endmacro

.globl _file_direct
_file_direct:
START 0
b Lfile
.globl _file_indirect
_file_indirect:
START 1
Lfile:
adr x0,Ldata_path
mov x1,#0
mov x2,#0
SC 398,-1,0
mov x19,x0
// Failed copyout cannot advance the shared open-description cursor.
bl Lfill
mov x0,x19
mov x1,#1
mov x2,#2
SC 396,14,14
bl Lempty
mov x0,x19
add x1,sp,#132
mov x2,#2
SC 396,2,0
PAIR 0x6261
mov x0,x19
SC 41,-1,0
mov x21,x0
// An ordinary read through a genuine dup consumes the very same cursor.
bl Lfill
mov x0,x21
add x1,sp,#132
mov x2,#2
SC 3,2,0
PAIR 0x6463
bl Lfill
mov x0,x21
add x1,sp,#132
mov x2,#2
mov x3,#0
SC 414,2,0
PAIR 0x6261
bl Lfill
mov x0,x21
add x1,sp,#132
mov x2,#2
mov x3,#-1
SC 414,22,22
bl Lempty
// XNU validates count>INT_MAX before even the descriptor or pointer.
mov x0,#999
mov x1,#1
mov x2,#0x80000000
SC 396,22,22
mov x0,#999
mov x1,#1
mov x2,#2
SC 396,9,9
bl Lempty
mov x0,x19
add x1,sp,#132
mov x2,#2
SC 396,2,0
PAIR 0x6665
mov x0,x19
SC 399,0,0
// Closing one descriptor leaves the actual shared alias alive at offset6.
bl Lfill
mov x0,x21
add x1,sp,#132
mov x2,#2
SC 396,2,0
PAIR 0x6867
bl Lfill
mov x0,x21
mov x1,#1
mov x2,#2
SC 396,0,0
bl Lempty
mov x0,x21
mov x1,#1
mov x2,#0
SC 396,0,0
bl Lempty
mov x0,x21
SC 6,0,0
mov x0,x21
SC 399,9,9
b Lpass

.globl _paths_direct
_paths_direct:
START 0
b Lpaths
.globl _paths_indirect
_paths_indirect:
START 1
Lpaths:
adr x0,Lmissing_path
mov x1,#0
SC 398,2,2
mov x0,#1
mov x1,#0
SC 398,14,14
adr x0,Lempty_path
mov x1,#0
SC 398,2,2
adr x0,Ldata_path
mov x1,#1
SC 398,30,30
adr x0,Ldata_path
mov x1,#0x80000000
SC 398,45,45
adr x0,Ldirectory
mov x1,#0x100000
SC 398,-1,0
mov x19,x0
mov x0,x19
adr x1,Lrelative
mov x2,#0
mov x3,#0
SC 464,-1,0
mov x21,x0
bl Lfill
mov x0,x21
add x1,sp,#132
mov x2,#2
SC 3,2,0
PAIR 0x6261
mov x0,x21
SC 399,0,0
// AT_FDCWD uses the guest launch namespace ("/"), not Windows CWD.
mov x0,#-2
adr x1,Lcwd_relative
mov x2,#0
mov x3,#0
SC 464,-1,0
SC 6,0,0
// Absolute paths ignore an invalid dirfd, as XNU openat requires.
mov x0,#999
adr x1,Ldata_path
mov x2,#0
mov x3,#0
SC 464,-1,0
SC 399,0,0
mov x0,#999
adr x1,Lrelative
mov x2,#0
mov x3,#0
SC 464,9,9
// Existing guarded pathname copyin precedes dirfd resolution.
mov x0,#999
mov x1,#1
mov x2,#0
mov x3,#0
SC 464,14,14
mov x0,x19
SC 399,0,0
b Lpass

.globl _fcntl_direct
_fcntl_direct:
START 0
b Lfcntl
.globl _fcntl_indirect
_fcntl_indirect:
START 1
Lfcntl:
adr x0,Ldata_path
mov x1,#0x1000000
SC 398,-1,0
mov x19,x0
mov x0,x19
mov x1,#1
SC 406,1,0
mov x0,x19
mov x1,#2
mov x2,#0
SC 92,0,0
mov x0,x19
mov x1,#1
SC 406,0,0
mov x0,x19
mov x1,#2
mov x2,#1
SC 406,0,0
mov x0,x19
mov x1,#1
SC 92,1,0
mov x0,x19
mov x1,#3
SC 406,0,0
// Genuine F_GETPATH output, including its NUL and untouched surrounding bytes.
mov x8,#0x5a5a
movk x8,#0x5a5a,lsl #16
movk x8,#0x5a5a,lsl #32
movk x8,#0x5a5a,lsl #48
stp x8,x8,[sp,#192]
stp x8,x8,[sp,#208]
stp x8,x8,[sp,#224]
stp x8,x8,[sp,#240]
mov x0,x19
mov x1,#50
add x2,sp,#200
SC 406,0,0
adr x9,Ldata_path
add x10,sp,#200
Lpath_bytes:
ldrb w8,[x9],#1
ldrb w11,[x10],#1
cmp w8,w11
b.ne Lfail
cbnz w8,Lpath_bytes
add x9,sp,#256
Lpath_after:
cmp x10,x9
b.hs Lpath_before
ldrb w8,[x10],#1
cmp w8,#0x5a
b.ne Lfail
b Lpath_after
Lpath_before:
ldr x8,[sp,#192]
mov x9,#0x5a5a
movk x9,#0x5a5a,lsl #16
movk x9,#0x5a5a,lsl #32
movk x9,#0x5a5a,lsl #48
cmp x8,x9
b.ne Lfail
mov x0,x19
mov x1,#50
mov x2,#1
SC 406,14,14
mov x0,x19
mov x1,#999
SC 406,45,45
mov x0,#999
mov x1,#1
SC 406,9,9
mov x0,x19
SC 41,-1,0
mov x21,x0
// CLOEXEC is per descriptor; dup starts clear and cannot mutate its source.
mov x0,x21
mov x1,#1
SC 406,0,0
mov x0,x19
mov x1,#1
SC 406,1,0
mov x0,x19
SC 399,0,0
mov x0,x21
SC 399,0,0
b Lpass

.globl _write_direct
_write_direct:
START 0
b Lwrite
.globl _write_indirect
_write_indirect:
START 1
Lwrite:
mov x0,#2
adr x1,Lwrite_data
mov x2,#8
SC 397,8,0
mov x0,#2
adr x1,Lwrite_data
mov x2,#8
SC 4,8,0
mov x0,#2
mov x1,#1
mov x2,#0
SC 397,0,0
mov x0,#2
mov x1,#1
mov x2,#8
SC 397,14,14
mov x0,#999
mov x1,#1
mov x2,#8
SC 397,9,9
mov x0,#999
mov x1,#1
mov x2,#0x80000000
SC 397,22,22
adr x0,Ldata_path
mov x1,#0
SC 398,-1,0
mov x19,x0
mov x0,x19
adr x1,Lwrite_data
mov x2,#8
SC 397,9,9
mov x0,x19
SC 399,0,0
mov x0,#2
SC 399,0,0
mov x0,#2
adr x1,Lwrite_data
mov x2,#8
SC 397,9,9
b Lpass

// Shared direct/indirect syscall assertion. Input arguments and meaningful
// output expectations are prepared by the guest; x22=-1 permits a dynamically
// allocated fd without assuming any particular host or guest descriptor value.
Lcall:
mov x4,#0
mov x5,#0x55
mov x6,#0x66
mov x7,#0x77
mov x16,x20
cbz x28,Largs_ready
mov x4,x3
mov x3,x2
mov x2,x1
mov x1,x0
mov x0,x20
mov x16,#0
Largs_ready:
stp x2,x3,[sp,#32]
stp x4,x5,[sp,#48]
stp x6,x7,[sp,#64]
// Start with opposite carry so preservation alone cannot pass either branch.
mov x8,#0xb0000000
cbz x23,Lflags_ready
mov x8,#0x90000000
Lflags_ready:
msr nzcv,x8
svc #0x80
mrs x8,nzcv
mov x9,#0x90000000
cbz x23,Lflags_check
orr x9,x9,#0x20000000
Lflags_check:
cmp x8,x9
b.ne Lfail
cbnz x1,Lfail
cmn x22,#1
b.eq Lreturn_regs
cmp x0,x22
b.ne Lfail
Lreturn_regs:
ldp x8,x9,[sp,#32]
cmp x2,x8
b.ne Lfail
cmp x3,x9
b.ne Lfail
ldp x8,x9,[sp,#48]
cmp x4,x8
b.ne Lfail
cmp x5,x9
b.ne Lfail
ldp x8,x9,[sp,#64]
cmp x6,x8
b.ne Lfail
cmp x7,x9
b.ne Lfail
ret
Lfill:
mov x8,#0x5a5a
movk x8,#0x5a5a,lsl #16
movk x8,#0x5a5a,lsl #32
movk x8,#0x5a5a,lsl #48
stp x8,x8,[sp,#128]
ret
Lpair:
ldrh w8,[sp,#132]
cmp w8,w25
b.ne Lfail
ldr w8,[sp,#128]
mov w9,#0x5a5a
movk w9,#0x5a5a,lsl #16
cmp w8,w9
b.ne Lfail
mov x10,#134
b Lbuffer_tail
Lempty:
mov x10,#128
Lbuffer_tail:
ldrb w8,[sp,x10]
cmp w8,#0x5a
b.ne Lfail
add x10,x10,#1
cmp x10,#144
b.lo Lbuffer_tail
ret
Lpass:
mov x16,#65535
svc #0x80
b .
Lfail:
mov x16,#65534
svc #0x80
b .
Ldata_path: .asciz "/process/data"
Lmissing_path: .asciz "/process/missing"
Lempty_path: .asciz ""
Ldirectory: .asciz "/process"
Lrelative: .asciz "data"
Lcwd_relative: .asciz "process/data"
Lwrite_data: .ascii "of-nocan"
.p2align 2
)";
}

int main(){fs::path root;try{
    const auto clang=ToolPaths::SwiftBin({})/"clang.exe",linker=ToolPaths::LlvmBin({})/"ld64.lld.exe";
    if(!fs::is_regular_file(clang)||!fs::is_regular_file(linker))return 77;
    root=fs::temp_directory_path()/("OPENFRUIT-nocancel-"+NewOperationId());
    const auto tree=root/"tree",source=root/"nocancel.s",object=root/"nocancel.o";
    const auto executable=tree/"process/main",interpreter=tree/"usr/lib/dyld",data=tree/"process/data";
    fs::create_directories(executable.parent_path());fs::create_directories(interpreter.parent_path());
    Write(source,assembly);Write(data,"abcdefgh");
    Run(clang,{L"-target",L"arm64-apple-macos11.0",L"-c",source.wstring(),L"-o",object.wstring()});
    Run(linker,{L"-arch",L"arm64",L"-platform_version",L"macos",L"11.0",L"27.0",L"-fixup_chains",L"-e",L"_main",L"-o",executable.wstring(),object.wstring()});
    Run(linker,{L"-dylib",L"-arch",L"arm64",L"-platform_version",L"macos",L"11.0",L"27.0",L"-headerpad",L"1000",L"-fixup_chains",L"-install_name",L"/usr/lib/dyld",L"-o",interpreter.wstring(),object.wstring()});
    auto bytes=Read(interpreter);DarwinImage metadata;std::string error;
    Require(InspectDarwinImage(bytes,0x0100000c,metadata,error),"Owned interpreter metadata: "+error);
    const auto header=std::find_if(metadata.segments.begin(),metadata.segments.end(),[](const auto& segment){return !segment.file_offset&&segment.file_size;});
    const auto text=std::find_if(metadata.sections.begin(),metadata.sections.end(),[](const auto& section){return section.name=="__text";});
    Require(header!=metadata.segments.end()&&text!=metadata.sections.end(),"Owned interpreter header/text absent");
    const auto state_offset=32+U32(bytes,20);
    Require(state_offset+288<=text->file_offset,"Owned interpreter LC_UNIXTHREAD padding absent");
    std::string state(288,'\0');U32(state,0,5);U32(state,4,288);U32(state,8,6);U32(state,12,68);
    std::memcpy(bytes.data()+state_offset,state.data(),state.size());U32(bytes,12,7);
    U32(bytes,16,U32(bytes,16)+1);U32(bytes,20,U32(bytes,20)+288);
    const auto executable_hash=Sha256File(executable),data_hash=Sha256File(data);
    struct Batch {const char* name;std::vector<unsigned> selectors;std::vector<int> errors;};
    const std::array<Batch,4> batches{{
        {"file",{398,396,396,41,3,414,414,396,396,396,399,396,396,396,6,399},
            {0,14,0,0,0,0,22,22,9,0,0,0,0,0,0,9}},
        {"paths",{398,398,398,398,398,398,464,3,399,464,6,464,399,464,464,399},
            {2,14,2,30,45,0,0,0,0,0,0,0,0,9,14,0}},
        {"fcntl",{398,406,92,406,406,92,406,406,406,406,406,41,406,406,399,399},
            {0,0,0,0,0,0,0,0,14,45,9,0,0,0,0,0}},
        {"write",{397,4,397,397,397,397,398,397,399,399,397},
            {0,0,0,14,9,22,0,9,0,0,9}}
    }};
    const std::set<unsigned> nocancel_selectors{396,397,398,399,406,414,464};
    std::array<std::set<unsigned>,2> observed;
    for(std::size_t mode=0;mode<2;++mode)for(const auto& batch:batches){
        const auto symbol=std::string("_")+batch.name+(mode?"_indirect":"_direct");
        const auto entry=std::find_if(metadata.exports.begin(),metadata.exports.end(),[&](const auto& value){return value.symbol==symbol;});
        Require(entry!=metadata.exports.end(),"Owned entry export absent: "+symbol);
        auto input=bytes;const auto pc=header->address+entry->value;
        std::memcpy(input.data()+state_offset+16+32*8,&pc,8);Write(interpreter,input);
        StderrPipe output;
        const auto result=MapDarwinArm64Images("/process/main",{tree},{},{},false,true);
        const auto output_bytes=output.Drain();
        Require(result.mapped&&Field(result.bootstrap,"entered").Bool(),"Owned guest did not enter: "+symbol+" "+result.diagnostic);
        Require(result.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&Number(result.bootstrap,"syscall_selector")==65535,
            "Owned nocancel consumer failed: "+symbol+" "+result.bootstrap.Serialize());
        Require(Read(interpreter)==input&&Sha256File(executable)==executable_hash
            &&Sha256File(data)==data_hash&&Read(data)=="abcdefgh","Probe mutated owned inputs");
        const auto& calls=Field(result.bootstrap,"file_call_prefix").ArrayItems();
        Require(calls.size()==batch.selectors.size(),"Truncated/unexpected file call batch: "+symbol);
        for(std::size_t i=0;i<calls.size();++i){
            const auto selector=static_cast<unsigned>(Number(calls[i],"selector"));
            Require(selector==batch.selectors[i]&&Field(calls[i],"errno").Int()==batch.errors[i],
                "Selector/argument forwarding or errno mismatch: "+symbol+" call "+std::to_string(i));
            if(nocancel_selectors.contains(selector))observed[mode].insert(selector);
        }
        const auto& summary=Field(result.bootstrap,"file_call_summary").ArrayItems();
        const std::set<unsigned> expected_selectors(batch.selectors.begin(),batch.selectors.end());
        std::set<unsigned> summary_selectors;
        Require(summary.size()==expected_selectors.size(),"Per-selector summary denominator differs: "+symbol);
        for(const auto& row:summary){
            const auto selector=static_cast<unsigned>(Number(row,"selector"));
            Require(expected_selectors.contains(selector)&&summary_selectors.insert(selector).second,
                "Unexpected/duplicate summary selector: "+symbol);
            const auto count=static_cast<std::uint64_t>(std::count(batch.selectors.begin(),batch.selectors.end(),selector));
            const auto last=std::find(batch.selectors.rbegin(),batch.selectors.rend(),selector);
            const auto index=batch.selectors.size()-1-static_cast<std::size_t>(last-batch.selectors.rbegin());
            Require(Number(row,"calls")==count&&Field(row,"errno").Int()==batch.errors[index]
                &&Number(row,"value")==Number(calls[index],"value")
                &&Number(row,"pc")==Number(calls[index],"pc")
                &&Field(row,"arguments").Serialize()==Field(calls[index],"arguments").Serialize(),
                "Summary lost the actual last invocation or count: "+symbol+" selector "+std::to_string(selector));
        }
        const auto& manifest=Field(result.bootstrap,"service_manifest").ArrayItems();
        for(const auto& alias:std::array<std::pair<unsigned,const char*>,7>{{
            {396,"read_nocancel"},{397,"write_nocancel"},{398,"open_nocancel"},
            {399,"close_nocancel"},{406,"fcntl_nocancel"},{414,"pread_nocancel"},{464,"openat_nocancel"}}}){
            Require(std::count_if(manifest.begin(),manifest.end(),[&](const auto& registration){
                return Number(registration,"selector_id")==alias.first&&registration.GetString("name")==alias.second;
            })==1,"Alias registration manifest differs from actual selector: "+symbol);
        }
        const auto& files=Field(result.bootstrap,"original_files");
        if(std::string(batch.name)=="file"){
            Require(Number(files,"opens")==1&&Number(files,"closes")==2
                &&Number(files,"reads")==7&&Number(files,"bytes_read")==10,
                "Ordinary/nocancel descriptor lifetime, read cursor or pread accounting differs");
        }
        if(std::string(batch.name)=="write"){
            Require(output_bytes=="of-nocanof-nocan","Native pipe peer did not receive the actual guest bytes");
            Require(Number(files,"write_calls")==3&&Number(files,"bytes_written")==16,
                "Native write results and actual output counters differ");
            const auto& outputs=Field(files,"output_descriptors").ArrayItems();
            Require(outputs.size()==1&&Field(outputs[0],"closed").Bool()
                &&Number(outputs[0],"fd")==2&&Number(outputs[0],"calls")==3
                &&Number(outputs[0],"bytes")==16
                &&outputs[0].GetString("prefix_hex")=="6f662d6e6f63616e6f662d6e6f63616e",
                "Native output evidence does not match the real peer stream");
        }else Require(output_bytes.empty(),"Readonly consumer unexpectedly wrote native stderr");
    }
    Require(observed[0]==nocancel_selectors&&observed[1]==nocancel_selectors,
        "Not all seven nocancel selectors executed through both syscall ABIs");
    std::cout<<"Darwin seven nocancel VFS aliases: original native providers, direct/indirect ABI, cursor/dup, pread, openat, flags, real output and errors PASS\n";
    fs::remove_all(root);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\nOwned fixture retained at "<<root.string()<<'\n';return 1;}}
