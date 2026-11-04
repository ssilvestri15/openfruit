#include "darwin_arm64.hpp"
#include "darwin_image.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "content_hash.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace OpenFruit;
namespace fs=std::filesystem;
namespace {
void Require(bool value,const std::string& why){if(!value)throw std::runtime_error(why);}
void Write(const fs::path& file,const std::string& bytes){std::ofstream out(file,std::ios::binary);out<<bytes;Require(bool(out),"Fixture write failed");}
std::string Read(const fs::path& file){std::ifstream in(file,std::ios::binary);Require(bool(in),"Fixture read failed");return {std::istreambuf_iterator<char>(in),{}};}
std::uint32_t U32(const std::string& bytes,std::size_t offset){Require(offset+4<=bytes.size(),"Fixture header truncated");std::uint32_t value;std::memcpy(&value,bytes.data()+offset,4);return value;}
void U32(std::string& bytes,std::size_t offset,std::uint32_t value){Require(offset+4<=bytes.size(),"Fixture patch outside owned header");std::memcpy(bytes.data()+offset,&value,4);}
void Run(const fs::path& tool,std::vector<std::wstring> arguments){arguments.insert(arguments.begin(),tool.wstring());const auto result=Win32Process::Run(tool.wstring(),arguments);Require(result.success,"Original fixture compiler/linker failed: "+result.std_out+result.std_err);}
const JsonValue& Field(const JsonValue& value,const char* name){const auto* field=value.Get(name);Require(field!=nullptr,std::string("Missing report field ")+name);return *field;}
std::uint64_t Number(const JsonValue& value,const char* name){return std::stoull(Field(value,name).Serialize());}
// Owned consumers exercise the real syscall dispatcher. A write-denied BSD366
// reply commits registration then returns EINVAL, without claiming unavailable
// pthread feature bits. All subsequent workqueue effects are real guest effects.
const char* assembly=R"(
.text
.p2align 2
.globl _main
_main: ret

.macro WORKQ op, count, priority
mov x0,#\op
mov x1,#0
mov x2,#\count
mov x3,#\priority
mov x16,#368
svc #0x80
.endmacro
.macro OK
b.cs Lfail
cbnz x0,Lfail
.endmacro
.macro ERR number
b.cc Lfail
cmp x0,#\number
b.ne Lfail
.endmacro
.macro SELF priority, voucher, flags
mov x0,#0x100
mov x1,#\priority
mov x2,#\voucher
mov x3,#\flags
mov x16,#478
svc #0x80
.endmacro

.globl _ordinary_policy
_ordinary_policy:
bl Lregister
SELF 0,0,2
OK
SELF 0,1,2
ERR 2
mov x0,#0x100
mov x1,#0
mov x2,#-1
mov x3,#2
mov x16,#478
svc #0x80
ERR 2
SELF 0,1,3
ERR 94
SELF 0x1ff,0,0x11
ERR 22
SELF 0x8ff,0,1
OK
SELF 0,0,4
OK
SELF 0,0,8
OK
b Lpass

.globl _unregistered
_unregistered:
mov x16,#367
svc #0x80
ERR 22
WORKQ 0x400,0,0
ERR 22
b Lpass

.globl _configuration
_configuration:
bl Lregister
adr x1,Lcfg2
mov x0,#0x400
mov x2,#24
mov x3,#0
mov x16,#368
svc #0x80
OK
adr x1,Lcfg1
mov x0,#0x400
mov x2,#16
mov x16,#368
svc #0x80
OK
mov x16,#367
svc #0x80
OK
mov x16,#367
svc #0x80
OK
mov x0,#0x10
mov x1,#0
mov x2,#0x99
mov x3,#0
mov x16,#368
svc #0x80
OK
b Lpass

.globl _errors
_errors:
bl Lregister
WORKQ 0x20,1,0x8ff
ERR 22
WORKQ 4,0,0
ERR 22
adr x1,LcfgBadVersion
mov x0,#0x400
mov x2,#24
mov x16,#368
svc #0x80
ERR 45
adr x1,LcfgBadFlags
mov x0,#0x400
mov x2,#24
mov x16,#368
svc #0x80
ERR 45
mov x0,#0x400
mov x1,#0
mov x2,#24
mov x16,#368
svc #0x80
ERR 14
mov x16,#367
svc #0x80
OK
WORKQ 0x20,0,0x8ff
ERR 22
mov x0,#0x20
mov x1,#0
movz x2,#1,lsl #16
mov x3,#0x8ff
mov x16,#368
svc #0x80
ERR 22
WORKQ 0x20,1,0
ERR 22
WORKQ 0x30,2,0x8ff
ERR 45
WORKQ 0x30,1,0x8ff
ERR 45
WORKQ 0x123,0,0
ERR 22
b Lpass

.globl _lifecycle
_lifecycle:
mov x19,#1
mov x20,#3
b Lstart
.globl _overcommit
_overcommit:
mov x19,#2
mov x20,#2
b Lstart
.globl _guard
_guard:
mov x19,#3
mov x20,#1
b Lstart
.globl _worker_policy
_worker_policy:
mov x19,#4
mov x20,#1
b Lstart
.globl _scheduler_accounting
_scheduler_accounting:
mov x19,#5
mov x20,#2
Lstart:
adrp x21,Lshared@PAGE
add x21,x21,Lshared@PAGEOFF
str x19,[x21,#24]
bl Lregister
cmp x19,#4
b.ne LobserverReady
// The observer must remain runnable when the worker deliberately drops to BG.
SELF 0x1ff,0,1
OK
LobserverReady:
// Give the creator a distinct mask; workers must reset their own masks only.
mov x0,#3
adrp x1,LmainMask@PAGE
add x1,x1,LmainMask@PAGEOFF
mov x2,#0
mov x16,#48
svc #0x80
OK
mov x16,#367
svc #0x80
OK
mov x0,#0x20
mov x1,#0
mov x2,x20
mov x3,#0x8ff
cmp x19,#2
b.eq LrequestOvercommit
cmp x19,#5
b.ne Lrequest
LrequestOvercommit:
movk x3,#0x8000,lsl #16
Lrequest:
mov x16,#368
svc #0x80
OK
mov x22,#60000
cmp x19,#5
b.ne Lwait
movz x22,#0x10,lsl #16
Lwait:
ldr x8,[x21]
cmp x8,x20
b.eq Ldone
subs x22,x22,#1
b.ne Lwait
b Lfail
Ldone:
cmp x19,#2
b.ne Lpass
ldr x8,[x21,#8]
ldr x9,[x21,#40]
cmp x8,x9
b.eq Lfail
ldr x8,[x21,#16]
ldr x9,[x21,#48]
cmp x8,x9
b.eq Lfail
b Lpass

Lregister:
adr x0,Lworker
mov x9,#0
.inst 0xdac10120
mov x1,x0
mov x2,#4096
adr x3,Lregistration
mov x4,#60
mov x5,#0
mov x16,#366
svc #0x80
ERR 22
ret

Lworker:
adrp x19,Lshared@PAGE
add x19,x19,Lshared@PAGEOFF
ldr x8,[x19,#24]
cmp x8,#3
b.eq LguardAccess
cbz x0,Lfail
cbz x1,Lfail
cbnz x3,Lfail
cbnz x5,Lfail
mov x20,x4
mov x21,x0
mov x22,x1
mov x8,sp
cmp x8,x0
b.ne Lfail
sub x8,x0,x2
mov x9,#0x3000
add x9,x9,#0x80,lsl #12
cmp x8,x9
b.ne Lfail
mrs x8,tpidrro_el0
add x9,x0,#16
cmp x8,x9
b.ne Lfail
mrs x8,tpidr_el0
cbnz x8,Lfail
mov x16,#-27
svc #0x80
cmp x0,x22
b.ne Lfail
// A rejected event-list return must leave the worker running.
mov x0,#4
mov x1,#1
mov x2,#1
mov x3,#0
mov x16,#368
svc #0x80
ERR 22
ldr x8,[x19,#24]
cmp x8,#4
b.eq LworkerPolicy
cmp x8,#5
b.eq LworkerAccounting
sub sp,sp,#16
mov x0,#0
mov x1,#0
mov x2,sp
mov x16,#48
svc #0x80
OK
ldr w8,[sp]
movz w9,#0xe027
movk w9,#0xfbfe,lsl #16
cmp w8,w9
b.ne Lfail
// Clear only this worker's mask. THREAD_RETURN must restore it before reuse.
str wzr,[sp]
mov x0,#3
mov x1,sp
mov x2,#0
mov x16,#48
svc #0x80
OK
add sp,sp,#16
ldr x23,[x19]
ldr x8,[x19,#24]
cmp x8,#2
b.eq LfirstOvercommit
cbnz x23,Lreused
str x21,[x19,#8]
str x22,[x19,#16]
mov x8,#0x4004
movk x8,#0x24,lsl #16
cmp x20,x8
b.ne Lfail
mrs x8,fpcr
cbnz x8,Lfail
mrs x8,fpsr
cbnz x8,Lfail
umov x8,v31.d[0]
cbnz x8,Lfail
mov x8,#0x400000
msr fpcr,x8
mov x8,#1
msr fpsr,x8
movi v31.16b,#0x5a
mov x8,#0x1234
str x8,[x21,#256]
b Lcompleted
Lreused:
ldr x8,[x19,#8]
cmp x21,x8
b.ne Lfail
ldr x8,[x19,#16]
cmp x22,x8
b.ne Lfail
mov x8,#0x4004
movk x8,#6,lsl #16
cmp x20,x8
b.ne Lfail
mrs x8,fpcr
cmp x8,#0x400000
b.ne Lfail
mrs x8,fpsr
cmp x8,#1
b.ne Lfail
umov x8,v31.d[0]
movz x9,#0x5a5a
movk x9,#0x5a5a,lsl #16
movk x9,#0x5a5a,lsl #32
movk x9,#0x5a5a,lsl #48
cmp x8,x9
b.ne Lfail
ldr x8,[x21,#256]
mov x9,#0x1234
cmp x8,x9
b.ne Lfail
b Lcompleted
LfirstOvercommit:
mov x8,#0x4004
movk x8,#0x25,lsl #16
cmp x20,x8
b.ne Lfail
cbnz x23,LsecondOvercommit
str x21,[x19,#8]
str x22,[x19,#16]
b Lcompleted
LsecondOvercommit:
str x21,[x19,#40]
str x22,[x19,#48]
Lcompleted:
add x23,x23,#1
str x23,[x19]
WORKQ 4,0,0
// A genuine THREAD_RETURN parks/resets the upcall. Reaching this branch after
// SVC is a failure even if the dispatcher reported a successful integer return.
b Lfail
LworkerAccounting:
// Contended CPU consumers allow the real native CPU timer and periodic load
// producer to affect scheduling. No injected usage/shift or elapsed-time input.
movz x9,#0x10,lsl #16
LconsumeCpu:
subs x9,x9,#1
b.ne LconsumeCpu
ldr x23,[x19]
b Lcompleted
LworkerPolicy:
SELF 0,0,2
OK
SELF 0,1,3
ERR 94
SELF 0x1ff,0,0x11
ERR 37
SELF 0,0,4
ERR 45
SELF 0,0,8
ERR 45
mov x0,#0x100
mov x1,#0x10ff
movk x1,#0x8000,lsl #16
mov x2,#0
mov x3,#1
mov x16,#478
svc #0x80
OK
SELF 0x20ff,0,1
OK
// The final valid QoS stage survives an independent voucher failure.
mov x0,#0x100
mov x1,#0x10ff
movk x1,#0x8000,lsl #16
mov x2,#1
mov x3,#3
mov x16,#478
svc #0x80
ERR 2
ldr x23,[x19]
b Lcompleted
LguardAccess:
sub x8,x2,#1
ldrb w8,[x8]
b Lfail
Lpass:
mov x16,#65535
svc #0x80
b .
Lfail:
mov x16,#21
svc #0x80
b .

.p2align 3
Lregistration:
.quad 60,48,0
.long 16,40,8
.quad 0
.long 0,0,0
.long 0x5a5a5a5a
Lcfg2:
.long 2,0
.quad 0x44,0x88
Lcfg1:
.long 1,0
.quad 0x55,0xffff
LcfgBadVersion:
.long 0,0
.quad 0,0
LcfgBadFlags:
.long 2,1
.quad 0,0
.data
.p2align 3
Lshared: .space 128
LmainMask: .long 0x20000000
)";
}
int main(){fs::path root;try{
    const auto clang=ToolPaths::SwiftBin({})/"clang.exe",linker=ToolPaths::LlvmBin({})/"ld64.lld.exe";
    if(!fs::is_regular_file(clang)||!fs::is_regular_file(linker))return 77;
    root=fs::temp_directory_path()/("OPENFRUIT-workqueue-"+NewOperationId());
    const auto tree=root/"tree",source=root/"workqueue.s",object=root/"workqueue.o";
    const auto executable=tree/"process/main",interpreter=tree/"usr/lib/dyld";
    fs::create_directories(executable.parent_path());fs::create_directories(interpreter.parent_path());
    Write(source,assembly);
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
    const auto executable_hash=Sha256File(executable);
    const auto probe=[&](const std::string& symbol){
        const auto entry=std::find_if(metadata.exports.begin(),metadata.exports.end(),[&](const auto& value){return value.symbol==symbol;});
        Require(entry!=metadata.exports.end(),"Owned entry export absent: "+symbol);
        auto input=bytes;const auto pc=header->address+entry->value;std::memcpy(input.data()+state_offset+16+32*8,&pc,8);Write(interpreter,input);
        DarwinClosureOptions options;
        if(symbol=="_scheduler_accounting")options.instruction_limit=20000000;
        auto result=MapDarwinArm64Images("/process/main",{tree},options,{},false,true);
        Require(result.mapped&&Field(result.bootstrap,"entered").Bool(),"Owned guest did not enter: "+symbol+" "+result.diagnostic);
        const auto& pac=Field(result.bootstrap,"pointer_authentication_policy");
        Require(Number(pac,"main_cpu_subtype")==0&&!Field(pac,"jop_enabled").Bool()
            &&!Field(pac,"ia_enabled").Bool()&&Field(pac,"ib_enabled").Bool()
            &&!Field(pac,"da_enabled").Bool()&&!Field(pac,"db_enabled").Bool(),
            "Ordinary ARM64 task/worker dispatch changed NOJOP or IB protection");
        Require(Read(interpreter)==input&&Sha256File(executable)==executable_hash,"Probe mutated owned input files");
        return result;
    };
    const auto passed=[&](const std::string& symbol){auto result=probe(symbol);
        Require(result.bootstrap.GetString("stop_reason")=="unsupported_interrupt"&&Number(result.bootstrap,"syscall_selector")==65535,
            "Owned workqueue consumer failed: "+symbol+" "+result.bootstrap.Serialize());return result;};
    passed("_unregistered");
    passed("_ordinary_policy");
    const auto configuration=passed("_configuration");const auto& config=Field(configuration.bootstrap,"workqueue");
    Require(Field(config,"opened").Bool()&&Number(config,"dispatch_serialno_offset")==0x99
        &&Number(config,"dispatch_label_offset")==0x88,"Setup v1/legacy update lost persistent serial/label state");
    passed("_errors");
    const auto lifecycle=passed("_lifecycle");const auto& queue=Field(lifecycle.bootstrap,"workqueue");
    const auto& registration=Field(lifecycle.bootstrap,"pthread_registration");
    Require(Field(registration,"registration_committed").Bool()&&Number(registration,"registration_errno")==22
        &&!Field(registration,"output_copied").Bool()&&!Field(registration,"feature_return_completed").Bool()
        &&Number(registration,"capabilities_available")==0x400000de,
        "Workqueue contract fixture fabricated pthread feature/copyout success");
    Require(Number(queue,"admissions")==3&&Number(queue,"reuses")==2&&Number(queue,"returns")==3
        &&Number(queue,"parks")==3&&Number(queue,"pending_thread_count")==0,"Queued constrained requests did not run/park/reuse actual workers");
    const auto& workers=Field(queue,"workers").ArrayItems();
    Require(workers.size()==1&&Field(workers[0],"pinned_control_port").Bool()&&Field(workers[0],"idle").Bool()
        &&Number(workers[0],"upcalls")==3&&Number(workers[0],"qos")==4&&!Field(workers[0],"overcommit").Bool(),
        "Ordinary requests lost the same pinned parked worker");
    Require(Number(workers[0],"self")-Number(workers[0],"stack_bottom")==512*1024+12*1024
        &&Number(workers[0],"tsd_base")==Number(workers[0],"self")+16,"Real worker stack geometry/TSD state differs");
    Require(Number(queue,"main_signal_mask")==0x20000000&&Number(workers[0],"signal_mask")==0xfbfee027,
        "Worker mask reset leaked to the creator or was not restored on return");
    const auto overcommit=passed("_overcommit");const auto& oc=Field(overcommit.bootstrap,"workqueue");
    Require(Number(oc,"admissions")==2&&Number(oc,"reuses")==0&&Field(oc,"workers").ArrayItems().size()==2,
        "Overcommit requests did not allocate two independent actual workers");
    for(const auto& worker:Field(oc,"workers").ArrayItems())Require(Field(worker,"overcommit").Bool()
        &&Field(worker,"pinned_control_port").Bool(),"Overcommit worker priority/port binding missing");
    const auto policy=passed("_worker_policy");const auto& policy_queue=Field(policy.bootstrap,"workqueue");
    const auto& policy_workers=Field(policy_queue,"workers").ArrayItems();
    Require(Number(policy_queue,"policy_updates")==4&&policy_workers.size()==1
        &&Number(policy_workers[0],"qos")==5&&Field(policy_workers[0],"overcommit").Bool()
        &&Number(policy_queue,"returns")==1,"SET_SELF did not commit real worker transitions or preserve QoS after voucher error");
    const auto accounting=passed("_scheduler_accounting");const auto& scheduler=Field(accounting.bootstrap,"scheduler_accounting");
    Require(Number(scheduler,"cpu_charged_100ns")>0&&Number(scheduler,"load_samples")>0
        &&Number(scheduler,"priority_ticks")>0,"Real contended guest execution never reached the CPU/load accounting producer");
    bool decayed=false;
    for(const auto& thread:Field(scheduler,"threads").ArrayItems())if(Number(thread,"sched_usage")>0
        &&Number(thread,"pri_shift")<127&&Number(thread,"effective_priority")<Number(thread,"base_priority"))decayed=true;
    Require(decayed,"Measured contended CPU usage never changed a live scheduling priority");
    const auto guard=probe("_guard");const auto& guard_workers=Field(Field(guard.bootstrap,"workqueue"),"workers").ArrayItems();
    Require(guard.bootstrap.GetString("stop_reason")=="unsupported_memory_access"&&guard_workers.size()==1
        &&Number(guard.bootstrap,"memory_address")==Number(guard_workers[0],"stack_bottom")-1,
        "Worker lower guard page was readable or fault attribution differs: "+guard.bootstrap.Serialize());
    std::cout<<"Darwin BSD367/368 native dispatcher, owned worker ABI/guard, queued admission, park/reuse and overcommit consumers PASS\n";
    fs::remove_all(root);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\nOwned fixture retained at "<<root.string()<<'\n';return 1;}}
