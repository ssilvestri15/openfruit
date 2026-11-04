#include "darwin_arm64.hpp"
#include "darwin_image.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "content_hash.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace OpenFruit;
namespace fs=std::filesystem;
namespace {
void Require(bool value,const std::string& why){if(!value)throw std::runtime_error(why);}
void Write(const fs::path& file,const std::string& bytes){std::ofstream out(file,std::ios::binary);out<<bytes;Require(bool(out),"Fixture write failed");}
std::string Read(const fs::path& file){std::ifstream in(file,std::ios::binary);Require(bool(in),"Fixture read failed");return {std::istreambuf_iterator<char>(in),{}};}
std::uint32_t U32(const std::string& bytes,std::size_t offset){Require(offset+4<=bytes.size(),"Fixture header truncated");std::uint32_t value;std::memcpy(&value,bytes.data()+offset,4);return value;}
void U32(std::string& bytes,std::size_t offset,std::uint32_t value){Require(offset+4<=bytes.size(),"Fixture patch outside owned header");std::memcpy(bytes.data()+offset,&value,4);}
void Run(const fs::path& tool,std::vector<std::wstring> arguments){arguments.insert(arguments.begin(),tool.wstring());const auto result=Win32Process::Run(tool.wstring(),arguments);Require(result.success,"Owned fixture compiler/linker failed: "+result.std_out+result.std_err);}
const JsonValue& Field(const JsonValue& value,const char* name){const auto* field=value.Get(name);Require(field!=nullptr,std::string("Missing report field ")+name);return *field;}
std::uint64_t Number(const JsonValue& value,const char* name){return std::stoull(Field(value,name).Serialize());}
struct NativePipe {
    HANDLE reader=nullptr,writer=nullptr;
    NativePipe(){Require(CreatePipe(&reader,&writer,nullptr,0)!=FALSE,"Owned native pipe creation failed");}
    NativePipe(const NativePipe&)=delete;NativePipe& operator=(const NativePipe&)=delete;
    ~NativePipe(){if(writer)CloseHandle(writer);if(reader)CloseHandle(reader);}
    void CloseWriter(){if(writer){CloseHandle(writer);writer=nullptr;}}
    void Preload(const std::string& bytes){DWORD written=0;
        Require(WriteFile(writer,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=FALSE
            &&written==bytes.size(),"Owned input pipe preload failed");}
    std::string Drain(){CloseWriter();std::string bytes;char buffer[128]{};
        for(;;){DWORD read=0;if(!ReadFile(reader,buffer,sizeof(buffer),&read,nullptr)){
                Require(GetLastError()==ERROR_BROKEN_PIPE,"Owned output pipe read failed");break;}
            if(!read)break;bytes.append(buffer,read);}
        return bytes;
    }
};

// Apple XNU f6217f89: task_info13/15/17, task.defs CountInOut[94],
// kern_prot.c token layout. Every token word is consumed in the guest. Values
// that the runtime must derive come from real BSD syscalls, never host inputs.
const char* assembly=R"(
.text
.p2align 2
.globl _main
_main: ret
.macro SETUP
sub sp,sp,#2,lsl #12
mov x16,#-28
svc #0x80
mov x19,x0
mov x16,#-26
svc #0x80
mov x20,x0
mov x24,x19
mov x26,#424
mov x27,#0
mov x28,#0
.endmacro
.macro QUERY flavor,count,status
mov x22,#\flavor
mov x23,#\count
mov x25,#\status
bl Lcall
.endmacro
.macro BSD selector,offset
mov x16,#\selector
svc #0x80
b.cs Lfail
cbnz x1,Lfail
str w0,[sp,#\offset]
.endmacro
.macro IO selector,value,error
mov x24,#\selector
mov x25,#\value
mov x26,#\error
bl Lstdio_call
.endmacro

.globl _tokens
_tokens:
SETUP
BSD 20,512
BSD 24,516
BSD 25,520
BSD 47,524
BSD 43,528
QUERY 15,8,0
// auid and asid have source-defined unattributed, non-login values.
ldr w8,[sp,#40]
cmn w8,#1
b.ne Lfail
ldr w8,[sp,#64]
cbnz w8,Lfail
ldr w8,[sp,#68]
cbz w8,Lfail
str w8,[sp,#532]
ldr w8,[sp,#60]
ldr w9,[sp,#512]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#44]
ldr w9,[sp,#520]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#48]
ldr w9,[sp,#528]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#52]
ldr w9,[sp,#516]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#56]
ldr w9,[sp,#524]
cmp w8,w9
b.ne Lfail
ldp x8,x9,[sp,#40]
stp x8,x9,[sp,#448]
ldp x8,x9,[sp,#56]
stp x8,x9,[sp,#464]
QUERY 13,2,0
ldr w8,[sp,#40]
ldr w9,[sp,#520]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#44]
ldr w9,[sp,#528]
cmp w8,w9
b.ne Lfail
QUERY 15,94,0
ldp x8,x9,[sp,#40]
ldp x10,x11,[sp,#448]
cmp x8,x10
b.ne Lfail
cmp x9,x11
b.ne Lfail
ldp x8,x9,[sp,#56]
ldp x10,x11,[sp,#464]
cmp x8,x10
b.ne Lfail
cmp x9,x11
b.ne Lfail
b Lpass

.globl _counts
_counts:
SETUP
QUERY 13,0,4
QUERY 13,1,4
QUERY 13,2,0
QUERY 13,3,0
QUERY 13,94,0
QUERY 13,95,0
QUERY 13,-1,0
QUERY 15,0,4
QUERY 15,7,4
QUERY 15,8,0
QUERY 15,9,0
QUERY 15,94,0
QUERY 15,95,0
QUERY 15,-1,0
QUERY 17,0,4
QUERY 17,3,4
QUERY 17,4,0
ldp x8,x9,[sp,#40]
stp x8,x9,[sp,#448]
QUERY 17,5,0
ldp x8,x9,[sp,#40]
ldp x10,x11,[sp,#448]
cmp x8,x10
b.ne Lfail
cmp x9,x11
b.ne Lfail
ldr w8,[sp,#56]
cmp w8,#1
b.ne Lfail
QUERY 17,6,0
QUERY 17,94,0
b Lpass

.globl _ports
_ports:
SETUP
mov x22,#15
mov x23,#8
mov x25,#0
mov x28,#3
movk x28,#0x1000,lsl #16
mov x24,#0
bl Lcall
mov x24,#-1
bl Lcall
// A real kernel host send right exists, but cannot convert to task_t.
mov x16,#-29
svc #0x80
mov x24,x0
mov x25,#4
mov x28,#0
bl Lcall
// Task send rights cannot stand in for a receive right.
mov x24,x19
mov x20,x19
mov x25,#0
mov x28,#9
movk x28,#0x1000,lsl #16
bl Lcall
b Lpass

.globl _exact_buffers
_exact_buffers:
SETUP
mov x26,#80
QUERY 15,8,0
mov x26,#56
QUERY 13,2,0
mov x26,#64
QUERY 17,4,0
mov x26,#68
QUERY 17,5,0
mov x26,#44
QUERY 15,7,4
b Lpass

.globl _audit_short
_audit_short:
SETUP
mov x26,#79
QUERY 15,8,0
b Lfail
.globl _audit_no_trailer
_audit_no_trailer:
SETUP
mov x26,#72
QUERY 15,8,0
b Lfail
.globl _audit_half_trailer
_audit_half_trailer:
SETUP
mov x26,#76
QUERY 15,8,0
b Lfail
.globl _error_short
_error_short:
SETUP
mov x26,#43
QUERY 15,7,4
b Lfail
.globl _bad_ndr
_bad_ndr:
SETUP
mov x27,#1
QUERY 15,8,0
b Lfail
.globl _bad_header
_bad_header:
SETUP
mov x27,#2
QUERY 15,8,0
b Lpass
.globl _descriptor_count
_descriptor_count:
SETUP
mov x27,#3
mov x28,#0xe
movk x28,#0x1000,lsl #16
QUERY 15,8,0
b Lpass
.globl _invalid_source
_invalid_source:
SETUP
// Copyin precedes destination resolution; descriptor-count validation precedes
// copyin. Neither transport rejection is a semantic task_info query.
mov x22,#0
mov x28,#2
movk x28,#0x1000,lsl #16
bl Linvalid_source_send
mov x22,#1
mov x28,#0xe
movk x28,#0x1000,lsl #16
bl Linvalid_source_send
b Lpass
Linvalid_source_send:
mov x0,#1
mov x1,#3
movk x1,#2,lsl #32
mov x2,#0x1513
movk x2,#40,lsl #32
lsl x3,x20,#32
mov x4,#3405
lsl x4,x4,#32
orr x5,x22,x20,lsl #32
mov x6,#424
mov x7,#0
mov x8,#0xa0000000
msr nzcv,x8
mov x16,#-47
svc #0x80
mrs x8,nzcv
mov x9,#0xa0000000
cmp x8,x9
b.ne Lfail
cmp x0,x28
b.ne Lfail
mov x8,#3
movk x8,#2,lsl #32
cmp x1,x8
b.ne Lfail
mov x8,#0x1513
movk x8,#40,lsl #32
cmp x2,x8
b.ne Lfail
lsl x8,x20,#32
cmp x3,x8
b.ne Lfail
mov x8,#3405
lsl x8,x8,#32
cmp x4,x8
b.ne Lfail
orr x8,x22,x20,lsl #32
cmp x5,x8
b.ne Lfail
cmp x6,#424
b.ne Lfail
cbnz x7,Lfail
ret

.globl _peer_tokens
_peer_tokens:
SETUP
QUERY 15,8,0
ldp x8,x9,[sp,#40]
stp x8,x9,[sp,#448]
ldp x8,x9,[sp,#56]
stp x8,x9,[sp,#464]
add x29,sp,#768
stp xzr,xzr,[x29]
stp xzr,xzr,[x29,#16]
str xzr,[x29,#32]
// Ordinary ARM64 task state has source NO_PTRAUTH representation. No test
// signs/strips an Apple pointer or injects a task identity.
mov x9,#0
Lstate_zero:
str xzr,[sp,x9]
add x9,x9,#8
cmp x9,#312
b.lo Lstate_zero
str x29,[sp,#40]
add x8,sp,#1,lsl #12
str x8,[sp,#288]
adr x8,Lpeer
str x8,[sp,#296]
mov w8,#1
str w8,[sp,#308]
mov w8,#6
str w8,[sp,#32]
mov w8,#68
str w8,[sp,#36]
mov w8,#0x1513
str w8,[sp]
mov w8,#312
str w8,[sp,#4]
str w19,[sp,#8]
str w20,[sp,#12]
mov w8,#3412
str w8,[sp,#20]
mov w8,#1
str w8,[sp,#28]
mov x0,sp
mov x1,#3
movk x1,#2,lsl #32
mov x2,#0x1513
movk x2,#312,lsl #32
orr x3,x19,x20,lsl #32
mov x4,#3412
lsl x4,x4,#32
lsl x5,x20,#32
mov x6,#80
mov x7,#0
mov x16,#-47
svc #0x80
cbnz x0,Lfail
ldr w8,[sp]
mov w9,#0x1200
movk w9,#0x8000,lsl #16
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#24]
cmp w8,#1
b.ne Lfail
ldr w8,[sp,#28]
cbz w8,Lfail
// Quantum preemption must dispatch the actual peer; no host result injection.
add x9,x29,#32
mov x10,#0x100
movk x10,#0x10,lsl #16
Lawait_peer:
ldar x8,[x9]
cbnz x8,Lpeer_done
subs x10,x10,#1
b.ne Lawait_peer
b Lfail
Lpeer_done:
ldp x8,x9,[x29]
ldp x10,x11,[sp,#448]
cmp x8,x10
b.ne Lfail
cmp x9,x11
b.ne Lfail
ldp x8,x9,[x29,#16]
ldp x10,x11,[sp,#464]
cmp x8,x10
b.ne Lfail
cmp x9,x11
b.ne Lfail
b Lpass
Lpeer:
mov x29,x0
mov x16,#-28
svc #0x80
mov x19,x0
mov x24,x19
mov x16,#-26
svc #0x80
mov x20,x0
mov x26,#424
mov x27,#0
mov x28,#0
QUERY 15,8,0
ldp x8,x9,[sp,#40]
stp x8,x9,[x29]
ldp x8,x9,[sp,#56]
stp x8,x9,[x29,#16]
mov x8,#1
add x9,x29,#32
stlr x8,[x9]
Lpeer_idle: b Lpeer_idle

// Original compiler-plugin StandardIO launch order: preserve private stdin,
// close0, preserve stdout (which may reuse0), then route ordinary stdout to
// stderr. Actual native pipe peers prove protocol/error separation.
.globl _stdio_aliases
_stdio_aliases:
sub sp,sp,#512
mov x0,#0
IO 41,-1,0
mov x19,x0
mov x0,#0
IO 6,0,0
mov x0,#1
IO 41,-1,0
mov x20,x0
mov x0,#2
mov x1,#1
IO 90,1,0
mov x0,x19
IO 41,-1,0
mov x21,x0
// Descriptor flags belong to the alias, not to the shared input description.
mov x0,x19
mov x1,#2
mov x2,#1
IO 92,0,0
mov x0,x19
mov x1,#1
IO 92,1,0
mov x0,x21
mov x1,#1
IO 92,0,0
bl Lstdio_fill
// Pipe pread is ESPIPE, and bad copyout cannot consume input bytes.
mov x0,x21
add x1,sp,#132
mov x2,#2
mov x3,#0
IO 153,29,29
mov x0,x19
mov x1,#1
mov x2,#2
IO 3,14,14
mov x27,#0
bl Lstdio_canary
mov x0,x19
add x1,sp,#132
mov x2,#2
IO 3,2,0
ldrh w8,[sp,#132]
mov w9,#0x6261
cmp w8,w9
b.ne Lfail
mov x27,#2
bl Lstdio_canary
bl Lstdio_fill
mov x0,x21
add x1,sp,#132
mov x2,#2
IO 3,2,0
ldrh w8,[sp,#132]
mov w9,#0x6463
cmp w8,w9
b.ne Lfail
mov x27,#2
bl Lstdio_canary
mov x0,x19
IO 6,0,0
bl Lstdio_fill
mov x0,x21
add x1,sp,#132
mov x2,#4
IO 3,4,0
ldr w8,[sp,#132]
mov w9,#0x6665
movk w9,#0x6867,lsl #16
cmp w8,w9
b.ne Lfail
mov x27,#4
bl Lstdio_canary
bl Lstdio_fill
mov x0,x21
mov x1,#1
mov x2,#1
IO 3,0,0
mov x27,#0
bl Lstdio_canary
mov x0,x20
mov x1,#1
mov x2,#8
IO 4,14,14
mov x0,x20
adr x1,Lstdio_protocol
mov x2,#8
IO 4,8,0
mov x0,#1
adr x1,Lstdio_error
mov x2,#8
IO 4,8,0
mov x0,#2
adr x1,Lstdio_error
mov x2,#8
IO 4,8,0
mov x0,#2
IO 6,0,0
// Closing original stderr leaves its stdout alias genuinely usable.
mov x0,#1
adr x1,Lstdio_error
mov x2,#8
IO 4,8,0
mov x0,#1
IO 6,0,0
// The private protocol descriptor still owns the original stdout handle.
mov x0,x20
adr x1,Lstdio_protocol
mov x2,#8
IO 4,8,0
mov x0,x20
IO 6,0,0
mov x0,x21
mov x1,#1
mov x2,#1
IO 3,0,0
mov x0,x21
IO 6,0,0
mov x0,#0
IO 41,9,9
mov x0,#1
adr x1,Lstdio_error
mov x2,#8
IO 4,9,9
b Lpass

.globl _stdio_pending
_stdio_pending:
sub sp,sp,#512
mov x0,#0
add x1,sp,#132
mov x2,#1
IO 3,0,0
// A live empty pipe is not EOF. Cancellation/deadline must stop before here.
b Lfail
.globl _stdio_pending_notified
_stdio_pending_notified:
// Tell the real native peer that guest startup completed before it arms cancellation.
sub sp,sp,#128
mov x0,#1
adr x1,Lstdio_protocol
mov x2,#1
IO 4,1,0
add sp,sp,#128
b _stdio_pending
.macro DELAYED_READ name,selector,indirect
.globl \name
\name:
sub sp,sp,#512
bl Lstdio_fill
.if \indirect
mov x0,#\selector
mov x1,#0
add x2,sp,#132
mov x3,#1
IO 0,1,0
.else
mov x0,#0
add x1,sp,#132
mov x2,#1
IO \selector,1,0
.endif
ldrb w8,[sp,#132]
cmp w8,#0x51
b.ne Lfail
mov x27,#1
bl Lstdio_canary
b Lpass
.endmacro
DELAYED_READ _stdio_delayed,3,0
DELAYED_READ _stdio_delayed_nocancel,396,0
DELAYED_READ _stdio_delayed_indirect,3,1
DELAYED_READ _stdio_delayed_indirect_nocancel,396,1
.globl _stdio_delayed_eof
_stdio_delayed_eof:
.globl _stdio_eof
_stdio_eof:
sub sp,sp,#512
bl Lstdio_fill
mov x0,#0
mov x1,#1
mov x2,#1
IO 3,0,0
mov x27,#0
bl Lstdio_canary
b Lpass
.globl _stdio_absent
_stdio_absent:
sub sp,sp,#512
mov x0,#0
IO 41,9,9
mov x0,#1
IO 41,9,9
b Lpass

Lstdio_call:
str x2,[sp,#32]
str x3,[sp,#40]
str x4,[sp,#48]
str x5,[sp,#56]
str x6,[sp,#64]
str x7,[sp,#72]
mov x8,#0xb0000000
cbz x26,Lstdio_flags_ready
mov x8,#0x90000000
Lstdio_flags_ready:
msr nzcv,x8
mov x16,x24
svc #0x80
mrs x8,nzcv
mov x9,#0x90000000
cbz x26,Lstdio_check_flags
orr x9,x9,#0x20000000
Lstdio_check_flags:
cmp x8,x9
b.ne Lfail
cbnz x1,Lfail
cmn x25,#1
b.eq Lstdio_check_regs
cmp x0,x25
b.ne Lfail
Lstdio_check_regs:
ldr x8,[sp,#32]
cmp x2,x8
b.ne Lfail
ldr x8,[sp,#40]
cmp x3,x8
b.ne Lfail
ldr x8,[sp,#48]
cmp x4,x8
b.ne Lfail
ldr x8,[sp,#56]
cmp x5,x8
b.ne Lfail
ldr x8,[sp,#64]
cmp x6,x8
b.ne Lfail
ldr x8,[sp,#72]
cmp x7,x8
b.ne Lfail
ret
Lstdio_fill:
mov x8,#0x5a5a
movk x8,#0x5a5a,lsl #16
movk x8,#0x5a5a,lsl #32
movk x8,#0x5a5a,lsl #48
stp x8,x8,[sp,#128]
ret
Lstdio_canary:
ldr w8,[sp,#128]
mov w9,#0x5a5a
movk w9,#0x5a5a,lsl #16
cmp w8,w9
b.ne Lfail
add x10,x27,#132
Lstdio_canary_tail:
ldrb w8,[sp,x10]
cmp w8,#0x5a
b.ne Lfail
add x10,x10,#1
cmp x10,#144
b.lo Lstdio_canary_tail
ret

// Receive-only mach_msg2 bypasses every packed send header/MIG identifier.
// XNU selects a real receive right and an empty queue before any message or
// trailer copyout. Even an inaccessible output pointer is irrelevant when the
// source-defined zero timeout returns MACH_RCV_TIMED_OUT.
.globl _receive_empty
_receive_empty:
SETUP
str xzr,[sp,#512]
str xzr,[sp,#520]
mov x0,x19
add x1,sp,#512
mov x2,#0
add x3,sp,#528
mov x16,#-24
svc #0x80
cbnz x0,Lfail
ldr w21,[sp,#528]
// A mapped but unreadable/unwritable region must also remain untouched.
str xzr,[sp,#536]
mov x0,x19
add x1,sp,#536
mov x2,#0x4000
mov x3,#0
mov x4,#1
mov x5,#0
mov x16,#-15
svc #0x80
cbnz x0,Lfail
bl Lreceive_fill
add x22,sp,#1024
mov x23,#108
mov x24,x21
mov x25,#0x4003
movk x25,#0x1000,lsl #16
mov x26,#0x102
movk x26,#0x400,lsl #16
movk x26,#4,lsl #32
mov x27,#0
mov x29,#4811
bl Lreceive_call
// Minimal receive flags and zero capacity/data still yield a real timeout.
mov x22,#0
mov x23,#0
mov x26,#0x102
mov x29,#3405
bl Lreceive_call
mov x22,#1
mov x23,#108
mov x26,#0x102
movk x26,#0x400,lsl #16
movk x26,#4,lsl #32
mov x29,#200
bl Lreceive_call
adr x22,Lreceive_readonly
mov x29,#3403
bl Lreceive_call
add x22,sp,#1025
mov x29,#3612
bl Lreceive_call
ldr x22,[sp,#536]
mov x29,#4800
bl Lreceive_call
// The kernel timeout parameter is uint32; high bits cannot invent a wait.
mov x22,#0
mov x27,#1
lsl x27,x27,#32
mov x29,#3412
bl Lreceive_call
mov x27,#0
// Receive size is low32 bits; the packed high priority is a send-only field.
add x22,sp,#1024
mov x23,#108
movk x23,#0xffff,lsl #32
movk x23,#0xffff,lsl #48
mov x29,#3405
bl Lreceive_call
mov x23,#108
mov x24,x20
mov x29,#4811
bl Lreceive_call
// Overflowing unused receive pointer must not be probed on the empty queue.
mov x22,#-1
mov x29,#-1
bl Lreceive_call
// Multiple send CFI classifications are irrelevant without MACH_SEND_MSG.
mov x22,#0
mov x29,#3405
movk x26,#6,lsl #32
bl Lreceive_call
// Expose the protected allocation only after polling: even a host API that
// bypassed guest protections must not have written a fabricated reply there.
ldr x21,[sp,#536]
mov x0,x19
mov x1,x21
mov x2,#0x4000
mov x3,#0
mov x4,#1
mov x16,#-14
svc #0x80
cbnz x0,Lfail
mov x10,#0
Lreceive_protected_unchanged:
ldrb w8,[x21,x10]
cbnz w8,Lfail
add x10,x10,#1
cmp x10,#128
b.lo Lreceive_protected_unchanged
b Lpass

.globl _receive_names
_receive_names:
SETUP
bl Lreceive_fill
mov x22,#0
mov x23,#108
mov x24,#0
mov x25,#0x4002
movk x25,#0x1000,lsl #16
// Invalid-name selection precedes the otherwise unsupported infinite wait.
mov x26,#2
mov x27,#0
mov x29,#3405
bl Lreceive_call
mov x24,#-1
mov x26,#0x102
bl Lreceive_call
mov x24,#0xad07
movk x24,#0xde,lsl #16
bl Lreceive_call
eor x24,x20,#1
bl Lreceive_call
// Retire an actual receive right, then use its old name.
mov x0,x19
mov x1,x20
mov x2,#1
mov x3,#-1
mov x16,#-19
svc #0x80
cbnz x0,Lfail
mov x24,x20
bl Lreceive_call
// Destroying a receive right with a send reference creates an actual deadname;
// its lookup failure must not be mistaken for an active wrong-right guard.
str xzr,[sp,#512]
str xzr,[sp,#520]
mov w8,#4
str w8,[sp,#512]
mov x0,x19
add x1,sp,#512
mov x2,#0
add x3,sp,#528
mov x16,#-24
svc #0x80
cbnz x0,Lfail
ldr w21,[sp,#528]
mov x0,x19
mov x1,x21
mov x2,#1
mov x3,#-1
mov x16,#-19
svc #0x80
cbnz x0,Lfail
mov x24,x21
bl Lreceive_call
b Lpass

.globl _receive_wait_positive
_receive_wait_positive:
SETUP
mov x26,#0x102
mov x27,#1
b Lreceive_unsupported
.globl _receive_wait_infinite
_receive_wait_infinite:
SETUP
mov x26,#2
mov x27,#0
b Lreceive_unsupported
.globl _receive_options_vector
_receive_options_vector:
SETUP
mov x26,#0x102
movk x26,#1,lsl #32
mov x27,#0
b Lreceive_unsupported
.globl _receive_options_sync
_receive_options_sync:
SETUP
mov x26,#0x4102
mov x27,#0
b Lreceive_unsupported
.globl _receive_options_strict
_receive_options_strict:
SETUP
mov x26,#0x302
mov x27,#0
b Lreceive_unsupported
.globl _receive_options_peek
_receive_options_peek:
SETUP
mov x26,#0x8102
mov x27,#0
b Lreceive_unsupported
.globl _receive_special_reply
_receive_special_reply:
SETUP
mov x16,#-50
svc #0x80
mov x20,x0
mov x26,#0x102
mov x27,#0
b Lreceive_unsupported
.globl _receive_wrong_right
_receive_wrong_right:
SETUP
mov x20,x19
mov x26,#0x102
mov x27,#0
Lreceive_unsupported:
bl Lreceive_fill
// Regression for stale BSD attribution: an unsupported later Mach trap must
// record rawX16=-47/interrupt2 rather than this successful getpid selector20.
mov x16,#20
svc #0x80
b.cs Lfail
cbnz x1,Lfail
mov x22,#1
mov x23,#108
mov x24,x20
mov x25,#0
mov x29,#3405
bl Lreceive_call
b Lfail

Lreceive_fill:
mov x8,#0x5a5a
movk x8,#0x5a5a,lsl #16
movk x8,#0x5a5a,lsl #32
movk x8,#0x5a5a,lsl #48
mov x9,#1024
Lreceive_fill_loop:
str x8,[sp,x9]
add x9,x9,#8
cmp x9,#1152
b.lo Lreceive_fill_loop
ret
Lreceive_call:
mov x0,x22
mov x1,x26
// Every send-only field is deliberately nonsensical, including known MIGids.
mov x2,#-1
mov x3,#-1
mov w4,#-1
orr x4,x4,x29,lsl #32
mov w5,#-1
orr x5,x5,x24,lsl #32
mov x6,x23
mov x7,x27
str x1,[sp,#768]
str x2,[sp,#776]
str x3,[sp,#784]
str x4,[sp,#792]
str x5,[sp,#800]
str x6,[sp,#808]
str x7,[sp,#816]
mov x8,#0xa0000000
msr nzcv,x8
mov x16,#-47
svc #0x80
mrs x8,nzcv
mov x9,#0xa0000000
cmp x8,x9
b.ne Lfail
cmp x0,x25
b.ne Lfail
ldr x8,[sp,#768]
ldr x9,[sp,#776]
cmp x1,x8
b.ne Lfail
cmp x2,x9
b.ne Lfail
ldr x8,[sp,#784]
ldr x9,[sp,#792]
cmp x3,x8
b.ne Lfail
cmp x4,x9
b.ne Lfail
ldr x8,[sp,#800]
ldr x9,[sp,#808]
cmp x5,x8
b.ne Lfail
cmp x6,x9
b.ne Lfail
ldr x8,[sp,#816]
cmp x7,x8
b.ne Lfail
// Check all potential header/payload/trailer bytes and readonly source bytes.
mov x10,#1024
adr x11,Lreceive_readonly
Lreceive_unchanged:
ldrb w8,[sp,x10]
cmp w8,#0x5a
b.ne Lfail
ldrb w8,[x11],#1
cmp w8,#0x5a
b.ne Lfail
add x10,x10,#1
cmp x10,#1152
b.lo Lreceive_unchanged
ret

// csops_audittoken consumes the actual task_info token. XNU kern_proc.c
// f6217f89 validates only PID and generation; identity/session words are not
// authentication claims. Both syscall entry ABIs execute this entire batch.
.globl _audit_csops_direct
_audit_csops_direct:
SETUP
QUERY 15,8,0
mov x28,#0
b Lcsops_batch
.globl _audit_csops_indirect
_audit_csops_indirect:
SETUP
QUERY 15,8,0
mov x28,#1
Lcsops_batch:
add x29,sp,#448
ldp x8,x9,[sp,#40]
stp x8,x9,[x29]
ldp x8,x9,[sp,#56]
stp x8,x9,[x29,#16]
ldr w21,[x29,#20]
mov x22,#0
add x23,sp,#544
mov x24,#4
mov x25,#0
mov x26,x21
mov x27,x29
// 0: genuine current token, real STATUS (no fabricated signature trust).
bl Lcsops
// 1: pid0 aliases self, not a fabricated PID in the token.
mov x26,#0
bl Lcsops
mov x26,x21
// 2-3: NULL is EINVAL before even the process lookup.
mov x27,#0
mov x25,#22
bl Lcsops
mov x26,#-1
bl Lcsops
// 4: missing PID precedes copyin of a nonNULL bad token.
mov x27,#1
mov x25,#3
bl Lcsops
mov x26,x21
mov x27,x29
// 5-6: independently mismatched PID and generation are ESRCH.
ldr w8,[x29,#20]
eor w8,w8,#1
str w8,[x29,#20]
bl Lcsops
str w21,[x29,#20]
ldr w8,[x29,#28]
eor w8,w8,#1
str w8,[x29,#28]
bl Lcsops
ldr w8,[sp,#68]
str w8,[x29,#28]
// 7: all six unrelated token words differ, but PID/generation match.
mov x9,#0
Lmutate_token:
ldr w8,[x29,x9]
eor w8,w8,#1
str w8,[x29,x9]
add x9,x9,#4
cmp x9,#20
b.lo Lmutate_token
ldr w8,[x29,#24]
eor w8,w8,#1
str w8,[x29,#24]
mov x25,#0
bl Lcsops
ldp x8,x9,[sp,#40]
stp x8,x9,[x29]
ldp x8,x9,[sp,#56]
stp x8,x9,[x29,#16]
// 8-9: unreadable and overflowing full32byte ranges are EFAULT.
mov x27,#1
mov x25,#14
bl Lcsops
mov x27,#-16
bl Lcsops
// 10: successful token admission cannot bypass a bad output pointer.
mov x27,x29
mov x23,#1
bl Lcsops
add x23,sp,#544
// 11-12: real absent CS_VALID/DEBUGGED => EINVAL for DER; token copyin
// nevertheless precedes that trust gate and must yield EFAULT on bad input.
mov x22,#16
mov x25,#22
bl Lcsops
mov x27,#1
mov x25,#14
bl Lcsops
mov x22,#0
// Allocate real guest memory and place a valid token across two16KiB pages.
// Source runtime mappings/protections, not injected host memory, govern copyin.
str xzr,[sp,#552]
mov x0,x19
add x1,sp,#552
mov x2,#0x8000
mov x3,#0
mov x4,#1
mov x5,#3
mov x16,#-15
svc #0x80
cbnz x0,Lfail
ldr x20,[sp,#552]
add x27,x20,#4,lsl #12
sub x27,x27,#16
ldp x8,x9,[x29]
stp x8,x9,[x27]
ldp x8,x9,[x29,#16]
stp x8,x9,[x27,#16]
// 13: readable boundary crossing must succeed, including every token word.
mov x25,#0
bl Lcsops
mov x0,x19
add x1,x20,#4,lsl #12
mov x2,#0x4000
mov x3,#0
mov x4,#0
mov x16,#-14
svc #0x80
cbnz x0,Lfail
// 14-15: mapped PROT_NONE and a partly readable32byte range both fail.
add x27,x20,#4,lsl #12
mov x25,#14
bl Lcsops
sub x27,x27,#16
bl Lcsops
b Lpass

Lcsops:
mov w8,#0x5a5a
movk w8,#0x5a5a,lsl #16
str w8,[sp,#540]
str w8,[sp,#544]
str w8,[sp,#548]
mov x0,x26
mov x1,x22
mov x2,x23
mov x3,x24
mov x4,x27
mov x16,#170
cbz x28,Lcsops_ready
mov x5,x4
mov x4,x3
mov x3,x2
mov x2,x1
mov x1,x0
mov x0,#170
mov x16,#0
Lcsops_ready:
mov x8,#0x90000000
msr nzcv,x8
svc #0x80
mrs x8,nzcv
mov x9,#0x90000000
cbz x25,Lcsops_flags
orr x9,x9,#0x20000000
Lcsops_flags:
cmp x8,x9
b.ne Lfail
cmp x0,x25
b.ne Lfail
cbnz x1,Lfail
mov w9,#0x5a5a
movk w9,#0x5a5a,lsl #16
ldr w8,[sp,#540]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#548]
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#544]
cbnz x25,Lcsops_error_output
cbnz w8,Lfail
ret
Lcsops_error_output:
cmp w8,w9
b.ne Lfail
ret

// Register contract, wire fields, trailer and byte canaries are checked for
// every query. x27 selects a deliberate request error; x28 is Mach trap status.
Lcall:
mov x8,#0x5a5a
movk x8,#0x5a5a,lsl #16
movk x8,#0x5a5a,lsl #32
movk x8,#0x5a5a,lsl #48
mov x9,#0
Lfill:
str x8,[sp,x9]
add x9,x9,#8
cmp x9,#432
b.lo Lfill
mov w8,#0x1513
str w8,[sp]
mov w8,#40
str w8,[sp,#4]
str w24,[sp,#8]
str w20,[sp,#12]
str wzr,[sp,#16]
mov w8,#3405
str w8,[sp,#20]
str wzr,[sp,#24]
mov w8,#1
str w8,[sp,#28]
str w22,[sp,#32]
str w23,[sp,#36]
cmp x27,#1
b.ne Lheader_mode
str wzr,[sp,#28]
Lheader_mode:
cmp x27,#2
b.ne Lrequest_ready
str wzr,[sp,#8]
Lrequest_ready:
mov x0,sp
mov x1,#3
movk x1,#2,lsl #32
mov x2,#0x1513
movk x2,#40,lsl #32
mov w3,w24
orr x3,x3,x20,lsl #32
mov x4,#3405
lsl x4,x4,#32
lsl x5,x20,#32
cmp x27,#3
b.ne Ldescriptor_ready
orr x5,x5,#1
Ldescriptor_ready:
mov x6,x26
mov x7,#0
mov x8,#0xa0000000
msr nzcv,x8
mov x16,#-47
svc #0x80
mrs x8,nzcv
mov x9,#0xa0000000
cmp x8,x9
b.ne Lfail
cmp x0,x28
b.ne Lfail
mov x8,#3
movk x8,#2,lsl #32
cmp x1,x8
b.ne Lfail
mov x8,#0x1513
movk x8,#40,lsl #32
cmp x2,x8
b.ne Lfail
mov w8,w24
orr x8,x8,x20,lsl #32
cmp x3,x8
b.ne Lfail
mov x8,#3405
lsl x8,x8,#32
cmp x4,x8
b.ne Lfail
lsl x8,x20,#32
cmp x27,#3
b.ne Ldescriptor_check
orr x8,x8,#1
Ldescriptor_check:
cmp x5,x8
b.ne Lfail
cmp x6,x26
b.ne Lfail
cbnz x7,Lfail
cbnz x28,Ltransport
ldr w8,[sp]
mov w9,#0x1200
cmp w8,w9
b.ne Lfail
ldr w8,[sp,#8]
cbnz w8,Lfail
ldr w8,[sp,#12]
cmp w8,w20
b.ne Lfail
ldr w8,[sp,#16]
cbnz w8,Lfail
ldr w8,[sp,#20]
cmp w8,#3505
b.ne Lfail
ldr w8,[sp,#24]
cbnz w8,Lfail
ldr w8,[sp,#28]
cmp w8,#1
b.ne Lfail
ldr w8,[sp,#32]
cmp w8,w25
b.ne Lfail
mov x10,#36
cbnz x25,Lsize
mov x9,#8
cmp x22,#15
b.eq Lcount
mov x9,#2
cmp x22,#13
b.eq Lcount
mov x9,#5
cmp x23,#4
b.ne Lcount
mov x9,#4
Lcount:
ldr w8,[sp,#36]
cmp w8,w9
b.ne Lfail
mov x10,#40
add x10,x10,x9,lsl #2
Lsize:
ldr w8,[sp,#4]
cmp w8,w10
b.ne Lfail
ldr w8,[sp,x10]
cbnz w8,Lfail
add x10,x10,#4
ldr w8,[sp,x10]
cmp w8,#8
b.ne Lfail
add x10,x10,#4
// Check every byte after the genuine reply and its trailer, including where
// a count or partial token would erroneously appear on an error reply.
Lcanary:
cmp x10,#432
b.hs Lreturn
ldrb w8,[sp,x10]
cmp w8,#0x5a
b.ne Lfail
add x10,x10,#1
b Lcanary
Ltransport:
// Transport errors must not fabricate any token reply or mutate the request.
ldr w8,[sp,#20]
cmp w8,#3405
b.ne Lfail
ldr w8,[sp,#32]
cmp w8,w22
b.ne Lfail
ldr w8,[sp,#36]
cmp w8,w23
b.ne Lfail
mov x10,#40
b Lcanary
Lreturn: ret
Lpass:
mov x16,#65535
svc #0x80
b .
Lfail:
mov x16,#65534
svc #0x80
b .
Lreceive_readonly: .space 128,0x5a
Lstdio_protocol: .ascii "protocol"
Lstdio_error: .ascii "stderr!!"
.p2align 2
)";
}

int main(){fs::path root;try{
    const auto clang=ToolPaths::SwiftBin({})/"clang.exe",linker=ToolPaths::LlvmBin({})/"ld64.lld.exe";
    if(!fs::is_regular_file(clang)||!fs::is_regular_file(linker))return 77;
    root=fs::temp_directory_path()/("OPENFRUIT-task-info-"+NewOperationId());
    const auto tree=root/"tree",source=root/"task-info.s",object=root/"task-info.o";
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
    const auto probe=[&](const std::string& symbol,const std::string& expected="unsupported_interrupt",
        const DarwinProcessStreams& streams=DarwinProcessStreams{},const DarwinClosureOptions& options=DarwinClosureOptions{}){
        const auto entry=std::find_if(metadata.exports.begin(),metadata.exports.end(),[&](const auto& value){return value.symbol==symbol;});
        Require(entry!=metadata.exports.end(),"Owned entry export absent: "+symbol);
        auto input=bytes;const auto pc=header->address+entry->value;std::memcpy(input.data()+state_offset+16+32*8,&pc,8);Write(interpreter,input);
        auto result=MapDarwinArm64Images("/process/main",{tree},options,{},false,true,streams);
        Require(result.mapped&&Field(result.bootstrap,"entered").Bool(),"Owned guest did not enter: "+symbol+" "+result.diagnostic);
        Require(result.bootstrap.GetString("stop_reason")==expected&&(expected!="unsupported_interrupt"||Number(result.bootstrap,"syscall_selector")==65535),
            "Owned task_info consumer failed: "+symbol+" "+result.bootstrap.Serialize());
        Require(Read(interpreter)==input&&Sha256File(executable)==executable_hash,"Probe mutated owned input files");
        if(!symbol.starts_with("_stdio_"))
            Require(Number(result.bootstrap,"mach_msg2_call_count")>0,"No real Mach message routing attempt recorded");
        const bool rejected_before_query=symbol=="_descriptor_count"||symbol=="_bad_ndr"||symbol=="_invalid_source"
            ||symbol.starts_with("_receive_")||symbol.starts_with("_stdio_");
        Require((Number(Field(result.bootstrap,"task_info"),"calls")==0)==rejected_before_query,
            "Transport rejection and semantic task_info invocation metrics were conflated");
        return result;
    };
    const auto first=probe("_tokens"),second=probe("_tokens");
    const auto& identity=Field(first.bootstrap,"audit_identity");const auto& next_identity=Field(second.bootstrap,"audit_identity");
    Require(Number(identity,"pid")>1&&Number(identity,"pid_version")>0
        &&Number(identity,"pid")!=Number(next_identity,"pid")
        &&Number(identity,"pid_version")!=Number(next_identity,"pid_version"),"Separate actual task lifetimes reused PID or audit generation");
    Require(Number(identity,"audit_user_id")==UINT32_MAX&&Number(identity,"audit_session_id")==0,"Default non-login audit identity differs");
    probe("_counts");probe("_ports");probe("_exact_buffers");probe("_peer_tokens");
    for(const auto* symbol:{"_audit_csops_direct","_audit_csops_indirect"}){
        const auto result=probe(symbol);
        const auto& signing=Field(result.bootstrap,"code_signing");
        const auto& calls=Field(signing,"call_prefix").ArrayItems();
        Require(Number(signing,"calls")==16&&calls.size()==16,
            std::string("Audit-token query batch was incomplete: ")+symbol);
        Require(Number(signing,"flags")==0,"Owned unsigned process acquired fabricated signature trust");
        const int errors[]={0,0,22,22,3,3,3,0,14,14,14,22,14,0,14,14};
        const bool token_copied[]={true,true,false,false,false,true,true,true,false,false,true,true,false,true,false,false};
        const bool token_matches[]={true,true,false,false,false,false,false,true,false,false,true,true,false,true,false,false};
        const auto& genuine=Field(Field(result.bootstrap,"audit_identity"),"audit_token").ArrayItems();
        Require(genuine.size()==8,"Actual task audit identity lacks eight words");
        for(std::size_t i=0;i<calls.size();++i){
            const auto context=std::string(symbol)+" call "+std::to_string(i);
            const auto& call=calls[i];const auto& token=Field(call,"audit_token").ArrayItems();
            Require(Field(call,"audited").Bool(),"Audit syscall was mislabeled as ordinary csops: "+context);
            Require(Field(call,"errno").Int()==errors[i],"Wrong source-defined errno: "+context);
            Require(Field(call,"audit_token_copied").Bool()==token_copied[i]
                &&Field(call,"audit_token_matches").Bool()==token_matches[i],
                "Copyin, identity admission and operation result were conflated: "+context);
            Require((Number(call,"audit_token_pointer")==0)==(i==2||i==3),
                "Wrong direct/indirect audit pointer: "+context);
            Require(token.size()==(token_copied[i]?8:0),"Diagnostic exposed an uncopied/partial token: "+context);
            Require(Field(call,"copied").Bool()==(errors[i]==0),"Output copyout mismatch: "+context);
            Require(Number(call,"status")==0,"Audit admission fabricated signing status: "+context);
            for(std::size_t word=0;word<token.size();++word){
                const bool changed=(i==5&&word==5)||(i==6&&word==7)
                    ||(i==7&&word!=5&&word!=7);
                Require((token[word].Serialize()!=genuine[word].Serialize())==changed,
                    "Copied token differs from the actual guest producer: "+context+" word "+std::to_string(word));
            }
        }
    }
    probe("_bad_header");probe("_descriptor_count");probe("_invalid_source");
    for(const auto* symbol:{"_audit_short","_audit_no_trailer","_audit_half_trailer","_error_short"})
        probe(symbol,"mach_msg2_reply_buffer_too_small");
    probe("_bad_ndr","unsupported_task_info_request_layout");
    const auto empty_receive=probe("_receive_empty");
    const auto& empty=Field(empty_receive.bootstrap,"mach_receive");
    const auto& empty_calls=Field(empty,"call_prefix").ArrayItems();
    Require(Number(empty,"calls")==11&&Number(empty,"empty_timeouts")==11
        &&Number(empty,"invalid_names")==0&&Number(empty,"unsupported_waits")==0&&empty_calls.size()==11,
        "Receive-only empty-queue semantic counters differ");
    Require(!Field(empty,"message_delivery_supported").Bool()&&!Field(empty,"blocking_receive_supported").Bool(),
        "Empty polling advertised unimplemented message delivery or blocking receive");
    for(std::size_t i=0;i<empty_calls.size();++i){const auto& call=empty_calls[i];
        Require(call.GetString("outcome")=="empty_timeout"&&Number(call,"result")==0x10004003
            &&Number(call,"normalized_timeout")==0
            &&Number(call,"timeout")==((i==6)?(1ULL<<32):0)
            &&Number(call,"receive_size")==((i==1)?0:108),
            "Receive-only timeout was confused with send/MIG parsing, size or guest memory");
    }
    const auto& raw_empty=Field(empty_receive.bootstrap,"mach_msg2_calls").ArrayItems();
    Require(raw_empty.size()==11&&Number(raw_empty[0],"options")==0x404000102ULL
        &&Number(raw_empty[0],"send_size")==UINT32_MAX&&Number(raw_empty[0],"id")==4811
        &&Number(raw_empty[1],"data")==0&&Number(raw_empty[2],"data")==1
        &&Number(raw_empty[9],"data")==UINT64_MAX,
        "Owned receive consumer did not exercise the original ABI and ignored stale send fields");
    const auto named_receive=probe("_receive_names");
    const auto& names=Field(named_receive.bootstrap,"mach_receive");
    Require(Number(names,"calls")==6&&Number(names,"invalid_names")==6
        &&Number(names,"empty_timeouts")==0&&Number(names,"unsupported_waits")==0,
        "Missing/retired/deadname lookup was conflated with a live queue or wait");
    const auto& name_calls=Field(names,"call_prefix").ArrayItems();
    Require(name_calls.size()==6,"Invalid-name batch was truncated");
    for(const auto& call:name_calls)
        Require(call.GetString("outcome")=="invalid_name"&&Number(call,"result")==0x10004002,
            "Invalid receive name returned an unrelated send/guard/memory error");
    for(const auto* symbol:{"_receive_wait_positive","_receive_wait_infinite",
        "_receive_options_vector","_receive_options_sync","_receive_options_strict",
        "_receive_options_peek",
        "_receive_special_reply","_receive_wrong_right"}){
        const std::string name=symbol;
        const auto outcome=name.starts_with("_receive_wait_")?"unsupported_wait"
            :name.starts_with("_receive_options_")?"unsupported_options"
            :name=="_receive_special_reply"?"unsupported_special_reply":"unsupported_guard";
        const auto expected=std::string("unsupported_mach_receive_")
            +(name.starts_with("_receive_wait_")?"wait":name.starts_with("_receive_options_")?"options"
                :name=="_receive_special_reply"?"special_reply":"guard");
        const auto result=probe(name,expected);
        Require(Number(result.bootstrap,"syscall_selector")==UINT64_MAX-46
            &&Number(result.bootstrap,"interrupt")==2,"Unsupported Mach trap retained stale BSD selector attribution");
        const auto& identity=Field(result.bootstrap,"thread_identity");
        const auto& bsd_calls=Field(identity,"call_prefix").ArrayItems();
        Require(Number(identity,"getpid_calls")==1&&bsd_calls.size()==1
            &&Number(bsd_calls[0],"raw_selector")==20&&Number(bsd_calls[0],"selector")==20,
            "Prior BSD getpid provenance was lost when capturing the later unsupported Mach trap");
        const auto& receive=Field(result.bootstrap,"mach_receive");
        const auto& calls=Field(receive,"call_prefix").ArrayItems();
        Require(Number(receive,"calls")==1&&Number(receive,"empty_timeouts")==0
            &&Number(receive,"invalid_names")==0
            &&Number(receive,"unsupported_waits")==(name.starts_with("_receive_wait_")?1:0)
            &&calls.size()==1&&calls[0].GetString("outcome")==outcome&&Field(calls[0],"result").IsNull(),
            "Unsupported receive path fabricated a result or empty-queue success: "+name);
    }
    {
        NativePipe input,output,errors;input.Preload("abcdefgh");input.CloseWriter();
        const DarwinProcessStreams streams{input.reader,output.writer,errors.writer};
        const auto result=probe("_stdio_aliases","unsupported_interrupt",streams);
        const auto protocol=output.Drain(),diagnostics=errors.Drain();
        Require(protocol=="protocolprotocol"&&diagnostics=="stderr!!stderr!!stderr!!",
            "Original dup/close/dup2 order mixed actual protocol and stderr pipe bytes");
        const auto& files=Field(result.bootstrap,"original_files");
        Require(Number(files,"reads")==5&&Number(files,"bytes_read")==8
            &&Number(files,"write_calls")==5&&Number(files,"bytes_written")==40,
            "Real stdin EOF/alias consumption and stdout/stderr byte counters differ");
        const auto& outputs=Field(files,"output_descriptors").ArrayItems();
        Require(outputs.size()==2,"Explicit stdout/error bindings were not distinct native descriptions");
        for(const auto& descriptor:outputs){
            const auto fd=Number(descriptor,"fd");
            Require((fd==1||fd==2)&&Field(descriptor,"closed").Bool(),
                "Closing original stdio slots or aliases corrupted output lifetime");
            Require(Number(descriptor,"calls")==(fd==1?2:3)
                &&Number(descriptor,"bytes")==(fd==1?16:24)
                &&descriptor.GetString("prefix_hex")==
                    (fd==1?"70726f746f636f6c70726f746f636f6c"
                        :"737464657272212173746465727221217374646572722121"),
                "Native descriptor evidence differs from actual pipe peer output");
        }
        const auto& calls=Field(result.bootstrap,"file_call_prefix").ArrayItems();
        Require(calls.size()>=4&&Number(calls[0],"selector")==41
            &&Field(calls[0],"arguments").ArrayItems()[0].Serialize()=="0"
            &&Number(calls[1],"selector")==6
            &&Field(calls[1],"arguments").ArrayItems()[0].Serialize()=="0"
            &&Number(calls[2],"selector")==41
            &&Field(calls[2],"arguments").ArrayItems()[0].Serialize()=="1"
            &&Number(calls[2],"value")==0
            &&Number(calls[3],"selector")==90
            &&Field(calls[3],"arguments").ArrayItems()[0].Serialize()=="2"
            &&Field(calls[3],"arguments").ArrayItems()[1].Serialize()=="1",
            "Owned stdio consumer did not reproduce original StandardIO descriptor reuse/order");
    }
    {
        NativePipe input;const DarwinProcessStreams streams{input.reader,nullptr,nullptr};
        DarwinClosureOptions options;options.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(300);
        const auto result=probe("_stdio_pending","deadline",streams,options);
        const auto& files=Field(result.bootstrap,"original_files");
        Require(Number(files,"reads")==0&&Number(files,"bytes_read")==0,
            "Live empty native input fabricated a completed read or EOF");
        const auto& waits=Field(result.bootstrap,"native_pipe_waits");
        Require(Number(waits,"parks")==1&&Number(waits,"wakes")==0,
            "Idle deadline did not leave the real read parked without a wake");
    }
    {
        NativePipe input,ready;const DarwinProcessStreams streams{input.reader,ready.writer,nullptr};
        CancellationSource cancellation;DarwinClosureOptions options;options.cancellation=cancellation.Token();
        options.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        std::atomic<bool> guest_ready=false;
        std::jthread canceller([&](std::stop_token stop){
            while(!stop.stop_requested()&&std::chrono::steady_clock::now()<options.deadline){
                DWORD available=0;
                if(PeekNamedPipe(ready.reader,nullptr,0,nullptr,&available,nullptr)&&available){
                    char marker=0;DWORD count=0;
                    if(ReadFile(ready.reader,&marker,1,&count,nullptr)&&count==1&&marker=='p'){
                        guest_ready=true;
                        std::this_thread::sleep_for(std::chrono::milliseconds(150));
                        cancellation.Cancel();
                    }
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });
        // Deliberately exceed the old startup-based 150ms timer. The peer must
        // synchronize with guest readiness, rather than cancelling initialization.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto result=probe("_stdio_pending_notified","cancelled",streams,options);
        canceller.request_stop();canceller.join();
        Require(guest_ready.load(),"Cancellation peer did not observe actual guest startup");
        const auto& files=Field(result.bootstrap,"original_files");
        Require(Number(files,"reads")==0&&Number(files,"bytes_read")==0,
            "Cancelling an idle read fabricated completion or consumed input");
        Require(Number(Field(result.bootstrap,"native_pipe_waits"),"parks")==1,
            "Cancellation did not exercise an actually parked reader");
    }
    for(const auto* symbol:{"_stdio_delayed","_stdio_delayed_nocancel","_stdio_delayed_indirect","_stdio_delayed_indirect_nocancel"}){
        NativePipe input;const DarwinProcessStreams streams{input.reader,nullptr,nullptr};
        std::atomic<bool> written=false;
        // Keep the writer open throughout guest completion. Delay exceeds the
        // removed 1500ms workaround and cannot be mistaken for real EOF.
        std::jthread writer([&]{std::this_thread::sleep_for(std::chrono::milliseconds(1700));
            DWORD count=0;written=WriteFile(input.writer,"Q",1,&count,nullptr)!=FALSE&&count==1;});
        DarwinClosureOptions options;options.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        const auto result=probe(symbol,"unsupported_interrupt",streams,options);
        writer.join();Require(written.load(),"Delayed native writer failed");
        const auto& files=Field(result.bootstrap,"original_files");
        Require(Number(files,"reads")==1&&Number(files,"bytes_read")==1,
            "Delayed actual read was counted more than once or fabricated EOF");
        const auto& waits=Field(result.bootstrap,"native_pipe_waits");
        Require(Number(waits,"parks")==1&&Number(waits,"wakes")==1&&Number(waits,"pending")==0,
            "Delayed reader did not park, wake and release its pending request exactly once");
    }
    {
        NativePipe input;const DarwinProcessStreams streams{input.reader,nullptr,nullptr};
        std::jthread closer([&]{std::this_thread::sleep_for(std::chrono::milliseconds(1700));input.CloseWriter();});
        DarwinClosureOptions options;options.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        const auto result=probe("_stdio_delayed_eof","unsupported_interrupt",streams,options);
        closer.join();const auto& files=Field(result.bootstrap,"original_files");
        Require(Number(files,"reads")==1&&Number(files,"bytes_read")==0,
            "Delayed writer close did not complete one genuine EOF read");
        const auto& waits=Field(result.bootstrap,"native_pipe_waits");
        Require(Number(waits,"parks")==1&&Number(waits,"wakes")==1&&Number(waits,"pending")==0,
            "Delayed real EOF did not wake and retire the parked read");
    }
    {
        NativePipe input;input.CloseWriter();
        const DarwinProcessStreams streams{input.reader,nullptr,nullptr};
        const auto result=probe("_stdio_eof","unsupported_interrupt",streams);
        const auto& files=Field(result.bootstrap,"original_files");
        Require(Number(files,"reads")==1&&Number(files,"bytes_read")==0,
            "A genuinely closed input writer did not produce real EOF");
    }
    probe("_stdio_absent");
    const auto reject_input=[&](void* handle){
        const auto before=Read(interpreter);
        const DarwinProcessStreams streams{handle,nullptr,nullptr};
        const auto result=MapDarwinArm64Images("/process/main",{tree},{},{},false,true,streams);
        const auto* entered=result.bootstrap.Get("entered");
        Require(!result.mapped&&(!entered||!entered->Bool())
            &&result.diagnostic.find("stdin byte-pipe binding failed")!=std::string::npos,
            "Invalid explicit native input was accepted or failed for an unrelated reason");
        Require(Read(interpreter)==before&&Sha256File(executable)==executable_hash,
            "Failed native stream admission mutated owned images");
    };
    reject_input(INVALID_HANDLE_VALUE);
    {NativePipe pipe;reject_input(pipe.writer);}
    struct NativeFile {HANDLE value=INVALID_HANDLE_VALUE;~NativeFile(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
    NativeFile disk{CreateFileW(executable.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
    Require(disk.value!=INVALID_HANDLE_VALUE,"Owned input-admission disk fixture could not open");
    reject_input(disk.value);
    std::cout<<"Darwin task_info/MIG, audit-token, receive-only polling and original stdio alias/pipe/admission consumers PASS\n";
    fs::remove_all(root);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\nOwned fixture retained at "<<root.string()<<'\n';return 1;}}
