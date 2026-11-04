#include "darwin_pthread_registration.hpp"
#include <iostream>
#include <algorithm>
#include <stdexcept>
using namespace OpenFruit;
void Require(bool ok,const char* reason){if(!ok)throw std::runtime_error(reason);}
void Put(std::array<std::uint8_t,60>& b,std::size_t p,std::uint64_t v,unsigned width=4){for(unsigned n=0;n<width;++n)b[p+n]=static_cast<std::uint8_t>(v>>(8*n));}
int main(){try{
    std::array<std::uint8_t,60> data{};Put(data,0,60,8);Put(data,8,48,8);Put(data,24,16);
    Put(data,28,40);Put(data,32,41);Put(data,48,1024);Put(data,52,0xffffffff);
    data[56]=0x5a;const auto before=data;DarwinPthreadRegistrationInput r;
    Require(!DecodeDarwinPthreadRegistration(64,true,60,data,999,r),"Growing registration input rejected");
    Require(r.copied_bytes==56&&r.input_version==60&&r.unknown_tail_bytes==4&&data==before,"Copy-in tail/version or caller memory changed");
    Require(r.tsd_offset==16&&r.max_tsd_offset==40&&r.dispatch_queue_offset==0&&r.return_to_kernel_offset==40
        &&r.mach_thread_self_offset==0&&r.wq_quantum_expiry_offset==0&&r.joinable_offset_bits==1024,"XNU offset bounds/untouched join bits differ");
    Require(DecodeDarwinPthreadRegistration(-1,true,0,{},0,r)==22&&r.copied_bytes==0,"Invalid pthread size lost error precedence/reset");
    Require(DecodeDarwinPthreadRegistration(65537,false,0,{},0,r)==22,"Oversize thread structure admitted");
    Require(DecodeDarwinPthreadRegistration(64,true,7,{},0,r)==22,"Short version header admitted");
    Require(DecodeDarwinPthreadRegistration(64,true,60,std::span(data).first(55),0,r)==14,"Partial copy-in accepted");
    Put(data,0,56,8);Require(DecodeDarwinPthreadRegistration(64,true,60,data,0,r)==22,"Version and requested size mismatch accepted");
    Require(!DecodeDarwinPthreadRegistration(65536,false,0,{},65528,r)&&r.dispatch_queue_offset==65528&&r.max_tsd_offset==65528,"Maximum thread/legacy offset boundary differs");
    Require(!DecodeDarwinPthreadRegistration(0,false,0,{},1,r)&&!r.dispatch_queue_offset&&!r.max_tsd_offset,"Zero pthread size fabricated TSD space");
    Put(data,0,56,8);Put(data,24,65);Put(data,8,1,8);Put(data,28,1);
    Require(!DecodeDarwinPthreadRegistration(64,true,56,data,0,r)&&!r.tsd_offset&&!r.dispatch_queue_offset&&!r.return_to_kernel_offset,"Out-of-range TSD base kept offsets");
    Put(data,0,8,8);Require(!DecodeDarwinPthreadRegistration(64,true,8,std::span(data).first(8),0,r)&&r.copied_bytes==8&&r.max_tsd_offset==56,"Older size-version zero-extension differs");

    // Copy-out and feature capability tests (BSD 366 bsdthread_register)
    DarwinPthreadRegistrationOutput out;
    out.version = 56;
    out.main_qos = 0x8ff; // THREAD_QOS_LEGACY (tier 4, relpri 0)
    out.stack_addr_hint = 0x21f1d0000ULL;
    out.mutex_default_policy = 0x100; // _PTHREAD_REG_DEFAULT_USE_ULOCK

    // Decode standard 60-byte input
    Put(data,0,60,8);Put(data,8,160,8);Put(data,24,224);
    Put(data,28,40);Put(data,32,24);Put(data,48,104);Put(data,52,960);
    Require(!DecodeDarwinPthreadRegistration(16384,true,60,data,0,r),"Standard input decode failed");
    Require(r.dispatch_queue_offset==160&&r.tsd_offset==224&&r.return_to_kernel_offset==40
        &&r.mach_thread_self_offset==24&&r.joinable_offset_bits==104&&r.wq_quantum_expiry_offset==960,
        "Decoded offsets do not match standard inputs");

    std::array<std::uint8_t,56> copyout{};
    Require(!EncodeDarwinPthreadRegistration(r,out,copyout),"Encode copyout failed");

    // Helper reader
    const auto ReadU64 = [&](std::size_t at) -> std::uint64_t {
        std::uint64_t val = 0; for(unsigned i=0;i<8;++i) val |= std::uint64_t(copyout[at+i]) << (8*i); return val;
    };
    const auto ReadU32 = [&](std::size_t at) -> std::uint32_t {
        std::uint32_t val = 0; for(unsigned i=0;i<4;++i) val |= std::uint32_t(copyout[at+i]) << (8*i); return val;
    };

    Require(ReadU64(0)==56,"Copy-out version mismatch");
    Require(ReadU64(8)==160,"Copy-out preserved dispatch_queue_offset mismatch");
    Require(ReadU64(16)==0x8ff,"Copy-out main_qos mismatch");
    Require(ReadU32(24)==224,"Copy-out preserved tsd_offset mismatch");
    Require(ReadU32(28)==40,"Copy-out preserved return_to_kernel_offset mismatch");
    Require(ReadU32(32)==24,"Copy-out preserved mach_thread_self_offset mismatch");
    Require(ReadU64(36)==0x21f1d0000ULL,"Copy-out stack_addr_hint mismatch");
    Require(ReadU32(44)==0x100,"Copy-out mutex_default_policy mismatch");
    Require(ReadU32(48)==104,"Copy-out preserved joinable_offset_bits mismatch");
    Require(ReadU32(52)==960,"Copy-out preserved wq_quantum_expiry_offset mismatch");

    // Partial/insufficient buffer rejection
    std::array<std::uint8_t,55> short_copyout{};
    Require(EncodeDarwinPthreadRegistration(r,out,short_copyout)==14,"Truncated copyout buffer accepted");

    // Decoder output determines copyout length, including old ABI prefixes.
    for(std::size_t size=8;size<=60;++size){
        data.fill(0x5a);Put(data,0,size,8);
        Require(!DecodeDarwinPthreadRegistration(16384,true,size,data,0,r),"Negotiated input prefix rejected");
        std::array<std::uint8_t,64> destination;destination.fill(0xa5);
        const auto count=std::min(size,DarwinPthreadRegistrationBytes);
        Require(!EncodeDarwinPthreadRegistration(r,out,std::span(destination).first(count)),"Negotiated copyout prefix rejected");
        Require(destination[0]==56&&destination[7]==0,"Prefix copyout omitted outgoing ABI version");
        for(std::size_t n=count;n<destination.size();++n)Require(destination[n]==0xa5,"Copyout overwrote unnegotiated tail");
        const auto before_copyout=destination;
        Require(EncodeDarwinPthreadRegistration(r,out,std::span(destination).first(count-1))==14&&destination==before_copyout,
            "Short negotiated buffer modified output or lost EFAULT");
    }
    Require(!DecodeDarwinPthreadRegistration(64,false,0,{},0,r),"Legacy input rejected");
    Require(!EncodeDarwinPthreadRegistration(r,out,{}),"Legacy input attempted copyout");
    DarwinPthreadRegistrationOutput no_providers;
    Require(!no_providers.main_qos&&!no_providers.mutex_default_policy&&!no_providers.stack_addr_hint,
        "Wire codec invented policy or address providers");
    Require(DarwinPthreadSupportedFeatures==0,"Wire codec published unimplemented capabilities");

    // Task publication ordering is independent of a successful userspace reply.
    Put(data,0,60,8);Put(data,8,160,8);Put(data,24,224);
    Require(!DecodeDarwinPthreadRegistration(16384,true,60,data,0,r),"Commit input decode failed");
    DarwinPthreadRegistrationState owner;
    Require(CommitDarwinPthreadRegistration(owner,r,-1,0x1000,0x2000,0x9000)==22
        &&!owner.registered&&!owner.stack_addr_hint,"Invalid size mutated owner registration");
    Require(!CommitDarwinPthreadRegistration(owner,r,16384,0x1000,0x2000,0x9000)
        &&owner.registered&&owner.thread_start==0x1000&&owner.workqueue_start==0x2000
        &&owner.pthread_bytes==16384&&owner.input.tsd_offset==224,"Registration did not publish owned entries and offsets");
    Require(EncodeDarwinPthreadRegistration(owner.input,out,short_copyout)==14
        &&owner.registered&&owner.thread_start==0x1000,"Failed reply encoding rolled back registration");
    const auto registered_input=owner.input.normalized_data;
    DarwinPthreadRegistrationInput other;
    Require(!DecodeDarwinPthreadRegistration(64,false,0,{},8,other),"Legacy duplicate input decode failed");
    Require(CommitDarwinPthreadRegistration(owner,other,64,0x3000,0x4000,0xa000)==22
        &&owner.stack_addr_hint==0xa000&&owner.thread_start==0x1000&&owner.workqueue_start==0x2000
        &&owner.pthread_bytes==16384&&owner.input.normalized_data==registered_input,
        "Duplicate registration lost stack-hint-before-duplicate ordering or replaced published entries");
    DarwinPthreadRegistrationState independent;
    Require(!CommitDarwinPthreadRegistration(independent,other,64,0x3000,0x4000,0xb000)
        &&independent.input.dispatch_queue_offset==8&&owner.thread_start==0x1000,
        "Independent task registration crossed owner or lost legacy offset");

    // BSD 368 WQOPS_SETUP_DISPATCH: packed little-endian, kernel-prefix copyin.
    data.fill(0);Put(data,0,2);Put(data,8,0x8877665544332211ULL,8);
    Put(data,16,0x1122334455667788ULL,8);data[24]=0xa5;
    const auto config_input=data;
    DarwinWorkqueueDispatchConfiguration cfg;
    Require(!DecodeDarwinWorkqueueDispatchConfiguration(24,data,cfg)
        &&cfg.version==2&&!cfg.flags&&cfg.serialno_offset==0x8877665544332211ULL
        &&cfg.label_offset==0x1122334455667788ULL&&cfg.has_label&&cfg.copied_bytes==24,
        "Full dispatch configuration ABI differs");
    const auto ReadConfigPrefix=[&](std::size_t at,std::size_t size){
        std::uint64_t value=0;
        for(std::size_t n=0;n<8&&at+n<size;++n)value|=std::uint64_t(data[at+n])<<(8*n);
        return value;
    };
    for(std::size_t size=0;size<=60;++size){
        cfg={11,12,13,14,15,true};const auto preserved=cfg;
        const auto copied=std::min(size,DarwinWorkqueueDispatchConfigurationBytes);
        Require(DarwinWorkqueueDispatchCopyinBytes(size)==copied,"Dispatch copyin limit differs");
        const auto error=DecodeDarwinWorkqueueDispatchConfiguration(size,std::span(data).first(copied),cfg);
        if(!size)Require(error==45&&cfg==preserved,"Empty configuration did not zero-extend version or preserve output");
        else {
            Require(!error&&cfg.version==2&&cfg.copied_bytes==copied&&cfg.has_label
                &&cfg.serialno_offset==ReadConfigPrefix(8,copied)
                &&cfg.label_offset==ReadConfigPrefix(16,copied),
                "Partial dispatch configuration was not zero-extended to kernel size");
            const auto decoded=cfg;
            Require(DecodeDarwinWorkqueueDispatchConfiguration(size,std::span(data).first(copied-1),cfg)==14
                &&cfg==decoded,"Short dispatch copyin lost EFAULT precedence or modified output");
        }
    }
    Require(data==config_input,"Dispatch codec modified original input or unknown tail");
    for(const auto size:std::array<std::uint64_t,6>{24,0x7fffffff,0x80000000,0xffffffff,
        0x5555555500000018ULL,0x11111111ffffffffULL}){
        Require(DarwinWorkqueueDispatchCopyinBytes(size)==24
            &&!DecodeDarwinWorkqueueDispatchConfiguration(size,std::span(data).first(24),cfg)
            &&cfg.copied_bytes==24,"Signed affinity narrowing or 24-byte clamp differs");
    }
    Require(DarwinWorkqueueDispatchCopyinBytes(0xffffffff00000001ULL)==1,
        "Setup affinity did not discard high syscall-register bits");
    Put(data,0,1);
    Require(!DecodeDarwinWorkqueueDispatchConfiguration(24,data,cfg)&&!cfg.has_label
        &&!cfg.label_offset&&cfg.serialno_offset==0x8877665544332211ULL,
        "Version-1 configuration incorrectly updates the label field");
    Put(data,0,0xffffffff);
    Require(!DecodeDarwinWorkqueueDispatchConfiguration(24,data,cfg)&&cfg.has_label
        &&cfg.version==0xffffffff,"Future dispatch version lost recognized prefix");
    for(unsigned bit=0;bit<32;++bit){
        Put(data,4,std::uint32_t{1}<<bit);const auto preserved=cfg;
        Require(DecodeDarwinWorkqueueDispatchConfiguration(24,data,cfg)==45&&cfg==preserved,
            "Unknown dispatch flag accepted or error mutated output");
        Require(DecodeDarwinWorkqueueDispatchConfiguration(24,std::span(data).first(23),cfg)==14
            &&cfg==preserved,"Flag validation preceded copyin failure");
    }
    Put(data,4,0);Put(data,0,0);const auto preserved_cfg=cfg;
    Require(DecodeDarwinWorkqueueDispatchConfiguration(24,data,cfg)==45&&cfg==preserved_cfg,
        "Unsupported dispatch version accepted or mutated output");

    // Workqueue request QoS deliberately ignores the entire relative byte.
    // Applying SET_SELF's relative-priority validator here would reject requests
    // XNU accepts; workq_reqthreads only extracts thread_qos and overcommit.
    DarwinWorkqueueRequest request;
    for(std::uint8_t tier=1;tier<=6;++tier)for(unsigned relative=0;relative<256;++relative){
        const auto priority=(1u<<(tier+7))|relative;
        Require(!DecodeDarwinWorkqueueRequest(0x20,true,1,priority,request)
            &&request.count==1&&request.qos_tier==tier&&!request.overcommit,
            "Workqueue request validated ignored relative priority or decoded wrong QoS");
        Require(!DecodeDarwinWorkqueueRequest(0x20,true,65535,priority|0x80000000u,request)
            &&request.count==65535&&request.qos_tier==tier&&request.overcommit,
            "Maximum overcommit request or QoS ignored-byte boundary differs");
    }
    Require(!DecodeDarwinWorkqueueRequest(0x20,true,0xaaaa00000001ULL,0xbbbbbbbb000008ffULL,request)
        &&request.count==1&&request.qos_tier==4&&!request.overcommit,
        "Request ABI did not narrow count/priority to int32 fields");
    Require(!DecodeDarwinWorkqueueRequest(0x20,true,1,0x3fffu,request)&&request.qos_tier==1,
        "Workqueue QoS does not select the least significant valid tier bit");
    Require(!DecodeDarwinWorkqueueRequest(0x20,true,1,0x1d8008ffu,request)
        &&request.qos_tier==4&&!request.overcommit,
        "Request incorrectly treats ignored priority flags as cooperative operation");
    const auto preserved_request=request;
    const auto RequestError=[&](std::uint32_t operation,bool opened,std::uint64_t count,
        std::uint64_t priority,int expected,const char* reason){
        Require(DecodeDarwinWorkqueueRequest(operation,opened,count,priority,request)==expected
            &&request==preserved_request,reason);
    };
    for(const auto count:std::array<std::uint64_t,5>{0,65536,0x7fffffff,0x80000000,0xffffffff})
        RequestError(0x20,true,count,0x8ff,22,"Invalid request count accepted or mutated output");
    RequestError(0x20,false,1,0x8ff,22,"Unopened workqueue request accepted");
    for(const auto priority:std::array<std::uint64_t,5>{0xff,0x4000ff,0x200008ff,0x020008ff,0x220008ff})
        RequestError(0x20,true,1,priority,22,"Invalid request priority accepted or mutated output");
    RequestError(0x30,true,0,0x8ff,22,"Cooperative unsupported error hid invalid count");
    RequestError(0x30,true,2,0,22,"Cooperative count error preceded unspecified QoS");
    RequestError(0x30,true,2,0x800008ffu,45,"Cooperative type conflict preceded source count limit");
    RequestError(0x30,true,1,0x800008ffu,22,"Cooperative overcommit conflict accepted");
    RequestError(0x30,true,1,0x8ff,45,"Cooperative workqueue claimed supported provider");
    RequestError(0x40,true,1,0x8ff,22,"Kevent return accidentally decoded as thread request");
    RequestError(0x100,true,1,0x8ff,22,"Workloop return accidentally decoded as thread request");
    RequestError(0xffffffff,true,1,0x8ff,22,"Unknown request operation accepted");
    Require(DarwinPthreadSupportedFeatures==0,"Workqueue codecs fabricated capability bits");

    std::cout<<"Darwin pthread registration and workqueue configuration/request ABI boundaries PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
