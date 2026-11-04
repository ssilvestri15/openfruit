#include "darwin_pthread_creation.hpp"
#include "darwin_thread_context.hpp"
#include <unicorn/arm64.h>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* text){if(!ok)throw std::runtime_error(text);}
void Uc(uc_err error){Require(error==UC_ERR_OK,uc_strerror(error));}
struct Engine {uc_engine* value=nullptr;Engine(){Uc(uc_open(UC_ARCH_ARM64,UC_MODE_ARM,&value));}~Engine(){uc_close(value);}};
void Put(std::array<std::uint8_t,56>& data,std::size_t at,std::uint64_t value,unsigned width=4){for(unsigned n=0;n<width;++n)data[at+n]=static_cast<std::uint8_t>(value>>(8*n));}
std::uint64_t Read(uc_engine* engine,int reg){std::uint64_t value=0;Uc(uc_reg_read(engine,reg,&value));return value;}
void TestKeventUpcall(){
    using Status=DarwinWorkqueuePreparationStatus;
    std::array<std::uint8_t,56> wire{};Put(wire,0,56,8);Put(wire,24,224);Put(wire,32,24);
    DarwinPthreadRegistrationState registration;registration.registered=true;
    registration.pthread_bytes=1024;registration.workqueue_start=0x10000;
    Require(!DecodeDarwinPthreadRegistration(registration.pthread_bytes,true,wire.size(),wire,0,registration.input),
        "Kevent registration decode failed");
    DarwinWorkqueueUpcallRequest request;
    request.self=0x21807;request.stack_bottom=0x21000;request.user_address_max=0x23fff;
    request.actual_tsd_base=request.self+registration.input.tsd_offset;
    request.first_use_tsd_installed=true;request.thread_port=1799;request.qos_tier=4;
    const std::uint64_t list=0x21800-DarwinWorkqueueKeventListLength*64;
    request.flags=DarwinWorkqueueKevent|DarwinWorkqueueEventManager;
    request.kevent_list=list;request.kevent_count=3;
    DarwinWorkqueueUpcallState state;
    const auto word64=[&](std::size_t at){return std::uint64_t{state.arm64_words[at]}|(std::uint64_t{state.arm64_words[at+1]}<<32);};
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,request,state)==Status::Ready,"Kevent upcall preparation failed");
    // _pthread_wqthread(self,kport,stackaddr,keventlist,flags,nkevents), SP at the list.
    Require(word64(6)==list&&word64(10)==3&&word64(62)==list
        &&word64(8)==(DarwinWorkqueueKevent|DarwinWorkqueueEventManager|DarwinWorkqueueNewSpi
            |DarwinWorkqueuePriorityQos|DarwinWorkqueueTsdBaseSet|4),"Kevent upcall registers wrong");
    auto bad=request;bad.kevent_list=list+64;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,bad,state)==Status::InvalidAddress,"Misplaced kevent list accepted");
    bad=request;bad.kevent_count=DarwinWorkqueueKeventListLength+1;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,bad,state)==Status::InvalidAddress,"Oversized kevent list accepted");
    bad=request;bad.flags=DarwinWorkqueueEventManager;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,bad,state)==Status::UnsupportedFlags,"Manager without kevent accepted");
    auto loop=request;loop.flags=DarwinWorkqueueKevent|DarwinWorkqueueWorkloop|DarwinWorkqueueOvercommit;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,loop,state)==Status::Ready
        &&word64(6)==list&&word64(62)==((list-8)&~std::uint64_t{15})
        &&word64(8)==(DarwinWorkqueueKevent|DarwinWorkqueueWorkloop|DarwinWorkqueueOvercommit|DarwinWorkqueueNewSpi
            |DarwinWorkqueuePriorityQos|DarwinWorkqueueTsdBaseSet|4),"Workloop upcall registers wrong");
    bad=request;bad.flags=DarwinWorkqueueWorkloop;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,bad,state)==Status::UnsupportedFlags,"Workloop without kevent accepted");
    bad=request;bad.flags|=DarwinWorkqueueWorkloop;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,bad,state)==Status::UnsupportedFlags,"Manager workloop accepted");
    bad=request;bad.stack_bottom=list;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,bad,state)==Status::InvalidAddress,"Stack below kevent list accepted");
}
void TestWorkqueuePreparation(){
    using Status=DarwinWorkqueuePreparationStatus;
    std::array<std::uint8_t,56> wire{};Put(wire,0,56,8);Put(wire,24,224);Put(wire,32,24);
    DarwinPthreadRegistrationState registration;registration.registered=true;
    registration.pthread_bytes=1024;registration.workqueue_start=0x10000;
    Require(!DecodeDarwinPthreadRegistration(registration.pthread_bytes,true,wire.size(),wire,0,registration.input),
        "Workqueue registration decode failed");
    DarwinWorkqueueUpcallRequest request;
    request.self=0x21807;request.stack_bottom=0x21000;request.user_address_max=0x23fff;
    request.actual_tsd_base=request.self+registration.input.tsd_offset;
    request.first_use_tsd_installed=true;request.thread_port=1799;request.qos_tier=1;
    DarwinWorkqueueUpcallState state;
    const auto word64=[](const auto& words,std::size_t at){
        return std::uint64_t{words[at]}|(std::uint64_t{words[at+1]}<<32);
    };
    for(std::uint8_t tier=1;tier<=6;++tier){
        request.qos_tier=tier;
        for(const auto flags:{0U,DarwinWorkqueueOvercommit}){
            request.flags=flags;
            Require(PrepareDarwinWorkqueueUpcallArm64(registration,request,state)==Status::Ready,
                "Ordinary workqueue first upcall preparation failed");
            Require(word64(state.arm64_words,0)==request.self&&word64(state.arm64_words,2)==request.thread_port
                &&word64(state.arm64_words,4)==request.stack_bottom&&!word64(state.arm64_words,6)
                &&word64(state.arm64_words,8)==(flags|DarwinWorkqueueNewSpi|DarwinWorkqueuePriorityQos
                    |DarwinWorkqueueTsdBaseSet|tier)&&!word64(state.arm64_words,10)
                &&word64(state.arm64_words,62)==(request.self&~std::uint64_t{15})
                &&word64(state.arm64_words,64)==registration.workqueue_start
                &&state.tsd_base==request.actual_tsd_base&&state.first_use,
                "Workqueue first upcall ABI differs from source");
        }
    }
    // This fresh-context consumer proves the entry/TSD flag reaches actual CPU
    // state. It does not implement reused-worker FP/context transitions.
    Engine engine;auto* e=engine.value;
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_ALL));Uc(uc_mem_map(e,0x20000,16384,UC_PROT_ALL));
    const std::array<std::uint32_t,2> code{0xd53bd066,0x910003e7}; // mrs x6,TPIDRRO_EL0; mov x7,sp
    Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    std::uint64_t creator=0xcafe;Uc(uc_reg_write(e,UC_ARM64_REG_X0,&creator));
    DarwinThreadContext context;Uc(context.InitializeArm64(e,state.arm64_words,state.tsd_base));
    Require(Read(e,UC_ARM64_REG_X0)==creator,"Workqueue fresh preparation altered creator");
    Uc(context.Restore(e));
    Require(Read(e,UC_ARM64_REG_X0)==request.self&&Read(e,UC_ARM64_REG_X1)==request.thread_port
        &&Read(e,UC_ARM64_REG_X2)==request.stack_bottom&&!Read(e,UC_ARM64_REG_X3)
        &&Read(e,UC_ARM64_REG_X4)==word64(state.arm64_words,8)&&!Read(e,UC_ARM64_REG_X5)
        &&Read(e,UC_ARM64_REG_PC)==registration.workqueue_start,"Workqueue ABI consumer mismatch");
    Uc(uc_emu_start(e,registration.workqueue_start,registration.workqueue_start+sizeof(code),0,code.size()));
    Require(Read(e,UC_ARM64_REG_X6)==request.actual_tsd_base
        &&Read(e,UC_ARM64_REG_X7)==(request.self&~std::uint64_t{15})
        &&(Read(e,UC_ARM64_REG_X4)&DarwinWorkqueueTsdBaseSet),"Workqueue first TSD/SP/flag consumer mismatch");
    // Reuse preserves the owner's current TSD, even if it differs from the
    // original self+offset. Only the GPR plan is tested; InitializeArm64 must
    // not be used to claim preservation of a parked worker's FP/NEON state.
    request.first_use=false;request.first_use_tsd_installed=false;
    request.flags=DarwinWorkqueueReuse|DarwinWorkqueueOvercommit;request.actual_tsd_base=0x23000;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,request,state)==Status::Ready
        &&!state.first_use&&state.tsd_base==request.actual_tsd_base
        &&word64(state.arm64_words,8)==(request.flags|DarwinWorkqueueNewSpi|DarwinWorkqueuePriorityQos|request.qos_tier),
        "Reuse lost owner TSD or incorrectly emitted first-use TSD flag");
    const auto preserved=state;const auto valid_request=request;const auto valid_registration=registration;
    const auto fail=[&](Status expected){
        Require(PrepareDarwinWorkqueueUpcallArm64(registration,request,state)==expected,"Workqueue preparation error differs");
        Require(state.arm64_words==preserved.arm64_words&&state.tsd_base==preserved.tsd_base
            &&state.first_use==preserved.first_use,"Failed workqueue preparation changed output");
        request=valid_request;registration=valid_registration;
    };
    registration.registered=false;fail(Status::Unregistered);
    registration.workqueue_start=0;fail(Status::InvalidEntrypoint);
    registration.workqueue_start=0x10001;fail(Status::InvalidEntrypoint);
    registration.workqueue_start=request.user_address_max+1;fail(Status::InvalidEntrypoint);
    request.thread_port=0;fail(Status::InvalidPort);request.thread_port=UINT32_MAX;fail(Status::InvalidPort);
    for(const auto flag:{DarwinWorkqueueNewSpi,DarwinWorkqueueTsdBaseSet,DarwinWorkqueueEventManager,DarwinWorkqueueWorkloop,0x01000000U,0x80000000U}){
        request.flags|=flag;fail(Status::UnsupportedFlags);
    }
    request.first_use=true;fail(Status::InconsistentLifecycle);
    request.flags=0;fail(Status::InconsistentLifecycle);
    request.first_use_tsd_installed=true;fail(Status::InconsistentLifecycle);
    request.qos_tier=0;fail(Status::InvalidQos);request.qos_tier=7;fail(Status::InvalidQos);
    request.self=0;fail(Status::InvalidAddress);request.stack_bottom=0;fail(Status::InvalidAddress);
    request.stack_bottom=request.self&~std::uint64_t{15};fail(Status::InvalidAddress);
    request.self=request.user_address_max+1;fail(Status::InvalidAddress);
    registration.pthread_bytes=0;fail(Status::InvalidAddress);
    registration.pthread_bytes=-1;fail(Status::InvalidAddress);
    request.user_address_max=request.self+registration.pthread_bytes-2;fail(Status::InvalidAddress);
    request.self=UINT64_MAX-100;request.user_address_max=UINT64_MAX;fail(Status::InvalidAddress);
    request.actual_tsd_base=0;fail(Status::TsdNotPrepared);
    request.actual_tsd_base=request.user_address_max+1;fail(Status::TsdNotPrepared);
    // First-use preconditions are explicit caller errors, not invented kernel errno.
    request=valid_request;request.first_use=true;request.flags=0;request.first_use_tsd_installed=true;
    request.actual_tsd_base=request.self+registration.input.tsd_offset;
    const auto first_request=request;
    const auto fail_first=[&](Status expected){fail(expected);request=first_request;};
    request.first_use_tsd_installed=false;fail_first(Status::TsdNotPrepared);
    request.actual_tsd_base++;fail_first(Status::TsdNotPrepared);
    registration.input.tsd_offset=0;fail_first(Status::TsdNotPrepared);
    registration.input.tsd_offset=registration.pthread_bytes;fail_first(Status::TsdNotPrepared);
    // Exact inclusive allocation limit and unaligned self are valid; only SP is aligned.
    request.user_address_max=request.self+registration.pthread_bytes-1;
    Require(PrepareDarwinWorkqueueUpcallArm64(registration,request,state)==Status::Ready,
        "Exact last allocation address was rejected");
}
}
int main(){try{
    // Owned registration copy-in fixture; offsets are decoded by the production
    // producer, not injected into the creation output or restored registers.
    std::array<std::uint8_t,56> wire{};Put(wire,0,56,8);Put(wire,24,224);Put(wire,32,24);
    DarwinPthreadRegistrationInput registration;
    Require(!DecodeDarwinPthreadRegistration(16384,true,wire.size(),wire,0,registration),"Registration decode failed");
    DarwinPthreadCreateRequest request;
    request.user_func=0x123456789abcdef0;request.user_arg=0x20000;
    request.user_stack=0x20800;request.user_pthread=0x21000;
    request.user_address_max=0x2ffff;request.thread_port=1799;
    request.flags=DarwinPthreadStartCustom|DarwinPthreadStartSuspended;
    DarwinPthreadCreationState state;
    Require(!PrepareDarwinPthreadCreationArm64(true,0x10000,registration,request,state),"Supported creation preparation failed");
    Require(state.initially_suspended&&state.tsd_base==request.user_pthread+registration.tsd_offset
        &&state.mach_self_copyout&&state.mach_self_address==state.tsd_base+registration.mach_thread_self_offset
        &&state.mach_self_value==request.thread_port,"Derived suspension/TSD/copyout differ");
    Require(!state.arm64_words[66]&&!state.arm64_words[67],"Fresh status flags inherited");
    Engine engine;auto* e=engine.value;
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_ALL));Uc(uc_mem_map(e,0x20000,8192,UC_PROT_ALL));
    // Owned backend consumes the produced copyout plan into actual task-shared
    // memory. This is a contract consumer, not proof of Main's publication path.
    Uc(uc_mem_write(e,state.mach_self_address,&state.mach_self_value,sizeof(state.mach_self_value)));
    // Guest stores X0-X5, actual TPIDRRO_EL0 and the port loaded from its derived
    // MACH_THREAD_SELF slot: ldr x7,[x6,#24]; str x7,[x3,#56].
    // Then mrs x8,TPIDR_EL0; str x8,[x3,#64] consumes owner-derived CPU info.
    const std::array<std::uint32_t,9> code{0xa9000460,0xa9010c62,0xa9021464,0xd53bd066,0xf9001866,0xf9400cc7,0xf9001c67,0xd53bd048,0xf9002068};
    Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    std::uint64_t creator=0xcafe;Uc(uc_reg_write(e,UC_ARM64_REG_X0,&creator));
    std::uint64_t dirty_status=0xa0000000;Uc(uc_reg_write(e,UC_ARM64_REG_NZCV,&dirty_status));
    Uc(uc_reg_write(e,UC_ARM64_REG_X28,&creator));
    Uc(uc_reg_write(e,UC_ARM64_REG_TPIDR_EL0,&creator));
    DarwinThreadContext context;Uc(context.InitializeArm64(e,state.arm64_words,state.tsd_base));
    Require(Read(e,UC_ARM64_REG_X0)==creator&&Read(e,UC_ARM64_REG_NZCV)==dirty_status
        &&Read(e,UC_ARM64_REG_X28)==creator&&Read(e,UC_ARM64_REG_TPIDR_EL0)==creator,"Preparation altered live creator");
    Uc(context.Restore(e));Require(Read(e,UC_ARM64_REG_SP)==request.user_stack,"SP producer/consumer mismatch");
    Require(!Read(e,UC_ARM64_REG_NZCV)&&!Read(e,UC_ARM64_REG_X28)&&!Read(e,UC_ARM64_REG_X30),
        "Fresh creation inherited creator status/unused GPR/LR");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10000+sizeof(code),0,code.size()));
    std::array<std::uint64_t,9> values{};Uc(uc_mem_read(e,request.user_arg,values.data(),sizeof(values)));
    const std::array<std::uint64_t,9> expected{request.user_pthread,request.thread_port,request.user_func,
        request.user_arg,request.user_stack,DarwinPthreadStartCustom|DarwinPthreadStartTsdBaseSet,state.tsd_base,request.thread_port,0};
    Require(values==expected,"Creation ABI did not reach actual guest entry consumer");
    const auto preserved=state;
    const auto fail=[&](bool registered,int expected_error){
        Require(PrepareDarwinPthreadCreationArm64(registered,0x10000,registration,request,state)==expected_error,"Creation error mismatch");
        Require(state.arm64_words==preserved.arm64_words&&state.tsd_base==preserved.tsd_base
            &&state.mach_self_address==preserved.mach_self_address&&state.mach_self_value==preserved.mach_self_value
            &&state.initially_suspended==preserved.initially_suspended&&state.mach_self_copyout==preserved.mach_self_copyout,
            "Failed preparation modified output/copyout/suspension state");
    };
    fail(false,22);request.thread_port=0;fail(true,24);request.thread_port=UINT32_MAX;fail(true,24);request.thread_port=1799;
    request.flags=0;fail(true,22);
    request.flags=DarwinPthreadStartCustom|DarwinPthreadStartSetSched;fail(true,45);
    request.flags=DarwinPthreadStartCustom|DarwinPthreadStartQosClass|0x2001;fail(true,45);
    request.flags=DarwinPthreadStartCustom|DarwinPthreadStartTsdBaseSet;fail(true,45);
    request.flags=DarwinPthreadStartCustom|0x80000000;fail(true,45);
    request.flags=DarwinPthreadStartCustom;request.user_pthread=UINT64_MAX-100;fail(true,14);
    request.user_pthread=UINT64_MAX-registration.tsd_offset-10;fail(true,14);
    request.user_pthread=0x21001;request.user_stack=0x20801;
    Require(!PrepareDarwinPthreadCreationArm64(true,0x10000,registration,request,state)
        &&state.tsd_base==request.user_pthread+registration.tsd_offset&&!state.initially_suspended,
        "Unaligned source ABI values were silently normalized/rejected");
    DarwinThreadContext unaligned;
    Uc(unaligned.InitializeArm64(e,state.arm64_words,state.tsd_base));Uc(unaligned.Restore(e));
    Require(Read(e,UC_ARM64_REG_SP)==request.user_stack&&Read(e,UC_ARM64_REG_X4)==request.user_stack
        &&Read(e,UC_ARM64_REG_TPIDRRO_EL0)==request.user_pthread+registration.tsd_offset,
        "Unaligned source SP/X4/TSD did not reach backend without rounding");
    // SP alignment exceptions are guest/backend execution semantics, not an
    // invented _bsdthread_create argument validation rule.
    request.user_address_max=request.user_pthread+registration.tsd_offset;
    Require(!PrepareDarwinPthreadCreationArm64(true,0x10000,registration,request,state)
        &&state.tsd_base==request.user_address_max,"Exact vm_map_max was incorrectly clamped");
    request.user_address_max=0x20000;
    Require(!PrepareDarwinPthreadCreationArm64(true,0x10000,registration,request,state)&&!state.tsd_base
        &&state.arm64_words[10]==(DarwinPthreadStartCustom|DarwinPthreadStartTsdBaseSet),"XNU TSD map-limit clamp differs");
    Put(wire,32,0);
    Require(!DecodeDarwinPthreadRegistration(16384,true,wire.size(),wire,0,registration)
        &&!PrepareDarwinPthreadCreationArm64(true,0x10000,registration,request,state)
        &&!state.mach_self_copyout&&!state.mach_self_address&&!state.mach_self_value,
        "Absent MACH_THREAD_SELF slot fabricated copyout plan");
    // A zero normalized TSD offset has neither kernel-set flag nor copyout.
    Put(wire,24,20000);
    Require(!DecodeDarwinPthreadRegistration(16384,true,wire.size(),wire,0,registration)
        &&!PrepareDarwinPthreadCreationArm64(true,0x10000,registration,request,state)
        &&!state.tsd_base&&!state.mach_self_copyout&&state.arm64_words[10]==DarwinPthreadStartCustom,
        "Unavailable registration TSD fabricated storage/flag");
    TestWorkqueuePreparation();
    TestKeventUpcall();
    std::cout<<"Darwin ARM64 CUSTOM pthread creation and ordinary workqueue preparation/first guest consumer PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
