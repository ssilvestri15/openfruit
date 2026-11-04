#include "darwin_thread_run_queue.hpp"
#include "darwin_pthread_policy.hpp"
#include <unicorn/arm64.h>
#include <array>
#include <iostream>
#include <stdexcept>
#include <utility>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
void Uc(uc_err error){if(error!=UC_ERR_OK)throw std::runtime_error(uc_strerror(error));}
struct Engine {uc_engine* value=nullptr;Engine(){Uc(uc_open(UC_ARCH_ARM64,UC_MODE_ARM,&value));Uc(uc_ctl_set_cpu_model(value,UC_CPU_ARM64_MAX));}~Engine(){if(value)uc_close(value);}};
void Write(uc_engine* e,int reg,std::uint64_t value){Uc(uc_reg_write(e,reg,&value));}
std::uint64_t Read(uc_engine* e,int reg){std::uint64_t value=0;Uc(uc_reg_read(e,reg,&value));return value;}
void PriorityScheduling(){
    Engine engine;auto* e=engine.value;DarwinThreadContext first,second;DarwinThreadRunQueue queue(0x10004);
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    const std::array<std::uint32_t,2> code{0xf9000020,0xd5033f5f};Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,11);Write(e,UC_ARM64_REG_X1,0x20000);Uc(first.Capture(e));
    Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,22);Write(e,UC_ARM64_REG_X1,0x20000);Uc(second.Capture(e));
    Require(queue.Admit(1,first)&&queue.Admit(2,second),"Priority consumer admission failed");
    DarwinPthreadRunQueuePolicyProvider owner(queue,2);
    DarwinPthreadPolicyState policy{{4,0},true,0};
    auto operations=owner.Operations();
    Require(owner.Ready()&&!operations.apply_voucher&&!operations.apply_timeshare,
        "CPU priority provider implied a voucher or fixed/timeshare provider");
    std::uint32_t encoded=0;Require(EncodeDarwinPthreadQos({6,-15},encoded),"Priority encoding failed");
    Require(!ApplyDarwinBsdthreadCtl(policy,0x100,encoded,0,DarwinSetSelfQos,DarwinPthreadPolicyKind::Ordinary,operations)
        &&queue.Lookup(2)->effective_priority==38,"SET_SELF did not reach queue owner");
    Require(!queue.SetEffectivePriority(99,40)&&!queue.SetEffectivePriority(2,-1)&&!queue.SetEffectivePriority(2,128)
        &&queue.Lookup(2)->effective_priority==38,"Invalid priority mutated queue");
    std::uint64_t selected=0;Uc(queue.Dispatch(e,0,selected));Require(selected==2,"Higher priority peer did not precede older FIFO entry");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10004,0,1));std::uint64_t observed=0;Uc(uc_mem_read(e,0x20000,&observed,8));
    Require(observed==22,"Selected peer did not execute its actual guest store");
    Uc(queue.Block(e,7,{}));Uc(queue.Dispatch(e,0,selected));Require(selected==1,"Waiting high priority thread ran");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10004,0,1));Uc(uc_mem_read(e,0x20000,&observed,8));Require(observed==11,"Lower runnable thread lost execution");
    Require(queue.Wake(7,1)==1,"Priority waiter not woken");Uc(queue.YieldCurrent(e));
    Uc(queue.Suspend(e,2));Uc(queue.Dispatch(e,0,selected));Require(selected==1,"Suspended priority peer ran");
    Require(queue.Resume(2),"Priority peer resume failed");Uc(queue.YieldCurrent(e));
    Uc(queue.Dispatch(e,0,selected));Require(selected==2,"Wake/resume lost priority");
    Require(EncodeDarwinPthreadQos({4,0},encoded),"Equal priority encoding failed");
    Require(ApplyDarwinBsdthreadCtl(policy,0x100,encoded,0,DarwinSetSelfQos|DarwinSetSelfVoucher,
        DarwinPthreadPolicyKind::Ordinary,operations)==45&&queue.Lookup(2)->effective_priority==31
        &&policy.qos==DarwinPthreadQos{4,0},"Missing voucher lost independent queue QoS effect or fabricated success");
    Uc(queue.YieldCurrent(e));Uc(queue.Dispatch(e,0,selected));Require(selected==1,"Equal priority FIFO order lost");
    Uc(queue.YieldCurrent(e));Uc(queue.Dispatch(e,0,selected));Require(selected==2,"Equal priority peer rotation lost");
    Require(queue.Terminate(2)&&!queue.SetEffectivePriority(2,46)&&!owner.Ready()
        &&owner.ApplyQos({6,0})==37,"Terminated peer accepted priority");
}
void OrdinaryPolicyProvider(){
    // Independent XNU expected base priorities, not the resolver under test.
    constexpr int expected[6][16]={
        {4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1},
        {4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1},
        {20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5},
        {31,31,30,29,29,28,27,27,26,25,25,24,23,23,22,21},
        {37,37,37,36,36,36,35,35,34,34,34,33,33,33,32,32},
        {46,46,45,45,44,44,43,43,42,41,41,40,40,39,39,38}};
    for(std::uint8_t tier=1;tier<=6;++tier)for(int magnitude=0;magnitude<16;++magnitude){
        Engine engine;auto* e=engine.value;DarwinThreadContext first,second;DarwinThreadRunQueue queue(0x10004);
        Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));
        Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
        const std::array<std::uint32_t,2> code{0xf9000020,0xd5033f5f};
        Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
        Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,11);Write(e,UC_ARM64_REG_X1,0x20000);Uc(first.Capture(e));
        Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,22);Uc(second.Capture(e));
        DarwinPthreadRunQueuePolicyProvider provider(queue,2),missing(queue,99);
        Require(!provider.Ready()&&provider.ApplyQos({tier,-magnitude})==37
            &&!missing.Ready(),"Unadmitted CPU context acquired a policy");
        Require(queue.Admit(1,first)&&queue.Admit(2,second,true),"Policy provider context admission failed");
        Require(provider.Ready()&&provider.ApplyQos({tier,-magnitude})==0
            &&queue.Lookup(2)->effective_priority==expected[tier-1][magnitude],
            "Real admitted provider lost fine priority or maintenance/default QoS band");
        for(const auto invalid:{DarwinPthreadQos{0,0},{7,0},{1,1},{1,-16}})
            Require(provider.ApplyQos(invalid)==4&&queue.Lookup(2)->effective_priority==expected[tier-1][magnitude],
                "Invalid ordinary policy changed live queue priority");
        Require(missing.ApplyQos({4,0})==37&&queue.Lookup(1)->effective_priority==31,
            "Unknown provider changed another admitted context");
        Require(queue.Resume(2),"Policy-bearing suspended peer could not resume");
        std::uint64_t selected=0;Uc(queue.Dispatch(e,0,selected));
        const auto wanted=expected[tier-1][magnitude]>31?2u:1u;
        Require(selected==wanted,"Ordinary CPU policy did not select the actual guest context");
        Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10004,0,1));
        std::uint64_t stored=0;Uc(uc_mem_read(e,0x20000,&stored,8));
        Require(stored==(wanted==2?22u:11u),"CPU provider failed its actual guest store consumer");
        Require(queue.Terminate(2)&&!provider.Ready()&&provider.ApplyQos({4,0})==37,
            "Retired admitted provider retained scheduling authority");
    }
}
void ExclusiveSwitch(){
    Engine engine;auto* e=engine.value;DarwinThreadContext reserver,writer;DarwinThreadRunQueue queue(0x10018);
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    // LDXR x0,[x1]; STXR w2,x3,[x1]. The peer performs real guest stores 7 -> 9 -> 7.
    const std::array<std::uint32_t,7> code{0xc85f7c20,0xc8027c23,0xd2800120,0xf9000020,0xd28000e0,0xf9000020,0xd5033f5f};
    Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    std::uint64_t value=7;Uc(uc_mem_write(e,0x20000,&value,sizeof(value)));
    Write(e,UC_ARM64_REG_X1,0x20000);Write(e,UC_ARM64_REG_X3,42);
    Uc(uc_emu_start(e,0x10000,0x10008,0,2));Uc(uc_mem_read(e,0x20000,&value,sizeof(value)));
    Require(Read(e,UC_ARM64_REG_W2)==0&&value==42,"Uninterrupted exclusive-store positive control failed");
    value=7;Uc(uc_mem_write(e,0x20000,&value,sizeof(value)));
    Write(e,UC_ARM64_REG_PC,0x10000);Uc(reserver.Capture(e));
    Write(e,UC_ARM64_REG_PC,0x10008);Uc(writer.Capture(e));
    Require(queue.Admit(1,reserver)&&queue.Admit(2,writer),"Exclusive peer admission failed");
    std::uint64_t selected=0;Uc(queue.Dispatch(e,0,selected));Require(selected==1,"Exclusive reserver not dispatched");
    Uc(uc_emu_start(e,0x10000,0x10004,0,1));Uc(queue.YieldCurrent(e));
    Uc(queue.Dispatch(e,1,selected));Require(selected==2,"Exclusive writer not dispatched");
    Uc(uc_emu_start(e,0x10008,0x10018,0,4));Require(queue.Terminate(2),"Exclusive writer termination failed");
    Uc(queue.Dispatch(e,2,selected));Require(selected==1,"Exclusive reserver did not resume");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,1));Uc(uc_mem_read(e,0x20000,&value,sizeof(value)));
    Require(Read(e,UC_ARM64_REG_W2)!=0&&value==7,"Saved exclusive reservation survived peer ABA stores/context switches");
}
void SuspendedContexts(){
    Engine engine,foreign;auto* e=engine.value;DarwinThreadContext first,second;DarwinThreadRunQueue queue(0x10008);
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    const std::array<std::uint32_t,3> code{0x91000400,0xf9000020,0xd5033f5f};Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    std::array<std::uint32_t,68> words{};words[0]=10;words[2]=0x20000;words[62]=0x20800;words[64]=0x10000;
    Uc(first.InitializeArm64(e,words,0x20200));words[0]=20;words[2]=0x20008;words[62]=0x20900;
    Uc(second.InitializeArm64(e,words,0x20400));
    Require(queue.Admit(1,first,true)&&queue.Admit(2,second,true),"Suspended initial contexts not admitted");
    Require(queue.Suspend(foreign.value,1)==UC_ERR_ARG&&queue.Lookup(1)->suspend_count==1,"Foreign suspend changed task count");
    Uc(queue.Suspend(e,1));Require(queue.Lookup(1)->suspend_count==2&&queue.Resume(1)&&queue.Lookup(1)->suspend_count==1,"Nested suspension not counted");
    std::uint64_t selected=0;Uc(queue.Dispatch(e,0,selected));Require(selected==0,"Partially resumed or initially suspended context executed");
    Require(queue.Resume(2)&&!queue.Resume(2),"Extra resume succeeded without a suspension");Uc(queue.Dispatch(e,0,selected));
    Require(selected==2&&Read(e,UC_ARM64_REG_X0)==20&&Read(e,UC_ARM64_REG_TPIDRRO_EL0)==0x20400,"Resumed context identity/TSD incorrect");
    Uc(uc_emu_start(e,0x10000,0x10004,0,1));Uc(queue.Suspend(e,2));Uc(queue.Suspend(e,2));Require(queue.Resume(2),"Nested current-thread suspension could not resume once");
    Uc(queue.Dispatch(e,1,selected));Require(selected==0&&queue.Running()==0,"Current suspended context still running");
    Require(queue.Resume(1),"Initial context did not resume");Uc(queue.Dispatch(e,2,selected));Require(selected==1,"Eligible context skipped");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,2));Uc(queue.Block(e,0x99,100));Uc(queue.Suspend(e,1));
    Require(queue.Wake(0x99,1)==1&&queue.Lookup(1)->suspend_count==1,"Wake discarded suspension count");
    Require(queue.Resume(2),"Final peer resume failed");Uc(queue.Dispatch(e,3,selected));
    Require(selected==2&&Read(e,UC_ARM64_REG_X0)==21&&Read(e,UC_ARM64_REG_PC)==0x10004,"Suspend lost actual instruction continuation");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,1));Uc(queue.Block(e,0x77,200));Uc(queue.Suspend(e,2));
    Uc(queue.Dispatch(e,200,selected));Require(selected==0&&queue.Lookup(2)->wake_reason==DarwinThreadRunQueue::WakeReason::TimedOut
        &&queue.Lookup(2)->suspend_count==1,"Deadline resumed a suspended waiter or failed to expire its wait");
    Require(queue.Resume(1),"Signaled suspended thread did not resume");Uc(queue.Dispatch(e,201,selected));Require(selected==1&&queue.Terminate(1),"Signaled context lifecycle failed");
    Require(!queue.Resume(1)&&queue.Suspend(e,1)==UC_ERR_ARG,"Terminated context revived through suspend/resume");
    Require(queue.Resume(2),"Timed-out suspended peer did not resume");Uc(queue.Dispatch(e,202,selected));Require(selected==2&&queue.Terminate(2),"Timed-out context lifecycle failed");
    std::array<std::uint64_t,2> output{};Uc(uc_mem_read(e,0x20000,output.data(),sizeof(output)));
    Require(output==std::array<std::uint64_t,2>{11,21},"Initialized suspended contexts did not produce their actual guest stores");
}
void SchedulingModes(){
    Engine engine,foreign;auto* e=engine.value;
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    // Two actual instructions per slice: each selected saved context appends its
    // marker to shared memory, then advances its own write pointer.
    const std::array<std::uint32_t,3> code{0xf9000020,0x91002021,0xd5033f5f};
    Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    DarwinThreadContext first,second,third;DarwinThreadRunQueue queue(0x10008);
    for(const auto& item:std::array<std::pair<DarwinThreadContext*,std::uint64_t>,3>{{{&first,11},{&second,22},{&third,33}}}){
        Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,item.second);Write(e,UC_ARM64_REG_X1,0x20000);
        Uc(item.first->Capture(e));
    }
    Require(queue.Admit(1,first)&&queue.Admit(2,second)&&queue.Admit(3,third,true),"Scheduling-mode admission failed");
    Require(queue.SetEffectivePriority(1,40)&&queue.SetEffectivePriority(2,39)&&queue.SetEffectivePriority(3,50),"Scheduling-mode base priority failed");
    Require(queue.UpdateTimeshareUsage(1,80,4)&&queue.Lookup(1)->base_priority==40&&queue.Lookup(1)->effective_priority==35,
        "Measured timeshare usage did not produce the source-derived priority penalty");
    Require(!queue.SetTimeshare(99,false)&&!queue.UpdateTimeshareUsage(99,1,0)
        &&!queue.UpdateTimeshareUsage(1,999,32)&&!queue.UpdateTimeshareUsage(1,999,126)
        &&queue.Lookup(1)->sched_usage==80&&queue.Lookup(1)->pri_shift==4&&queue.Lookup(1)->effective_priority==35,
        "Unknown/invalid scheduling accounting mutated saved state");
    Require(queue.SetTimeshare(3,false)&&queue.Lookup(3)->suspend_count==1,
        "Mode change revived a suspended context");
    std::uint64_t selected=0;
    const auto execute=[&](std::uint64_t wanted,std::uint64_t marker){
        Uc(queue.Dispatch(e,0,selected));Require(selected==wanted,"Mode/accounting selected the wrong actual guest context");
        const auto output=Read(e,UC_ARM64_REG_X1);Write(e,UC_ARM64_REG_PC,0x10000);
        Uc(uc_emu_start(e,0x10000,0x10008,0,2));std::uint64_t observed=0;Uc(uc_mem_read(e,output,&observed,8));
        Require(observed==marker,"Scheduling decision did not reach the actual guest store");
    };
    execute(2,22); // Unused peer outranks CPU-consuming timeshare context1.
    Require(queue.PreemptCurrent(foreign.value,true)==UC_ERR_ARG&&queue.Running()==2
        &&queue.Lookup(2)->state==DarwinThreadRunQueue::State::Running,
        "Foreign-engine quantum transition altered live task state");
    Require(queue.SetTimeshare(1,false)&&queue.Lookup(1)->effective_priority==40,
        "Fixed mode retained a timeshare decay penalty");
    Uc(queue.PreemptCurrent(e,false));execute(1,11); // Higher priority preempts even a head-requeued peer.
    Require(queue.SetEffectivePriority(2,40),"Equal-priority peer update failed");
    Uc(queue.PreemptCurrent(e,true));execute(2,22); // FIXED still rotates on quantum expiry.
    Uc(queue.PreemptCurrent(e,false));execute(2,22); // Non-expired preemption retains head position.
    Uc(queue.YieldCurrent(e));execute(1,11); // Explicit yield relinquishes its place.
    Uc(queue.PreemptCurrent(e,true));execute(2,22);
    Uc(queue.PreemptCurrent(e,true));execute(1,11); // TIMESHaRE also rotates at an equal-priority quantum.
    Require(queue.UpdateTimeshareUsage(1,128,4)&&queue.Lookup(1)->effective_priority==40,
        "Fixed thread decayed under timeshare accounting update");
    Require(queue.SetTimeshare(1,true)&&queue.Lookup(1)->effective_priority==32,
        "Returning to timeshare ignored retained measured usage");
    Uc(queue.PreemptCurrent(e,true));execute(2,22);
    Require(queue.Resume(3),"Higher-priority suspended peer could not resume");
    Uc(queue.PreemptCurrent(e,false));execute(3,33); // Higher priority wake/resume outranks preempted head.
    Uc(queue.Block(e,0x777,{}));execute(2,22);
    Require(queue.UpdateTimeshareUsage(2,UINT32_MAX,0)&&queue.Lookup(2)->effective_priority==0,
        "Large measured usage underflowed source priority floor");
    Require(queue.UpdateTimeshareUsage(2,UINT32_MAX,127)&&queue.Lookup(2)->effective_priority==40,
        "No-contention shift127 applied a CPU penalty");
    Require(queue.Wake(0x777,1)==1,"Mode-bearing waiter did not wake");
    Uc(queue.PreemptCurrent(e,false));execute(3,33);
    Require(queue.Terminate(3)&&!queue.SetTimeshare(3,true)&&!queue.UpdateTimeshareUsage(3,0,127),
        "Terminated context accepted mode/accounting authority");
    Require(queue.Terminate(1)&&queue.Terminate(2)&&queue.PreemptCurrent(e,true)==UC_ERR_ARG,
        "Empty queue manufactured a quantum transition");
    std::uint8_t calibrated=0;
    Require(DarwinThreadRunQueue::CalibrateTimeshareShift(1250000,0,calibrated)&&calibrated==127
        &&DarwinThreadRunQueue::CalibrateTimeshareShift(1250000,1,calibrated)&&calibrated==16
        &&DarwinThreadRunQueue::CalibrateTimeshareShift(1250000,2,calibrated)&&calibrated==15
        &&DarwinThreadRunQueue::CalibrateTimeshareShift(1250000,4,calibrated)&&calibrated==14,
        "100ns timebase/default-load shift calibration differs from XNU");
    calibrated=77;
    Require(!DarwinThreadRunQueue::CalibrateTimeshareShift(0,2,calibrated)
        &&!DarwinThreadRunQueue::CalibrateTimeshareShift(UINT64_MAX,2,calibrated)
        &&!DarwinThreadRunQueue::CalibrateTimeshareShift(1250000,128,calibrated)&&calibrated==77,
        "Invalid accounting calibration published a shift");
    Require(DarwinThreadRunQueue::AgeTimeshareUsage(31,0)==31
        &&DarwinThreadRunQueue::AgeTimeshareUsage(31,1)==18
        &&DarwinThreadRunQueue::AgeTimeshareUsage(31,2)==12
        &&DarwinThreadRunQueue::AgeTimeshareUsage(7,1)==3
        &&DarwinThreadRunQueue::AgeTimeshareUsage(UINT32_MAX,32)==0,
        "Pinned 5/8 aging table lost shift rounding or long-idle reset");
}
}
int main(){try{
    PriorityScheduling();OrdinaryPolicyProvider();ExclusiveSwitch();SuspendedContexts();SchedulingModes();
    Engine engine,foreign;auto* e=engine.value;DarwinThreadContext first,second,empty,foreign_context;DarwinThreadRunQueue queue(0x10008);
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    const std::array<std::uint32_t,3> code{0x91000400,0xf9000020,0xd5033f5f};Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,10);Write(e,UC_ARM64_REG_X1,0x20000);Write(e,UC_ARM64_REG_TPIDRRO_EL0,0x20200);Uc(first.Capture(e));
    Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_X0,20);Write(e,UC_ARM64_REG_X1,0x20008);Write(e,UC_ARM64_REG_TPIDRRO_EL0,0x20400);Uc(second.Capture(e));
    Require(!queue.Admit(0,first)&&!queue.Admit(3,empty)&&queue.Admit(1,first)&&queue.Admit(2,second)
        &&!queue.Admit(1,second)&&!queue.Admit(3,first),"Invalid/duplicate/context-alias admission accepted");
    Uc(foreign_context.Capture(foreign.value));
    Require(!queue.Admit(4,foreign_context)&&queue.Size()==2,"Foreign-engine CPU context admitted to task queue");
    std::uint64_t selected=99;Require(queue.Dispatch(foreign.value,0,selected)==UC_ERR_ARG&&selected==0&&queue.Running()==0,"Foreign engine changed run state");
    Uc(queue.Dispatch(e,0,selected));Require(selected==1&&Read(e,UC_ARM64_REG_TPIDRRO_EL0)==0x20200,"First runnable context not restored");
    Require(queue.Dispatch(e,0,selected)==UC_ERR_ARG,"Two contexts simultaneously marked running");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,1));Uc(queue.YieldCurrent(e));
    Uc(queue.Dispatch(e,1,selected));Require(selected==2&&Read(e,UC_ARM64_REG_X0)==20,"Yield failed to select peer context");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,2));Uc(queue.Block(e,0x99,{}));
    Uc(queue.Dispatch(e,2,selected));Require(selected==1&&Read(e,UC_ARM64_REG_X0)==11&&Read(e,UC_ARM64_REG_PC)==0x10004,"Saved instruction continuation lost");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,1));Uc(queue.Block(e,0x99,100));
    std::array<std::uint64_t,2> output{};Uc(uc_mem_read(e,0x20000,output.data(),sizeof(output)));Require(output==std::array<std::uint64_t,2>{11,21},"Scheduled guest stores or task memory sharing failed");
    const auto dispatches_before_foreign=queue.Dispatches();
    Require(queue.Dispatch(foreign.value,100,selected)==UC_ERR_ARG&&selected==0&&queue.Running()==0
        &&queue.Dispatches()==dispatches_before_foreign&&queue.Lookup(1)->state==DarwinThreadRunQueue::State::Waiting
        &&queue.Lookup(1)->deadline==100&&queue.Lookup(1)->wake_reason==DarwinThreadRunQueue::WakeReason::None,
        "Rejected foreign dispatch expired a task wait or changed runnable state");
    Uc(queue.Dispatch(e,99,selected));Require(selected==0&&queue.Expire(99)==0,"Waiting thread ran before a wake/deadline");
    Require(queue.Wake(0x77,1)==0&&queue.Wake(0x99,1)==1&&queue.Lookup(2)->wake_reason==DarwinThreadRunQueue::WakeReason::Signaled,"Wait-key FIFO/wake-one failed");
    Uc(queue.Dispatch(e,99,selected));Require(selected==2,"FIFO wake selected newer waiter");Require(queue.Terminate(2)&&!queue.Terminate(2),"Termination was not idempotently rejected");
    Require(queue.Expire(100)==1&&queue.Lookup(1)->wake_reason==DarwinThreadRunQueue::WakeReason::TimedOut&&queue.Wake(0x99,8)==0,"Exact deadline or wake/timeout state exclusivity failed");
    Uc(queue.Dispatch(e,100,selected));Require(selected==1&&Read(e,UC_ARM64_REG_X0)==11,"Timed-out thread context lost");
    Uc(queue.Block(e,0x44,{}));Require(queue.CancelWait(1)&&!queue.CancelWait(1)&&queue.Lookup(1)->wake_reason==DarwinThreadRunQueue::WakeReason::Cancelled,"Cancellation/wait state failed");
    Uc(queue.Dispatch(e,101,selected));Require(selected==1&&queue.Terminate(1)&&queue.Size()==2&&!queue.Admit(1,first)
        &&queue.Lookup(1)->context==nullptr,"Terminated thread identity reused or context reference retained");
    Uc(queue.Dispatch(e,102,selected));Require(selected==0&&queue.YieldCurrent(e)==UC_ERR_ARG&&queue.Block(e,1,{})==UC_ERR_ARG,"Empty run queue manufactured execution");
    Require(queue.Admit(3,first),"Released context storage could not be admitted with a fresh identity");
    Require(queue.Admit(4,second),"Released peer context could not be admitted");
    Uc(queue.Dispatch(e,103,selected));Require(selected==3,"New identity did not keep FIFO order");Uc(queue.Block(e,0x55,{}));
    Uc(queue.Dispatch(e,103,selected));Require(selected==4,"Runnable peer lost during blocking");Uc(queue.Block(e,0x55,{}));
    DarwinThreadRunQueue unconfigured;
    Require(unconfigured.Admit(1,first)&&!unconfigured.Admit(2,second),"Peer admitted without exclusive-monitor provider");
    const auto before_invalid=Read(e,UC_ARM64_REG_PC);
    Require(DarwinThreadContext::ClearExclusiveMonitor(e,0x10000)==UC_ERR_ARG
        &&DarwinThreadContext::ClearExclusiveMonitor(e,0)==UC_ERR_ARG&&Read(e,UC_ARM64_REG_PC)==before_invalid,
        "Invalid exclusive-clear instruction altered guest continuation");
    Require(queue.Wake(0x55,8)==2&&queue.Lookup(3)->wake_reason==DarwinThreadRunQueue::WakeReason::Signaled
        &&queue.Lookup(4)->wake_reason==DarwinThreadRunQueue::WakeReason::Signaled,"Wake-all did not release both actual waiters");
    std::cout<<"Darwin executed run queue, yield/wait/FIFO wake/deadline/cancellation/termination consumers PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
