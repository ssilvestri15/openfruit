#include "darwin_thread_context.hpp"
#include <unicorn/arm64.h>
#include <array>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool condition,const char* why){if(!condition)throw std::runtime_error(why);}
void Uc(uc_err error){if(error!=UC_ERR_OK)throw std::runtime_error(uc_strerror(error));}
struct Engine {uc_engine* value=nullptr;Engine(){Uc(uc_open(UC_ARCH_ARM64,UC_MODE_ARM,&value));Uc(uc_ctl_set_cpu_model(value,UC_CPU_ARM64_MAX));Uc(uc_ctl_context_mode(value,UC_CTL_CONTEXT_CPU));}~Engine(){if(value)uc_close(value);}};
void Write(uc_engine* e,int reg,std::uint64_t value){Uc(uc_reg_write(e,reg,&value));}
std::uint64_t Read(uc_engine* e,int reg){std::uint64_t value=0;Uc(uc_reg_read(e,reg,&value));return value;}
void Key(uc_engine* e,std::uint64_t value){uc_arm64_cp_reg key{2,1,3,0,0,value};Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&key));}
std::uint64_t Key(uc_engine* e){uc_arm64_cp_reg key{2,1,3,0,0,0};Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&key));return key.val;}
void FreshFloatingPointContexts(){
    Engine engine;auto* e=engine.value;
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));
    // Actual guest reads of FPCR and FPSR, after restoring the new thread.
    const std::array<std::uint32_t,2> code{0xd53b4400,0xd53b4421};
    Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    uc_arm64_cp_reg access{1,0,3,0,2,3ULL<<20};Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&access));
    std::array<std::uint32_t,68> words{};words[64]=0x10000;
    const std::array<std::uint64_t,2> creator_vector{0x1122334455667788,0x8877665544332211};
    for(unsigned n=0;n<96;++n){
        const auto fpcr=std::uint64_t((n%3+1)<<22),fpsr=std::uint64_t(n%4+1);
        Write(e,UC_ARM64_REG_X0,0xface0000+n);Write(e,UC_ARM64_REG_FPCR,fpcr);Write(e,UC_ARM64_REG_FPSR,fpsr);
        Uc(uc_reg_write(e,UC_ARM64_REG_Q31,creator_vector.data()));Key(e,0x12340000+n);
        DarwinThreadContext creator,newborn;Uc(creator.Capture(e));
        Uc(newborn.InitializeArm64(e,words,0x20000+n*8));
        std::array<std::uint64_t,2> actual{};Uc(uc_reg_read(e,UC_ARM64_REG_Q31,actual.data()));
        Require(Read(e,UC_ARM64_REG_X0)==0xface0000+n&&Read(e,UC_ARM64_REG_FPCR)==fpcr
            &&Read(e,UC_ARM64_REG_FPSR)==fpsr&&actual==creator_vector&&Key(e)==0x12340000+n,
            "Fresh FP snapshot changed creator registers, flags, vector or task key");
        Uc(newborn.Restore(e));Uc(uc_emu_start(e,0x10000,0x10008,0,2));
        Require(Read(e,UC_ARM64_REG_X0)==0&&Read(e,UC_ARM64_REG_X1)==0,
            "New thread guest observed inherited FPCR or FPSR");
        Uc(creator.Restore(e));
        Require(Read(e,UC_ARM64_REG_FPCR)==fpcr&&Read(e,UC_ARM64_REG_FPSR)==fpsr,
            "New thread execution changed saved creator FP state");
    }
}
int X(unsigned i){return i<29?UC_ARM64_REG_X0+int(i):i==29?UC_ARM64_REG_X29:UC_ARM64_REG_X30;}
uc_arm64_cp_reg PacHalf(unsigned i){return {2,1+i/4,3,0,i%4,0};}
struct CpuState {
    std::array<std::uint64_t,31> gpr{};
    std::array<std::uint64_t,8> control{};
    std::array<std::array<std::uint64_t,2>,32> vectors{};
    std::array<std::uint64_t,10> keys{};
    bool operator==(const CpuState&) const =default;
};
CpuState Snapshot(uc_engine* e){
    CpuState state;
    for(unsigned i=0;i<31;++i)state.gpr[i]=Read(e,X(i));
    const std::array<int,8> registers{UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_NZCV,
        UC_ARM64_REG_TPIDRRO_EL0,UC_ARM64_REG_TPIDR_EL0,UC_ARM64_REG_FPCR,UC_ARM64_REG_FPSR,UC_ARM64_REG_PSTATE};
    for(unsigned i=0;i<registers.size();++i)state.control[i]=Read(e,registers[i]);
    for(unsigned i=0;i<32;++i)Uc(uc_reg_read(e,UC_ARM64_REG_Q0+i,state.vectors[i].data()));
    for(unsigned i=0;i<10;++i){auto reg=PacHalf(i);Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&reg));state.keys[i]=reg.val;}
    return state;
}
void SetCpu(uc_engine* e,std::uint64_t seed){
    for(unsigned i=0;i<31;++i)Write(e,X(i),seed+i);
    Write(e,UC_ARM64_REG_SP,0x20e00+seed%128);Write(e,UC_ARM64_REG_PC,0x10100);
    Write(e,UC_ARM64_REG_NZCV,0xa0000000);Write(e,UC_ARM64_REG_TPIDRRO_EL0,seed+0x20000);
    Write(e,UC_ARM64_REG_TPIDR_EL0,seed+0x30000);Write(e,UC_ARM64_REG_FPCR,0x800000);Write(e,UC_ARM64_REG_FPSR,3);
    for(unsigned i=0;i<32;++i){const std::array<std::uint64_t,2> q{seed+i,~(seed+i)};Uc(uc_reg_write(e,UC_ARM64_REG_Q0+i,q.data()));}
    for(unsigned i=0;i<10;++i){auto reg=PacHalf(i);reg.val=seed+0xabc000+i;Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&reg));}
}
void WorkqueueReuse(){
    Engine engine,foreign;auto* e=engine.value;
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));
    Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    // Guest consumers: store all32 Q registers, then read/store FPCR, FPSR,
    // both TLS/CPU registers, SP and NZCV. No floating-point operation repairs
    // the state under test, and the creator has deliberately different values.
    std::array<std::uint32_t,44> code{};
    for(unsigned i=0;i<32;++i)code[i]=0x3d800020|(i<<10)|i; // str qi,[x1,#i*16]
    const std::array<std::uint32_t,12> tail{0xd53b4402,0xd53b4423,0xf9010022,0xf9010423,
        0xd53bd064,0xd53bd045,0xf9010824,0xf9010c25,0x910003e6,0xf9011026,0xd53b4207,0xf9011427};
    for(unsigned i=0;i<tail.size();++i)code[32+i]=tail[i];
    Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    uc_arm64_cp_reg access{1,0,3,0,2,3ULL<<20};Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&access));
    SetCpu(e,0x12340000);Write(e,UC_ARM64_REG_FPCR,0x400000);Write(e,UC_ARM64_REG_FPSR,1);
    const auto original_worker=Snapshot(e);
    DarwinThreadContext worker,creator,empty;Uc(worker.Capture(e));
    std::array<std::uint32_t,68> words{};
    const auto put=[&](unsigned offset,std::uint64_t value){words[offset]=std::uint32_t(value);words[offset+1]=std::uint32_t(value>>32);};
    SetCpu(e,0xface0000);const auto initial_creator=Snapshot(e);Uc(creator.Capture(e));
    Require(empty.SetWorkqueueStateArm64(e,words)==UC_ERR_ARG
        &&worker.SetWorkqueueStateArm64(nullptr,words)==UC_ERR_ARG
        &&worker.SetWorkqueueStateArm64(foreign.value,words)==UC_ERR_ARG
        &&worker.SetWorkqueueStateArm64(e,std::span(words).first(67))==UC_ERR_ARG,
        "Workqueue reuse accepted empty, null, foreign or undersized context input");
    const std::array<std::uint32_t,69> oversized{};
    Require(worker.SetWorkqueueStateArm64(e,oversized)==UC_ERR_ARG,"Oversized workqueue state accepted");
    words[66]=0x10000000;Require(worker.SetWorkqueueStateArm64(e,words)==UC_ERR_ARG,"Unsupported workqueue input CPSR accepted");words[66]=0;
    words[67]=1;Require(worker.SetWorkqueueStateArm64(e,words)==UC_ERR_ARG,"Opaque workqueue input state accepted");words[67]=0;
    Require(Snapshot(e)==initial_creator&&worker.Captures()==1,"Rejected workqueue update changed creator CPU or published capture");
    Uc(worker.Restore(e));Require(Snapshot(e)==original_worker,"Rejected workqueue update modified original saved worker");Uc(creator.Restore(e));
    for(unsigned n=0;n<96;++n){
        SetCpu(e,0xface0000+n*0x100);const auto live_creator=Snapshot(e);Uc(creator.Capture(e));
        for(unsigned i=0;i<31;++i)put(2*i,0xbeef000000000000ULL+n*0x100+i);
        put(2,0x20000);put(62,0x20f00);put(64,0x10000);
        const auto captures=worker.Captures();Uc(worker.SetWorkqueueStateArm64(e,words));
        Require(Snapshot(e)==live_creator&&worker.Captures()==captures,
            "Workqueue preparation changed live creator CPU or capture accounting");
        Uc(worker.Restore(e));const auto reused=Snapshot(e);
        for(unsigned i=0;i<31;++i){const auto expected=std::uint64_t(words[2*i])|(std::uint64_t(words[2*i+1])<<32);
            Require(reused.gpr[i]==expected,"Reused worker GPR retained stale thread-return state");}
        Require(reused.control[0]==0x20f00&&reused.control[1]==0x10000&&reused.control[2]==0,
            "Reused worker PC/SP/user CPSR did not reset to upcall state");
        Require(reused.control[3]==original_worker.control[3]&&reused.control[4]==original_worker.control[4]
            &&reused.control[5]==original_worker.control[5]&&reused.control[6]==original_worker.control[6]
            &&reused.vectors==original_worker.vectors&&reused.keys==original_worker.keys,
            "Workqueue reuse reset FP/NEON, TLS/CPU identity or PAC keys");
        Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10000+sizeof(code),0,code.size()));Uc(worker.Capture(e));
        std::array<std::uint64_t,70> observed{};Uc(uc_mem_read(e,0x20000,observed.data(),sizeof(observed)));
        for(unsigned i=0;i<32;++i)Require(observed[2*i]==original_worker.vectors[i][0]
            &&observed[2*i+1]==original_worker.vectors[i][1],"Actual reused guest observed changed NEON state");
        Require(observed[64]==0x400000&&observed[65]==1&&observed[66]==original_worker.control[3]
            &&observed[67]==original_worker.control[4]&&observed[68]==0x20f00&&observed[69]==0,
            "Actual reused guest observed wrong FP/TLS/CPU/SP/NZCV state");
        Uc(creator.Restore(e));Require(Snapshot(e)==live_creator,"Reused guest execution changed saved creator CPU");
    }
}
std::uint64_t TaskPacControl(uc_engine* e){
    uc_arm64_cp_reg reg{1,0,3,0,0,0};Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&reg));return reg.val;
}
void TaskPacPolicyContexts(bool jop){
    // Establish one task ABI before any translation. Context operations must
    // preserve this policy: ARM64 NOJOP retains IB return protection, whereas
    // ARM64e enables IA/DA/DB too (XNU ptrauth.h, kern_exec.c task NOJOP).
    Engine engine;auto* e=engine.value;Write(e,UC_ARM64_REG_PSTATE,0);
    const auto update=[&](unsigned crn,unsigned crm,unsigned op1,unsigned op2,std::uint64_t clear,std::uint64_t set){
        uc_arm64_cp_reg reg{crn,crm,3,op1,op2,0};Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&reg));
        reg.val=(reg.val&~clear)|set;Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&reg));
    };
    update(1,1,6,0,0,(1ULL<<17)|(1ULL<<16)|(1ULL<<10)|1ULL);
    update(1,1,4,0,0,(1ULL<<41)|(1ULL<<40)|(1ULL<<31));
    update(2,0,0,2,63ULL|(63ULL<<16),16ULL|(16ULL<<16)|(1ULL<<37)|(1ULL<<38));
    const auto jop_bits=(1ULL<<31)|(1ULL<<27)|(1ULL<<13);
    update(1,0,0,0,jop_bits|(1ULL<<30),(1ULL<<30)|(jop?jop_bits:0));
    update(1,0,0,2,0,3ULL<<20);
    for(unsigned i=0;i<10;++i){auto reg=PacHalf(i);reg.val=0x123456789abcdef0ULL+i*0x11223344556677ULL;Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&reg));}
    const auto task_control=TaskPacControl(e);const auto task_keys=Snapshot(e).keys;
    const auto policy_intact=[&]{
        Require(TaskPacControl(e)==task_control&&Snapshot(e).keys==task_keys,
            "Thread context changed task SCTLR or pointer-authentication keys");
    };
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));
    Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    // Each real PAC/AUT service stores its output in shared guest memory.
    // No host-side pointer strip or authentication can manufacture a pass.
    const std::array<std::uint32_t,8> instructions{
        0xdac10020,0xdac11020,0xdac10820,0xdac11820,
        0xdac10c20,0xdac11c20,0xdac10420,0xdac11420};
    std::array<std::uint32_t,16> services{};
    for(unsigned i=0;i<instructions.size();++i){services[2*i]=instructions[i];services[2*i+1]=0xf9000040;} // str x0,[x2]
    Uc(uc_mem_write(e,0x10000,services.data(),sizeof(services)));
    // mov x30,x2; eor x30,x30,x5; autib x30,x1; ret. A signature
    // produced in the creator must reach this actual guest return consumer.
    const std::array<std::uint32_t,4> returning{0xaa0203fe,0xca0503de,0xdac1143e,0xd65f03c0};
    const std::array<std::uint32_t,2> target{0xd2800543,0xf9000083}; // mov x3,#42; str x3,[x4]
    Uc(uc_mem_write(e,0x10400,returning.data(),sizeof(returning)));
    Uc(uc_mem_write(e,0x10500,target.data(),sizeof(target)));
    const auto operate=[&](unsigned index,std::uint64_t input,std::uint64_t modifier){
        Write(e,UC_ARM64_REG_X0,input);Write(e,UC_ARM64_REG_X1,modifier);Write(e,UC_ARM64_REG_X2,0x20000);
        const auto pc=0x10000ULL+index*8;Uc(uc_emu_start(e,pc,pc+8,0,2));
        std::uint64_t output=0;Uc(uc_mem_read(e,0x20000,&output,sizeof(output)));return output;
    };
    constexpr std::uint64_t modifier=0x20800,return_pc=0x10500;
    std::array<std::uint64_t,4> signatures{};
    for(unsigned key=0;key<4;++key){
        const auto pointer=key==0||key==3?return_pc:0x20040;
        signatures[key]=operate(key*2,pointer,modifier);
        Require((signatures[key]!=pointer)==(jop||key==3),"Task policy selected incorrect PAC signing behavior");
    }
    const auto consumers=[&]{
        policy_intact();
        for(unsigned key=0;key<4;++key){
            const auto pointer=key==0||key==3?return_pc:0x20040;
            const bool active=jop||key==3;
            Require(operate(key*2+1,signatures[key],modifier)==pointer,
                "Restored context could not authenticate creator-produced pointer");
            const auto corrupt=signatures[key]^(1ULL<<48);
            const auto wrong=operate(key*2+1,signatures[key],modifier+8);
            const auto corrupted=operate(key*2+1,corrupt,modifier);
            if(active){
                Require(wrong!=pointer&&corrupted!=pointer,"Restored context accepted corrupt PAC or wrong discriminator");
            }else{
                Require(wrong==pointer&&corrupted==corrupt,"NOJOP authentication stripped or changed pointer bits");
                Require(operate(key*2,corrupt,modifier)==corrupt,"NOJOP signing changed high pointer bits");
            }
        }
        for(const auto corruption:{0ULL,1ULL<<48}){
            const std::uint64_t empty=0;Uc(uc_mem_write(e,0x20008,&empty,sizeof(empty)));
            Write(e,UC_ARM64_REG_X1,modifier);Write(e,UC_ARM64_REG_X2,signatures[3]);
            Write(e,UC_ARM64_REG_X4,0x20008);Write(e,UC_ARM64_REG_X5,corruption);
            const auto error=uc_emu_start(e,0x10400,0x10508,0,6);
            std::uint64_t observed=0;Uc(uc_mem_read(e,0x20008,&observed,sizeof(observed)));
            Require(corruption?(error!=UC_ERR_OK&&observed==0):(error==UC_ERR_OK&&observed==42),
                "Restored context failed valid IB return or executed a corrupted IB return");
        }
        policy_intact();
    };
    Write(e,UC_ARM64_REG_X0,0xface1234);Write(e,UC_ARM64_REG_X28,0xdeadbeef);
    Write(e,UC_ARM64_REG_PC,0x10400);Write(e,UC_ARM64_REG_SP,0x20e00);Write(e,UC_ARM64_REG_NZCV,0xa0000000);
    Write(e,UC_ARM64_REG_TPIDRRO_EL0,0x20200);Write(e,UC_ARM64_REG_TPIDR_EL0,0x1234);
    Write(e,UC_ARM64_REG_FPCR,0x400000);Write(e,UC_ARM64_REG_FPSR,1);
    const std::array<std::uint64_t,2> vector{0x1122334455667788,0x8877665544332211};
    Uc(uc_reg_write(e,UC_ARM64_REG_Q31,vector.data()));
    const auto creator_cpu=Snapshot(e);DarwinThreadContext creator,newborn;Uc(creator.Capture(e));
    std::array<std::uint32_t,68> words{};words[62]=0x20d00;words[64]=0x10400;
    Uc(newborn.InitializeArm64(e,words,0x20400));
    Require(Snapshot(e)==creator_cpu,"PAC-aware newborn preparation changed creator CPU");policy_intact();
    Uc(newborn.Restore(e));consumers();
    // Reuse an existing worker snapshot while a different creator context is
    // live. Integer reinitialization must retain task policy and all keys.
    Uc(creator.Restore(e));Require(Snapshot(e)==creator_cpu,"Newborn PAC execution changed saved creator");
    words[62]=0x20c00;words[64]=0x10400;Uc(newborn.SetWorkqueueStateArm64(e,words));
    Require(Snapshot(e)==creator_cpu,"PAC-aware workqueue preparation changed live creator CPU");policy_intact();
    Uc(newborn.Restore(e));consumers();
    Uc(creator.Restore(e));Require(Snapshot(e)==creator_cpu,"Reused worker PAC execution changed saved creator");
    consumers();
    Uc(creator.Restore(e));Require(Snapshot(e)==creator_cpu,"Creator PAC consumer overwrote saved creator");policy_intact();
}
}
int main(){try{
    FreshFloatingPointContexts();
    WorkqueueReuse();
    TaskPacPolicyContexts(false);TaskPacPolicyContexts(true);
    Engine engine,foreign;auto* e=engine.value;DarwinThreadContext first,second,empty;
    Require(empty.Restore(e)==UC_ERR_ARG&&empty.Capture(nullptr)==UC_ERR_ARG,"Uninitialized/null context admitted");
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_READ|UC_PROT_EXEC));
    Uc(uc_mem_map(e,0x20000,4096,UC_PROT_READ|UC_PROT_WRITE));
    // Owned guest instructions: add x0,x0,#1; str x0,[x1]. Executed against the
    // same task mappings after each real backend context switch.
    const std::array<std::uint32_t,2> code{0x91000400,0xf9000020};Uc(uc_mem_write(e,0x10000,code.data(),sizeof(code)));
    const std::array<std::uint64_t,2> vector1{0x1122334455667788,0x8877665544332211},vector2{0x99,0xaa};
    Write(e,UC_ARM64_REG_X0,10);Write(e,UC_ARM64_REG_X1,0x20000);Write(e,UC_ARM64_REG_X30,0x1111);
    Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_SP,0x20800);Write(e,UC_ARM64_REG_NZCV,0xa0000000);
    Write(e,UC_ARM64_REG_TPIDRRO_EL0,0x20200);Write(e,UC_ARM64_REG_TPIDR_EL0,0x20300);
    Write(e,UC_ARM64_REG_FPCR,0x400000);Write(e,UC_ARM64_REG_FPSR,1);Uc(uc_reg_write(e,UC_ARM64_REG_Q0,vector1.data()));Key(e,0x12345678);
    Uc(first.Capture(e));
    Write(e,UC_ARM64_REG_X0,20);Write(e,UC_ARM64_REG_X1,0x20008);Write(e,UC_ARM64_REG_X30,0x2222);
    Write(e,UC_ARM64_REG_PC,0x10000);Write(e,UC_ARM64_REG_SP,0x20900);Write(e,UC_ARM64_REG_NZCV,0x60000000);
    Write(e,UC_ARM64_REG_TPIDRRO_EL0,0x20400);Write(e,UC_ARM64_REG_TPIDR_EL0,0x20500);
    Write(e,UC_ARM64_REG_FPCR,0x800000);Write(e,UC_ARM64_REG_FPSR,2);Uc(uc_reg_write(e,UC_ARM64_REG_Q0,vector2.data()));Key(e,0x87654321);
    Uc(second.Capture(e));
    Require(first.Restore(foreign.value)==UC_ERR_ARG&&first.Capture(foreign.value)==UC_ERR_ARG,"Cross-task engine accepted");
    Uc(first.Restore(e));
    Require(Read(e,UC_ARM64_REG_SP)==0x20800&&Read(e,UC_ARM64_REG_X30)==0x1111&&Read(e,UC_ARM64_REG_NZCV)==0xa0000000,"General/control state not isolated");
    Require(Read(e,UC_ARM64_REG_TPIDRRO_EL0)==0x20200&&Read(e,UC_ARM64_REG_TPIDR_EL0)==0x20300,"TSD state not isolated");
    std::array<std::uint64_t,2> vector{};Uc(uc_reg_read(e,UC_ARM64_REG_Q0,vector.data()));
    Require(vector==vector1&&Read(e,UC_ARM64_REG_FPCR)==0x400000&&Read(e,UC_ARM64_REG_FPSR)==1&&Key(e)==0x12345678,"SIMD/FP/PAC state not isolated");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,2));Uc(first.Capture(e));
    Uc(second.Restore(e));
    Require(Read(e,UC_ARM64_REG_X0)==20&&Read(e,UC_ARM64_REG_SP)==0x20900&&Read(e,UC_ARM64_REG_NZCV)==0x60000000,"Second context corrupted by first execution");
    Require(Read(e,UC_ARM64_REG_TPIDRRO_EL0)==0x20400&&Read(e,UC_ARM64_REG_TPIDR_EL0)==0x20500&&Key(e)==0x87654321,"Second system registers corrupted");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,2));Uc(second.Capture(e));
    std::array<std::uint64_t,2> shared{};Uc(uc_mem_read(e,0x20000,shared.data(),sizeof(shared)));
    Require(shared==std::array<std::uint64_t,2>{11,21},"Context restore rolled back task shared memory");
    Uc(first.Restore(e));Require(Read(e,UC_ARM64_REG_X0)==11&&Read(e,UC_ARM64_REG_PC)==0x10008&&first.Captures()==2,"Suspended first context did not resume its execution state");
    Uc(second.Restore(e));Require(Read(e,UC_ARM64_REG_X0)==21&&second.Captures()==2,"Suspended second context did not resume its execution state");
    DarwinThreadContext newborn,rejected;
    std::array<std::uint32_t,68> words{};
    const auto put=[&](std::size_t offset,std::uint64_t value){words[offset]=static_cast<std::uint32_t>(value);words[offset+1]=static_cast<std::uint32_t>(value>>32);};
    put(0,30);put(2,0x20010);put(60,0x9988776655443322);put(62,0x20a00);put(64,0x10000);words[66]=0x80000000;
    Write(e,UC_ARM64_REG_X28,0xf00dbaad);Uc(uc_reg_write(e,UC_ARM64_REG_Q31,vector1.data()));
    Require(rejected.InitializeArm64(nullptr,words,0x20600)==UC_ERR_ARG
        &&rejected.InitializeArm64(e,std::span(words).first(67),0x20600)==UC_ERR_ARG&&!rejected.Saved(),"Invalid initialization published a context");
    words[67]=1;Require(rejected.InitializeArm64(e,words,0x20600)==UC_ERR_ARG&&!rejected.Saved(),"Opaque authenticated-state flags admitted");words[67]=0;
    const std::uint64_t modeled_cpu_identity=0x1234;
    Uc(newborn.InitializeArm64(e,words,0x20600,modeled_cpu_identity));
    Uc(uc_reg_read(e,UC_ARM64_REG_Q0,vector.data()));
    Require(Read(e,UC_ARM64_REG_X0)==21&&Read(e,UC_ARM64_REG_X28)==0xf00dbaad&&Read(e,UC_ARM64_REG_SP)==0x20900
        &&Read(e,UC_ARM64_REG_FPCR)==0x800000&&vector==vector2&&Key(e)==0x87654321
        &&Read(e,UC_ARM64_REG_TPIDR_EL0)==0x20500,
        "Fresh-context preparation changed the creator's live CPU");
    Require(newborn.InitializeArm64(e,words,0x20600)==UC_ERR_ARG,"Existing context overwritten by initialization");
    Uc(newborn.Restore(e));Uc(uc_reg_read(e,UC_ARM64_REG_Q31,vector.data()));
    Require(Read(e,UC_ARM64_REG_X28)==0&&Read(e,UC_ARM64_REG_X30)==0x9988776655443322
        &&Read(e,UC_ARM64_REG_SP)==0x20a00&&Read(e,UC_ARM64_REG_NZCV)==0x80000000
        &&Read(e,UC_ARM64_REG_TPIDRRO_EL0)==0x20600&&Read(e,UC_ARM64_REG_TPIDR_EL0)==modeled_cpu_identity
        &&Read(e,UC_ARM64_REG_FPCR)==0&&Read(e,UC_ARM64_REG_FPSR)==0&&vector==std::array<std::uint64_t,2>{}
        &&Key(e)==0x87654321,"Fresh wire/NEON/TSD/process-key state did not reach restored context");
    Uc(uc_emu_start(e,Read(e,UC_ARM64_REG_PC),0x10008,0,2));
    std::uint64_t newborn_output=0;Uc(uc_mem_read(e,0x20010,&newborn_output,sizeof(newborn_output)));
    Require(newborn_output==31,"Initialized context did not execute the supplied guest entry state");
    std::cout<<"Darwin same-engine CPU/TSD/SIMD/PAC isolation and shared-memory consumers PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
