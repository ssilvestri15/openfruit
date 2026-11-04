#include "darwin_pointer_auth.hpp"
#include <unicorn/arm64.h>
#include <array>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* text){if(!ok)throw std::runtime_error(text);}
void Uc(uc_err e){Require(e==UC_ERR_OK,uc_strerror(e));}
const char* stage="initialization";
struct Engine {uc_engine* p=nullptr;Engine(){Uc(uc_open(UC_ARCH_ARM64,UC_MODE_ARM,&p));Uc(uc_ctl_set_cpu_model(p,UC_CPU_ARM64_MAX));}~Engine(){uc_close(p);}};
void Cp(uc_engine* e,unsigned crn,unsigned crm,unsigned op1,unsigned op2,std::uint64_t value){uc_arm64_cp_reg r{crn,crm,3,op1,op2,value};Uc(uc_reg_write(e,UC_ARM64_REG_CP_REG,&r));}
void Update(uc_engine* e,unsigned crn,unsigned crm,unsigned op1,unsigned op2,std::uint64_t clear,std::uint64_t set){uc_arm64_cp_reg r{crn,crm,3,op1,op2,0};Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&r));Cp(e,crn,crm,op1,op2,(r.val&~clear)|set);}
std::uint64_t Reg(uc_engine* e,int reg){std::uint64_t value=0;Uc(uc_reg_read(e,reg,&value));return value;}
void Set(uc_engine* e,int reg,std::uint64_t value){Uc(uc_reg_write(e,reg,&value));}
std::uint64_t Sign(uc_engine* e,std::uint64_t pointer,std::uint64_t modifier){Set(e,UC_ARM64_REG_X0,pointer);Set(e,UC_ARM64_REG_X1,modifier);Uc(uc_emu_start(e,0x10000,0x10004,0,1));return Reg(e,UC_ARM64_REG_X0);}
void NoJopConversions(){
    // A fresh task engine establishes policy before translating any PAC service.
    // IB remains enabled; IA/DA/DB identity must not become an all-key bypass.
    Engine engine;auto* e=engine.p;Set(e,UC_ARM64_REG_PSTATE,0);
    Update(e,1,1,6,0,0,(1ULL<<17)|(1ULL<<16)|(1ULL<<10)|1ULL);
    Update(e,1,1,4,0,0,(1ULL<<41)|(1ULL<<40)|(1ULL<<31));
    Update(e,2,0,0,2,63ULL|(63ULL<<16),16ULL|(16ULL<<16)|(1ULL<<37)|(1ULL<<38));
    Update(e,1,0,0,0,(1ULL<<31)|(1ULL<<27)|(1ULL<<13),1ULL<<30);
    Cp(e,2,1,0,0,0x123456789abcdef0);Cp(e,2,1,0,1,0xfedcba9876543210);
    Cp(e,2,1,0,2,0x1122334455667788);Cp(e,2,1,0,3,0x8877665544332211);
    Cp(e,2,2,0,0,0x1122334455667788);Cp(e,2,2,0,1,0x8877665544332211);
    Cp(e,2,2,0,2,0x123456789abcdef0);Cp(e,2,2,0,3,0xfedcba9876543210);
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_ALL));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_ALL));Uc(uc_mem_map(e,0x30000,4096,UC_PROT_ALL));
    const std::array<std::uint32_t,9> services{0xdac10020,0xdac11020,0xdac10820,0xdac11820,0xdac143e0,0xdac10420,0xdac11420,0xdac10c20,0xdac11c20};
    Uc(uc_mem_write(e,0x10000,services.data(),sizeof(services)));
    const std::array<std::uint32_t,2> target{0xd2800541,0xf9000041};Uc(uc_mem_write(e,0x20000,target.data(),sizeof(target)));
    const auto operate=[&](std::uint64_t pc,std::uint64_t value,std::uint64_t modifier){
        Set(e,UC_ARM64_REG_X0,value);Set(e,UC_ARM64_REG_X1,modifier);
        Uc(uc_emu_start(e,pc,pc+4,0,1));return Reg(e,UC_ARM64_REG_X0);
    };
    const std::uint64_t high_bits=0x0020000000020000ULL;
    for(const auto pc:{0x10000ULL,0x10004ULL,0x10008ULL,0x1000cULL,0x1001cULL,0x10020ULL}){
        Require(operate(pc,0x20000,0xb5ab)==0x20000,"NOJOP guest IA/DA/DB operation changed unsigned pointer");
        Require(operate(pc,high_bits,0xb5ab)==high_bits,"NOJOP guest operation stripped invalid high bits");
    }
    // PAC may legitimately be zero for a specific pointer/modifier. Select a
    // nonzero signature with actual PACIB, without assuming every signature
    // differs from its pointer. An inactive IB key still fails this bounded loop.
    std::uint64_t ib_modifier=0x30800,signed_ib=0x20000;
    for(unsigned i=0;i<256&&signed_ib==0x20000;++i){
        ib_modifier=0x30800+i*16;signed_ib=operate(0x10014,0x20000,ib_modifier);
    }
    Require(signed_ib!=0x20000,"NOJOP disabled IB signing for all 256 stack modifiers");
    Require(operate(0x10018,signed_ib,ib_modifier)==0x20000,"NOJOP IB valid return failed");
    const auto bad_ib=operate(0x10018,signed_ib^(1ULL<<48),ib_modifier);
    Require(bad_ib!=0x20000,"NOJOP IB corrupt return bypassed authentication");
    Require(uc_emu_start(e,bad_ib,0,0,1)!=UC_ERR_OK,"NOJOP poisoned IB return became executable");
    std::uint64_t wrong_ib_modifier=ib_modifier,wrong_ib_signature=signed_ib;
    for(unsigned i=1;i<=256&&wrong_ib_signature==signed_ib;++i){
        wrong_ib_modifier=ib_modifier+i*16;wrong_ib_signature=operate(0x10014,0x20000,wrong_ib_modifier);
    }
    Require(wrong_ib_signature!=signed_ib,"NOJOP IB signing ignored all distinct stack modifiers");
    Require(operate(0x10018,signed_ib,wrong_ib_modifier)!=0x20000,"NOJOP IB accepted wrong stack discriminator");
    Set(e,UC_ARM64_REG_X0,0xdeadbeef);Set(e,UC_ARM64_REG_X1,0xface1234);Set(e,UC_ARM64_REG_X28,0xbeef);
    Set(e,UC_ARM64_REG_SP,0x30800);Set(e,UC_ARM64_REG_PC,0x20000);Set(e,UC_ARM64_REG_NZCV,0xa0000000);
    Set(e,UC_ARM64_REG_TPIDRRO_EL0,0x30f00);Set(e,UC_ARM64_REG_TPIDR_EL0,0x30e00);
    Set(e,UC_ARM64_REG_FPCR,0x400000);Set(e,UC_ARM64_REG_FPSR,1);
    const std::array<std::uint64_t,2> vector{0x1122334455667788,0x99aabbccddeeff00};Uc(uc_reg_write(e,UC_ARM64_REG_Q31,vector.data()));
    uc_arm64_cp_reg before{1,0,3,0,0,0};Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&before));
    const auto preserved=[&]{
        std::array<std::uint64_t,2> q{};Uc(uc_reg_read(e,UC_ARM64_REG_Q31,q.data()));
        uc_arm64_cp_reg after{1,0,3,0,0,0};Uc(uc_reg_read(e,UC_ARM64_REG_CP_REG,&after));
        Require(Reg(e,UC_ARM64_REG_X0)==0xdeadbeef&&Reg(e,UC_ARM64_REG_X1)==0xface1234&&Reg(e,UC_ARM64_REG_X28)==0xbeef
            &&Reg(e,UC_ARM64_REG_SP)==0x30800&&Reg(e,UC_ARM64_REG_PC)==0x20000&&Reg(e,UC_ARM64_REG_NZCV)==0xa0000000
            &&Reg(e,UC_ARM64_REG_TPIDRRO_EL0)==0x30f00&&Reg(e,UC_ARM64_REG_TPIDR_EL0)==0x30e00
            &&Reg(e,UC_ARM64_REG_FPCR)==0x400000&&Reg(e,UC_ARM64_REG_FPSR)==1&&q==vector&&before.val==after.val,
            "NOJOP conversion changed creator CPU or PAC policy");
    };
    std::uint64_t output=0xcafe;
    Uc(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,0x20000,output));Require(output==0x20000,"NOJOP strict utility rejected raw function pointer");preserved();
    Uc(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,high_bits,output));Require(output==high_bits,"NOJOP strict utility stripped pointer");preserved();
    Uc(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,0,output));Require(output==0,"NOJOP strict null pointer changed");preserved();
    output=0xcafe;Require(AuthenticateDarwinFunctionPointer(e,0x10000,0x10004,0x20000,output)==UC_ERR_ARG&&output==0xcafe,"NOJOP bypassed service validation");preserved();
    std::array<std::uint64_t,2> inputs{0x20000,high_bits},outputs{0xcafe,0xbeef};
    Uc(ConvertDarwinFunctionPointersFromUser(e,0x10004,inputs,outputs));Require(outputs==inputs,"NOJOP BSD conversion changed pointer representations");preserved();
    const auto target_pc=outputs[0];
    Require(uc_emu_start(e,outputs[1],0,0,1)!=UC_ERR_OK,"NOJOP BSD conversion canonicalized invalid pointer");Set(e,UC_ARM64_REG_PC,0x20000);preserved();
    inputs={0,0x20000};Uc(ConvertDarwinFunctionPointersFromUser(e,0x10004,inputs,inputs));Require(!inputs[0]&&inputs[1]==0x20000,"NOJOP in-place conversion changed null/function pair");preserved();
    const auto retained=outputs;Require(ConvertDarwinFunctionPointersFromUser(e,0x10000,inputs,outputs)==UC_ERR_ARG&&outputs==retained,"NOJOP invalid provider changed output");preserved();
    std::array<std::uint32_t,68> wire{},converted{};
    const auto put=[&](std::size_t at,std::uint64_t value){wire[at]=std::uint32_t(value);wire[at+1]=std::uint32_t(value>>32);};
    for(std::size_t i=0;i<58;++i)wire[i]=std::uint32_t(0x12340000+i);
    put(58,high_bits);put(60,signed_ib);put(62,0x30801);put(64,0x20000);wire[66]=0xa0000005;wire[67]=0xff00000e;
    auto expected=wire;expected[66]=0xa0000000;expected[67]=1;
    Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,wire,converted));Require(converted==expected,"NOJOP Mach state changed raw pointer, IB LR or NO_PTRAUTH flags");preserved();
    wire=converted;Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,wire,wire));Require(wire==expected,"NOJOP in-place Mach state conversion changed representation");preserved();
    converted=wire;Require(ConvertDarwinThreadStateArm64(e,0x10000,0x1000c,0x10010,wire,converted)==UC_ERR_ARG&&converted==wire,"NOJOP invalid Mach provider changed output");preserved();
    wire={};expected=wire;expected[67]=1;
    Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,wire,converted));Require(converted==expected,"NOJOP zero Mach state fabricated pointers");preserved();
    // The actual raw conversion consumer reaches an owned target, without
    // manually pre-authenticating or stripping the value returned by the helper.
    Set(e,UC_ARM64_REG_X2,0x30000);Uc(uc_emu_start(e,target_pc,target_pc+sizeof(target),0,target.size()));
    std::uint64_t stored=0;Uc(uc_mem_read(e,0x30000,&stored,8));Require(stored==42,"NOJOP converted raw target did not execute");
}
}
int main(){try{
    Engine engine;auto* e=engine.p;
    Set(e,UC_ARM64_REG_PSTATE,0);
    Update(e,1,1,6,0,0,(1ULL<<17)|(1ULL<<16)|(1ULL<<10)|1ULL);
    Update(e,1,1,4,0,0,(1ULL<<41)|(1ULL<<40)|(1ULL<<31));
    Update(e,2,0,0,2,63ULL|(63ULL<<16),16ULL|(16ULL<<16)|(1ULL<<37)|(1ULL<<38));
    Update(e,1,0,0,0,0,(1ULL<<31)|(1ULL<<30)|(1ULL<<27)|(1ULL<<13));
    Cp(e,2,1,0,0,0x123456789abcdef0);Cp(e,2,1,0,1,0xfedcba9876543210);
    Set(e,UC_ARM64_REG_PSTATE,0);
    Uc(uc_mem_map(e,0x10000,4096,UC_PROT_ALL));Uc(uc_mem_map(e,0x20000,4096,UC_PROT_ALL));Uc(uc_mem_map(e,0x30000,4096,UC_PROT_ALL));
    const std::array<std::uint32_t,9> service{0xdac10020,0xdac11020,0xdac10820,0xdac11820,0xdac143e0,0xdac10420,0xdac11420,0xdac10c20,0xdac11c20};
    Uc(uc_mem_write(e,0x10000,service.data(),sizeof(service)));
    // Actual guest target stores42. Successful output must reach that target.
    const std::array<std::uint32_t,2> target{0xd2800541,0xf9000041};
    Uc(uc_mem_write(e,0x20000,target.data(),sizeof(target)));
    stage="guest signing";const auto signed_pointer=Sign(e,0x20000,0);
    Require(signed_pointer!=0x20000,"PAC signing was inactive");
    const auto wrong_modifier=Sign(e,0x20000,7);
    Set(e,UC_ARM64_REG_X0,0xdeadbeef);Set(e,UC_ARM64_REG_X1,0xface1234);Set(e,UC_ARM64_REG_X28,0xbeef);
    Set(e,UC_ARM64_REG_SP,0x30800);Set(e,UC_ARM64_REG_PC,0x20000);Set(e,UC_ARM64_REG_NZCV,0xa0000000);
    Set(e,UC_ARM64_REG_TPIDRRO_EL0,0x30f00);Set(e,UC_ARM64_REG_TPIDR_EL0,0x30e00);
    Set(e,UC_ARM64_REG_FPCR,0x400000);Set(e,UC_ARM64_REG_FPSR,1);
    const std::array<std::uint64_t,2> vector{0x1122334455667788,0x99aabbccddeeff00};Uc(uc_reg_write(e,UC_ARM64_REG_Q31,vector.data()));
    const auto preserved=[&]{
        std::array<std::uint64_t,2> q{};Uc(uc_reg_read(e,UC_ARM64_REG_Q31,q.data()));
        Require(Reg(e,UC_ARM64_REG_X0)==0xdeadbeef&&Reg(e,UC_ARM64_REG_X1)==0xface1234&&Reg(e,UC_ARM64_REG_X28)==0xbeef
            &&Reg(e,UC_ARM64_REG_SP)==0x30800&&Reg(e,UC_ARM64_REG_PC)==0x20000&&Reg(e,UC_ARM64_REG_NZCV)==0xa0000000
            &&Reg(e,UC_ARM64_REG_TPIDRRO_EL0)==0x30f00&&Reg(e,UC_ARM64_REG_TPIDR_EL0)==0x30e00
            &&Reg(e,UC_ARM64_REG_FPCR)==0x400000&&Reg(e,UC_ARM64_REG_FPSR)==1&&q==vector,"Authentication changed creator CPU");
    };
    std::uint64_t output=0xcafe;
    stage="valid authentication";Uc(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,signed_pointer,output));preserved();
    stage="guest target";Set(e,UC_ARM64_REG_X2,0x30000);Uc(uc_emu_start(e,output,output+sizeof(target),0,target.size()));
    std::uint64_t stored=0;Uc(uc_mem_read(e,0x30000,&stored,8));Require(stored==42,"Authenticated output did not execute actual guest target");
    // Reset the owned caller context; no output injection into auth helper.
    Set(e,UC_ARM64_REG_X0,0xdeadbeef);Set(e,UC_ARM64_REG_X1,0xface1234);Set(e,UC_ARM64_REG_PC,0x20000);
    output=0xcafe;
    Require(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,signed_pointer^(1ULL<<48),output)==UC_ERR_EXCEPTION&&output==0xcafe,"Corrupted PAC accepted");preserved();
    Require(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,wrong_modifier,output)==UC_ERR_EXCEPTION&&output==0xcafe,"Wrong discriminator accepted");preserved();
    // BSD366 converts its two arguments before the registration body. Unlike
    // the strict authentication utility, XNU preserves AUT poison and does not
    // reject a duplicate registration because its unused pointers were invalid.
    stage="BSD function pointer conversion";
    std::array<std::uint64_t,2> function_inputs{signed_pointer,wrong_modifier},function_outputs{0xcafe,0xbeef};
    Uc(ConvertDarwinFunctionPointersFromUser(e,0x10004,function_inputs,function_outputs));preserved();
    Require(function_outputs[0]==0x20000&&function_outputs[1]!=0x20000,
        "BSD pointer conversion stripped poison or rejected a correct signature");
    Require(uc_emu_start(e,function_outputs[1],0,0,1)!=UC_ERR_OK,
        "Converted authentication poison became an executable mapped address");
    Set(e,UC_ARM64_REG_PC,0x20000);preserved();
    function_inputs={signed_pointer^(1ULL<<48),0};
    Uc(ConvertDarwinFunctionPointersFromUser(e,0x10004,function_inputs,function_outputs));preserved();
    Require(function_outputs[0]!=0x20000&&!function_outputs[1],"Corrupt/null conversion lost poison or null semantics");
    function_inputs={0,signed_pointer};function_outputs=function_inputs;
    Uc(ConvertDarwinFunctionPointersFromUser(e,0x10004,function_outputs,function_outputs));preserved();
    Require(!function_outputs[0]&&function_outputs[1]==0x20000,"In-place pair conversion lost input/null values");
    const auto preserved_outputs=function_outputs;
    Require(ConvertDarwinFunctionPointersFromUser(e,0x10000,function_inputs,function_outputs)==UC_ERR_ARG
        &&function_outputs==preserved_outputs,"Invalid conversion provider modified output");preserved();
    Require(ConvertDarwinFunctionPointersFromUser(nullptr,0x10004,function_inputs,function_outputs)==UC_ERR_ARG
        &&function_outputs==preserved_outputs,"Null conversion provider admitted");
    // Source-format Mach creation state is produced by actual guest PACIA/PACDA,
    // not manually pre-authenticated pointers. The creator CPU remains intact.
    Cp(e,2,2,0,0,0x1122334455667788);Cp(e,2,2,0,1,0x8877665544332211);
    uc_context* saved=nullptr;Uc(uc_context_alloc(e,&saved));Uc(uc_context_save(e,saved));
    const auto sign_at=[&](std::uint64_t pc,std::uint64_t value,std::uint64_t modifier){
        Set(e,UC_ARM64_REG_X0,value);Set(e,UC_ARM64_REG_X1,modifier);
        Uc(uc_emu_start(e,pc,pc+4,0,1));return Reg(e,UC_ARM64_REG_X0);
    };
    std::array<std::uint32_t,68> wire{},converted{};
    const auto put=[&](std::size_t at,std::uint64_t value){wire[at]=std::uint32_t(value);wire[at+1]=std::uint32_t(value>>32);};
    const auto word64=[](const auto& words,std::size_t at){return std::uint64_t(words[at])|(std::uint64_t(words[at+1])<<32);};
    put(64,sign_at(0x10000,0x20000,29825));put(60,sign_at(0x10000,0x20004,30675));
    put(62,sign_at(0x10008,0x30801,52205));put(58,sign_at(0x10008,0x30e00,17687));
    std::uint64_t ib_modifier=0x30800,signed_ib_lr=0x20004;
    for(unsigned i=0;i<256&&signed_ib_lr==0x20004;++i){
        ib_modifier=0x30800+i*16;signed_ib_lr=sign_at(0x10014,0x20004,ib_modifier);
    }
    Require(signed_ib_lr!=0x20004,"Enabled JOP disabled IB signing for all 256 stack modifiers");
    Require(sign_at(0x10018,signed_ib_lr,ib_modifier)==0x20004,"Enabled JOP rejected correct IB return");
    const auto bad_ib_lr=sign_at(0x10018,signed_ib_lr^(1ULL<<48),ib_modifier);
    Require(bad_ib_lr!=0x20004&&uc_emu_start(e,bad_ib_lr,0,0,1)!=UC_ERR_OK,"Enabled JOP accepted corrupt IB return");
    std::uint64_t wrong_ib_modifier=ib_modifier,wrong_ib_signature=signed_ib_lr;
    for(unsigned i=1;i<=256&&wrong_ib_signature==signed_ib_lr;++i){
        wrong_ib_modifier=ib_modifier+i*16;wrong_ib_signature=sign_at(0x10014,0x20004,wrong_ib_modifier);
    }
    Require(wrong_ib_signature!=signed_ib_lr,"Enabled JOP IB signing ignored all distinct stack modifiers");
    Require(sign_at(0x10018,signed_ib_lr,wrong_ib_modifier)!=0x20004,"Enabled JOP accepted IB wrong stack discriminator");
    wire[66]=0xa0000005;wire[67]=0xff00000c; // TSSF_NONE does not activate high-byte blending.
    Uc(uc_context_restore(e,saved));uc_context_free(saved);
    stage="Mach state conversion";Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,wire,converted));preserved();
    Require(word64(converted,64)==0x20000&&word64(converted,60)==0x20004&&word64(converted,62)==0x30801
        &&word64(converted,58)==0x30e00&&converted[66]==0xa0000000&&!converted[67],"Mach state discriminators/keys/status differ");
    auto bad=wire;bad[67]=1;bad[64]=0x20000;bad[65]=0;
    Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,bad,converted));preserved();
    Require(word64(converted,64)!=0x20000,"NO_PTRAUTH bypassed enabled JOP task");
    const auto poison=word64(converted,64);
    Require(uc_emu_start(e,poison,0,0,1)!=UC_ERR_OK,"Authentication poison became executable raw PC");
    Set(e,UC_ARM64_REG_PC,0x20000);preserved();
    bad=wire;bad[63]^=1u<<16;
    Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,bad,converted));preserved();
    const auto data_poison=word64(converted,62);
    Require(data_poison!=0x30801,"Corrupted DA stack pointer was accepted");
    Set(e,UC_ARM64_REG_X2,data_poison);Require(uc_emu_start(e,0x20004,0x20008,0,1)!=UC_ERR_OK,"DA authentication poison became writable guest memory");
    Set(e,UC_ARM64_REG_PC,0x20000);preserved();
    bad=wire;bad[67]=2;bad[60]=std::uint32_t(signed_ib_lr);bad[61]=std::uint32_t(signed_ib_lr>>32);
    Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,bad,converted));preserved();
    Require(word64(converted,60)==signed_ib_lr,"Actual IB signed LR was stripped/authenticated under IA");
    bad[60]=0x20004;bad[61]=0;
    Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,bad,converted));preserved();
    Require(word64(converted,60)!=0x20004,"Unsigned IB flagged LR bypassed authentication");
    bad={};Uc(ConvertDarwinThreadStateArm64(e,0x10004,0x1000c,0x10010,bad,converted));preserved();
    Require(converted==bad,"Zero state pointers were fabricated");
    converted=wire;
    Require(ConvertDarwinThreadStateArm64(e,0x10000,0x1000c,0x10010,wire,converted)==UC_ERR_ARG&&converted==wire,"Invalid Mach state provider changed output");
    Cp(e,2,1,0,0,0x76543210);
    Require(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,signed_pointer,output)==UC_ERR_EXCEPTION&&output==0xcafe,"Wrong task key accepted");preserved();
    Require(AuthenticateDarwinFunctionPointer(e,0x10000,0x10004,signed_pointer,output)==UC_ERR_ARG&&output==0xcafe,"Wrong service admitted");
    Require(AuthenticateDarwinFunctionPointer(nullptr,0x10004,0x10000,signed_pointer,output)==UC_ERR_ARG,"Null engine admitted");
    Uc(AuthenticateDarwinFunctionPointer(e,0x10004,0x10000,0,output));Require(output==0,"Null optional entry not preserved");
    stage="NOJOP same-task conversions";NoJopConversions();
    std::cout<<"Same-engine JOP/NOJOP pointer conversion, enforced IB, failure preservation and guest targets PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<stage<<": "<<e.what()<<'\n';return 1;}}
