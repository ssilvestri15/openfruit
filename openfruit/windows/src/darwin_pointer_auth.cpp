#include "darwin_pointer_auth.hpp"
#include <unicorn/arm64.h>
#include <cstddef>

namespace OpenFruit {
uc_err AuthenticateDarwinFunctionPointer(uc_engine* engine,std::uint64_t auth_pc,
    std::uint64_t sign_pc,std::uint64_t input,std::uint64_t& output) noexcept {
    if(!engine||!auth_pc||!sign_pc||(auth_pc&3)||(sign_pc&3)
        ||auth_pc>UINT64_MAX-4||sign_pc>UINT64_MAX-4)return UC_ERR_ARG;
    std::size_t architecture=0;auto error=uc_query(engine,UC_QUERY_ARCH,&architecture);
    if(error!=UC_ERR_OK)return error;if(architecture!=UC_ARCH_ARM64)return UC_ERR_ARG;
    std::uint32_t auth=0,sign=0;
    error=uc_mem_read(engine,auth_pc,&auth,4);if(error!=UC_ERR_OK)return error;
    error=uc_mem_read(engine,sign_pc,&sign,4);if(error!=UC_ERR_OK)return error;
    if(auth!=0xdac11020||sign!=0xdac10020)return UC_ERR_ARG;
    uc_arm64_cp_reg control{1,0,3,0,0,0};
    error=uc_reg_read(engine,UC_ARM64_REG_CP_REG,&control);
    if(error!=UC_ERR_OK)return error;
    // IA sign/auth is architectural identity for the task's NOJOP ABI. Keep
    // every input bit: this is not a strip or a claim of signature validity.
    if(!(control.val&(1ULL<<31))){output=input;return UC_ERR_OK;}
    if(!input){output=0;return UC_ERR_OK;}
    uc_context* saved=nullptr;error=uc_context_alloc(engine,&saved);
    if(error!=UC_ERR_OK)return error;
    error=uc_context_save(engine,saved);
    if(error!=UC_ERR_OK){uc_context_free(saved);return error;}
    std::uint64_t value=input,modifier=0,recovered=0;
    error=uc_reg_write(engine,UC_ARM64_REG_X0,&value);
    if(error==UC_ERR_OK)error=uc_reg_write(engine,UC_ARM64_REG_X1,&modifier);
    const auto step=[&](std::uint64_t pc){
        if(error!=UC_ERR_OK)return;
        error=uc_emu_start(engine,pc,pc+4,0,1);
        if(error!=UC_ERR_OK)return;
        std::uint64_t completed=0;error=uc_reg_read(engine,UC_ARM64_REG_PC,&completed);
        if(error==UC_ERR_OK&&completed!=pc+4)error=UC_ERR_EXCEPTION;
    };
    step(auth_pc);
    if(error==UC_ERR_OK)error=uc_reg_read(engine,UC_ARM64_REG_X0,&recovered);
    // Architectural AUT may poison instead of raising an exception. Re-sign
    // under the unchanged task key and discriminator; poisoned/invalid values
    // must not be accepted merely because their low bits name mapped code.
    step(sign_pc);
    if(error==UC_ERR_OK)error=uc_reg_read(engine,UC_ARM64_REG_X0,&value);
    if(error==UC_ERR_OK&&value!=input)error=UC_ERR_EXCEPTION;
    const auto restored=uc_context_restore(engine,saved);uc_context_free(saved);
    if(restored!=UC_ERR_OK)return restored;
    if(error==UC_ERR_OK)output=recovered;
    return error;
}
uc_err ConvertDarwinFunctionPointersFromUser(uc_engine* engine,std::uint64_t auth_pc,
    const std::array<std::uint64_t,2>& input,std::array<std::uint64_t,2>& output) noexcept {
    if(!engine||!auth_pc||(auth_pc&3)||auth_pc>UINT64_MAX-4)return UC_ERR_ARG;
    std::size_t architecture=0;auto error=uc_query(engine,UC_QUERY_ARCH,&architecture);
    if(error!=UC_ERR_OK)return error;if(architecture!=UC_ARCH_ARM64)return UC_ERR_ARG;
    std::uint32_t opcode=0;error=uc_mem_read(engine,auth_pc,&opcode,4);
    if(error!=UC_ERR_OK)return error;if(opcode!=0xdac11020)return UC_ERR_ARG;
    uc_arm64_cp_reg control{1,0,3,0,0,0};error=uc_reg_read(engine,UC_ARM64_REG_CP_REG,&control);
    if(error!=UC_ERR_OK)return error;
    // XNU machine_thread_function_pointers_convert_from_user returns before
    // authentication for same-task NOJOP callers; even high bits are retained.
    if(!(control.val&(1ULL<<31))){output=input;return UC_ERR_OK;}
    uc_context* saved=nullptr;error=uc_context_alloc(engine,&saved);if(error!=UC_ERR_OK)return error;
    error=uc_context_save(engine,saved);if(error!=UC_ERR_OK){uc_context_free(saved);return error;}
    auto converted=input;const std::uint64_t modifier=0;
    for(auto& value:converted){
        if(!value||error!=UC_ERR_OK)continue;
        error=uc_reg_write(engine,UC_ARM64_REG_X0,&value);
        if(error==UC_ERR_OK)error=uc_reg_write(engine,UC_ARM64_REG_X1,&modifier);
        if(error==UC_ERR_OK)error=uc_emu_start(engine,auth_pc,auth_pc+4,0,1);
        std::uint64_t completed=0;
        if(error==UC_ERR_OK)error=uc_reg_read(engine,UC_ARM64_REG_PC,&completed);
        if(error==UC_ERR_OK&&completed!=auth_pc+4)error=UC_ERR_EXCEPTION;
        if(error==UC_ERR_OK)error=uc_reg_read(engine,UC_ARM64_REG_X0,&value);
        // No re-sign/compare: ml_auth_ptr_unchecked returns authentication
        // poison without turning it into an eager syscall validation failure.
    }
    const auto restored=uc_context_restore(engine,saved);uc_context_free(saved);
    if(restored!=UC_ERR_OK)return restored;
    if(error==UC_ERR_OK)output=converted;
    return error;
}
uc_err ConvertDarwinThreadStateArm64(uc_engine* engine,std::uint64_t code_pc,
    std::uint64_t data_pc,std::uint64_t strip_pc,
    const std::array<std::uint32_t,68>& input,std::array<std::uint32_t,68>& output) noexcept {
    if(!engine)return UC_ERR_ARG;
    std::size_t architecture=0;auto error=uc_query(engine,UC_QUERY_ARCH,&architecture);
    if(error!=UC_ERR_OK)return error;if(architecture!=UC_ARCH_ARM64)return UC_ERR_ARG;
    const std::array<std::uint64_t,3> pcs{code_pc,data_pc,strip_pc};
    const std::array<std::uint32_t,3> expected{0xdac11020,0xdac11820,0xdac143e0};
    for(std::size_t i=0;i<pcs.size();++i){
        if(!pcs[i]||(pcs[i]&3)||pcs[i]>UINT64_MAX-4)return UC_ERR_ARG;
        std::uint32_t opcode=0;error=uc_mem_read(engine,pcs[i],&opcode,4);
        if(error!=UC_ERR_OK)return error;if(opcode!=expected[i])return UC_ERR_ARG;
    }
    uc_arm64_cp_reg control{1,0,3,0,0,0};error=uc_reg_read(engine,UC_ARM64_REG_CP_REG,&control);
    if(error!=UC_ERR_OK)return error;
    const auto jop_keys=control.val&((1ULL<<31)|(1ULL<<27));
    if(!jop_keys){
        // XNU same-task NOJOP ARM_THREAD_STATE64 conversion leaves all pointer
        // representations untouched and publishes NO_PTRAUTH, not IB_SIGNED_LR.
        auto state=input;state[66]&=0xf0000000u;state[67]=1;
        output=state;return UC_ERR_OK;
    }
    if(jop_keys!=((1ULL<<31)|(1ULL<<27)))return UC_ERR_ARG;
    uc_context* saved=nullptr;error=uc_context_alloc(engine,&saved);if(error!=UC_ERR_OK)return error;
    error=uc_context_save(engine,saved);if(error!=UC_ERR_OK){uc_context_free(saved);return error;}
    auto state=input;
    const auto get=[&](std::size_t at){return std::uint64_t(state[at])|(std::uint64_t(state[at+1])<<32);};
    const auto put=[&](std::size_t at,std::uint64_t value){state[at]=std::uint32_t(value);state[at+1]=std::uint32_t(value>>32);};
    const auto operate=[&](std::uint64_t pc,std::uint64_t value,std::uint64_t modifier){
        if(error==UC_ERR_OK)error=uc_reg_write(engine,UC_ARM64_REG_X0,&value);
        if(error==UC_ERR_OK)error=uc_reg_write(engine,UC_ARM64_REG_X1,&modifier);
        if(error==UC_ERR_OK)error=uc_emu_start(engine,pc,pc+4,0,1);
        std::uint64_t completed=0;
        if(error==UC_ERR_OK)error=uc_reg_read(engine,UC_ARM64_REG_PC,&completed);
        if(error==UC_ERR_OK&&completed!=pc+4)error=UC_ERR_EXCEPTION;
        if(error==UC_ERR_OK)error=uc_reg_read(engine,UC_ARM64_REG_X0,&value);
        return value;
    };
    // NO_PTRAUTH is ignored for enabled-JOP targets. IB LR is retained only
    // when it really carries a signature; an unsigned flagged LR authenticates.
    bool ib_lr=(state[67]&2)!=0;
    if(ib_lr&&operate(strip_pc,get(60),0)==get(60))ib_lr=false;
    if(get(64))put(64,operate(code_pc,get(64),29825));
    if(get(60)&&!ib_lr)put(60,operate(code_pc,get(60),30675));
    if(get(62))put(62,operate(data_pc,get(62),52205));
    if(get(58))put(58,operate(data_pc,get(58),17687));
    // Existing context ABI stores user NZCV only; flags are representation
    // metadata consumed here, not guest PSTATE or inherited privilege bits.
    state[66]&=0xf0000000u;state[67]=0;
    const auto restored=uc_context_restore(engine,saved);uc_context_free(saved);
    if(restored!=UC_ERR_OK)return restored;
    if(error==UC_ERR_OK)output=state;
    return error;
}
}
