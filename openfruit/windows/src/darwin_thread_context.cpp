#include "darwin_thread_context.hpp"
#include <unicorn/arm64.h>
#include <cstddef>
#include <array>

namespace OpenFruit {
uc_err DarwinThreadContext::ClearExclusiveMonitor(uc_engine* engine,std::uint64_t pc) noexcept {
    if(!engine||!pc||(pc&3)||pc>UINT64_MAX-4)return UC_ERR_ARG;
    std::size_t architecture=0;auto error=uc_query(engine,UC_QUERY_ARCH,&architecture);
    if(error!=UC_ERR_OK)return error;if(architecture!=UC_ARCH_ARM64)return UC_ERR_ARG;
    std::uint32_t instruction=0;error=uc_mem_read(engine,pc,&instruction,sizeof(instruction));
    if(error!=UC_ERR_OK)return error;if(instruction!=0xd5033f5f)return UC_ERR_ARG;
    std::uint64_t original_pc=0;error=uc_reg_read(engine,UC_ARM64_REG_PC,&original_pc);
    if(error!=UC_ERR_OK)return error;
    error=uc_emu_start(engine,pc,pc+4,0,1);
    std::uint64_t completed_pc=0;
    const auto read_error=uc_reg_read(engine,UC_ARM64_REG_PC,&completed_pc);
    const auto restore_error=uc_reg_write(engine,UC_ARM64_REG_PC,&original_pc);
    if(error!=UC_ERR_OK)return error;if(read_error!=UC_ERR_OK)return read_error;
    if(restore_error!=UC_ERR_OK)return restore_error;
    return completed_pc==pc+4?UC_ERR_OK:UC_ERR_EXCEPTION;
}
uc_err DarwinThreadContext::InitializeArm64(uc_engine* engine,std::span<const std::uint32_t> words,std::uint64_t tsd,
    std::uint64_t cpu_identity) noexcept {
    if(!engine||context_||words.size()!=68||(words[66]&~0xf0000000u)||words[67])return UC_ERR_ARG;
    std::size_t architecture=0;auto error=uc_query(engine,UC_QUERY_ARCH,&architecture);
    if(error!=UC_ERR_OK)return error;if(architecture!=UC_ARCH_ARM64)return UC_ERR_ARG;
    uc_context* prepared=nullptr;error=uc_context_alloc(engine,&prepared);if(error!=UC_ERR_OK)return error;
    uc_context* creator=nullptr;error=uc_context_alloc(engine,&creator);
    if(error!=UC_ERR_OK){uc_context_free(prepared);return error;}
    error=uc_context_save(engine,creator);
    if(error!=UC_ERR_OK){uc_context_free(creator);uc_context_free(prepared);return error;}
    // Unicorn 2.1.4's saved-context FPCR/FPSR writers call vfp_set_fpscr,
    // which consults ARMCPU ISA metadata outside the copied CPUARMState.
    // Use the complete owning CPU for FP initialization, snapshot it, then
    // restore the creator before editing the context's plain register fields.
    const std::uint32_t fp_default=0;
    error=uc_reg_write(engine,UC_ARM64_REG_FPCR,&fp_default);
    if(error==UC_ERR_OK)error=uc_reg_write(engine,UC_ARM64_REG_FPSR,&fp_default);
    if(error==UC_ERR_OK)error=uc_context_save(engine,prepared);
    const auto restored=uc_context_restore(engine,creator);uc_context_free(creator);
    if(restored!=UC_ERR_OK){uc_context_free(prepared);return restored;}
    if(error!=UC_ERR_OK){uc_context_free(prepared);return error;}
    const auto write=[&](int reg,const void* value){if(error==UC_ERR_OK)error=uc_context_reg_write(prepared,reg,value);};
    for(std::size_t i=0;i<31;++i){
        const auto value=std::uint64_t(words[2*i])|(std::uint64_t(words[2*i+1])<<32);
        write(i<29?UC_ARM64_REG_X0+int(i):i==29?UC_ARM64_REG_X29:UC_ARM64_REG_X30,&value);
    }
    const auto sp=std::uint64_t(words[62])|(std::uint64_t(words[63])<<32);
    const auto pc=std::uint64_t(words[64])|(std::uint64_t(words[65])<<32);
    write(UC_ARM64_REG_SP,&sp);write(UC_ARM64_REG_PC,&pc);write(UC_ARM64_REG_PSTATE,&words[66]);
    write(UC_ARM64_REG_TPIDRRO_EL0,&tsd);
    // XNU arm64/cswitch.s SET_THREAD_REGISTERS reloads CPU_TPIDR_EL0 on a
    // fresh thread switch; a guest-modified creator register is not its source.
    write(UC_ARM64_REG_TPIDR_EL0,&cpu_identity);
    const std::array<std::uint64_t,2> vector{};
    for(int i=0;i<32;++i)write(UC_ARM64_REG_Q0+i,vector.data());
    if(error!=UC_ERR_OK){uc_context_free(prepared);return error;}
    engine_=engine;context_=prepared;saved_=true;captures_=1;return UC_ERR_OK;
}
DarwinThreadContext::~DarwinThreadContext(){if(context_)uc_context_free(context_);}
uc_err DarwinThreadContext::SetWorkqueueStateArm64(uc_engine* engine,
    std::span<const std::uint32_t> words) noexcept {
    if(!saved_||!context_||!engine||engine!=engine_||words.size()!=68||words[66]||words[67])return UC_ERR_ARG;
    std::size_t architecture=0;auto error=uc_query(engine,UC_QUERY_ARCH,&architecture);
    if(error!=UC_ERR_OK)return error;if(architecture!=UC_ARCH_ARM64)return UC_ERR_ARG;
    uc_context* prepared=nullptr;error=uc_context_alloc(engine,&prepared);if(error!=UC_ERR_OK)return error;
    uc_context* creator=nullptr;error=uc_context_alloc(engine,&creator);
    if(error!=UC_ERR_OK){uc_context_free(prepared);return error;}
    error=uc_context_save(engine,creator);
    if(error!=UC_ERR_OK){uc_context_free(creator);uc_context_free(prepared);return error;}
    // Copy the complete saved CPU through the supported backend API, rather
    // than memcpy an opaque uc_context or initialize from the creator. In
    // particular, do not invoke Unicorn's saved-context FPCR/FPSR writers.
    error=uc_context_restore(engine,context_);
    if(error==UC_ERR_OK)error=uc_context_save(engine,prepared);
    const auto restored=uc_context_restore(engine,creator);uc_context_free(creator);
    if(restored!=UC_ERR_OK){uc_context_free(prepared);return restored;}
    if(error!=UC_ERR_OK){uc_context_free(prepared);return error;}
    const auto write=[&](int reg,const void* value){if(error==UC_ERR_OK)error=uc_context_reg_write(prepared,reg,value);};
    for(std::size_t i=0;i<31;++i){
        const auto value=std::uint64_t(words[2*i])|(std::uint64_t(words[2*i+1])<<32);
        write(i<29?UC_ARM64_REG_X0+int(i):i==29?UC_ARM64_REG_X29:UC_ARM64_REG_X30,&value);
    }
    const auto sp=std::uint64_t(words[62])|(std::uint64_t(words[63])<<32);
    const auto pc=std::uint64_t(words[64])|(std::uint64_t(words[65])<<32);
    const std::uint32_t user_cpsr=0;
    // XNU f6217f.../osfmk/arm64/status.c:thread_set_wq_state64 updates only
    // integer saved state then sets PSR64_USER64_DEFAULT. No FP reset or TSD
    // initialization belongs to reuse. Zero is this backend's user-CPSR scope.
    write(UC_ARM64_REG_SP,&sp);write(UC_ARM64_REG_PC,&pc);write(UC_ARM64_REG_PSTATE,&user_cpsr);
    if(error!=UC_ERR_OK){uc_context_free(prepared);return error;}
    uc_context_free(context_);context_=prepared;return UC_ERR_OK;
}
uc_err DarwinThreadContext::Capture(uc_engine* engine) noexcept {
    if(!engine||(engine_&&engine_!=engine))return UC_ERR_ARG;
    if(!context_){
        const auto error=uc_context_alloc(engine,&context_);
        if(error!=UC_ERR_OK)return error;
        engine_=engine;
    }
    saved_=false;
    const auto error=uc_context_save(engine,context_);
    if(error==UC_ERR_OK){saved_=true;++captures_;}
    return error;
}
uc_err DarwinThreadContext::Restore(uc_engine* engine) const noexcept {
    if(!saved_||!engine||engine!=engine_)return UC_ERR_ARG;
    return uc_context_restore(engine,context_);
}
}
