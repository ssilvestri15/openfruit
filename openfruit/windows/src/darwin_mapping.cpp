#include "darwin_mapping.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdio>
#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <unicorn/unicorn.h>

namespace OpenFruit {
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
struct Handle { HANDLE value = INVALID_HANDLE_VALUE; ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
template<class Control> std::string Snapshot(const DarwinClosureImage& image, const Control& control) {
    Handle file{CreateFileW(image.source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    Require(file.value != INVALID_HANDLE_VALUE, "Original image cannot be acquired immutably.");
    LARGE_INTEGER size{};
    Require(GetFileSizeEx(file.value, &size) && size.QuadPart > 0 && size.QuadPart <= 512ll * 1024 * 1024,
        "Original mapping input exceeds file budget.");
    std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
    for (std::size_t offset = 0; offset < bytes.size();) {
        control();
        DWORD read = 0;
        Require(ReadFile(file.value, bytes.data() + offset,
            static_cast<DWORD>(std::min<std::size_t>(1024 * 1024, bytes.size() - offset)), &read, nullptr) && read,
            "Original mapping snapshot read failed.");
        offset += read;
    }
    const auto hash = Sha256(bytes);
    control();
    Require(hash && *hash == image.metadata.sha256, "Original image changed after dependency inspection.");
    return bytes;
}
std::uint64_t Add(std::uint64_t address, std::int64_t addend) {
    if (addend >= 0) {
        Require(static_cast<std::uint64_t>(addend) <= UINT64_MAX - address, "Bind addend overflows address.");
        return address + static_cast<std::uint64_t>(addend);
    }
    const auto magnitude = std::uint64_t(-(addend + 1)) + 1;
    Require(address >= magnitude, "Bind addend underflows address."); return address - magnitude;
}
DWORD Protection(std::uint32_t bits) {
    if (bits & 4) return bits & 2 ? PAGE_EXECUTE_READWRITE : bits & 1 ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    return bits & 2 ? PAGE_READWRITE : bits & 1 ? PAGE_READONLY : PAGE_NOACCESS;
}
}
DarwinMappedImages::~DarwinMappedImages() { for (const auto& image : images_) if (image.allocation) VirtualFree(image.allocation, 0, MEM_RELEASE); }
JsonValue DarwinProcessThread::ToJson() const {
    auto value=JsonValue::ObjectValue();value.Set("owner",JsonValue::String(owner));value.Set("cpu",JsonValue::Number(std::to_string(cpu)));
    value.Set("original",original.ToJson());value.Set("pc",JsonValue::Number(std::to_string(pc)));value.Set("sp",JsonValue::Number(std::to_string(sp)));
    value.Set("runtime_initialized",JsonValue::Boolean(false));return value;
}
bool DarwinMappedImages::ProcessThread(const std::string& executable,const DarwinProcessStack& stack,
    DarwinProcessThread& output,std::string& error) const {
    output={};error.clear();try{
        const auto& main=Find(executable);const auto& args=stack.Arguments();const auto range=stack.Range();
        const auto header=main.original.shared_cache?main.base:reinterpret_cast<std::uint64_t>(main.allocation);
        Require(args.main_header==header&&args.cpu==main.original.metadata.cpu&&args.kernel_args%16==0
            &&args.kernel_args>=range.address&&args.kernel_args-range.address<range.size,"Thread stack does not belong to mapped executable.");
        Require(!main.original.metadata.interpreter.empty(),"Dynamic process interpreter metadata is absent.");
        const DarwinClosureEdge* edge=nullptr;
        for(const auto& candidate:closure_.edges)if(candidate.owner==executable&&candidate.interpreter){
            Require(!edge&&candidate.install_name==main.original.metadata.interpreter&&!candidate.resolved_path.empty(),"Original interpreter edge is ambiguous or unresolved.");edge=&candidate;}
        Require(edge,"Original interpreter edge is absent.");const auto& interpreter=Find(edge->resolved_path);
        const auto& source=interpreter.original.metadata;Require(source.file_type==7&&source.cpu==args.cpu&&source.unix_thread.present,"Original interpreter Unix thread state is absent or incompatible.");
        Require(source.unix_thread.sp==0,"Original custom initial stack state is unsupported.");
        const auto base=interpreter.original.shared_cache?interpreter.base:reinterpret_cast<std::uint64_t>(interpreter.allocation);
        Require(source.unix_thread.pc>=interpreter.base&&source.unix_thread.pc-interpreter.base<=UINT64_MAX-base,"Initial interpreter PC overflows mapped address.");
        DarwinProcessThread thread;thread.owner=edge->resolved_path;thread.cpu=source.cpu;thread.original=source.unix_thread;
        thread.pc=base+source.unix_thread.pc-interpreter.base;thread.sp=args.kernel_args;
        output=std::move(thread);return true;
    }catch(const std::exception& failure){error=failure.what();return false;}
}
DarwinProcessArguments::~DarwinProcessArguments(){if(allocation_&&owns_allocation_)VirtualFree(allocation_,0,MEM_RELEASE);}
DarwinMappedRange DarwinProcessArguments::Range() const noexcept{return {reinterpret_cast<std::uint64_t>(allocation_),allocation_size_,3,allocation_};}
JsonValue DarwinProcessArguments::ToJson() const {
    auto result=JsonValue::ObjectValue();const auto* words=static_cast<const std::uint64_t*>(allocation_);
    for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
        {"kernel_args",kernel_args},{"program_vars",program_vars},{"argv",argv},{"envp",envp},{"apple",apple},
        {"main_header",main_header},{"main_entry",main_entry},{"stack_size_hint",stack_size_hint},
        {"argc",argc},{"environment_count",environment_count},{"apple_count",apple_count},
        {"allocation_size",allocation_size_},{"cpu",cpu},{"platform",platform},{"kernel_header_readback",words[0]},{"kernel_argc_readback",words[1]}})
        result.Set(key,JsonValue::Number(std::to_string(value)));
    result.Set("runtime_initialized",JsonValue::Boolean(false));return result;
}
DarwinProcessStack::~DarwinProcessStack(){if(reservation_)VirtualFree(reservation_,0,MEM_RELEASE);}
DarwinMappedRange DarwinProcessStack::Range() const noexcept{return {usable_address_,usable_size_,3,reinterpret_cast<void*>(usable_address_)};}
JsonValue DarwinProcessStack::ToJson() const {
    auto result=JsonValue::ObjectValue();
    for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
        {"reservation",reinterpret_cast<std::uint64_t>(reservation_)},{"reservation_size",reservation_size_},
        {"usable_address",usable_address_},{"usable_size",usable_size_},{"darwin_page_size",page_size_},
        {"stack_top",stack_top_},{"kernel_sp",arguments_->kernel_args},{"requested_size",requested_size_},{"effective_limit",effective_limit_}})
        result.Set(key,JsonValue::Number(std::to_string(value)));
    result.Set("startup_parameters_prepared",JsonValue::Boolean(startup_parameters_prepared_));
    result.Set("runtime_initialized",JsonValue::Boolean(false));return result;
}
std::unique_ptr<DarwinProcessStack> DarwinMappedImages::ProcessStack(const std::string& executable,
    const std::vector<std::string>& args,const std::vector<std::string>& environment,
    const std::vector<std::string>& caller_apple,std::string& error,std::uint64_t inherited_soft_limit) const {
    error.clear();try {
        const std::array<std::string_view,4> keys={"stack_guard=","malloc_entropy=","ptr_munge=","main_stack="};
        for(const auto& value:caller_apple)for(const auto key:keys)
            Require(!value.starts_with(key),"Caller Apple vector conflicts with process-owned startup key.");
        struct Entropy { std::array<std::uint64_t,4> words{};~Entropy(){SecureZeroMemory(words.data(),sizeof(words));} } entropy;
        Require(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(entropy.words.data()),sizeof(entropy.words),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0,
            "Windows Darwin startup entropy generation failed.");
        entropy.words[0]&=~(0xffULL<<8); // XNU stack protector's embedded zero byte.
        const auto format=[](std::string_view key,std::initializer_list<std::uint64_t> values){
            std::string value(key);bool first=true;
            for(const auto word:values){char hex[19]{};std::snprintf(hex,sizeof(hex),"0x%016llx",static_cast<unsigned long long>(word));
                if(!first)value+=',';value+=hex;first=false;}return value;};
        auto apple=caller_apple;
        apple.push_back(format(keys[0],{entropy.words[0]}));
        apple.push_back(format(keys[1],{entropy.words[1],entropy.words[2]}));
        apple.push_back(format(keys[2],{entropy.words[3]}));
        // Reserve exact string storage before addresses exist. These zeros are
        // never exposed to a consumer; replace only this owned string in place.
        apple.push_back(format(keys[3],{0,0,0,0}));
        auto arguments=ProcessArguments(executable,args,environment,apple,error);Require(bool(arguments),error.c_str());
        auto stack=DarwinProcessStack::Create(*arguments,error,inherited_soft_limit);Require(bool(stack),error.c_str());
        const auto actual=format(keys[3],{stack->stack_top_,stack->usable_size_,reinterpret_cast<std::uint64_t>(stack->reservation_),
            stack->reservation_size_-stack->page_size_}); // Exclude the extra upper Windows guard.
        Require(actual.size()==apple.back().size(),"Darwin main-stack string storage differs.");
        const auto* pointers=reinterpret_cast<const std::uint64_t*>(stack->Arguments().apple);
        auto* destination=reinterpret_cast<char*>(pointers[apple.size()-1]);
        std::memcpy(destination,actual.c_str(),actual.size()+1);
        stack->startup_parameters_prepared_=true;return stack;
    }catch(const std::exception& failure){error=failure.what();return {};}
}
std::unique_ptr<DarwinProcessStack> DarwinProcessStack::Create(const DarwinProcessArguments& source,
    std::string& error,std::uint64_t inherited_soft_limit){
    error.clear();try {
        Require(source.platform==1&&(source.cpu==0x01000007||source.cpu==0x0100000c),"Darwin stack platform/CPU defaults are unavailable.");
        Require(source.allocation_&&source.allocation_size_&&source.allocation_size_<=1024*1024,"Invalid Darwin argument block backing.");
        Require(source.argc&&source.argc<=65536&&source.environment_count<=65536&&source.apple_count<=65536,"Invalid Darwin stack argument counts.");
        auto stack=std::unique_ptr<DarwinProcessStack>(new DarwinProcessStack);
        stack->page_size_=source.cpu==0x0100000c?16384:4096;
        constexpr std::uint64_t maximum=64*1024*1024;
        stack->requested_size_=source.stack_size_hint;
        stack->effective_limit_=source.stack_size_hint?source.stack_size_hint:inherited_soft_limit?inherited_soft_limit:8*1024*1024-(source.cpu==0x0100000c?16384:0);
        Require(stack->effective_limit_&&stack->effective_limit_<=maximum,"Darwin stack exceeds supported allocation budget.");
        stack->usable_size_=(stack->effective_limit_+stack->page_size_-1)&~(stack->page_size_-1);
        Require(source.allocation_size_+stack->page_size_<=stack->usable_size_,"Darwin stack has no working space after argument frame.");
        const auto lower_extent=source.stack_size_hint?stack->usable_size_+stack->page_size_:
            std::max(maximum,stack->usable_size_+stack->page_size_);
        stack->reservation_size_=lower_extent+stack->page_size_; // Additional upper Windows boundary guard.
        stack->reservation_=VirtualAlloc(nullptr,static_cast<SIZE_T>(stack->reservation_size_),MEM_RESERVE,PAGE_NOACCESS);
        Require(stack->reservation_,"Windows guarded stack reservation failed.");
        stack->stack_top_=reinterpret_cast<std::uint64_t>(stack->reservation_)+lower_extent;
        stack->usable_address_=stack->stack_top_-stack->usable_size_;
        Require(VirtualAlloc(reinterpret_cast<void*>(stack->usable_address_),static_cast<SIZE_T>(stack->usable_size_),MEM_COMMIT,PAGE_READWRITE),"Windows guarded stack commit failed.");
        const auto frame=stack->stack_top_-source.allocation_size_;
        stack->arguments_=std::unique_ptr<DarwinProcessArguments>(new DarwinProcessArguments);
        auto& args=*stack->arguments_;args.owns_allocation_=false;args.allocation_=reinterpret_cast<void*>(frame);args.allocation_size_=source.allocation_size_;
        std::memcpy(args.allocation_,source.allocation_,source.allocation_size_);
        const auto old_base=reinterpret_cast<std::uint64_t>(source.allocation_);
        const auto relocate=[&](std::uint64_t value){if(!value)return std::uint64_t(0);Require(value>=old_base&&value-old_base<source.allocation_size_,"Darwin argument pointer escapes source frame.");return frame+value-old_base;};
        const auto pointer_words=2+source.argc+1+source.environment_count+1+source.apple_count+1;
        Require(pointer_words<=source.allocation_size_/8&&9<=source.allocation_size_/8-pointer_words,"Darwin argument frame table is invalid.");
        auto* words=static_cast<std::uint64_t*>(args.allocation_);
        for(std::size_t i=2;i<pointer_words;++i)words[i]=relocate(words[i]);
        for(std::size_t i=1;i<4;++i)words[pointer_words+i]=relocate(words[pointer_words+i]);
        for(std::size_t i=5;i<9;++i)words[pointer_words+i]=relocate(words[pointer_words+i]);
        args.kernel_args=frame;args.program_vars=relocate(source.program_vars);args.argv=relocate(source.argv);args.envp=relocate(source.envp);args.apple=relocate(source.apple);
        args.main_header=source.main_header;args.main_entry=source.main_entry;args.stack_size_hint=source.stack_size_hint;args.cpu=source.cpu;args.platform=source.platform;
        args.argc=source.argc;args.environment_count=source.environment_count;args.apple_count=source.apple_count;
        return stack;
    } catch(const std::exception& failure){error=failure.what();return {};}
}
std::unique_ptr<DarwinProcessArguments> DarwinMappedImages::ProcessArguments(const std::string& executable,
    const std::vector<std::string>& args,const std::vector<std::string>& environment,
    const std::vector<std::string>& apple_args,std::string& error) const {
    error.clear();try {
        const auto& image=Find(executable);const auto& metadata=image.original.metadata;
        Require(metadata.file_type==2&&metadata.entrypoint.present,"Process arguments require an original executable with LC_MAIN.");
        Require(!args.empty()&&!args.front().empty()&&args.size()<=65536&&environment.size()<=65536&&apple_args.size()<=65536,"Darwin process argument count is invalid.");
        constexpr std::size_t budget=1024*1024;
        const auto pointer_words=2+args.size()+1+environment.size()+1+apple_args.size()+1;
        Require(pointer_words<=budget/8-9,"Darwin process argument table exceeds budget.");
        const auto tables_size=(pointer_words+9)*8;std::size_t bytes=tables_size;
        for(const auto* list:{&args,&environment,&apple_args})for(const auto& value:*list){
            Require(value.find('\0')==std::string::npos,"Darwin process argument contains embedded NUL.");
            Require(value.size()<budget-bytes,"Darwin process argument bytes exceed budget.");bytes+=value.size()+1;
        }
        auto state=std::unique_ptr<DarwinProcessArguments>(new DarwinProcessArguments);
        state->allocation_size_=(bytes+4095)&~std::size_t(4095);
        state->allocation_=VirtualAlloc(nullptr,state->allocation_size_,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        Require(state->allocation_,"Windows Darwin argument allocation failed.");
        const auto base=reinterpret_cast<std::uint64_t>(state->allocation_);
        state->main_header=image.original.shared_cache?image.base:reinterpret_cast<std::uint64_t>(image.allocation);
        Require(metadata.entrypoint.address>=image.base&&metadata.entrypoint.address-image.base<=UINT64_MAX-state->main_header,"Mapped main entrypoint overflows.");
        state->main_entry=state->main_header+metadata.entrypoint.address-image.base;
        state->stack_size_hint=metadata.entrypoint.stack_size;state->argc=args.size();
        state->cpu=metadata.cpu;state->platform=metadata.platform;
        state->environment_count=environment.size();state->apple_count=apple_args.size();state->kernel_args=base;
        auto* words=static_cast<std::uint64_t*>(state->allocation_);words[0]=state->main_header;words[1]=args.size();
        std::size_t cursor=2,strings=tables_size;
        const auto array=[&](const std::vector<std::string>& values){const auto address=base+cursor*8;
            for(const auto& value:values){words[cursor++]=base+strings;std::memcpy(static_cast<char*>(state->allocation_)+strings,value.c_str(),value.size()+1);strings+=value.size()+1;}
            words[cursor++]=0;return address;};
        state->argv=array(args);state->envp=array(environment);state->apple=array(apple_args);
        Require(cursor==pointer_words&&strings==bytes,"Darwin argument block layout disagrees.");
        // ProgramVars points to writable process variables, not directly to arrays.
        const auto variables=pointer_words;words[variables]=args.size();words[variables+1]=state->argv;words[variables+2]=state->envp;
        const auto basename=args.front().find_last_of('/');words[variables+3]=words[2]+(basename==std::string::npos?0:basename+1);
        state->program_vars=base+(variables+4)*8;
        words[variables+4]=state->main_header;
        for(std::size_t i=0;i<4;++i)words[variables+5+i]=base+(variables+i)*8;
        return state;
    } catch(const std::exception& failure){error=failure.what();return {};}
}
JsonValue DarwinInitializer::ToJson() const {
    auto result=JsonValue::ObjectValue();result.Set("owner",JsonValue::String(owner));result.Set("section",JsonValue::String(section));
    result.Set("offset_encoding",JsonValue::Boolean(offset_encoding));
    for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
        {"original_slot",original_slot},{"slot",slot},{"original_target",original_target},{"target",target}})
        result.Set(key,JsonValue::Number(std::to_string(value)));
    return result;
}
const DarwinMappedImages::Image& DarwinMappedImages::Find(const std::string& path) const {
    const auto found = std::find_if(images_.begin(), images_.end(), [&](const auto& image) { return image.original.virtual_path == path; });
    Require(found != images_.end(), "Symbol provider is not mapped."); return *found;
}
std::string DarwinMappedImages::Dependency(const Image& owner, std::uint32_t ordinal) const {
    Require(ordinal && ordinal <= owner.original.metadata.dependencies.size(), "Invalid symbol dependency ordinal.");
    const auto& name = owner.original.metadata.dependencies[ordinal - 1].install_name;
    const DarwinClosureEdge* selected = nullptr;
    for (const auto& edge : closure_.edges) if (edge.owner == owner.original.virtual_path && edge.install_name == name && !edge.interpreter) {
        Require(!selected || selected->resolved_path == edge.resolved_path, "Ambiguous symbol dependency binding."); selected = &edge;
    }
    Require(selected, "Symbol dependency is absent from original graph."); return selected->resolved_path;
}
DarwinMappedImages::Resolved DarwinMappedImages::Resolve(const std::string& path, const std::string& name, std::vector<std::string>& stack, bool shallow) const {
    if (path.empty()) return {};
    const auto key = path + '\0' + name;
    Require(stack.size() < 64 && std::find(stack.begin(), stack.end(), key) == stack.end(), "Cyclic or excessive symbol re-export lookup.");
    stack.push_back(key);
    struct Pop { std::vector<std::string>& stack; ~Pop() { stack.pop_back(); } } pop{stack};
    const auto& image = Find(path); const auto& metadata = image.original.metadata;
    const auto symbol = std::lower_bound(metadata.exports.begin(), metadata.exports.end(), name,
        [](const auto& entry, const auto& value) { return entry.symbol < value; });
    if (symbol != metadata.exports.end() && symbol->symbol == name) {
        if (symbol->flags & 8) return Resolve(Dependency(image, symbol->library_ordinal), symbol->imported_name, stack,shallow);
        Require(!(symbol->flags & 0x30) && (symbol->flags & 3) != 1, "TLS/resolver/function-variant export execution is unavailable.");
        if ((symbol->flags & 3) == 2) return {symbol->value, true, bool(symbol->flags&4),image.original.shared_cache};
        if(image.original.shared_cache){
            Require(symbol->value<=UINT64_MAX-image.base,"Original cached export address overflow.");
            const auto address=image.base+symbol->value;
            Require(cache_memory_&&std::any_of(cache_memory_->Ranges().begin(),cache_memory_->Ranges().end(),[&](const auto& range){return address>=range.address&&address-range.address<range.size&&range.protection;}),"Original cached export points outside guest cache ranges.");
            return {address,true,bool(symbol->flags&4),true};
        }
        Require(symbol->value < image.size, "Export offset exceeds mapped image.");
        const auto original_address = Add(image.base, std::bit_cast<std::int64_t>(symbol->value));
        Require(std::any_of(metadata.segments.begin(), metadata.segments.end(), [&](const auto& segment) {
            return original_address >= segment.address && original_address - segment.address < segment.size && segment.initial_protection;
        }), "Export points outside mapped segments.");
        return {reinterpret_cast<std::uint64_t>(image.allocation) + symbol->value, true,bool(symbol->flags&4),false};
    }
    if(!shallow) for (std::uint32_t i = 0; i < metadata.dependencies.size(); ++i) if (metadata.dependencies[i].reexport) {
        const auto result = Resolve(Dependency(image, i + 1), name, stack); if (result.found) return result;
    }
    return {};
}
DarwinMappedImages::Resolved DarwinMappedImages::ResolveWeak(const std::string& name) const {
    Resolved selected;
    std::vector<std::uint64_t> cached_definitions;
    // Initial global images remain in loader registration order. A strong
    // definition replaces a weak one; otherwise retain the first definition.
    for(const auto& image:images_) {
        if(!(image.original.metadata.header_flags&0x8000)) continue; // MH_WEAK_DEFINES
        std::vector<std::string> stack;
        const auto candidate=Resolve(image.original.virtual_path,name,stack,true);
        if(!candidate.found) continue;
        if(candidate.cached) cached_definitions.push_back(candidate.address);
        if(!selected.found || (selected.weak_definition&&!candidate.weak_definition)) selected=candidate;
    }
    if(selected.found&&!selected.cached) {
        // Shared-cache clients need original patch-table metadata when a
        // separately loaded image overrides the cache's canonical definition.
        Require(std::all_of(cached_definitions.begin(),cached_definitions.end(),[&](auto address){return address==selected.address;}),
            "Weak-definition override of cached clients requires original cache patch metadata.");
    }
    return selected;
}
const void* DarwinMappedImages::Symbol(const std::string& image, const std::string& name, std::string& error) const {
    error.clear();
    try { std::vector<std::string> stack; const auto result = Resolve(image, name, stack);
        Require(result.found, "Original exported symbol is missing."); return reinterpret_cast<const void*>(result.address);
    } catch (const std::exception& failure) { error = failure.what(); return nullptr; }
}
std::unique_ptr<DarwinMappedImages> DarwinMappedImages::Load(const std::string& executable,
    const std::vector<std::filesystem::path>& trees, std::string& error, const DarwinClosureOptions& options, DarwinMappingMode mode,
    const std::function<std::uint64_t(const DyldCacheSlideFixup&)>& cache_signer,
    const std::vector<std::string>& plugins,
    const std::function<void(const DarwinClosure&)>& prepare_task) {
    error.clear();
    try {
        auto result = std::unique_ptr<DarwinMappedImages>(new DarwinMappedImages);
        result->closure_ = DarwinClosure::Inspect(executable, plugins, trees, options);
        Require(result->closure_.analyzed, result->closure_.diagnostic.c_str());
        Require(mode == DarwinMappingMode::NativeCpu ? result->closure_.cpu == DarwinProcessCpu()
            : result->closure_.cpu == 0x0100000c && uc_arch_supported(UC_ARCH_ARM64), "Foreign ISA execution backend is unavailable.");
        Require(result->closure_.StrongImagesResolved(), "Original strong runtime providers are missing.");
        // The guest task ABI must be selected from the admitted main image
        // before any shared-cache or image pointer is signed. Reuse this exact
        // closure rather than inspect/load a second copy of the executable.
        if(prepare_task)prepare_task(result->closure_);
        if(!result->closure_.EagerInitializationOrder(executable,plugins,result->initialization_order_,error,options))throw std::runtime_error(error);
        SYSTEM_INFO system{}; GetSystemInfo(&system); std::uint64_t total = 0;
        const auto control = [&] {
            const auto context = CurrentOperationContext();
            Require(!options.cancellation.Requested() && (!context || !context->CancellationRequested()), "Darwin mapping cancelled.");
            Require(std::chrono::steady_clock::now() < options.deadline && (!context || !context->DeadlineExceeded()), "Darwin mapping deadline exceeded.");
        };
        if(std::any_of(result->closure_.images.begin(),result->closure_.images.end(),[](const auto& image){return image.shared_cache;})){
            Require(mode==DarwinMappingMode::Arm64Guest,"Original cached VM addresses require the ARM64 guest backend.");
            result->cache_memory_=result->closure_.original_cache->MapMemory(error);Require(bool(result->cache_memory_),error.c_str());
        }
        for (const auto& original : result->closure_.images) {
            control(); const auto& metadata = original.metadata;
            for (const auto command : metadata.required_commands)
                Require(command == 0x80000018 || command == 0x8000001c || command == 0x8000001f
                    || command == 0x80000022 || command == 0x80000023 || command == 0x80000028
                    || command == 0x80000033 || command == 0x80000034, "Required Mach-O command is unsupported by native mapper.");
            if(original.shared_cache){Image image;image.original=original;image.base=metadata.cache_header_address;Require(image.base,"Original cached image header VM address absent.");result->images_.push_back(std::move(image));continue;}
            Require(!metadata.legacy_fixups_required, "Legacy dyld fixup application is unavailable.");
            Require(!metadata.chained_fixups.present || metadata.chained_fixups.pointers_walked, "Chained pointer format cannot be applied.");
            Image image; image.original = original;
            const auto header = std::find_if(metadata.segments.begin(), metadata.segments.end(), [](const auto& segment) {
                return !segment.file_offset && segment.file_size;
            });
            Require(header != metadata.segments.end(), "Mach-O header mapping is missing."); image.base = header->address;
            for (const auto& segment : metadata.segments) {
                if (segment.address < image.base) { Require(!segment.initial_protection && !segment.file_size, "Unsupported segment below header base."); continue; }
                Require((segment.address - image.base) % system.dwPageSize == 0, "Segment cannot preserve Windows page protections.");
                image.size = std::max(image.size, segment.address - image.base + segment.size);
            }
            Require(image.size && image.size <= 512ull * 1024 * 1024 - total, "Native image mapping budget exceeded."); total += image.size;
            const auto bytes = Snapshot(original, control);
            // Register ownership before allocating so all subsequent failures roll back.
            result->images_.push_back(std::move(image)); auto& mapped = result->images_.back();
            mapped.allocation = VirtualAlloc(nullptr, static_cast<SIZE_T>(mapped.size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            Require(mapped.allocation, "Windows native image allocation failed.");
            for (const auto& segment : metadata.segments) if (segment.file_size) {
                std::memcpy(static_cast<char*>(mapped.allocation) + segment.address - mapped.base,
                    bytes.data() + metadata.slice_offset + segment.file_offset, static_cast<std::size_t>(segment.file_size));
            }
        }
        for (auto& image : result->images_) {
            if(image.original.shared_cache)continue;
            // The dynamic linker (MH_DYLINKER, file_type == 7) relocates and PAC-signs
            // itself at runtime via rebaseSelf(). Applying loader fixups here would
            // cause dyld to double-rebase its own pointers during bootstrap.
            if(image.original.metadata.file_type==7)continue;
            const auto& metadata = image.original.metadata;
            for (const auto& pointer : metadata.chained_fixups.pointers) {
                control(); std::uint64_t value = 0;
                if (pointer.bind) {
                    const auto& entry = metadata.chained_fixups.imports[pointer.import_index]; std::vector<std::string> stack;
                    std::string provider;
                    if (entry.library_ordinal > 0) provider = result->Dependency(image, entry.library_ordinal);
                    else if (entry.library_ordinal == 0) provider = image.original.virtual_path;
                    else if (entry.library_ordinal == -1) provider = executable;
                    else if(entry.library_ordinal==-3) provider="<weak-lookup>";
                    else throw std::runtime_error("Flat namespace binding is unavailable. Owner: "+image.original.virtual_path+"; symbol: "+entry.symbol);
                    Resolved symbol;
                    try{symbol=entry.library_ordinal==-3?result->ResolveWeak(entry.symbol):result->Resolve(provider,entry.symbol,stack);}catch(const std::exception& failure){throw std::runtime_error(std::string(failure.what())+" Owner: "+image.original.virtual_path+"; provider: "+provider+"; symbol: "+entry.symbol);}
                    if(!symbol.found&&!entry.weak)throw std::runtime_error("Original strong imported symbol is missing. Owner: "+image.original.virtual_path+"; provider: "+provider+"; symbol: "+entry.symbol);
                    Require(symbol.found || entry.weak, "Original strong imported symbol is missing.");
                    Require(symbol.found || (!entry.addend && !pointer.addend), "Missing weak symbol addend semantics are unavailable.");
                    if (symbol.found) value = Add(Add(symbol.address, entry.addend), pointer.addend);
                    if(entry.library_ordinal==-3) result->weak_bindings_.push_back({image.original.virtual_path,entry.symbol,value});
                } else {
                    const auto target = pointer.target_is_offset ? pointer.target : pointer.target - image.base;
                    Require(pointer.target_is_offset || pointer.target >= image.base, "Rebase target precedes image base.");
                    Require(target < image.size && std::any_of(metadata.segments.begin(), metadata.segments.end(), [&](const auto& segment) {
                        return segment.address >= image.base && target >= segment.address - image.base
                            && target - (segment.address - image.base) < segment.size && segment.initial_protection;
                    }), "Rebase target exceeds mapped segments.");
                    value = reinterpret_cast<std::uint64_t>(image.allocation) + target;
                    // dyld chained rebases store the top byte separately from
                    // the VM target. Translate/check the untagged target first,
                    // then retain the original metadata on the private pointer.
                    Require((value >> 56) == 0, "Mapped rebase address overlaps original high8 metadata.");
                    value |= std::uint64_t(pointer.high8) << 56;
                }
                if (pointer.authenticated) {
                    Require(bool(cache_signer), "Original authenticated pointer signer is unavailable.");
                    Require(pointer.key==0||pointer.key==2,"Original chained pointer B-key signer is unavailable.");
                    DyldCacheSlideFixup fixup;
                    fixup.authenticated = true;
                    fixup.target = value;
                    fixup.address = reinterpret_cast<std::uint64_t>(image.allocation) + pointer.address - image.base;
                    fixup.diversity = pointer.diversity;
                    fixup.address_diversity = pointer.address_diversity;
                    fixup.key_is_data = (pointer.key == 2);
                    value = cache_signer(fixup);
                }
                Require(pointer.address >= image.base && pointer.address - image.base <= image.size - 8,
                    "Fixup write exceeds mapped image.");
                if (image.original.metadata.file_type == 2) {
                    std::uint64_t raw = 0;
                    std::memcpy(&raw, static_cast<char*>(image.allocation) + pointer.address - image.base, 8);
                    image.raw_fixups.push_back({pointer.address - image.base, raw});
                }
                std::memcpy(static_cast<char*>(image.allocation) + pointer.address - image.base, &value, 8); ++result->applied_;
            }
        }
        if(result->cache_memory_){
            const auto& ranges=result->cache_memory_->Ranges();
            const DyldCacheMemoryRange* cached_range=nullptr;
            std::size_t fixup_idx=0;
            const auto walked=result->closure_.original_cache->WalkSlideFixups([&](const DyldCacheSlideFixup& fixup){
                if((++fixup_idx & 0xfff) == 0) control();
                std::uint64_t value=fixup.target|(std::uint64_t(fixup.high8)<<56);
                if(fixup.authenticated){Require(bool(cache_signer),"Original cached authenticated pointer signer is unavailable.");value=cache_signer(fixup);}
                if(!cached_range||fixup.address<cached_range->address||fixup.address>cached_range->address+cached_range->size-8){
                    const auto range=std::find_if(ranges.begin(),ranges.end(),[&](const auto& m){return fixup.address>=m.address&&fixup.address-m.address<=m.size-8;});
                    Require(range!=ranges.end(),"Original cache fixup escapes private mapping.");
                    cached_range=&(*range);
                }
                std::uint64_t raw=0;std::memcpy(&raw,static_cast<char*>(cached_range->bytes)+fixup.address-cached_range->address,8);Require(raw==fixup.raw,"Original cached fixup source word changed.");std::memcpy(static_cast<char*>(cached_range->bytes)+fixup.address-cached_range->address,&value,8);++result->applied_;
            });Require(walked.Get("complete")->Bool(),walked.GetString("error").c_str());
        }
        // Decode from final private bytes, after every standalone/cache fixup.
        // Do not run any initializer or claim dependency/runtime initialization.
        const auto ranges=result->Ranges();
        for(const auto& image:result->images_){
            const auto& metadata=image.original.metadata;
            const auto runtime_base=image.original.shared_cache?image.base:reinterpret_cast<std::uint64_t>(image.allocation);
            for(const auto kind:{9U,22U}) for(const auto& section:metadata.sections){
                if((section.flags&255)!=kind)continue;
                control();const std::uint64_t width=kind==22?4:8;
                Require(section.address%width==0&&section.size%width==0,"Initializer section alignment/size is invalid.");
                Require(section.size/width<=65536-result->initializers_.size(),"Initializer count budget exceeded.");
                const auto owner=std::find_if(metadata.segments.begin(),metadata.segments.end(),[&](const auto& s){return s.name==section.segment_name;});
                Require(owner!=metadata.segments.end()&&(owner->initial_protection&1),"Initializer section is not readable.");
                Require(kind!=22||!(owner->initial_protection&2),"Initializer offsets must be in a read-only segment.");
                Require(section.address>=image.base&&section.address-image.base<=UINT64_MAX-runtime_base,"Initializer section precedes image header or overflows.");
                const auto start=runtime_base+section.address-image.base;
                for(std::uint64_t offset=0;offset<section.size;offset+=width){
                    control();Require(offset<=UINT64_MAX-start,"Initializer slot address overflows.");const auto slot=start+offset;
                    const auto range=std::find_if(ranges.begin(),ranges.end(),[&](const auto& r){return (r.protection&1)&&r.size>=width&&slot>=r.address&&slot-r.address<=r.size-width;});
                    Require(range!=ranges.end()&&range->host_bytes,"Initializer slot escapes readable mapped memory.");
                    std::uint64_t value=0;std::memcpy(&value,static_cast<const char*>(range->host_bytes)+slot-range->address,static_cast<std::size_t>(width));
                    std::uint64_t relative=value;
                    if(kind==9){Require(value>=runtime_base,"Initializer pointer precedes owning image.");relative=value-runtime_base;}
                    Require(relative<=UINT64_MAX-image.base&&relative<=UINT64_MAX-runtime_base,"Initializer target overflows.");
                    const auto original_target=image.base+relative,target=runtime_base+relative;
                    Require(std::any_of(metadata.segments.begin(),metadata.segments.end(),[&](const auto& s){return (s.initial_protection&4)&&original_target>=s.address&&original_target-s.address<s.size;}),"Initializer target is not executable code in owning image.");
                    result->initializers_.push_back({image.original.virtual_path,section.name,section.address+offset,slot,original_target,target,kind==22});
                }
            }
        }
        for (auto& image : result->images_) {
            if(image.original.shared_cache)continue;
            control(); DWORD old = 0;
            Require(VirtualProtect(image.allocation, static_cast<SIZE_T>(image.size), PAGE_NOACCESS, &old), "Cannot protect image gaps.");
            for (const auto& segment : image.original.metadata.segments) if (segment.size && segment.address >= image.base) {
                Require(VirtualProtect(static_cast<char*>(image.allocation) + segment.address - image.base,
                    static_cast<SIZE_T>(segment.size), Protection(segment.initial_protection), &old), "Cannot preserve original segment protections.");
            }
            Require(FlushInstructionCache(GetCurrentProcess(), image.allocation, static_cast<SIZE_T>(image.size)), "Cannot synchronize original image code.");
        }
        return result;
    } catch (const std::exception& failure) { error = failure.what(); return {}; }
}
std::vector<DarwinMappedRange> DarwinMappedImages::Ranges() const {
    std::vector<DarwinMappedRange> result;
    for (const auto& image : images_) for (const auto& segment : image.original.metadata.segments)
        if (!image.original.shared_cache && segment.size && segment.address >= image.base && segment.initial_protection)
            result.push_back({reinterpret_cast<std::uint64_t>(image.allocation) + segment.address - image.base,
                segment.size, segment.initial_protection,static_cast<char*>(image.allocation)+segment.address-image.base});
    if(cache_memory_)for(const auto& range:cache_memory_->Ranges())result.push_back({range.address,range.size,range.protection,range.bytes});
    if(cache_memory_){const auto& dynamic=cache_memory_->DynamicRange();if(dynamic.size)result.push_back({dynamic.address,dynamic.size,dynamic.protection,dynamic.bytes});}
    return result;
}
int DarwinMappedImages::FilePathByIdentity(std::uint32_t filesystem,std::uint64_t object,std::string& path) const {
    path.clear();return cache_memory_?cache_memory_->FilePathByIdentity(filesystem,object,path):2;
}
std::uint64_t DarwinMappedImages::SharedRegionStart() const noexcept {
    // Report an actual mapped cache region, never a conventional address or
    // guessed fallback. The cache view validates its original range metadata.
    if(!cache_memory_||!closure_.original_cache||cache_memory_->Ranges().empty())return 0;
    return cache_memory_->Ranges().front().address;
}
bool DarwinMappedImages::PrepareForDynamicLinkerBootstrap(const std::string& executable, std::string& error) {
    error.clear();
    try {
        const auto it = std::find_if(images_.begin(), images_.end(), [&](const auto& img) {
            return img.original.virtual_path == executable;
        });
        if (it == images_.end() || it->original.shared_cache || it->original.metadata.file_type != 2 || !it->allocation || it->raw_fixups.empty()) {
            return true;
        }
        DWORD old = 0;
        Require(VirtualProtect(it->allocation, static_cast<SIZE_T>(it->size), PAGE_READWRITE, &old), "Cannot unprotect executable for dyld bootstrap.");
        for (const auto& rf : it->raw_fixups) {
            std::memcpy(static_cast<char*>(it->allocation) + rf.offset, &rf.raw, 8);
        }
        Require(VirtualProtect(it->allocation, static_cast<SIZE_T>(it->size), PAGE_NOACCESS, &old), "Cannot protect executable gaps.");
        for (const auto& segment : it->original.metadata.segments) if (segment.size && segment.address >= it->base) {
            Require(VirtualProtect(static_cast<char*>(it->allocation) + segment.address - it->base,
                static_cast<SIZE_T>(segment.size), Protection(segment.initial_protection), &old), "Cannot preserve original segment protections.");
        }
        Require(FlushInstructionCache(GetCurrentProcess(), it->allocation, static_cast<SIZE_T>(it->size)), "Cannot synchronize executable code.");
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}
}

