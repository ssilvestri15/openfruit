#include "darwin_arm64.hpp"
#include "darwin_files.hpp"
#include "darwin_sysctl.hpp"
#include "darwin_process_identity.hpp"
#include "darwin_pthread_registration.hpp"
#include "darwin_pthread_creation.hpp"
#include "darwin_kevent.hpp"
#include "darwin_pthread_policy.hpp"
#include "darwin_pointer_auth.hpp"
#include "darwin_thread_context.hpp"
#include "darwin_thread_run_queue.hpp"
#include "darwin_loader_policy.hpp"
#include "darwin_clock_epoch.hpp"
#include "darwin_vm_backing.hpp"
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>
#include <windows.h>
#include <realtimeapiset.h>
#include <bcrypt.h>
#include <array>
#include <algorithm>
#include <atomic>
#include <bit>
#include <cstring>
#include <stdexcept>

namespace OpenFruit {
namespace {
void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void Uc(uc_err status) { if (status != UC_ERR_OK) throw std::runtime_error(uc_strerror(status)); }
bool GuestAccessPermitted(uc_engine* engine,std::uint64_t address,std::size_t size,std::uint32_t permission)noexcept {
    if(!size||address>UINT64_MAX-size)return false;
    uc_mem_region* regions=nullptr;std::uint32_t count=0;
    if(uc_mem_regions(engine,&regions,&count)!=UC_ERR_OK)return false;
    auto cursor=address;const auto end=address+size;
    while(cursor<end){
        const uc_mem_region* match=nullptr;
        for(std::uint32_t i=0;i<count;++i)if(regions[i].begin<=cursor&&cursor<=regions[i].end){match=&regions[i];break;}
        if(!match||(match->perms&permission)!=permission){uc_free(regions);return false;}
        if(match->end>=end-1){cursor=end;break;}
        cursor=match->end+1;
    }
    uc_free(regions);return cursor==end;
}
bool GuestRangeUnmapped(uc_engine* engine,std::uint64_t address,std::size_t size)noexcept {
    if(!size||address>UINT64_MAX-size)return false;
    uc_mem_region* regions=nullptr;std::uint32_t count=0;
    if(uc_mem_regions(engine,&regions,&count)!=UC_ERR_OK)return false;
    const auto end=address+size;
    bool free_range=true;
    for(std::uint32_t i=0;i<count;++i){
        if(address<=regions[i].end&&(end-1)>=regions[i].begin){
            free_range=false;
            break;
        }
    }
    uc_free(regions);
    return free_range;
}
bool FindUnmappedGuestRange(uc_engine* engine,std::uint64_t hint,std::uint64_t size,std::uint64_t align_mask,std::uint64_t& result)noexcept {
    if(!size||size>0x00007fffffffffffULL)return false;
    uc_mem_region* regions=nullptr;std::uint32_t count=0;
    if(uc_mem_regions(engine,&regions,&count)!=UC_ERR_OK)return false;
    std::uint64_t candidate=(hint+align_mask)&~align_mask;
    constexpr std::uint64_t max_va=0x00007fffffffffffULL;
    bool found=false;
    while(candidate<=max_va-size){
        const auto end=candidate+size;
        bool collision=false;
        std::uint64_t next_candidate=candidate;
        for(std::uint32_t i=0;i<count;++i){
            const auto r_begin=regions[i].begin;
            const auto r_end=regions[i].end;
            if(candidate<=r_end&&(end-1)>=r_begin){
                collision=true;
                if(r_end<max_va){
                    const auto jumped=(r_end+1+align_mask)&~align_mask;
                    if(jumped>next_candidate)next_candidate=jumped;
                }
            }
        }
        if(!collision){
            result=candidate;
            found=true;
            break;
        }
        if(next_candidate<=candidate){
            if(candidate>max_va-(align_mask+1))break;
            candidate+=(align_mask+1);
        } else {
            candidate=next_candidate;
        }
    }
    uc_free(regions);
    return found;
}
struct Engine { uc_engine* value = nullptr; ~Engine() { if (value) uc_close(value); } };
struct Allocation { void* value = nullptr; ~Allocation() { if (value) VirtualFree(value, 0, MEM_RELEASE); } };
struct Guest;
std::uint64_t AllocateGuestThreadId() {
    // All engines in this native runtime share one monotonically allocated
    // identity namespace. Exhaustion must not wrap or reuse a live identity.
    static std::atomic<std::uint64_t> next{1};
    auto id=next.load(std::memory_order_relaxed);
    do { Check(id&&id<UINT64_MAX,"Guest thread identity namespace exhausted."); }
    while(!next.compare_exchange_weak(id,id+1,std::memory_order_relaxed));
    return id;
}
// A task-local namespace. Its task control send right owns a real guest binding;
// numeric names are never Windows handles or process identifiers.
struct MachTask {
    Guest* owner;
    const std::uint32_t pid=AllocateDarwinProcessId();
    const std::uint32_t pid_version=AllocateDarwinProcessGeneration();
    const DarwinProcessAuditSession audit_session{};
    // A freshly created root task has no inherited or installed Seatbelt profile.
    // Installing/inheriting profiles is unsupported and must not silently succeed.
    enum class SandboxState { NoProfile };
    const SandboxState sandbox=SandboxState::NoProfile;
    // No native code-sign validator or enforcement/provider has populated this
    // fresh task. Original-file provenance does not confer Apple platform trust.
    struct CodeSigning {std::uint32_t flags=0;bool signature_validated=false;
        bool enforcement=false,platform_binary=false,platform_path=false;
        std::uint32_t Status() const noexcept{return flags|(enforcement?0x1000U:0)
            |(platform_binary?0x04000000U:0)|(platform_path?0x08000000U:0);}};
    const CodeSigning code_signing{};
    const DarwinLoaderPolicy loader_policy;
    // Existing guest CPU model has one CPU in cluster zero. CPU identity is
    // task-owned model metadata, not a mutable creator TPIDR_EL0 snapshot.
    const std::uint64_t modeled_cpu_identity=0;
    enum class Object { Task, Thread, Reply, SpecialReply, Host, Clock, Semaphore };
    struct Thread {MachTask* task;std::uint32_t control_name=0,special_reply_name=0;
        std::uint64_t id=AllocateGuestThreadId(),tsd_base=0;bool alive=true,admitted=false;
        std::size_t remaining_quantum=65536;
        std::uint64_t last_wake_generation=0;
        std::uint32_t signal_mask=0;
        struct PendingRead {
            DarwinFiles::ReadLease lease;
            std::uint64_t requested=0,syscall_pc=0;
            std::optional<std::uint64_t> position;
            bool active=false;
        } pending_read;
        struct WorkqueueBinding {
            bool member=false,idle=false,overcommit=false;
            std::uint8_t qos=0;
            std::uint64_t allocation=0,allocation_size=0,self=0,stack_bottom=0;
            std::uint64_t blocked_at=0,upcalls=0;
            std::optional<std::uint8_t> kevent_bucket; // bound kqworkq servicer
            std::optional<std::uint64_t> workloop;     // bound workloop servicer
        } workqueue;
        // A SYNC_WAIT kevent_id parked on (workloop id, waiter ident).
        std::optional<std::pair<std::uint64_t,std::uint64_t>> workloop_wait;
        DarwinThreadContext context;DarwinPthreadPolicyState policy{};};
    Thread thread{this};
    std::vector<std::unique_ptr<Thread>> peers;
    Thread* current_thread=&thread;
    DarwinThreadRunQueue run_queue;
    struct Entry {
        // XNU IE_BITS_GEN exposes six generation bits plus forced low bits 3.
        // Original libplatform reserves the low owner bit for lock waiters.
        std::uint32_t generation=7,type=0,send_refs=0,dead_refs=0;
        MachTask* task=nullptr;bool pinned=false;
        Object object=Object::Task;bool thread_bound=false;
        Thread* thread_object=nullptr; // borrowed from this task; cleared before retirement
        std::uint64_t context=0;bool guarded=false;
        // An allocated receive right owns an actual empty message queue.
        // Nonblocking empty polls are supported; message delivery and blocking
        // receives still require their own queue/scheduler contracts.
        std::vector<std::vector<std::uint8_t>> messages;
    };
    std::vector<Entry> ports{1};
    std::uint32_t self_name=0,host_name=0,bootstrap_name=0,debug_control_name=0;
    std::string text_path;
    std::optional<DarwinFileSignature> text_signature;
    // Current engine owns exactly one guest execution context. XNU excludes the
    // calling thread from restart synchronization; multi-thread AST/fault ack is
    // unavailable until the guest scheduler is implemented.
    struct RestartableRange {std::uint64_t location;std::uint16_t length,recovery;std::uint32_t flags;};
    static_assert(sizeof(RestartableRange)==16);
    std::array<RestartableRange,64> restartable_ranges{};std::size_t restartable_count=0;
    std::size_t restartable_register_calls=0,restartable_sync_calls=0;
    std::uint32_t RegisterRestartable(std::array<RestartableRange,64> ranges,std::size_t count){
        if(!count||count>ranges.size())return 4;
        std::sort(ranges.begin(),ranges.begin()+count,[](const auto& a,const auto& b){return a.location!=b.location?a.location<b.location:a.length<b.length;});
        for(std::size_t i=0;i<count;++i){const auto& r=ranges[i];
            if(r.length>4096||r.recovery>4096||r.flags||r.location>UINT64_MAX-r.length||r.location>UINT64_MAX-r.recovery)return 4;
            if(i+1<count&&r.location+r.length>ranges[i+1].location)return 4;
        }
        if(restartable_count)return 46; // Release XNU permits one registration.
        restartable_ranges=ranges;restartable_count=count;return 0;
    }

    DarwinProcessCredentials credentials;
    static constexpr std::uint64_t kRlimInfinity=0x7fffffffffffffffULL;
    std::array<std::array<std::uint64_t,2>,9> rlimits{{
        {kRlimInfinity,kRlimInfinity},
        {kRlimInfinity,kRlimInfinity},
        {kRlimInfinity,kRlimInfinity},
        {8ULL*1024*1024,64ULL*1024*1024},
        {0,kRlimInfinity},
        {kRlimInfinity,kRlimInfinity},
        {kRlimInfinity,kRlimInfinity},
        {2048,4096},
        {4096,4096}
    }};
    DarwinPthreadRegistrationState pthread_registration;
    struct Workqueue {
        bool opened=false;
        DarwinWorkqueueDispatchConfiguration configuration{};
        std::uint32_t allow_sigmask=0;
        std::vector<DarwinWorkqueueRequest> requests;
        std::uint64_t opens=0,setups=0,requests_received=0,threads_requested=0;
        std::uint64_t admissions=0,returns=0,reuses=0,parks=0,policy_updates=0;
        DarwinWorkqKqueue kqueue;
        std::uint8_t manager_qos=0; // WQOPS_SET_EVENT_MANAGER_PRIORITY thread QoS
        std::uint64_t kevent_calls=0,kevent_returns=0,kevent_upcalls=0;
        std::map<std::uint64_t,DarwinWorkloop> workloops;
        std::uint64_t kevent_id_calls=0,workloop_returns=0,workloop_upcalls=0,workloop_parks=0;
    } workqueue;
    explicit MachTask(Guest& guest,DarwinLoaderPolicy policy={},std::uint64_t exclusive_clear_pc=0):owner(&guest),loader_policy(policy),run_queue(exclusive_clear_pc){
        const auto index=static_cast<std::uint32_t>(ports.size());
        ports.push_back({7,0x10000,1,0,this,true});
        self_name=(index<<8)|ports[index].generation;
        Check(CaptureDarwinProcessCredentials(credentials)==0,"Native credential snapshot failed.");
    }
    MachTask(const MachTask&)=delete;MachTask& operator=(const MachTask&)=delete;
    ~MachTask(){for(auto& port:ports){port.thread_object=nullptr;port.task=nullptr;port.type=0;port.send_refs=0;port.dead_refs=0;}
        thread.task=nullptr;thread.id=0;thread.tsd_base=0;owner=nullptr;}
    const Entry* Resolve(std::uint32_t name)const noexcept{
        if(!name||name==0xffffffff)return nullptr;
        const auto index=name>>8;if(index>=ports.size())return nullptr;
        const auto& entry=ports[index];
        return entry.generation==(name&0xff)&&entry.type&&entry.task==this?&entry:nullptr;
    }
    MachTask* ResolveSend(std::uint32_t name)const noexcept{
        const auto* entry=Resolve(name);
        return entry&&entry->object==Object::Task&&(entry->type&0x10000)&&entry->send_refs?entry->task:nullptr;
    }
    const Thread* ResolveThread(std::uint32_t name)const noexcept{
        const auto* entry=Resolve(name);
        return entry&&entry->object==Object::Thread&&(entry->type&0x10000)&&entry->send_refs
            &&entry->thread_object&&entry->thread_object->task==this&&entry->thread_object->alive&&entry->thread_object->id?entry->thread_object:nullptr;
    }
    std::uint32_t Allocate(Object object,std::uint32_t type,std::uint32_t refs=0)noexcept{
        // Names cannot alias existing entries. Exhaustion is an allocation
        // failure, never namespace wraparound or successful fake right creation.
        if(!owner||ports.size()>=0x1000000)return 0;
        try {
            const auto index=static_cast<std::uint32_t>(ports.size());
            Entry entry;entry.object=object;entry.type=type;entry.send_refs=refs;entry.task=this;
            ports.push_back(std::move(entry));return (index<<8)|ports[index].generation;
        }catch(...){return 0;}
    }
    Thread* CurrentThread()noexcept{
        return current_thread&&current_thread->task==this&&current_thread->alive?current_thread:nullptr;
    }
    const Thread* CurrentThread()const noexcept{
        return current_thread&&current_thread->task==this&&current_thread->alive?current_thread:nullptr;
    }
    Thread* LookupOwnedThread(std::uint64_t id)noexcept{
        if(thread.id==id)return &thread;
        for(auto& peer:peers)if(peer->id==id)return peer.get();
        return nullptr;
    }
    bool SelectOwnedThread(std::uint64_t id)noexcept{
        auto* selected=LookupOwnedThread(id);
        const auto* queued=run_queue.Lookup(id);
        if(!selected||!selected->alive||!selected->admitted||selected->task!=this
            ||run_queue.Running()!=id||!queued||queued->context!=&selected->context)return false;
        current_thread=selected;return true;
    }
    std::size_t LiveThreadCount()const noexcept{
        std::size_t count=thread.alive&&thread.admitted?1:0;
        for(const auto& peer:peers)if(peer->alive&&peer->admitted)++count;
        return count;
    }
    // Prepared peers are not runnable. Main owns authenticated state preparation
    // and actual ABI copyout before Publish; rollback burns identity/name safely.
    std::uint32_t PrepareOwnedThread(uc_engine* engine,std::span<const std::uint32_t> words,
        std::uint64_t tsd,std::uint32_t& name,std::uint64_t& id){
        name=0;id=0;
        if(!owner||!engine||thread.context.BoundEngine()!=engine)return 4;
        std::unique_ptr<Thread> peer;
        try{peer=std::make_unique<Thread>(this);peers.reserve(peers.size()+1);}
        catch(const std::bad_alloc&){return 3;}
        const auto error=peer->context.InitializeArm64(engine,words,tsd,modeled_cpu_identity);
        if(error!=UC_ERR_OK)return error==UC_ERR_NOMEM?3:4;
        peer->tsd_base=tsd;
        if(const auto* creator=CurrentThread())peer->signal_mask=creator->signal_mask;
        const auto control=Allocate(Object::Thread,0x10000,1);
        if(!control)return 3;
        peer->control_name=control;ports[control>>8].thread_object=peer.get();
        id=peer->id;name=control;peers.push_back(std::move(peer));return 0;
    }
    bool PublishOwnedThread(std::uint32_t name,bool suspended){
        auto* peer=const_cast<Thread*>(ResolveThread(name));
        if(!peer||peer==&thread||peer->admitted||run_queue.Lookup(peer->id))return false;
        if(!run_queue.Admit(peer->id,peer->context,suspended))return false;
        peer->admitted=true;return true;
    }
    bool RollbackPreparedThread(std::uint32_t name)noexcept{
        auto* peer=const_cast<Thread*>(ResolveThread(name));
        if(!peer||peer==&thread||peer->admitted||run_queue.Lookup(peer->id))return false;
        const auto found=std::find_if(peers.begin(),peers.end(),[&](const auto& p){return p.get()==peer;});
        if(found==peers.end())return false;
        for(std::size_t i=1;i<ports.size();++i)if(ports[i].thread_object==peer)
            Retire((static_cast<std::uint32_t>(i)<<8)|ports[i].generation,ports[i]);
        peers.erase(found);return true;
    }
    std::uint32_t SuspendOwnedThread(uc_engine* engine,std::uint32_t name){
        const auto* peer=ResolveThread(name);if(!peer)return 4;
        const auto* queued=run_queue.Lookup(peer->id);if(!peer->admitted||!queued)return 4;
        if(!engine||peer->context.BoundEngine()!=engine)return 4;
        if(queued->suspend_count==UINT32_MAX)return 5;
        return run_queue.Suspend(engine,peer->id)==UC_ERR_OK?0:5;
    }
    std::uint32_t ResumeOwnedThread(std::uint32_t name){
        const auto* peer=ResolveThread(name);if(!peer||!peer->admitted)return 4;
        return run_queue.Resume(peer->id)?0:5;
    }
    std::uint32_t TerminateOwnedThread(uc_engine* engine,std::uint32_t name){
        auto* peer=const_cast<Thread*>(ResolveThread(name));if(!peer||!peer->admitted)return 4;
        if(!engine||peer->context.BoundEngine()!=engine)return 4;
        // Capture a running peer before revoking queue ownership. Main stops the
        // engine when caller==target; a terminated caller never returns success.
        if(run_queue.Running()==peer->id&&run_queue.YieldCurrent(engine)!=UC_ERR_OK)return 5;
        if(!run_queue.Terminate(peer->id))return 5;
        for(std::size_t i=1;i<ports.size();++i){auto& port=ports[i];if(port.thread_object!=peer)continue;
            const auto port_name=(static_cast<std::uint32_t>(i)<<8)|port.generation;
            if(port.object==Object::Thread){
                const auto refs=port.send_refs;Unbind(port_name,port);
                port.type=refs?0x100000:0;port.dead_refs=refs;port.send_refs=0;
                port.pinned=false;port.guarded=false;port.context=0;port.messages.clear();
            }else Unbind(port_name,port); // Task-owned reply receive right remains owned.
        }
        peer->alive=false;if(current_thread==peer)current_thread=nullptr;
        // Keep admitted tombstones owned until task teardown; never free borrowed CPU state.
        return 0;
    }
    std::uint32_t CopyThreadSend()noexcept{
        auto* selected=CurrentThread();if(!selected||!owner)return 0;
        auto& thread=*selected;
        if(ResolveThread(thread.control_name)!=&thread){
            const auto name=Allocate(Object::Thread,0x10000,1);
            if(name)ports[name>>8].thread_object=&thread;
            thread.control_name=name;return name;
        }
        auto& entry=ports[thread.control_name>>8];if(entry.send_refs<0xffff)++entry.send_refs;
        return thread.control_name;
    }
    std::uint32_t ReplyPort(bool special)noexcept{
        auto* selected=CurrentThread();if(!selected||!owner)return 0;
        auto& thread=*selected;
        const auto name=Allocate(special?Object::SpecialReply:Object::Reply,special?0x30000:0x20000,special?1:0);
        if(!name)return 0;
        if(special){
            if(thread.special_reply_name){auto& old=ports[thread.special_reply_name>>8];old.thread_bound=false;old.thread_object=nullptr;}
            thread.special_reply_name=name;if(name){auto& entry=ports[name>>8];entry.thread_bound=true;entry.thread_object=&thread;}
        }
        return name;
    }
    std::uint32_t ConstructPort(std::uint32_t flags,std::uint64_t context)noexcept{
        const std::uint32_t type=(flags&4)?0x30000:0x20000;
        const std::uint32_t refs=(flags&4)?1:0;
        const auto name=Allocate(Object::Reply,type,refs);
        if(name){
            auto& entry=ports[name>>8];
            entry.context=context;
            entry.guarded=(flags&1)!=0;
        }
        return name;
    }
    struct RightResult {std::uint32_t code=0;bool pinned_guard=false;};
    void Unbind(std::uint32_t name,Entry& entry)noexcept{
        if(auto* bound=entry.thread_object){
            if(bound->control_name==name)bound->control_name=0;
            if(bound->special_reply_name==name)bound->special_reply_name=0;
        }
        entry.thread_object=nullptr;entry.thread_bound=false;
        if(host_name==name)host_name=0;
    }
    void Retire(std::uint32_t name,Entry& entry)noexcept{
        Unbind(name,entry);entry.type=0;entry.send_refs=0;entry.dead_refs=0;entry.context=0;entry.guarded=false;entry.messages.clear();
    }
    RightResult ModRefs(std::uint32_t name,std::uint32_t right,std::int32_t delta)noexcept{
        if(right>=5)return {18};
        if(!name||name==0xffffffff)return {right==0||right==2?0u:15u};
        if(!Resolve(name))return {15};
        auto& entry=ports[name>>8];const auto bit=1u<<(16+right);
        if(!(entry.type&bit))return {17};
        if(right==1){
            if(delta==0)return {};
            if(delta!=-1)return {18};
            const auto remaining=entry.send_refs;Unbind(name,entry);entry.messages.clear();entry.send_refs=0;
            if(remaining){entry.type=0x100000;entry.dead_refs=remaining;entry.pinned=false;}
            else Retire(name,entry);
            return {};
        }
        // No send-once or port-set creation is currently exposed. Reject
        // absent rights above rather than manufacture success for those types.
        if(right==2||right==3)return {17};
        if(delta>65535||delta<-65535)return {18};
        auto& refs=right==4?entry.dead_refs:entry.send_refs;
        if(refs==65535&&delta!=-65535)return {};
        const auto next=std::int64_t(refs)+delta;if(next<0)return {18};
        if(!next&&entry.pinned)return {20,true};
        refs=static_cast<std::uint32_t>(std::min<std::int64_t>(next,65535));
        if(!refs){entry.type&=~bit;if(!entry.type)Retire(name,entry);}
        return {};
    }
    RightResult Deallocate(std::uint32_t name)noexcept{
        if(!name||name==0xffffffff)return {};
        const auto* entry=Resolve(name);if(!entry)return {15};
        if(entry->type&0x10000)return ModRefs(name,0,-1);
        if(entry->type&0x100000)return ModRefs(name,4,-1);
        return {17};
    }
    std::uint32_t CopySelfSend()noexcept{
        if(ResolveSend(self_name)!=this||!owner)return 0;
        auto& entry=ports[self_name>>8];
        // Darwin copyout pegs a saturated 16-bit user-reference count.
        if(entry.send_refs<0xffff)++entry.send_refs;
        return self_name;
    }
    std::uint32_t CopyHostSend()noexcept{
        if(!owner)return 0;
        if(!host_name||!Resolve(host_name)){
            host_name=Allocate(Object::Host,0x10000,1);
            return host_name;
        }
        auto& entry=ports[host_name>>8];
        if(entry.send_refs<0xffff)++entry.send_refs;
        return host_name;
    }
    std::uint32_t GetSpecialPort(int which)noexcept{
        if(!owner)return 0;
        if(which==1)return CopySelfSend();
        if(which==2)return CopyHostSend();
        // Fresh root tasks have no inherited bootstrap/access/debug send rights.
        // A null special port is not a manufactured task-control port.
        return 0;
    }

};
void InitializePointerAuthentication(uc_engine* engine, bool jop_enabled) {
    // Per-engine keys initialize original guest PAC/AUT instruction semantics.
    struct Keys { std::array<std::uint64_t, 10> words{}; ~Keys() { SecureZeroMemory(words.data(), sizeof(words)); } } keys;
    Check(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(keys.words.data()),
        static_cast<ULONG>(sizeof(keys.words)), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
        "Windows ARM64 process key generation failed.");
    const auto write = [&](std::uint32_t crn, std::uint32_t crm, std::uint32_t op1, std::uint32_t op2, std::uint64_t value) {
        uc_arm64_cp_reg reg{crn, crm, 3, op1, op2, value}; Uc(uc_reg_write(engine, UC_ARM64_REG_CP_REG, &reg));
    };
    const auto update = [&](std::uint32_t crn, std::uint32_t crm, std::uint32_t op1, std::uint32_t op2,
                            std::uint64_t clear, std::uint64_t set) {
        uc_arm64_cp_reg reg{crn, crm, 3, op1, op2, 0}; Uc(uc_reg_read(engine, UC_ARM64_REG_CP_REG, &reg));
        write(crn, crm, op1, op2, (reg.val & ~clear) | set);
    };
    for (std::uint32_t i=0; i<4; ++i) write(2, 1, 0, i, keys.words[i]);
    for (std::uint32_t i=0; i<4; ++i) write(2, 2, 0, i, keys.words[4+i]);
    for (std::uint32_t i=0; i<2; ++i) write(2, 3, 0, i, keys.words[8+i]);
    // Non-secure AArch64 world; allow PAC and key access through EL2/EL3.
    update(1, 1, 6, 0, 0, (1ULL<<17)|(1ULL<<16)|(1ULL<<10)|1ULL);
    update(1, 1, 4, 0, 0, (1ULL<<41)|(1ULL<<40)|(1ULL<<31));
    // Explicit 48-bit lower/upper VA ranges with top-byte tags preserved.
    update(2, 0, 0, 2, 63ULL|(63ULL<<16), 16ULL|(16ULL<<16)|(1ULL<<37)|(1ULL<<38));
    // XNU exec policy: ordinary ARM64 tasks have NOJOP. IA/DA/DB PAC/AUT
    // then act as no-ops, but process-dependent IB return protection remains.
    constexpr auto jop_keys=(1ULL<<31)|(1ULL<<27)|(1ULL<<13);
    update(1, 0, 0, 0, jop_keys|(1ULL<<30), (1ULL<<30)|(jop_enabled?jop_keys:0));
}

// One engine owns both loader PAC state and original guest mappings.
// Member order closes the engine before releasing any mapped host memory.
struct Guest {
    Guest(const Guest&)=delete;Guest& operator=(const Guest&)=delete;
    Guest(Guest&&)=delete;Guest& operator=(Guest&&)=delete;
    Allocation signer_code;
    std::unique_ptr<DarwinMappedImages> mapped;
    Engine engine;
    // Destroy the namespace/bindings before closing the actual guest engine.
    std::unique_ptr<MachTask> task;
    std::unique_ptr<DarwinFiles> files;
    std::uint32_t main_subtype=0;
    bool jop_enabled=false;
    Guest(const std::string& executable, const std::vector<std::filesystem::path>& trees,
          const DarwinClosureOptions& options, const std::vector<std::string>& plugins,
          const DarwinProcessStreams& streams = {}) {
        std::string error;
        signer_code.value=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        Check(signer_code.value,"Windows ARM64 signer storage unavailable.");
        Uc(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &engine.value));
        Uc(uc_ctl_set_cpu_model(engine.value, UC_CPU_ARM64_MAX));
        std::uint32_t user_pstate=0; Uc(uc_reg_write(engine.value,UC_ARM64_REG_PSTATE,&user_pstate));
        Uc(uc_reg_read(engine.value,UC_ARM64_REG_PSTATE,&user_pstate));
        Check((user_pstate&0x1f)==0,"ARM64 user exception level was not initialized.");
        // OPENFRUIT-owned signing/CLREX service instructions; original code is untouched.
        const std::uint32_t signing_instructions[]={0xdac10020,0xdac10820,0xd5033f5f,0xdac11020,0xdac11820,0xdac143e0};
        std::memcpy(signer_code.value,signing_instructions,sizeof(signing_instructions));
        const auto signer_address=reinterpret_cast<std::uint64_t>(signer_code.value);
        Uc(uc_mem_map_ptr(engine.value,signer_address,4096,UC_PROT_READ|UC_PROT_EXEC,signer_code.value));
        std::size_t signed_pointers=0;
        const auto sign=[&](const DyldCacheSlideFixup& fixup){
            Check(fixup.authenticated&&fixup.address<(1ULL<<48),"Original cached PAC location exceeds signer VA range.");
            if(!jop_enabled){++signed_pointers;return fixup.target;}
            // Bound translated-code growth during millions of scalar PAC runs.
            // Flushing backend translations preserves guest registers and PAC keys.
            if(signed_pointers && signed_pointers%65536==0) Uc(uc_ctl_flush_tb(engine.value));
            std::uint64_t value=fixup.target;
            const std::uint64_t modifier=fixup.address_diversity
                ?(fixup.address&0x0000ffffffffffffULL)|(std::uint64_t(fixup.diversity)<<48)
                :fixup.diversity;
            Uc(uc_reg_write(engine.value,UC_ARM64_REG_X0,&value));Uc(uc_reg_write(engine.value,UC_ARM64_REG_X1,&modifier));
            const auto begin=signer_address+(fixup.key_is_data?4:0);
            Uc(uc_emu_start(engine.value,begin,begin+4,0,1));
            std::uint64_t pc=0;Uc(uc_reg_read(engine.value,UC_ARM64_REG_PC,&pc));Check(pc==begin+4,"Original cached pointer signing did not finish.");
            Uc(uc_reg_read(engine.value,UC_ARM64_REG_X0,&value));++signed_pointers;return value;
        };
        const auto prepare_task=[&](const DarwinClosure& closure){
            const auto main_path=NormalizeDarwinVirtualPath(executable);
            const auto main=std::find_if(closure.images.begin(),closure.images.end(),[&](const auto& image){return image.virtual_path==main_path;});
            Check(main!=closure.images.end()&&main->metadata.cpu==0x0100000c,"ARM64 task main ABI is missing.");
            main_subtype=main->metadata.subtype;
            const auto base=main_subtype&0x00ffffffu;
            // The existing image parser admits ARM64 and ARM64e v0. Other
            // ABI versions remain rejected there; do not infer from dyld or
            // cache CPU subtype, or assume an unverified Apple plugin-host
            // code-signing/entitlement exception from an executable's name.
            Check((main_subtype&0x7f000000u)==0&&(base==0||base==2),"Unsupported ARM64 task pointer-authentication ABI.");
            jop_enabled=base==2;
            InitializePointerAuthentication(engine.value,jop_enabled);
        };
        mapped=DarwinMappedImages::Load(executable,trees,error,options,DarwinMappingMode::Arm64Guest,sign,plugins,prepare_task);
        Check(bool(mapped),error.c_str());
        files=std::make_unique<DarwinFiles>(mapped->OriginalClosure(),options);
        if(streams.input)Check(!files->BindInput(0,streams.input).error,"Native task stdin byte-pipe binding failed.");
        if(streams.output)Check(!files->BindOutput(1,streams.output).error,"Native task stdout binding failed.");
        const auto stderr_handle=GetStdHandle(STD_ERROR_HANDLE);
        if(streams.error)Check(!files->BindOutput(2,streams.error).error,"Native task stderr binding failed.");
        else if(stderr_handle&&stderr_handle!=INVALID_HANDLE_VALUE)
            Check(!files->BindOutput(2,stderr_handle).error,"Native task stderr binding failed.");
        for (const auto& range : mapped->Ranges()) {
            Check((range.protection & 1) != 0, "Unreadable original segment cannot initialize ARM64 guest memory.");
            const auto rounded = (range.size + 4095) & ~std::uint64_t(4095);
            Check(range.host_bytes,"Original guest mapping lacks backing memory.");
            Uc(uc_mem_map_ptr(engine.value,range.address,rounded,range.protection,range.host_bytes));
        }
        // Native launch permits executable/loader-relative paths within this
        // admitted mounted namespace; actual file opens still enforce host ACL,
        // canonical containment and original source identities.
        const auto& closure=mapped->OriginalClosure();
        task=std::make_unique<MachTask>(*this,DarwinLoaderPolicy(closure.original_directories.contains("/")&&!closure.original_files.empty(),true),signer_address+8);
        task->text_path=NormalizeDarwinVirtualPath(executable);
    }
};

struct Control {
    const DarwinClosureOptions& options;
    bool rejected = false;
    const char* diagnostic = "ARM64 execution rejected.";
    std::size_t instructions = 0;
    static void Code(uc_engine* engine, std::uint64_t, std::uint32_t, void* context) {
        auto& state = *static_cast<Control*>(context); ++state.instructions;
        const auto operation = CurrentOperationContext();
        if (state.options.cancellation.Requested() || (operation && operation->CancellationRequested())) {
            state.rejected = true; state.diagnostic = "ARM64 execution cancelled."; uc_emu_stop(engine);
        } else if (std::chrono::steady_clock::now() >= state.options.deadline || (operation && operation->DeadlineExceeded())) {
            state.rejected = true; state.diagnostic = "ARM64 execution deadline exceeded."; uc_emu_stop(engine);
        }
    }
    static void Interrupt(uc_engine* engine, std::uint32_t, void* context) {
        auto& state = *static_cast<Control*>(context);
        state.rejected = true; state.diagnostic = "Darwin exception/syscall service is unavailable."; uc_emu_stop(engine);
    }
};
struct BootstrapTrace {
    static constexpr std::uint64_t commpage_address=0xfffffc000ULL;
    static constexpr std::uint64_t commpage_ro_address=0xfffff4000ULL;
    // No Darwin kernel-debug collector/typefilter is registered in this runtime.
    // Windows operation telemetry is a separate service and enables no kdebug bits.
    static constexpr std::uint32_t kdebug_flags=0;
    // XNU atm_types.h: ATM_TRACE_DISABLE means do not initialize new logging.
    // There is no guest ATM/new-logging collector; host operation telemetry
    // does not supply one. Publish that explicit disabled provider policy.
    static constexpr std::uint32_t atm_diagnostic_config=0x100;
    // No scheduler publisher maintains COMM_PAGE_APPROX_TIME. XNU publishes
    // this flag as zero when CONFIG_MACH_APPROXIMATE_TIME is disabled; original
    // wrappers then use the real absolute clock, never the zero-filled counter.
    static constexpr std::uint8_t approximate_time_supported=0;
    // The native runtime has no guest kernel debugger provider. Publish that
    // negative capability explicitly; do not infer Apple firmware/boot policy
    // from a zero-filled commpage or Windows debugger attachment.
    static constexpr std::uint32_t debugger_flags=0;
    // No optional dyld system overrides are enabled by this native provider.
    static constexpr std::uint64_t dyld_flags=0;
    // DTrace DOF is disabled by default in userspace.
    static constexpr std::uint8_t dtrace_dof_enabled=0;
    // No CSR relaxation is enabled in this provider. This is its own policy,
    // not a claim to enforce or reconstruct an installed Apple boot policy.
    static constexpr std::uint32_t csr_config=0;
    static constexpr std::uint32_t multiuser_config=0;
    static constexpr std::uint8_t aprr_support=0;
    static constexpr std::uint64_t quiescent_counter=0;
    static constexpr std::uint8_t physical_cpus=1;
    static constexpr std::uint8_t logical_cpus=1;
    static constexpr std::uint8_t active_cpus=1;
    static constexpr std::uint8_t ncpus=1;
    static constexpr std::uint8_t cpu_clusters=1;
    static constexpr std::uint16_t cache_linesize=128;
    static constexpr std::uint32_t cpu_family=0x1b588bb3;
    static constexpr std::uint64_t commpage_memory_size=4ULL*1024*1024*1024;
    static constexpr std::uint64_t cpu_capabilities64=
        0x00000008ULL|0x00000040ULL|0x00000080ULL|0x00000100ULL|0x00000200ULL|
        0x00000400ULL|0x00000800ULL|0x00001000ULL|0x00002000ULL|0x00004000ULL|
        0x00008000ULL|0x00010000ULL|0x01000000ULL|0x02000000ULL|0x04000000ULL|
        0x80000000ULL|0x0000000100000000ULL|0x0000000200000000ULL|0x0000010000000000ULL|
        0x0000020000000000ULL|0x0000040000000000ULL|0x0000080000000000ULL|0x0000200000000000ULL|
        0x0000400000000000ULL|0x0001000000000000ULL|0x0002000000000000ULL|0x0004000000000000ULL|
        0x0008000000000000ULL|0x0010000000000000ULL|0x0020000000000000ULL|0x0040000000000000ULL|
        // The selected Unicorn backend traps on MRS DIT. Do not advertise DIT
        // and thereby select an unsupported original guest instruction path.
        0x0080000000000000ULL|0x0100000000000000ULL|0x0400000000000000ULL;
    static constexpr std::uint16_t commpage_version=3;
    const DarwinClosureOptions& options;
    MachTask& task;
    const DarwinProcessStack& stack;
    std::size_t callbacks=0,prefix_size=0;
    std::size_t block_quantum_end=0;
    std::array<std::pair<std::uint64_t,std::uint32_t>,16> prefix{};
    struct Instruction {std::uint64_t pc=0;std::uint32_t opcode=0;
        std::array<std::uint64_t,32> registers{};
        std::uint64_t load_address=0,load_value=0;bool load_observed=false;};
    std::array<Instruction,64> recent{};
    std::size_t recent_count=0;
    std::uint64_t last_pc=0,memory_address=0,syscall_selector=0;
    std::uint32_t last_opcode=0,interrupt=0;
    int memory_type=0,memory_size=0;
    std::size_t commpage_reads=0;
    std::size_t kdebug_reads=0;
    std::size_t atm_reads=0;
    std::size_t debugger_reads=0;
    struct DebuggerRead {std::uint64_t pc,address;std::uint32_t size,value;};
    std::array<DebuggerRead,16> debugger_prefix{};std::size_t debugger_prefix_size=0;
    std::array<DebuggerRead,16> atm_prefix{};std::size_t atm_prefix_size=0;
    std::array<DebuggerRead,16> approximate_prefix{};std::size_t approximate_prefix_size=0,approximate_reads=0;
    std::size_t cpu_reads=0,dyld_flags_reads=0,dof_reads=0,multiuser_reads=0,aprr_reads=0,quiescent_counter_reads=0;
    std::size_t kernel_page_reads=0,user_page_reads=0;
    std::uint8_t page_shift=0;
    struct GeometryRead {std::uint64_t pc,address;std::uint8_t value;};
    std::array<GeometryRead,16> geometry_prefix{};std::size_t geometry_prefix_size=0;
    std::size_t timebase_reads=0,absolute_calls=0,continuous_calls=0;
    std::uint64_t continuous_bias=0,absolute_first=0,absolute_last=0,continuous_first=0,continuous_last=0;
    DarwinClockEpoch boot_epoch{};
    std::size_t boottime_reads=0;
    struct BootTimeRead {std::uint64_t pc,address,value;};
    std::array<BootTimeRead,16> boottime_prefix{};
    std::size_t boottime_prefix_size=0;
    std::size_t calendar_snapshot_reads=0;
    struct CalendarCall {std::uint64_t pc;std::array<std::uint64_t,3> args;DarwinCalendarTime sample;int error;bool timeval_copied,absolute_copied;};
    std::vector<CalendarCall> calendar_prefix;
    std::uint64_t calendar_calls=0;
    struct EntropyCall {std::uint64_t pc,address,size;int error;bool generated,copied;};
    std::vector<EntropyCall> entropy_prefix;
    std::uint64_t entropy_calls=0;
    struct TimebaseCall {std::uint64_t pc,selector,address;bool copied,readback_verified;};
    std::array<TimebaseCall,16> timebase_prefix{};std::size_t timebase_prefix_size=0,timebase_calls=0,timebase_copyout_failures=0;
    struct ClockCall{std::uint64_t pc,selector,ticks;};
    std::array<ClockCall,16> clock_prefix{};std::size_t clock_prefix_size=0;
    struct TaskCall{std::uint64_t pc,selector;std::uint32_t port;};
    std::array<TaskCall,16> task_prefix{};std::size_t task_prefix_size=0,task_self_calls=0,host_self_calls=0;
    std::array<TaskCall,16> port_prefix{};std::size_t port_prefix_size=0,reply_calls=0,thread_calls=0,special_reply_calls=0,port_construct_calls=0;
    struct BsdCall {std::uint64_t pc,raw_selector,selector,x0,x1,nzcv_before,nzcv_after;};
    DarwinPthreadRegistrationInput pthread_input{};std::array<std::uint64_t,6> pthread_arguments{};
    int pthread_decode_error=0;bool pthread_input_decoded=false;
    bool pthread_entry_auth_pending=false,pthread_entries_converted=false,host_auth_operation=false;
    bool pthread_registration_committed=false,pthread_output_copied=false;
    bool pthread_output_verified=false;
    bool pthread_features_returned=false,scheduler_clock_ready=false;
    std::uint32_t pthread_available_features=0;
    int pthread_registration_error=0;
    std::array<std::uint8_t,DarwinPthreadRegistrationBytes> pthread_output_readback{};
    uc_err pthread_entry_auth_error=UC_ERR_OK;
    std::array<std::uint64_t,2> pthread_converted_entries{};
    std::uint64_t pointer_auth_sign_pc=0,pointer_auth_pc=0;
    std::array<BsdCall,16> bsd_prefix{};std::size_t bsd_prefix_size=0,selfid_calls=0,crossarch_calls=0,getpid_calls=0,proc_info_calls=0,munmap_calls=0,mprotect_calls=0,sigprocmask_calls=0,map_with_linking_calls=0,bsdthread_register_calls=0,shm_open_calls=0,shm_unlink_calls=0;
    std::size_t bsdthread_ctl_calls=0;
    std::size_t csr_calls=0,shared_region_calls=0;
    std::size_t credential_calls=0;
    bool exited=false;
    int exit_status=0;
    std::uint64_t all_image_info_addr=0,all_image_info_size=0;
    struct PlatformCall {std::uint64_t pc,code,input,base,nzcv;};
    std::array<PlatformCall,16> platform_prefix{};std::size_t platform_prefix_size=0,platform_calls=0;
    struct CodeSignCall {std::uint64_t pc;std::array<std::uint64_t,4> args;std::uint32_t status;bool copied;int error;
        std::uint64_t audit_token_pointer=0;DarwinAuditToken audit_token{};bool audit_token_copied=false,audit_token_matches=false,audited=false;};
    std::vector<CodeSignCall> code_sign_prefix;std::size_t code_sign_calls=0;
    enum class Handler {
        TimebaseInfo,
        ModRefs,
        Deallocate,
        AbsoluteClock,
        ContinuousClock,
        TaskSelf,
        HostSelf,
        ThreadSelf,
        Reply,
        SpecialReply,
        ThreadSelfId,
        GetTid,
        Exit,
        Crossarch,
        Platform,
        Csrctl,
        SharedRegion,
        VmProtect,
        VmMap,
        VmAllocate,
        VmDeallocate,
        GetPid,
        ProcInfo,
        Munmap,
        PortConstruct,
        MachMsg2,
        Open,
        OpenAt,
        FsGetPath,
        Close,
        Read,
        Pread,
        Seek,
        Fcntl,
        MacSyscall,
        Sysctl,
        CsOps,
        CsOpsAuditToken,
        Stat,
        Fstat,
        Mmap,
        Write,
        Sigprocmask,
        MapWithLinking,
        Mprotect,
        Access,
        BsdthreadRegister,
        WorkqOpen,
        WorkqKernreturn,
        ShmOpen,
        ShmUnlink,
        Ioctl,
        GetTimeOfDay,
        GetEntropy,
        Socket,
        Issetugid,
        GetAttrList,
        UlockWait,
        UlockWake,
        GetUid,
        GetEuid,
        GetGid,
        GetEgid,
        GetPpid,
        GetGroups,
        GetRlimit,
        SetRlimit,
        Madvise,
        Mincore,
        PsynchMutexWait,
        PsynchMutexDrop,
        PsynchCvBroad,
        PsynchCvSignal,
        PsynchCvWait,
        PsynchCvClrPrepost,
        PsynchRwLongrdlock,
        PsynchRwYieldwrlock,
        PsynchRwDowngrade,
        PsynchRwUpgrade,
        PsynchRwRdlock,
        PsynchRwWrlock,
        PsynchRwUnlock,
        PsynchRwUnlock2,
        UlockWait2,
        Sigaction,
        Sigaltstack,
        ThreadSwitch,
        SemaphoreSignal,
        SemaphoreSignalAll,
        SemaphoreSignalThread,
        SemaphoreWait,
        SemaphoreWaitSignal,
        SemaphoreTimedwait,
        SemaphoreTimedwaitSignal,
        Dup,
        Dup2,
        BsdthreadCtl,
        KeventQos,
        KeventId
    };
    struct Registration {std::uint32_t selector;const char* name;Handler handler;bool bsd;};
    static constexpr std::array registrations={
        Registration{1,"exit",Handler::Exit,true},
        Registration{202,"__sysctl",Handler::Sysctl,true},
        Registration{169,"csops",Handler::CsOps,true},
        Registration{170,"csops_audittoken",Handler::CsOpsAuditToken,true},
        Registration{197,"mmap",Handler::Mmap,true},
        Registration{338,"stat64",Handler::Stat,true},
        Registration{339,"fstat64",Handler::Fstat,true},
        Registration{220,"getattrlist",Handler::GetAttrList,true},
        Registration{381,"__mac_syscall",Handler::MacSyscall,true},
        Registration{3,"read",Handler::Read,true},
        Registration{4,"write",Handler::Write,true},
        Registration{5,"open",Handler::Open,true},
        Registration{33,"access",Handler::Access,true},
        Registration{463,"openat",Handler::OpenAt,true},
        Registration{427,"fsgetpath",Handler::FsGetPath,true},
        Registration{6,"close",Handler::Close,true},
        Registration{41,"dup",Handler::Dup,true},
        Registration{90,"dup2",Handler::Dup2,true},
        Registration{92,"fcntl",Handler::Fcntl,true},
        Registration{116,"gettimeofday",Handler::GetTimeOfDay,true},
        Registration{500,"getentropy",Handler::GetEntropy,true},
        Registration{153,"pread",Handler::Pread,true},
        // XNU's ordinary wrappers test pthread cancellation and then delegate
        // to these same VFS operations. Nocancel entry points omit that test;
        // this does not advertise guest pthread cancellation support.
        Registration{396,"read_nocancel",Handler::Read,true},
        Registration{397,"write_nocancel",Handler::Write,true},
        Registration{398,"open_nocancel",Handler::Open,true},
        Registration{399,"close_nocancel",Handler::Close,true},
        Registration{406,"fcntl_nocancel",Handler::Fcntl,true},
        Registration{414,"pread_nocancel",Handler::Pread,true},
        Registration{464,"openat_nocancel",Handler::OpenAt,true},
        Registration{199,"lseek",Handler::Seek,true},
        Registration{54,"ioctl",Handler::Ioctl,true},
        Registration{97,"socket",Handler::Socket,true},
        Registration{309,"__psynch_rw_unlock2",Handler::PsynchRwUnlock2,true},
        Registration{0xffffffed,"_kernelrpc_mach_port_mod_refs_trap",Handler::ModRefs,false},
        Registration{0xffffffee,"_kernelrpc_mach_port_deallocate_trap",Handler::Deallocate,false},
        Registration{0xffffffe8,"_kernelrpc_mach_port_construct_trap",Handler::PortConstruct,false},
        Registration{0xffffffd1,"mach_msg2_trap",Handler::MachMsg2,false},
        Registration{0xffffffa7,"mach_timebase_info_trap",Handler::TimebaseInfo,false},
        Registration{0xfffffffd,"MACH_ARM_TRAP_ABSTIME",Handler::AbsoluteClock,false},
        Registration{0xfffffffc,"MACH_ARM_TRAP_CONTTIME",Handler::ContinuousClock,false},
        Registration{0xffffffe3,"host_self_trap",Handler::HostSelf,false},
        Registration{0xffffffe4,"task_self_trap",Handler::TaskSelf,false},
        Registration{0xffffffe5,"thread_self_trap",Handler::ThreadSelf,false},
        Registration{0xffffffe6,"mach_reply_port",Handler::Reply,false},
        Registration{0xffffffce,"thread_get_special_reply_port",Handler::SpecialReply,false},
        Registration{0xfffffff6,"_kernelrpc_mach_vm_allocate_trap",Handler::VmAllocate,false},
        Registration{0xfffffff4,"_kernelrpc_mach_vm_deallocate_trap",Handler::VmDeallocate,false},
        Registration{0xfffffff2,"_kernelrpc_mach_vm_protect_trap",Handler::VmProtect,false},
        Registration{0xfffffff1,"_kernelrpc_mach_vm_map_trap",Handler::VmMap,false},
        Registration{20,"getpid",Handler::GetPid,true},
        Registration{24,"getuid",Handler::GetUid,true},
        Registration{25,"geteuid",Handler::GetEuid,true},
        Registration{43,"getegid",Handler::GetEgid,true},
        Registration{47,"getgid",Handler::GetGid,true},
        Registration{79,"getgroups",Handler::GetGroups,true},
        Registration{327,"issetugid",Handler::Issetugid,true},
        Registration{48,"sigprocmask",Handler::Sigprocmask,true},
        Registration{73,"munmap",Handler::Munmap,true},
        Registration{74,"mprotect",Handler::Mprotect,true},
        Registration{75,"madvise",Handler::Madvise,true},
        Registration{266,"shm_open",Handler::ShmOpen,true},
        Registration{267,"shm_unlink",Handler::ShmUnlink,true},
        Registration{336,"proc_info",Handler::ProcInfo,true},
        Registration{366,"bsdthread_register",Handler::BsdthreadRegister,true},
        Registration{367,"workq_open",Handler::WorkqOpen,true},
        Registration{368,"workq_kernreturn",Handler::WorkqKernreturn,true},
        Registration{374,"kevent_qos",Handler::KeventQos,true},
        Registration{375,"kevent_id",Handler::KeventId,true},
        // XNU and the retained original kernel stub agree: mov x16,#0x1de.
        // 439 is kas_info and must not route through pthread policy handling.
        Registration{478,"bsdthread_ctl",Handler::BsdthreadCtl,true},
        Registration{194,"getrlimit",Handler::GetRlimit,true},
        Registration{195,"setrlimit",Handler::SetRlimit,true},
        Registration{372,"thread_selfid",Handler::ThreadSelfId,true},
        Registration{286,"gettid",Handler::GetTid,true},
        Registration{38,"sys_crossarch_trap",Handler::Crossarch,true},
        Registration{483,"csrctl",Handler::Csrctl,true},
        Registration{294,"shared_region_check_np",Handler::SharedRegion,true},
        Registration{550,"map_with_linking_np",Handler::MapWithLinking,true},
        Registration{0x80000000,"platform_syscall",Handler::Platform,false}};
    struct RightCall {std::uint64_t pc,selector,target,name,right,delta,result,before_refs,after_refs,nzcv;};
    std::array<RightCall,16> rights_prefix{};std::size_t rights_prefix_size=0,mod_refs_calls=0,deallocate_calls=0;
    struct VmProtectCall {std::uint64_t pc,selector,target,address,size,set_max,prot,result;};
    std::array<VmProtectCall,16> vm_protect_prefix{};std::size_t vm_protect_prefix_size=0,vm_protect_calls=0;
    struct VmAllocation {
        std::uint64_t address = 0;
        std::uint64_t size = 0;
        std::shared_ptr<DarwinVmBacking> host_memory;
        std::shared_ptr<DarwinPrivateFileMapping> file_mapping;
        std::uint32_t current_protection=3,maximum_protection=7,tag=0,inheritance=1;
        std::uint64_t backing_offset=0;
    };
    std::vector<VmAllocation> vm_allocations{};
    std::uint64_t next_vm_address = 0x100000000ULL;
    struct MmapCall {std::uint64_t pc;std::array<std::uint64_t,6> args;std::uint64_t address;int error;JsonValue source;};
    std::vector<MmapCall> mmap_prefix;std::uint64_t mmap_calls=0;
    uc_engine* bound_engine = nullptr;
    struct VmMapCall {std::uint64_t pc,selector,target,address,size,flags,prot,result,mapped_address=0;};
    std::array<VmMapCall,16> vm_map_prefix{};std::size_t vm_map_prefix_size=0,vm_map_calls=0;VmMapCall vm_map_last{};
    struct PendingMachThreadCreate {
        bool pending=false;
        std::array<std::uint32_t,68> user_state{};
        std::uint64_t reply_address=0;
        std::uint32_t reply_name=0,receive_size=0;
    } mach_thread_create;
    bool thread_lifecycle_reschedule=false;
    std::uint64_t pipe_read_parks=0,pipe_read_wakes=0;
    static std::uint64_t PipeReadKey(const MachTask::Thread& thread){
        Check(thread.id<0x0100000000000000ULL,"Pipe wait-key namespace exhausted.");
        return 0xf500000000000000ULL|thread.id;
    }
    std::size_t PumpPipeReads(){
        std::size_t pending=0;
        const auto service=[&](MachTask::Thread& thread){
            auto& request=thread.pending_read;
            if(!request.active)return;
            const auto* entry=task.run_queue.Lookup(thread.id);
            if(!thread.alive||!entry||entry->state==DarwinThreadRunQueue::State::Terminated){request={};return;}
            ++pending;
            if(entry->state!=DarwinThreadRunQueue::State::Waiting||entry->wait_key!=PipeReadKey(thread))return;
            const auto ready=task.owner->files->ReadCapacity(request.lease,request.requested,request.position);
            if(!ready.pending)pipe_read_wakes+=task.run_queue.Wake(PipeReadKey(thread),1);
        };
        service(task.thread);for(auto& peer:task.peers)service(*peer);
        return pending;
    }

    // Pinned XNU workqueue_internal.h uses a 200us stalled-worker window.
    // QueryUnbiasedInterruptTimePrecise reports 100ns ticks.
    static constexpr std::uint64_t workqueue_busy_window=2000;
    static constexpr std::uint32_t workqueue_thread_mask=0x04011fd8U;
    std::optional<std::uint64_t> workqueue_retry_deadline;
    // One modeled CPU, non-clutch XNU timeshare accounting in Windows 100ns
    // absolute units. CPU charge comes from the executing native thread only.
    static constexpr std::uint64_t scheduler_tick=1250000,load_interval=150000;
    std::uint64_t load_stamp=0,priority_stamp=0,cpu_charged=0,load_samples=0,priority_ticks=0;
    std::array<std::uint32_t,4> scheduler_load{};
    std::array<std::uint8_t,4> scheduler_shifts{127,127,127,127};
    std::uint64_t cpu_segment_id=0,cpu_segment_stamp=0;
    static bool ReadCpuTime(std::uint64_t& time) noexcept {
        FILETIME created{},exited{},kernel{},user{};
        if(!GetThreadTimes(GetCurrentThread(),&created,&exited,&kernel,&user))return false;
        const auto value=[](FILETIME input){return(std::uint64_t(input.dwHighDateTime)<<32)|input.dwLowDateTime;};
        time=value(kernel)+value(user);return true;
    }
    static unsigned SchedulerBucket(int base) noexcept {return base>31?0:base>20?1:base>4?2:3;}
    void UpdateScheduler(std::uint64_t now){
        if(!load_stamp){load_stamp=priority_stamp=now;return;}
        auto& queue=task.run_queue;
        if(now-load_stamp>=load_interval){
            std::array<std::uint32_t,4> load{};
            const auto sample=[&](const MachTask::Thread& thread){
                const auto* entry=queue.Lookup(thread.id);
                if(thread.alive&&entry&&entry->timeshare&&!entry->suspend_count
                    &&(entry->state==DarwinThreadRunQueue::State::Runnable||entry->state==DarwinThreadRunQueue::State::Running))
                    ++load[SchedulerBucket(entry->base_priority)];
            };
            sample(task.thread);for(const auto& peer:task.peers)sample(*peer);
            // sched_average.c weighted lower-band contributions, NCPUS=1.
            load[0]+=std::min(load[1],2u);
            load[0]+=std::min(load[2],1u);load[1]+=std::min(load[2],1u);
            if(load[3]){++load[0];++load[1];++load[2];}
            for(unsigned b=0;b<load.size();++b){
                const auto bucket_load=load[b]>1?std::min(load[b],127u):0u;
                scheduler_load[b]=(scheduler_load[b]*6+((bucket_load<<4)*10))>>4;
            }
            // Sample once at the observed boundary. Never synthesize past
            // loads when a native interval crossed multiple maintenance dates.
            ++load_samples;load_stamp=now;
        }
        const auto ticks=(now-priority_stamp)/scheduler_tick;
        if(!ticks)return;
        for(unsigned bucket=0;bucket<scheduler_load.size();++bucket){
            const auto scaled=scheduler_load[bucket];
            const auto load=(scaled>>4)+((scaled&8)!=0);
            if(!DarwinThreadRunQueue::CalibrateTimeshareShift(scheduler_tick,load,scheduler_shifts[bucket])){
                reason="scheduler_shift_calibration_failure";return;}
        }
        const auto update=[&](MachTask::Thread& thread){
            const auto* entry=queue.Lookup(thread.id);if(!thread.alive||!entry)return;
            const auto shift=entry->timeshare?scheduler_shifts[SchedulerBucket(entry->base_priority)]:127;
            if(!queue.UpdateTimeshareUsage(thread.id,DarwinThreadRunQueue::AgeTimeshareUsage(entry->sched_usage,
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(ticks,32))),shift))
                reason="scheduler_accounting_update_failure";
        };
        update(task.thread);for(auto& peer:task.peers)update(*peer);
        priority_ticks+=ticks;priority_stamp+=ticks*scheduler_tick;
    }
    void ChargeCpu(std::uint64_t id,std::uint64_t delta){
        cpu_charged+=delta;
        auto& queue=task.run_queue;const auto* entry=queue.Lookup(id);
        if(!entry||entry->state==DarwinThreadRunQueue::State::Terminated||!entry->timeshare||entry->pri_shift==127)return;
        const auto usage=static_cast<std::uint32_t>(std::min<std::uint64_t>(UINT32_MAX,std::uint64_t(entry->sched_usage)+delta));
        if(!queue.UpdateTimeshareUsage(id,usage,entry->pri_shift))reason="scheduler_cpu_charge_failure";
    }
    bool RefreshSchedulerShift(std::uint64_t id) noexcept {
        auto& queue=task.run_queue;const auto* entry=queue.Lookup(id);if(!entry)return false;
        return queue.UpdateTimeshareUsage(id,entry->sched_usage,
            entry->timeshare?scheduler_shifts[SchedulerBucket(entry->base_priority)]:127);
    }
    bool ChargeCpuSegment(){
        if(!cpu_segment_id)return true;
        std::uint64_t now=0;
        if(!ReadCpuTime(now)||now<cpu_segment_stamp){reason="scheduler_cpu_clock_failure";return false;}
        ChargeCpu(cpu_segment_id,now-cpu_segment_stamp);cpu_segment_stamp=now;
        return !reason;
    }
    std::size_t LiveWorkqueueWorkers(bool constrained_only=false) const noexcept {
        std::size_t count=0;
        for(const auto& peer:task.peers)if(peer->alive&&peer->workqueue.member
            &&(!constrained_only||(!peer->workqueue.overcommit&&!peer->workqueue.idle)))++count;
        return count;
    }
    static DarwinKeventClock KeventNow() noexcept {
        ULONGLONG absolute=0,continuous=0;
        QueryUnbiasedInterruptTimePrecise(&absolute);QueryInterruptTimePrecise(&continuous);
        return {absolute,continuous};
    }
    bool PrepareWorkqueueUpcall(uc_engine* engine,MachTask::Thread& worker,
        const DarwinWorkqueueRequest& request,bool first,std::optional<std::uint8_t> kevent_bucket={},
        std::optional<std::uint64_t> workloop={}){
        auto& binding=worker.workqueue;
        // Validate owner preconditions before changing the saved continuation.
        if(worker.policy.voucher){reason="unsupported_workqueue_voucher_release";return false;}
        DarwinWorkqueueUpcallRequest upcall;
        upcall.self=binding.self;upcall.stack_bottom=binding.stack_bottom;
        upcall.user_address_max=0x0000ffffffffffffULL;
        upcall.actual_tsd_base=worker.tsd_base;upcall.thread_port=worker.control_name;
        upcall.qos_tier=request.qos_tier;upcall.first_use=first;
        upcall.first_use_tsd_installed=first;
        upcall.flags=(request.overcommit?DarwinWorkqueueOvercommit:0)|(first?0:DarwinWorkqueueReuse);
        if(kevent_bucket){
            // workq_setup_thread gathers the bucket's events onto the new stack.
            auto& kqueue=task.workqueue.kqueue;
            if(!kqueue.Bind(*kevent_bucket)){reason="kevent_bucket_binding_failure";return false;}
            const auto events=kqueue.Collect(*kevent_bucket,KeventNow(),DarwinWorkqueueKeventListLength);
            upcall.kevent_list=(binding.self&~std::uint64_t{15})-std::uint64_t{DarwinWorkqueueKeventListLength}*DarwinKeventQosBytes;
            upcall.kevent_count=static_cast<std::uint32_t>(events.size());
            std::vector<std::uint8_t> bytes(events.size()*DarwinKeventQosBytes);
            for(std::size_t n=0;n<events.size();++n)
                EncodeDarwinKeventQos(events[n],std::span<std::uint8_t,DarwinKeventQosBytes>(bytes.data()+n*DarwinKeventQosBytes,DarwinKeventQosBytes));
            if(!bytes.empty()&&uc_mem_write(engine,upcall.kevent_list,bytes.data(),bytes.size())!=UC_ERR_OK){
                reason="kevent_upcall_copyout_failure";return false;}
            upcall.flags|=DarwinWorkqueueKevent|(*kevent_bucket==DarwinWorkqKqueue::ManagerBucket?DarwinWorkqueueEventManager:0);
            binding.kevent_bucket=kevent_bucket;++task.workqueue.kevent_upcalls;
        }else if(workloop){
            // workq_setup_thread for a workloop request: the bound workloop's
            // events below the stack top and its kqueue id below the list.
            const auto found=task.workqueue.workloops.find(*workloop);
            if(found==task.workqueue.workloops.end()||found->second.Serviced()){reason="workloop_servicer_binding_failure";return false;}
            const auto events=found->second.BeginService(KeventNow(),DarwinWorkqueueKeventListLength);
            upcall.kevent_list=(binding.self&~std::uint64_t{15})-std::uint64_t{DarwinWorkqueueKeventListLength}*DarwinKeventQosBytes;
            upcall.kevent_count=static_cast<std::uint32_t>(events.size());
            std::vector<std::uint8_t> bytes(8+events.size()*DarwinKeventQosBytes);
            for(unsigned n=0;n<8;++n)bytes[n]=static_cast<std::uint8_t>(*workloop>>(8*n));
            for(std::size_t n=0;n<events.size();++n)
                EncodeDarwinKeventQos(events[n],std::span<std::uint8_t,DarwinKeventQosBytes>(bytes.data()+8+n*DarwinKeventQosBytes,DarwinKeventQosBytes));
            if(uc_mem_write(engine,upcall.kevent_list-8,bytes.data(),bytes.size())!=UC_ERR_OK){
                reason="workloop_upcall_copyout_failure";return false;}
            upcall.flags|=DarwinWorkqueueKevent|DarwinWorkqueueWorkloop;
            binding.workloop=workloop;++task.workqueue.workloop_upcalls;
        }
        DarwinWorkqueueUpcallState prepared;
        if(PrepareDarwinWorkqueueUpcallArm64(task.pthread_registration,upcall,prepared)
            !=DarwinWorkqueuePreparationStatus::Ready){reason="workqueue_upcall_precondition_failure";return false;}
        const auto status=worker.context.SetWorkqueueStateArm64(engine,prepared.arm64_words);
        if(status!=UC_ERR_OK){reason="workqueue_upcall_context_failure";return false;}
        binding.qos=request.qos_tier;binding.overcommit=request.overcommit;
        binding.blocked_at=0;
        worker.remaining_quantum=65536;
        // Voucher creation/retention is not provided by this task. Reject any
        // unexpected non-null association instead of silently discarding it.
        worker.signal_mask|=~workqueue_thread_mask&~task.workqueue.allow_sigmask;
        worker.policy.qos={request.qos_tier,0};
        return true;
    }
    MachTask::Thread* CreateWorkqueueWorker(uc_engine* engine,const DarwinWorkqueueRequest& request,
        std::optional<std::uint8_t> kevent_bucket,std::optional<std::uint64_t> workloop={}){
        const auto page=stack.PageSize(),mask=page-1;
        const auto pthread_bytes=task.pthread_registration.pthread_bytes;
        if(pthread_bytes<=0){reason="workqueue_pthread_size_unavailable";return nullptr;}
        constexpr std::uint64_t stack_bytes=512*1024,arm64_pthread_offset=12*1024;
        const auto payload=stack_bytes+((std::uint64_t(pthread_bytes)+arm64_pthread_offset+mask)&~mask);
        const auto total=page+payload;
        std::uint64_t base=0;
        if(!FindUnmappedGuestRange(engine,next_vm_address,total,mask,base)){
            reason="workqueue_stack_address_exhausted";return nullptr;}
        auto backing=DarwinVmBacking::Allocate(total);
        if(!backing){reason="workqueue_stack_allocation_failure";return nullptr;}
        try{vm_allocations.reserve(vm_allocations.size()+2);}catch(...){reason="workqueue_stack_tracking_failure";return nullptr;}
        if(uc_mem_map_ptr(engine,base,total,UC_PROT_NONE,backing->Bytes())!=UC_ERR_OK){
            reason="workqueue_stack_mapping_failure";return nullptr;}
        if(uc_mem_protect(engine,base+page,payload,UC_PROT_READ|UC_PROT_WRITE)!=UC_ERR_OK){
            uc_mem_unmap(engine,base,total);reason="workqueue_stack_protection_failure";return nullptr;}
        vm_allocations.push_back({base,page,backing,nullptr,0,7,30});
        vm_allocations.push_back({base+page,payload,backing,nullptr,3,7,30,1,page});
        next_vm_address=std::max(next_vm_address,base+total);
        const auto self=base+page+stack_bytes+arm64_pthread_offset;
        const auto tsd=self+task.pthread_registration.input.tsd_offset;
        std::array<std::uint32_t,68> initial{};
        std::uint32_t name=0;std::uint64_t id=0;
        auto code=task.PrepareOwnedThread(engine,initial,tsd,name,id);
        if(code){UnmapVmRange(engine,base,base+total);reason="workqueue_thread_preparation_failure";return nullptr;}
        auto* worker=task.LookupOwnedThread(id);
        worker->workqueue.member=true;worker->workqueue.allocation=base;
        worker->workqueue.allocation_size=total;worker->workqueue.self=self;
        worker->workqueue.stack_bottom=base+page;
        // Task-local control right is real, immovable across this namespace,
        // and pinned until actual thread retirement (not a numerical handle).
        task.ports[name>>8].pinned=true;
        if(!PrepareWorkqueueUpcall(engine,*worker,request,true,kevent_bucket,workloop)){
            task.RollbackPreparedThread(name);UnmapVmRange(engine,base,base+total);return nullptr;}
        bool published=false;
        try{published=task.PublishOwnedThread(name,true);}catch(const std::bad_alloc&){}
        if(!published){task.RollbackPreparedThread(name);UnmapVmRange(engine,base,base+total);
            reason="workqueue_thread_publication_failure";return nullptr;}
        return worker;
    }
    enum class Admission { Admitted, Exhausted };
    std::optional<Admission> AdmitWorkqueueWorker(uc_engine* engine,const DarwinWorkqueueRequest& request,
        std::optional<std::uint8_t> kevent_bucket,std::optional<std::uint64_t> workloop={}){
        MachTask::Thread* worker=nullptr;
        for(auto& peer:task.peers)if(peer->alive&&peer->workqueue.member&&peer->workqueue.idle){worker=peer.get();break;}
        const bool reuse=worker!=nullptr;
        if(!worker){
            if(LiveWorkqueueWorkers()>=512)return Admission::Exhausted;
            worker=CreateWorkqueueWorker(engine,request,kevent_bucket,workloop);if(!worker)return std::nullopt;
        }else if(!PrepareWorkqueueUpcall(engine,*worker,request,false,kevent_bucket,workloop))return std::nullopt;
        DarwinPthreadRunQueuePolicyProvider provider(task.run_queue,worker->id);
        if(provider.ApplyQos(worker->policy.qos)!=0){reason="workqueue_priority_provider_failure";return std::nullopt;}
        if(!RefreshSchedulerShift(worker->id)){reason="workqueue_scheduler_shift_failure";return std::nullopt;}
        if(reuse){
            if(!task.run_queue.CancelWait(worker->id)){reason="workqueue_reuse_wait_binding_failure";return std::nullopt;}
        }else if(!task.run_queue.Resume(worker->id)){reason="workqueue_first_resume_failure";return std::nullopt;}
        worker->workqueue.idle=false;++worker->workqueue.upcalls;
        ++task.workqueue.admissions;if(reuse)++task.workqueue.reuses;
        return Admission::Admitted;
    }
    void PumpWorkqueue(uc_engine* engine,std::uint64_t now){
        if(reason||!task.workqueue.opened)return;
        workqueue_retry_deadline.reset();
        for(auto& peer:task.peers){auto& binding=peer->workqueue;
            if(!binding.member)continue;
            if(!peer->alive&&binding.allocation_size){
                if(UnmapVmRange(engine,binding.allocation,binding.allocation+binding.allocation_size)){
                    reason="workqueue_stack_retirement_failure";return;}
                binding.allocation_size=0;continue;
            }
            const auto* entry=task.run_queue.Lookup(peer->id);
            if(peer->alive&&!binding.idle&&entry&&(entry->state==DarwinThreadRunQueue::State::Waiting||entry->suspend_count)){
                if(!binding.blocked_at)binding.blocked_at=now;
            }else binding.blocked_at=0;
        }
        // kqworkq thread requests: non-manager buckets are overcommit, and the
        // manager runs at the event manager priority; one servicer per bucket.
        for(;;){
            const auto bucket=task.workqueue.kqueue.PendingBucket(KeventNow());
            if(!bucket)break;
            const bool manager=*bucket==DarwinWorkqKqueue::ManagerBucket;
            const DarwinWorkqueueRequest request{1,manager?(task.workqueue.manager_qos?task.workqueue.manager_qos:std::uint8_t{4}):*bucket,!manager};
            const auto admitted=AdmitWorkqueueWorker(engine,request,bucket);
            if(!admitted)return;
            if(*admitted==Admission::Exhausted)break;
        }
        // Workloop thread requests: one servicer per workloop at its request QoS.
        for(auto& [id,workloop]:task.workqueue.workloops){
            const auto priority=workloop.ServicerPriority(KeventNow());
            if(!priority)continue;
            auto bits=(*priority&0x3f00u)>>8;std::uint8_t tier=4;
            if(bits){tier=1;while(!(bits&1u)){++tier;bits>>=1;}}
            const DarwinWorkqueueRequest request{1,tier,(*priority&0x80000000u)!=0};
            const auto admitted=AdmitWorkqueueWorker(engine,request,std::nullopt,id);
            if(!admitted)return;
            if(*admitted==Admission::Exhausted)break;
        }
        auto& pending=task.workqueue.requests;
        while(!pending.empty()){
            auto chosen=pending.end();
            for(auto candidate=pending.begin();candidate!=pending.end();++candidate){
                if(!candidate->count)continue;
                if(!candidate->overcommit&&LiveWorkqueueWorkers(true)>=64)continue;
                bool allowed=candidate->overcommit;
                if(!allowed){
                    std::size_t active=0;
                    std::array<std::uint64_t,7> last_blocked{};
                    for(const auto& peer:task.peers){const auto& binding=peer->workqueue;
                        if(!peer->alive||!binding.member||binding.idle
                            ||std::max<unsigned>(binding.qos,2)<std::max<unsigned>(candidate->qos_tier,2))continue;
                        const auto* queued=task.run_queue.Lookup(peer->id);if(!queued)continue;
                        if(!queued->suspend_count&&(queued->state==DarwinThreadRunQueue::State::Runnable||queued->state==DarwinThreadRunQueue::State::Running))++active;
                        else if((queued->state==DarwinThreadRunQueue::State::Waiting||queued->suspend_count)&&binding.blocked_at){
                            const auto bucket=std::max<unsigned>(binding.qos,2);
                            last_blocked[bucket]=std::max(last_blocked[bucket],binding.blocked_at);
                        }
                    }
                    // One busy allowance per QoS bucket, as XNU's lastblocked_ts.
                    for(const auto blocked:last_blocked)if(blocked
                        &&(now<=blocked||now-blocked<workqueue_busy_window)){
                            ++active;const auto deadline=blocked+workqueue_busy_window;
                            if(!workqueue_retry_deadline||deadline<*workqueue_retry_deadline)workqueue_retry_deadline=deadline;
                    }
                    allowed=active<1; // existing modeled CPU count
                }
                if(allowed&&(chosen==pending.end()||candidate->qos_tier>chosen->qos_tier))chosen=candidate;
            }
            if(chosen==pending.end())break;
            const auto admitted=AdmitWorkqueueWorker(engine,*chosen,{});
            if(!admitted)return;
            if(*admitted==Admission::Exhausted)break;
            --chosen->count;
            if(!chosen->count)pending.erase(chosen);
        }
    }
    struct PthreadPolicyBinding {
        BootstrapTrace& trace;
        MachTask::Thread& thread;
        DarwinPthreadRunQueuePolicyProvider cpu;
        PthreadPolicyBinding(BootstrapTrace& owner,MachTask::Thread& selected)
            :trace(owner),thread(selected),cpu(owner.task.run_queue,selected.id){}
        bool Ready() const noexcept {
            return thread.alive&&thread.task==&trace.task
                &&trace.task.CurrentThread()==&thread&&trace.task.run_queue.Running()==thread.id&&cpu.Ready();
        }
        static int Qos(void* raw,DarwinPthreadQos qos) noexcept {
            auto& binding=*static_cast<PthreadPolicyBinding*>(raw);
            if(!binding.Ready()||!binding.trace.ChargeCpuSegment())return 37;
            const auto code=binding.cpu.ApplyQos(qos);
            return code?code:binding.trace.RefreshSchedulerShift(binding.thread.id)?0:4;
        }
        static int Voucher(void* raw,std::uint32_t name) noexcept {
            auto& binding=*static_cast<PthreadPolicyBinding*>(raw);
            if(!binding.Ready())return 37;
            // This namespace exposes no IKOT_VOUCHER construction/association.
            // Null really clears an empty association. Task/thread/receive rights
            // and arbitrary names cannot masquerade as voucher send rights.
            if(name==UINT32_MAX)return 17; // KERN_INVALID_RIGHT
            if(name)return 4; // KERN_INVALID_ARGUMENT; SET_SELF maps to ENOENT
            if(binding.thread.policy.voucher){
                binding.trace.reason="unsupported_pthread_voucher_release";return 4;
            }
            binding.thread.policy.voucher=0;
            return 0;
        }
        static int Workqueue(void* raw,DarwinPthreadQos qos,bool overcommit) noexcept {
            auto& binding=*static_cast<PthreadPolicyBinding*>(raw);
            if(!binding.Ready())return 37;
            auto& worker=binding.thread.workqueue;
            if(!worker.member||worker.idle||!binding.trace.task.workqueue.opened)return 4;
            // Scheduled/active counts are derived from these actual bindings.
            // XNU changes bucket/type before its independent thread-policy stage;
            // preserve that ordering, then redrive only at a safe engine boundary.
            worker.qos=qos.tier;worker.overcommit=overcommit;
            ++binding.trace.task.workqueue.policy_updates;
            binding.trace.thread_lifecycle_reschedule=true;
            return 0;
        }
        static int Timeshare(void* raw,bool timeshare) noexcept {
            auto& binding=*static_cast<PthreadPolicyBinding*>(raw);
            if(!binding.Ready()||!binding.trace.ChargeCpuSegment())return 37;
            if(!binding.trace.task.run_queue.SetTimeshare(binding.thread.id,timeshare))return 4;
            if(!binding.trace.RefreshSchedulerShift(binding.thread.id))return 4;
            binding.trace.thread_lifecycle_reschedule=true;
            return 0;
        }
        DarwinPthreadPolicyOperations Operations() noexcept {
            return {this,Qos,Voucher,Timeshare,Workqueue};
        }
    };
    struct KeventCall {std::uint64_t pc;std::int32_t fd,nchanges,nevents;std::uint32_t flags;DarwinKeventQos change;};
    std::vector<KeventCall> kevent_prefix;
    void RecordKevent(std::uint64_t pc,std::int32_t fd,std::int32_t nchanges,std::int32_t nevents,
        std::uint32_t flags,const DarwinKeventQos& change){
        if(kevent_prefix.size()>=32)kevent_prefix.erase(kevent_prefix.begin());
        kevent_prefix.push_back({pc,fd,nchanges,nevents,flags,change});
    }
    static std::uint64_t WorkloopWaitKey(const MachTask::Thread& thread){
        Check(thread.id<0x0100000000000000ULL,"Workloop wait-key namespace exhausted.");
        return 0xf300000000000000ULL|thread.id;
    }
    // Releases a thread parked in SYNC_WAIT on this workloop knote; it retries
    // its kevent_id, which then completes.
    void WakeWorkloopWaiter(std::uint64_t workloop,std::uint64_t ident){
        const auto wake=[&](MachTask::Thread& thread){
            if(thread.workloop_wait&&thread.workloop_wait->first==workloop&&thread.workloop_wait->second==ident)
                task.run_queue.Wake(WorkloopWaitKey(thread),1);
        };
        wake(task.thread);for(auto& peer:task.peers)wake(*peer);
    }
    std::optional<std::uint64_t> NextKeventDeadline() const noexcept {
        auto next=task.workqueue.kqueue.NextDeadline();
        for(const auto& [id,workloop]:task.workqueue.workloops)
            if(const auto deadline=workloop.NextDeadline();deadline&&(!next||*deadline<*next))next=deadline;
        return next;
    }
    std::uint32_t AvailablePthreadFeatures(){
        auto* selected=task.CurrentThread();
        if(!scheduler_clock_ready||!load_stamp||!task.pthread_registration.registered
            ||!selected||!selected->alive||selected->task!=&task)return 0;
        PthreadPolicyBinding binding(*this,*selected);const auto operations=binding.Operations();
        if(!binding.cpu.Ready()||!operations.apply_qos||!operations.apply_voucher
            ||!operations.apply_timeshare||!operations.update_workqueue)return 0;
        // Actual task/queue/workqueue providers, not the wire-only codec mask.
        // KEVENT is the process kqworkq, WORKLOOP its dynamic workloop kqueues;
        // DISPATCHFUNC/COOPERATIVE stay absent.
        return DarwinPthreadFeatureFinePrio|DarwinPthreadFeatureBsdthreadCtl|DarwinPthreadFeatureKevent|DarwinPthreadFeatureWorkloop
            |DarwinPthreadFeatureSetSelf|DarwinPthreadFeatureQosMaintenance|DarwinPthreadFeatureQosDefault;
    }
    struct MachMsg2Call {
        std::uint64_t pc=0, data=0, options=0, send_size=0, ports=0, id=0, rcv=0, rcv_size=0, timeout=0;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<MachMsg2Call> mach_msg2_calls{};
    std::size_t mach_msg2_call_count=0;
    struct MachReceiveCall {
        std::uint64_t pc,options,timeout;
        std::uint32_t receive_name,receive_size,normalized_timeout;
        const char* outcome=nullptr;
        std::optional<std::uint32_t> result;
    };
    std::vector<MachReceiveCall> mach_receive_prefix;
    std::size_t mach_receive_calls=0,mach_receive_empty_timeouts=0,mach_receive_invalid_names=0,mach_receive_unsupported_waits=0;
    struct TaskInfoCall {
        std::uint64_t pc=0;
        std::uint32_t target=0,flavor=0,input_count=0,normalized_count=0,output_count=0;
        std::uint32_t kern_return=0,reply_size=0,copyout_bytes=0;
        bool result_ready=false,copied=false;
    };
    std::array<TaskInfoCall,16> task_info_prefix{};
    std::size_t task_info_calls=0,task_info_prefix_size=0;
    ~BootstrapTrace() {
        for(const auto& alloc : vm_allocations) {
            if(bound_engine && alloc.size) uc_mem_unmap(bound_engine, alloc.address, alloc.size);

        }
    }
    bool ReserveVmAllocation() noexcept{try{vm_allocations.reserve(vm_allocations.size()+1);return true;}catch(...){return false;}}
    static void AppendVmSlices(std::vector<VmAllocation>& output,const VmAllocation& region,
        std::uint64_t begin,std::uint64_t end,bool erase,bool set_max,std::uint32_t protection){
        const auto limit=region.address+region.size;
        if(end<=region.address||begin>=limit){output.push_back(region);return;}
        const auto left=std::max(begin,region.address),right=std::min(end,limit);
        if(region.address<left){auto slice=region;slice.size=left-region.address;output.push_back(std::move(slice));}
        if(!erase){auto slice=region;slice.address=left;slice.size=right-left;slice.backing_offset+=left-region.address;
            if(set_max){slice.maximum_protection=protection;slice.current_protection&=protection;}else slice.current_protection=protection;
            output.push_back(std::move(slice));}
        if(right<limit){auto slice=region;slice.address=right;slice.size=limit-right;slice.backing_offset+=right-region.address;output.push_back(std::move(slice));}
    }
    std::uint32_t ProtectVmRange(uc_engine* engine,std::uint64_t begin,std::uint64_t size,bool set_max,std::uint32_t protection){
        if(!GuestAccessPermitted(engine,begin,size,0))return 1; // KERN_INVALID_ADDRESS
        const auto end=begin+size;
        for(const auto& region:vm_allocations)if(begin<region.address+region.size&&end>region.address&&(protection&~region.maximum_protection))return 2;
        std::vector<VmAllocation> plan;try{plan.reserve(vm_allocations.size()*3);
            for(const auto& region:vm_allocations)AppendVmSlices(plan,region,begin,end,false,set_max,protection);
        }catch(...){return 3;}
        if(set_max){
            // Unknown image/stack maximum protections are not invented.
            auto cursor=begin;while(cursor<end){const auto found=std::find_if(vm_allocations.begin(),vm_allocations.end(),[&](const auto& region){return region.address<=cursor&&cursor<region.address+region.size;});
                if(found==vm_allocations.end())return 4;cursor=std::min(end,found->address+found->size);}
            for(const auto& region:plan)if(region.address>=begin&&region.address+region.size<=end)
                if(uc_mem_protect(engine,region.address,region.size,region.current_protection)!=UC_ERR_OK){reason="vm_protect_backend_failure";uc_emu_stop(engine);return 14;}
        }else if(uc_mem_protect(engine,begin,size,protection)!=UC_ERR_OK){reason="vm_protect_backend_failure";uc_emu_stop(engine);return 14;}
        vm_allocations=std::move(plan);return 0;
    }
    bool CanReplaceVmRange(uc_engine* engine,std::uint64_t begin,std::uint64_t end){
        uc_mem_region* ranges=nullptr;std::uint32_t count=0;
        if(uc_mem_regions(engine,&ranges,&count)!=UC_ERR_OK)return false;
        bool permitted=true;
        for(std::uint32_t n=0;n<count&&permitted;++n){
            auto cursor=std::max(begin,ranges[n].begin);const auto limit=std::min(end,ranges[n].end+1);
            while(cursor<limit){const auto found=std::find_if(vm_allocations.begin(),vm_allocations.end(),[&](const auto& region){return region.address<=cursor&&cursor<region.address+region.size;});
                if(found==vm_allocations.end()){permitted=false;break;}cursor=std::min(limit,found->address+found->size);}
        }
        uc_free(ranges);return permitted;
    }
    std::uint32_t UnmapVmRange(uc_engine* engine,std::uint64_t begin,std::uint64_t end){
        std::vector<VmAllocation> retained;try{retained.reserve(vm_allocations.size()*2+1);
            for(const auto& region:vm_allocations)AppendVmSlices(retained,region,begin,end,true,false,0);
        }catch(...){return 3;}
        uc_mem_region* regions=nullptr;std::uint32_t count=0;if(uc_mem_regions(engine,&regions,&count)!=UC_ERR_OK){reason="vm_unmap_region_failure";uc_emu_stop(engine);return 14;}
        for(std::uint32_t i=0;i<count;++i){const auto start=std::max(begin,regions[i].begin),finish=std::min(end,regions[i].end+1);
            if(start<finish&&uc_mem_unmap(engine,start,finish-start)!=UC_ERR_OK){uc_free(regions);reason="vm_unmap_backend_failure";uc_emu_stop(engine);return 14;}}
        uc_free(regions);vm_allocations=std::move(retained);return 0;
    }
    struct VmMigCall {std::uint64_t pc,size,address;std::uint32_t flags,current,maximum,tag,result;};
    std::vector<VmMigCall> vm_mig_prefix;
    std::uint64_t vm_mig_calls=0;
    const char* reason=nullptr;
    std::array<char,1024> open_path{};std::size_t open_path_bytes=0;bool open_path_terminated=false;
    struct FileCall {std::uint64_t pc,selector;std::array<std::uint64_t,4> args;std::uint64_t value;int error;};
    std::array<FileCall,16> file_prefix{};std::size_t file_prefix_size=0;
    // Only registered VFS selectors enter this table, so its cardinality is
    // bounded by the dispatcher. Retain late operations after the prefix fills.
    std::map<std::uint64_t,std::pair<std::size_t,FileCall>> file_by_selector;
    struct SignatureCall {std::uint64_t pc;std::array<std::uint64_t,4> args;std::array<std::uint64_t,3> request;DarwinFileSignature evidence;int error;bool copied;};
    std::vector<SignatureCall> signature_prefix;std::uint64_t signature_calls=0;
    struct LibraryCall {std::uint64_t pc;std::array<std::uint64_t,4> args;std::array<std::uint64_t,3> request;JsonValue evidence;std::string reason;int error;std::size_t message_bytes;};
    std::vector<LibraryCall> library_prefix;std::uint64_t library_calls=0;
    struct UnhandledFcntlCall {std::uint64_t pc;std::array<std::uint64_t,4> args;std::array<std::uint64_t,3> request;bool request_read;int error;};
    std::vector<UnhandledFcntlCall> unhandled_fcntl_prefix;
    struct MetadataCall {std::uint64_t pc,selector;std::array<std::uint64_t,4> args;std::string path;DarwinFileMetadata metadata;bool copied;int error;};
    std::vector<MetadataCall> metadata_prefix;std::uint64_t metadata_calls=0;
    struct IdentityPathCall {std::uint64_t pc;std::array<std::uint32_t,2> fsid;std::uint64_t object;std::string path;bool copied;int error;};
    std::vector<IdentityPathCall> identity_path_prefix;std::size_t identity_path_calls=0;
    struct SandboxCall {std::uint64_t pc,call;std::array<std::uint64_t,3> arguments{};std::array<std::uint64_t,6> request{};
        std::string policy,operation;std::uint64_t decision=UINT64_MAX;int error=0;bool decision_written=false;};
    std::vector<SandboxCall> sandbox_prefix;
    struct SysctlCall {std::uint64_t pc;std::array<std::uint64_t,6> arguments{};
        std::vector<std::int32_t> mib;std::string name;std::uint64_t capacity=0,output_length=0;
        int error=0;bool mib_copied=false,length_copied=false;};
    std::vector<SysctlCall> sysctl_prefix;
    std::size_t sysctl_calls=0;
    struct FatalApi {std::uint64_t address;std::string symbol;unsigned reason_argument;};
    struct FatalObservation {std::uint64_t pc;std::string symbol,reason;
        std::array<std::uint64_t,6> arguments{};bool terminated=false,readable=true;};
    std::vector<FatalApi> fatal_apis;
    std::vector<FatalObservation> fatal_observations;
    bool fatal_capture_failed=false;
    static bool Bias(std::uint64_t& result){
        // Use the shared tick-resolution clocks to obtain the suspend bias.
        // Subtracting two independently sampled precise clocks would add call
        // latency and make Apple's before/after offset comparison spin.
        for(int attempt=0;attempt<8;++attempt){
            ULONGLONG before=0,unbiased=0,after=0;QueryInterruptTime(&before);
            if(!QueryUnbiasedInterruptTime(&unbiased))return false;
            QueryInterruptTime(&after);
            if(before==after&&after>=unbiased){result=after-unbiased;return true;}
        }
        return false;
    }
    bool host_context_operation=false;
    // After the diagnostic prefix of an unbounded session, execution is accounted
    // per translated basic block instead of per instruction, so the CPU backend
    // runs whole blocks without a host call per guest instruction.
    static void Block(uc_engine* engine,std::uint64_t address,std::uint32_t size,void* context){
        auto& trace=*static_cast<BootstrapTrace*>(context);
        if(trace.host_context_operation||trace.host_auth_operation)return;
        const auto before = trace.callbacks;
        const std::size_t block = std::max<std::uint32_t>(1, size / 4);
        trace.last_pc = address;
        if (trace.options.instruction_limit &&
            block > trace.options.instruction_limit - std::min(before, trace.options.instruction_limit)) {
            trace.reason = "instruction_budget";
            uc_emu_stop(engine);
            return;
        }
        trace.callbacks += block;
        if(trace.block_quantum_end&&trace.callbacks>=trace.block_quantum_end){uc_emu_stop(engine);return;}
        if((before>>16)!=(trace.callbacks>>16)){
            const auto operation=CurrentOperationContext();
            if(trace.options.cancellation.Requested()||(operation&&operation->CancellationRequested())){trace.reason="cancelled";uc_emu_stop(engine);}
            else if(std::chrono::steady_clock::now()>=trace.options.deadline||(operation&&operation->DeadlineExceeded())){trace.reason="deadline";uc_emu_stop(engine);}
        }
    }
    static void Code(uc_engine* engine,std::uint64_t address,std::uint32_t,void* context){
        auto& trace=*static_cast<BootstrapTrace*>(context);
        if(trace.host_context_operation&&address==trace.task.run_queue.ExclusiveClearPC())return;
        if(trace.host_auth_operation&&(address==trace.pointer_auth_pc||address==trace.pointer_auth_sign_pc
            ||address==trace.pointer_auth_sign_pc+16||address==trace.pointer_auth_sign_pc+20))return;
        ++trace.callbacks;trace.last_pc=address;
        if(trace.options.instruction_limit>20000000&&trace.prefix_size>=trace.prefix.size()){
            if((trace.callbacks&0xffff)==0){
                const auto operation=CurrentOperationContext();
                if(trace.options.cancellation.Requested()||(operation&&operation->CancellationRequested())){trace.reason="cancelled";uc_emu_stop(engine);}
                else if(std::chrono::steady_clock::now()>=trace.options.deadline||(operation&&operation->DeadlineExceeded())){trace.reason="deadline";uc_emu_stop(engine);}
            }
            return;
        }
        trace.last_opcode=0;uc_mem_read(engine,address,&trace.last_opcode,4);
        if(trace.prefix_size<trace.prefix.size())trace.prefix[trace.prefix_size++]={address,trace.last_opcode};
        auto& instruction=trace.recent[trace.recent_count++%trace.recent.size()];instruction={};
        instruction.pc=address;instruction.opcode=trace.last_opcode;
        static const int kTraceRegs[32]={
            UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,
            UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7,
            UC_ARM64_REG_X8,UC_ARM64_REG_X9,UC_ARM64_REG_X10,UC_ARM64_REG_X11,
            UC_ARM64_REG_X12,UC_ARM64_REG_X13,UC_ARM64_REG_X14,UC_ARM64_REG_X15,
            UC_ARM64_REG_X16,UC_ARM64_REG_X17,UC_ARM64_REG_X18,UC_ARM64_REG_X19,
            UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,
            UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,
            UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_X30,UC_ARM64_REG_SP
        };
        void* reg_ptrs[32];
        for(int i=0;i<32;++i)reg_ptrs[i]=&instruction.registers[i];
        if(uc_reg_read_batch(engine,const_cast<int*>(kTraceRegs),reg_ptrs,32)!=UC_ERR_OK){
            trace.reason="instruction_register_failure";uc_emu_stop(engine);return;
        }
        // Observe only decoded 64-bit unsigned-immediate LDR operands. This is
        // diagnostic readback of mapped guest memory, never a load substitute.
        if((trace.last_opcode&0xffc00000u)==0xf9400000u){
            const auto base=instruction.registers[(trace.last_opcode>>5)&31];
            const auto offset=std::uint64_t((trace.last_opcode>>10)&4095)*8;
            if(base<=UINT64_MAX-offset){instruction.load_address=base+offset;
                instruction.load_observed=uc_mem_read(engine,instruction.load_address,&instruction.load_value,8)==UC_ERR_OK;}}

        // Observe generic Darwin fatal API entrypoints resolved from original
        // export metadata. This never replaces an instruction or API return.
        if(trace.fatal_observations.size()<4&&!trace.fatal_apis.empty())for(const auto& api:trace.fatal_apis)if(api.address==address){
            try{
                FatalObservation observed;observed.pc=address;observed.symbol=api.symbol;
                std::copy_n(instruction.registers.begin(),observed.arguments.size(),observed.arguments.begin());
                const auto pointer=observed.arguments[api.reason_argument];
                if(!pointer)observed.terminated=true;
                else for(std::size_t i=0;i<1024;++i){char c=0;
                    if(pointer>UINT64_MAX-i||!GuestAccessPermitted(engine,pointer+i,1,UC_PROT_READ)
                        ||uc_mem_read(engine,pointer+i,&c,1)!=UC_ERR_OK){observed.readable=false;break;}
                    if(!c){observed.terminated=true;break;}observed.reason.push_back(c);
                }
                trace.fatal_observations.push_back(std::move(observed));
            }catch(...){trace.fatal_capture_failed=true;}
            break;
        }
        if((trace.callbacks&0xfff)==0){
            const auto operation=CurrentOperationContext();
            if(trace.options.cancellation.Requested()||(operation&&operation->CancellationRequested())){trace.reason="cancelled";uc_emu_stop(engine);}
            else if(std::chrono::steady_clock::now()>=trace.options.deadline||(operation&&operation->DeadlineExceeded())){trace.reason="deadline";uc_emu_stop(engine);}
        }
    }
    static void Interrupt(uc_engine* engine,std::uint32_t number,void* context){
        auto& trace=*static_cast<BootstrapTrace*>(context);
        // Unicorn ARM EXCP_PREFETCH_ABORT=3 includes architectural address-size
        // faults before a mapped-memory hook can run. An authenticated poison
        // PC must remain a real fetch fault, not be decoded as a BSD selector.
        if(number==3){
            trace.interrupt=number;trace.reason="guest_prefetch_abort";
            trace.memory_type=UC_MEM_FETCH_UNMAPPED;trace.memory_size=4;
            if(uc_reg_read(engine,UC_ARM64_REG_PC,&trace.memory_address)!=UC_ERR_OK)
                trace.reason="guest_prefetch_abort_pc_read_failure";
            uc_emu_stop(engine);return;
        }
        auto* selected_thread=trace.task.CurrentThread();
        if(!selected_thread){trace.reason="guest_current_thread_binding_failure";uc_emu_stop(engine);return;}
        std::uint64_t selector=0,pc=0;
        const auto selector_status=uc_reg_read(engine,UC_ARM64_REG_X16,&selector);
        const auto pc_status=uc_reg_read(engine,UC_ARM64_REG_PC,&pc);
        if(trace.options.instruction_limit>20000000&&pc_status==UC_ERR_OK&&pc>=4){
            trace.last_pc=pc-4;
            trace.last_opcode=0;uc_mem_read(engine,trace.last_pc,&trace.last_opcode,4);
            if((trace.callbacks&0x7f)==0){
                const auto operation=CurrentOperationContext();
                if(trace.options.cancellation.Requested()||(operation&&operation->CancellationRequested())){trace.reason="cancelled";uc_emu_stop(engine);return;}
                if(std::chrono::steady_clock::now()>=trace.options.deadline||(operation&&operation->DeadlineExceeded())){trace.reason="deadline";uc_emu_stop(engine);return;}
            }
        }
        const auto raw_selector=selector;
        // Capture before dispatch: a handler may stop without reaching the
        // generic unsupported-interrupt branch. Otherwise an earlier BSD call
        // can be reported as the cause of a later Mach trap.
        if(selector_status==UC_ERR_OK&&pc_status==UC_ERR_OK&&number==2
            &&trace.last_opcode==0xd4001001&&pc==trace.last_pc+4){
            trace.syscall_selector=raw_selector;trace.interrupt=number;
        }
        bool indirect=false;
        if(selector_status==UC_ERR_OK&&selector==0){
            if(uc_reg_read(engine,UC_ARM64_REG_X0,&selector)!=UC_ERR_OK){trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
            indirect=true;
        }
        const auto low=static_cast<std::uint32_t>(selector),high=static_cast<std::uint32_t>(selector>>32);
        const auto registration=std::find_if(registrations.begin(),registrations.end(),[&](const auto& item){return item.selector==low;});
        if(selector_status==UC_ERR_OK&&pc_status==UC_ERR_OK&&number==2
            &&trace.last_opcode==0xd4001001&&pc==trace.last_pc+4
            &&registration!=registrations.end()&&(!indirect||registration->bsd)
            &&(registration->bsd?high==0:(high==0||high==0xffffffff))){
            const auto handler=registration->handler;
            if(handler==Handler::Exit){
                std::uint64_t status_arg=0;
                if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&status_arg)!=UC_ERR_OK){
                    trace.reason="exit_register_failure";uc_emu_stop(engine);return;
                }
                trace.exited=true;
                trace.exit_status=static_cast<int>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(status_arg)));
                trace.reason="exited";
                uc_emu_stop(engine);return;
            }
            if(handler==Handler::GetEntropy){
                EntropyCall call{};call.pc=trace.last_pc;std::uint64_t flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK
                    ||uc_reg_read(engine,UC_ARM64_REG_X0+(indirect?1:0),&call.address)!=UC_ERR_OK
                    ||uc_reg_read(engine,UC_ARM64_REG_X1+(indirect?1:0),&call.size)!=UC_ERR_OK){trace.reason="entropy_register_failure";uc_emu_stop(engine);return;}
                // XNU checks the full size_t limit before copyout. Never log entropy.
                std::array<std::uint8_t,256> bytes{};
                if(call.size>bytes.size())call.error=22;
                else if(call.size){
                    if(!GuestAccessPermitted(engine,call.address,call.size,UC_PROT_WRITE))call.error=14;
                    else if(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(call.size),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)call.error=5;
                    else{call.generated=true;
                        if(uc_mem_write(engine,call.address,bytes.data(),call.size)!=UC_ERR_OK){SecureZeroMemory(bytes.data(),bytes.size());trace.reason="entropy_copyout_failure";uc_emu_stop(engine);return;}
                        call.copied=true;}
                }
                SecureZeroMemory(bytes.data(),bytes.size());
                ++trace.entropy_calls;if(trace.entropy_prefix.size()<16)trace.entropy_prefix.push_back(call);
                const std::uint64_t value=call.error,zero=0,after=call.error?(flags|0x20000000ULL):(flags&~0x20000000ULL);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&value)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="entropy_return_failure";uc_emu_stop(engine);}
                return;
            }
            if(handler==Handler::GetTimeOfDay){
                CalendarCall call{};call.pc=trace.last_pc;std::uint64_t flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="calendar_register_failure";uc_emu_stop(engine);return;}
                for(unsigned n=0;n<3;++n)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(n)+(indirect?1:0),&call.args[n])!=UC_ERR_OK){trace.reason="calendar_register_failure";uc_emu_stop(engine);return;}
                if(call.args[0]||call.args[2]){const auto sample=DarwinCalendarTime::Capture();if(!sample){trace.reason="calendar_capture_failure";uc_emu_stop(engine);return;}call.sample=*sample;}
                if(call.args[0]){
                    const auto bytes=call.sample.Timeval64();
                    if(!GuestAccessPermitted(engine,call.args[0],bytes.size(),UC_PROT_WRITE))call.error=14;
                    else if(uc_mem_write(engine,call.args[0],bytes.data(),bytes.size())!=UC_ERR_OK){trace.reason="calendar_copyout_failure";uc_emu_stop(engine);return;}
                    else call.timeval_copied=true;
                }
                // Deprecated kernel timezone state is not installed in this task.
                // Preserve ordered timeval copyout, but never fabricate timezone data.
                if(!call.error&&call.args[1])call.error=45;
                if(!call.error&&call.args[2]){
                    const auto absolute=call.sample.AbsoluteTime();
                    if(!GuestAccessPermitted(engine,call.args[2],8,UC_PROT_WRITE))call.error=14;
                    else if(uc_mem_write(engine,call.args[2],&absolute,8)!=UC_ERR_OK){trace.reason="calendar_absolute_copyout_failure";uc_emu_stop(engine);return;}
                    else call.absolute_copied=true;
                }
                const std::uint64_t value=call.error,zero=0,after=call.error?(flags|0x20000000ULL):(flags&~0x20000000ULL);
                ++trace.calendar_calls;if(trace.calendar_prefix.size()<16)trace.calendar_prefix.push_back(call);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&value)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="calendar_return_failure";uc_emu_stop(engine);}
                return;
            }
            if(handler==Handler::Sysctl){
                if(!trace.task.owner||trace.task.owner->engine.value!=engine||selected_thread->task!=&trace.task){
                    trace.reason="sysctl_task_binding_failure";uc_emu_stop(engine);return;}
                try{
                    SysctlCall call;call.pc=trace.last_pc;auto& a=call.arguments;std::uint64_t flags=0;
                    if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="sysctl_register_failure";uc_emu_stop(engine);return;}
                    for(unsigned i=0;i<a.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i)+(indirect?1:0),&a[i])!=UC_ERR_OK){
                        trace.reason="sysctl_register_failure";uc_emu_stop(engine);return;}
                    const auto count=static_cast<std::uint32_t>(a[1]);DarwinSysctlResult response;
                    if(count<2||count>12)call.error=22;
                    else{
                        call.mib.resize(count);const auto bytes=count*sizeof(std::int32_t);
                        if(!GuestAccessPermitted(engine,a[0],bytes,UC_PROT_READ)||uc_mem_read(engine,a[0],call.mib.data(),bytes)!=UC_ERR_OK)call.error=14;
                        else call.mib_copied=true;
                    }
                    if(!call.error&&a[3]){
                        if(!GuestAccessPermitted(engine,a[3],8,UC_PROT_READ)||uc_mem_read(engine,a[3],&call.capacity,8)!=UC_ERR_OK)call.error=14;
                        else call.length_copied=true;
                    }
                    if(!call.error){
                        const DarwinSysctl registry(trace.stack.PageSize());
                        if(call.mib.size()==2&&call.mib[0]==0&&call.mib[1]==3){
                            if(!a[5])call.error=2;
                            else if(a[5]>=1024)call.error=63;
                            else if(!GuestAccessPermitted(engine,a[4],static_cast<std::size_t>(a[5]),UC_PROT_READ))call.error=14;
                            else{
                                call.name.resize(static_cast<std::size_t>(a[5]));
                                if(uc_mem_read(engine,a[4],call.name.data(),call.name.size())!=UC_ERR_OK)call.error=14;
                                else response=registry.NameToOid(call.name);
                            }
                        }else{
                            response=registry.Read(call.mib);
                            // Only existing read-only nodes can reject a write;
                            // nonexistent nodes remain absent, not manufactured.
                            if(!response.error&&a[4]&&a[5])call.error=1;
                        }
                        if(!call.error)call.error=response.error;
                    }
                    if(!call.error){
                        const auto required=response.bytes.size();
                        // XNU SYSCTL_OUT does not partially copy a scalar/chunk
                        // when too short; it returns ENOMEM with oldidx still0.
                        if(a[2]&&call.capacity<required)call.error=12;
                        else{
                            call.output_length=required;
                            if(a[2]&&required){
                                if(!GuestAccessPermitted(engine,a[2],required,UC_PROT_WRITE))call.error=14;
                                else if(uc_mem_write(engine,a[2],response.bytes.data(),required)!=UC_ERR_OK){
                                    trace.reason="sysctl_copyout_failure";uc_emu_stop(engine);return;}
                            }
                        }
                    }
                    // XNU publishes oldidx only on success or ENOMEM; other
                    // errors must not modify the length or output buffer.
                    if((!call.error||call.error==12)&&a[3]){
                        if(!GuestAccessPermitted(engine,a[3],8,UC_PROT_WRITE))call.error=14;
                        else if(uc_mem_write(engine,a[3],&call.output_length,8)!=UC_ERR_OK){trace.reason="sysctl_length_copyout_failure";uc_emu_stop(engine);return;}
                    }
                    const std::uint64_t result=call.error,zero=0,after=call.error?(flags|0x20000000ULL):(flags&~0x20000000ULL);
                    ++trace.sysctl_calls;if(trace.sysctl_prefix.size()<16)trace.sysctl_prefix.push_back(std::move(call));
                    if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK
                        ||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="sysctl_return_failure";uc_emu_stop(engine);}
                    return;
                }catch(...){trace.reason="sysctl_service_failure";uc_emu_stop(engine);return;}
            }
            if(handler==Handler::MacSyscall){
                if(!trace.task.owner||trace.task.owner->engine.value!=engine||selected_thread->task!=&trace.task){
                    trace.reason="sandbox_task_binding_failure";uc_emu_stop(engine);return;}
                std::array<std::uint64_t,3> args{};std::uint64_t flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="sandbox_register_failure";uc_emu_stop(engine);return;}
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i)+(indirect?1:0),&args[i])!=UC_ERR_OK){
                    trace.reason="sandbox_register_failure";uc_emu_stop(engine);return;}
                try {
                SandboxCall call;call.pc=trace.last_pc;call.call=static_cast<std::uint32_t>(args[1]);call.arguments=args;
                const auto string_in=[&](std::uint64_t address,std::string& value,std::size_t limit){
                    for(std::size_t i=0;i<limit;++i){char c=0;
                        if(address>UINT64_MAX-i||!GuestAccessPermitted(engine,address+i,1,UC_PROT_READ)
                            ||uc_mem_read(engine,address+i,&c,1)!=UC_ERR_OK)return 14;
                        if(!c)return 0;value.push_back(c);}
                    return 63;
                };
                call.error=string_in(args[0],call.policy,32); // XNU MAC_MAX_POLICY_NAME
                if(!call.error&&call.policy=="AMFI"){
                    if(call.call!=90)trace.reason="unsupported_mac_policy_call";
                    else {std::array<std::uint64_t,2> request{};
                        if(!GuestAccessPermitted(engine,args[2],sizeof(request),UC_PROT_READ)
                            ||uc_mem_read(engine,args[2],request.data(),sizeof(request))!=UC_ERR_OK)call.error=14;
                        else {call.request[0]=request[0];call.request[1]=request[1];
                            std::uint64_t output=0;call.error=trace.task.loader_policy.Query(request[0],output);
                            if(!call.error){
                                if(!GuestAccessPermitted(engine,request[1],sizeof(output),UC_PROT_WRITE))call.error=14;
                                else if(uc_mem_write(engine,request[1],&output,sizeof(output))!=UC_ERR_OK)trace.reason="loader_policy_copyout_failure";
                                else {call.decision=output;call.decision_written=true;call.operation="dyld-loader-path-policy";}
                            }
                        }
                    }
                }else if(!call.error&&call.policy!="Sandbox"){
                    // No policy callback is registered for this name. XNU
                    // returns ENOPOLICY without dereferencing its opaque arg.
                    call.error=103;
                }else if(!call.error&&call.call!=2){
                    trace.reason="unsupported_mac_policy_call";
                }else if(!call.error){
                    if(!GuestAccessPermitted(engine,args[2],sizeof(call.request),UC_PROT_READ)
                        ||uc_mem_read(engine,args[2],call.request.data(),sizeof(call.request))!=UC_ERR_OK)call.error=14;
                    else {
                        const auto& r=call.request;
                        call.error=string_in(r[2],call.operation,256);
                        if(!call.error&&(call.operation!="syscall-unix"||r[3]!=65||r[4]>UINT32_MAX||(r[5]&~1ULL))){
                            trace.reason="unsupported_sandbox_check";
                        }else if(!call.error){
                            // PID is a signed 64-bit field in this original userland ABI.
                            // Only this live task is visible; no host PID translation.
                            if(r[1]!=trace.task.pid)call.error=3; // ESRCH
                            else if(!GuestAccessPermitted(engine,r[0],8,UC_PROT_WRITE))call.error=14;
                            else if(trace.task.sandbox==MachTask::SandboxState::NoProfile){
                                // No Seatbelt rule denies the operation. This is NOT
                                // evidence that the requested BSD service is implemented.
                                call.decision=0;
                                if(uc_mem_write(engine,r[0],&call.decision,8)!=UC_ERR_OK){
                                    trace.reason="sandbox_copyout_failure";
                                }else call.decision_written=true;
                            }
                        }
                    }
                }
                const auto error=call.error;
                if(trace.sandbox_prefix.size()<16)trace.sandbox_prefix.push_back(std::move(call));
                if(trace.reason){trace.syscall_selector=raw_selector;trace.interrupt=number;uc_emu_stop(engine);return;}
                const std::uint64_t result=error,zero=0,after=error?(flags|0x20000000ULL):(flags&~0x20000000ULL);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK
                    ||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="sandbox_return_failure";uc_emu_stop(engine);}
                return;
                }catch(...){trace.reason="sandbox_service_failure";uc_emu_stop(engine);return;}
            }
            if(handler==Handler::Mmap){
                std::array<std::uint64_t,6> args{};std::uint64_t before=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i)+(indirect?1:0),&args[i])!=UC_ERR_OK){trace.reason="mmap_register_failure";uc_emu_stop(engine);return;}
                if(!trace.task.owner||trace.task.owner->engine.value!=engine||!trace.task.owner->files
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&before)!=UC_ERR_OK){trace.reason="mmap_binding_failure";uc_emu_stop(engine);return;}
                int error=0;std::uint64_t address=0;auto source=JsonValue::ObjectValue();
                const auto page_size=trace.stack.PageSize(),mask=page_size-1;
                const auto flags=static_cast<std::uint32_t>(args[3]),prot=static_cast<std::uint32_t>(args[2])&7U;
                const bool fixed=(flags&0x10U)!=0;
                const auto base_flags=flags&~(0x40000U|0x10U);
                if(!args[1]||args[5]>INT64_MAX||args[1]>UINT64_MAX-args[5]
                    ||args[0]>0x00007fffffffffffULL-mask||((flags&0x40000U)&&(args[5]&mask)))error=22;
                else if(base_flags!=2U)error=45;
                else if(fixed&&((args[0]&mask)!=(args[5]&mask)))error=22;
                else {
                    try{
                        auto mapping=trace.task.owner->files->PrivateMapping(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[4])),args[5],args[1],page_size,error);
                        if(mapping){
                            std::uint64_t candidate=0;
                            bool found=false;
                            if(fixed){
                                candidate=args[0]&~mask;
                                if(candidate>0x00007fffffffffffULL-mapping->Size()){
                                    error=12;
                                }else{
                                    // Replace tracked guest reservations/mappings, including ownership metadata.
                                    if(!trace.CanReplaceVmRange(engine,candidate,candidate+mapping->Size()))error=45;
                                    else if(!trace.ReserveVmAllocation())error=12;
                                    else found=trace.UnmapVmRange(engine,candidate,candidate+mapping->Size())==0;
                                }
                            }else{
                                const auto hint=args[0]?args[0]:trace.next_vm_address;
                                found=FindUnmappedGuestRange(engine,hint,mapping->Size(),mask,candidate);
                                if(!found&&args[0])found=FindUnmappedGuestRange(engine,trace.next_vm_address,mapping->Size(),mask,candidate);
                            }
                            if(!found){if(!error)error=12;}
                            else {
                                source=mapping->ToJson();trace.vm_allocations.reserve(trace.vm_allocations.size()+1);
                                trace.mmap_prefix.reserve(16);
                                if(uc_mem_map_ptr(engine,candidate,mapping->Size(),prot,mapping->Bytes())!=UC_ERR_OK)error=12;
                                else {address=candidate+mapping->Delta();trace.vm_allocations.push_back({candidate,mapping->Size(),nullptr,std::move(mapping),static_cast<std::uint32_t>(args[2]),7});
                                    trace.next_vm_address=std::max(trace.next_vm_address,candidate+trace.vm_allocations.back().size);}
                            }
                        }
                    }catch(const std::bad_alloc&){error=12;}
                    catch(...){trace.reason="mmap_source_failure";uc_emu_stop(engine);return;}
                }
                ++trace.mmap_calls;if(trace.mmap_prefix.size()<16)trace.mmap_prefix.push_back({trace.last_pc,args,address,error,std::move(source)});
                const std::uint64_t result=error?std::uint64_t(error):address,zero=0,after=error?(before|0x20000000ULL):(before&~0x20000000ULL);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK
                    ||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="mmap_return_failure";uc_emu_stop(engine);return;}
                return;
            }
            if(handler==Handler::CsOps||handler==Handler::CsOpsAuditToken){
                std::array<std::uint64_t,5> args{};std::uint64_t before=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i)+(indirect?1:0),&args[i])!=UC_ERR_OK){trace.reason="codesign_register_failure";uc_emu_stop(engine);return;}
                if(!trace.task.owner||trace.task.owner->engine.value!=engine||selected_thread->task!=&trace.task
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&before)!=UC_ERR_OK){trace.reason="codesign_binding_failure";uc_emu_stop(engine);return;}
                const auto pid=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[0]));
                const auto op=static_cast<std::uint32_t>(args[1]);
                int error=0;bool copied=false;
                const bool audited=handler==Handler::CsOpsAuditToken;
                const auto token_pointer=audited?args[4]:0;
                DarwinAuditToken token{};bool token_copied=false,token_matches=false;
                const bool for_self=pid==0||pid==static_cast<std::int32_t>(trace.task.pid);
                // XNU kern_proc.c: the audited wrapper rejects NULL before the
                // permission filter, proc_find and token copyin. Read operations
                // are unprivileged; mutation of another task requires root.
                const bool unrestricted=op==0||op==5||op==18||op==6||op==7||op==16
                    ||op==11||op==10||op==14||op==15||op==17;
                if(audited&&!token_pointer)error=22; // EINVAL
                else if(!unrestricted&&!for_self&&trace.task.credentials.uid!=0)error=1; // EPERM
                else if(!for_self)error=3; // ESRCH: only this process exists in the guest namespace.
                else if(audited){
                    if(!GuestAccessPermitted(engine,token_pointer,sizeof(token),UC_PROT_READ)
                        ||uc_mem_read(engine,token_pointer,token.data(),sizeof(token))!=UC_ERR_OK)error=14; // EFAULT
                    else{
                        token_copied=true;
                        // This API binds a process lifetime, not all credentials:
                        // XNU compares only audit PID and p_idversion.
                        token_matches=token[5]==trace.task.pid&&token[7]==trace.task.pid_version;
                        if(!token_matches)error=3;
                    }
                }
                if(!error&&op==0){ // CS_OPS_STATUS
                    const auto status=trace.task.code_signing.Status();
                    if(args[2]){
                        if(!GuestAccessPermitted(engine,args[2],sizeof(status),UC_PROT_WRITE))error=14;
                        else if(uc_mem_write(engine,args[2],&status,sizeof(status))!=UC_ERR_OK){trace.reason="codesign_copyout_failure";uc_emu_stop(engine);return;}
                        else copied=true;
                    }
                }else if(!error&&(op==11||op==14||op==7||op==16)){
                    // IDENTITY/TEAMID/XML/DER entitlements require CS_VALID or
                    // CS_DEBUGGED in pinned XNU; neither authority is granted.
                    error=(op==11||op==14)&&args[3]<8?34:22;
                }else if(!error&&op==5){ // CS_OPS_CDHASH: exact 20-byte output
                    if(args[3]!=20)error=22;
                    else if(!trace.task.text_signature)error=80; // EBADEXEC
                    else if(!GuestAccessPermitted(engine,args[2],20,UC_PROT_WRITE))error=14;
                    else if(uc_mem_write(engine,args[2],trace.task.text_signature->cdhash.data(),20)!=UC_ERR_OK){trace.reason="codesign_copyout_failure";uc_emu_stop(engine);return;}
                    else copied=true;
                }else if(!error&&op==6){ // CS_OPS_PIDOFFSET, not a pathname
                    const std::uint64_t offset=0; // Only the registered thin slice is supported.
                    if(!GuestAccessPermitted(engine,args[2],8,UC_PROT_WRITE))error=14;
                    else if(uc_mem_write(engine,args[2],&offset,8)!=UC_ERR_OK){trace.reason="codesign_copyout_failure";uc_emu_stop(engine);return;}
                    else copied=true;
                }else if(!error){
                    trace.reason="unsupported_codesign_operation";uc_emu_stop(engine);return;
                }
                ++trace.code_sign_calls;
                if(trace.code_sign_prefix.size()<16)trace.code_sign_prefix.push_back({trace.last_pc,{args[0],args[1],args[2],args[3]},trace.task.code_signing.Status(),copied,error,
                    token_pointer,token,token_copied,token_matches,audited});
                const std::uint64_t result=static_cast<std::uint64_t>(error),zero=0,after=error?(before|0x20000000ULL):(before&~0x20000000ULL);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK
                    ||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="codesign_return_failure";uc_emu_stop(engine);return;}
                return;
            }
            if(handler==Handler::Open||handler==Handler::OpenAt||handler==Handler::Stat||handler==Handler::Fstat||handler==Handler::FsGetPath||handler==Handler::Close||handler==Handler::Write||handler==Handler::Read||handler==Handler::Pread
                ||handler==Handler::Seek||handler==Handler::Fcntl||handler==Handler::Access||handler==Handler::Ioctl||handler==Handler::GetAttrList
                ||handler==Handler::Dup||handler==Handler::Dup2){
                std::array<std::uint64_t,5> args{};std::uint64_t flags=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i)+(indirect?1:0),&args[i])!=UC_ERR_OK){trace.reason="file_register_failure";uc_emu_stop(engine);return;}
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK||!trace.task.owner||!trace.task.owner->files){trace.reason="file_binding_failure";uc_emu_stop(engine);return;}
                auto& files=*trace.task.owner->files;DarwinFileResult outcome;
                DarwinFileMetadata metadata;bool metadata_copied=false;std::string metadata_path;
                try{
                    const auto fd=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[0]));
                    if(handler==Handler::Open||handler==Handler::OpenAt||handler==Handler::Stat||handler==Handler::Access||handler==Handler::GetAttrList){
                        const auto pathname=args[handler==Handler::OpenAt?1:0];
                        trace.open_path_bytes=0;trace.open_path_terminated=false;
                        for(std::size_t i=0;i<trace.open_path.size();++i){
                            char c=0;if(pathname>UINT64_MAX-i||!GuestAccessPermitted(engine,pathname+i,1,UC_PROT_READ)
                                ||uc_mem_read(engine,pathname+i,&c,1)!=UC_ERR_OK){outcome.error=14;break;}
                            if(!c){trace.open_path_terminated=true;break;}trace.open_path[trace.open_path_bytes++]=c;
                        }
                        if(!outcome.error&&!trace.open_path_terminated)outcome.error=63;
                        if(!outcome.error){const auto path=std::string(trace.open_path.data(),trace.open_path_bytes);
                            if(handler==Handler::Stat){metadata_path=path;outcome=files.Stat(path,metadata);}
                            else if(handler==Handler::Access){outcome=files.Access(path,static_cast<std::uint32_t>(args[1]));}
                            else if(handler==Handler::GetAttrList){
                                metadata_path=path;outcome=files.Stat(path,metadata);
                                if(!outcome.error){
#pragma pack(push,2)
                                    struct GuestAttrList {
                                        std::uint16_t bitmapcount=0;
                                        std::uint16_t reserved=0;
                                        std::uint32_t commonattr=0;
                                        std::uint32_t volattr=0;
                                        std::uint32_t dirattr=0;
                                        std::uint32_t fileattr=0;
                                        std::uint32_t forkattr=0;
                                    };
#pragma pack(pop)
                                    GuestAttrList alist{};
                                    if(!GuestAccessPermitted(engine,args[1],sizeof(alist),UC_PROT_READ)
                                        ||uc_mem_read(engine,args[1],&alist,sizeof(alist))!=UC_ERR_OK){
                                        outcome.error=14;
                                    }else{
                                        std::vector<std::uint8_t> buf;buf.resize(4,0);
                                        std::uint32_t ret_cmn=0,ret_vol=0,ret_dir=0,ret_file=0,ret_fork=0;
                                        std::size_t ret_attrs_offset=0;
                                        if(alist.commonattr&0x80000000U){
                                            ret_attrs_offset=buf.size();buf.resize(buf.size()+20,0);ret_cmn|=0x80000000U;
                                        }
                                        auto align_buf=[&](std::size_t a){while(buf.size()%a!=0)buf.push_back(0);};
                                        auto put_u32=[&](std::uint32_t v){align_buf(4);const auto* p=reinterpret_cast<const std::uint8_t*>(&v);buf.insert(buf.end(),p,p+4);};
                                        auto put_u64=[&](std::uint64_t v){align_buf(8);const auto* p=reinterpret_cast<const std::uint8_t*>(&v);buf.insert(buf.end(),p,p+8);};
                                        auto put_timespec=[&](std::int64_t s,std::uint32_t ns){
                                            align_buf(8);const auto* ps=reinterpret_cast<const std::uint8_t*>(&s);buf.insert(buf.end(),ps,ps+8);
                                            std::uint64_t ns64=ns;const auto* pn=reinterpret_cast<const std::uint8_t*>(&ns64);buf.insert(buf.end(),pn,pn+8);
                                        };
                                        if(alist.commonattr&0x00000002U){put_u32(metadata.device);ret_cmn|=0x00000002U;}
                                        if(alist.commonattr&0x00000004U){align_buf(4);put_u32(metadata.device);put_u32(0);ret_cmn|=0x00000004U;}
                                        if(alist.commonattr&0x00000008U){
                                            std::uint32_t t=(metadata.mode&0170000)==0040000?2:(metadata.mode&0170000)==0120000?3:1;
                                            put_u32(t);ret_cmn|=0x00000008U;
                                        }
                                        if(alist.commonattr&0x00000010U){put_u32(1);ret_cmn|=0x00000010U;}
                                        if(alist.commonattr&0x00000020U){align_buf(4);put_u32(static_cast<std::uint32_t>(metadata.inode));put_u32(0);ret_cmn|=0x00000020U;}
                                        if(alist.commonattr&0x00000040U){align_buf(4);put_u32(static_cast<std::uint32_t>(metadata.inode));put_u32(0);ret_cmn|=0x00000040U;}
                                        if(alist.commonattr&0x00000080U){align_buf(4);put_u32(1);put_u32(0);ret_cmn|=0x00000080U;}
                                        if(alist.commonattr&0x00000100U){put_u32(0);ret_cmn|=0x00000100U;}
                                        if(alist.commonattr&0x00000200U){put_timespec(metadata.times[3].seconds,metadata.times[3].nanoseconds);ret_cmn|=0x00000200U;}
                                        if(alist.commonattr&0x00000400U){put_timespec(metadata.times[1].seconds,metadata.times[1].nanoseconds);ret_cmn|=0x00000400U;}
                                        if(alist.commonattr&0x00000800U){put_timespec(metadata.times[2].seconds,metadata.times[2].nanoseconds);ret_cmn|=0x00000800U;}
                                        if(alist.commonattr&0x00001000U){put_timespec(metadata.times[0].seconds,metadata.times[0].nanoseconds);ret_cmn|=0x00001000U;}
                                        if(alist.commonattr&0x00002000U){put_timespec(0,0);ret_cmn|=0x00002000U;}
                                        if(alist.commonattr&0x00004000U){align_buf(4);std::array<std::uint8_t,32> fndr{};buf.insert(buf.end(),fndr.begin(),fndr.end());ret_cmn|=0x00004000U;}
                                        if(alist.commonattr&0x00008000U){put_u32(metadata.uid);ret_cmn|=0x00008000U;}
                                        if(alist.commonattr&0x00010000U){put_u32(metadata.gid);ret_cmn|=0x00010000U;}
                                        if(alist.commonattr&0x00020000U){put_u32(metadata.mode&07777);ret_cmn|=0x00020000U;}
                                        if(alist.commonattr&0x00040000U){put_u32(metadata.flags);ret_cmn|=0x00040000U;}
                                        if(alist.fileattr&0x00000001U){put_u32(metadata.links);ret_file|=0x00000001U;}
                                        if(alist.fileattr&0x00000002U){put_u64(metadata.size);ret_file|=0x00000002U;}
                                        if(alist.fileattr&0x00000004U){put_u64(metadata.blocks*512);ret_file|=0x00000004U;}
                                        if(alist.fileattr&0x00000008U){put_u32(metadata.io_blocksize?metadata.io_blocksize:4096);ret_file|=0x00000008U;}
                                        if(alist.fileattr&0x00000010U){put_u32(0);ret_file|=0x00000010U;}
                                        if(alist.fileattr&0x00000200U){put_u64(metadata.size);ret_file|=0x00000200U;}
                                        if(alist.fileattr&0x00000400U){put_u64(metadata.blocks*512);ret_file|=0x00000400U;}
                                        if(alist.fileattr&0x00001000U){put_u64(0);ret_file|=0x00001000U;}
                                        if(alist.fileattr&0x00002000U){put_u64(0);ret_file|=0x00002000U;}
                                        if(ret_attrs_offset){
                                            std::uint32_t rset[5]={ret_cmn,ret_vol,ret_dir,ret_file,ret_fork};
                                            std::memcpy(&buf[ret_attrs_offset],rset,20);
                                        }
                                        std::uint32_t total=static_cast<std::uint32_t>(buf.size());
                                        std::memcpy(&buf[0],&total,4);
                                        if(total>args[3]){
                                            outcome.error=34;
                                        }else if(!GuestAccessPermitted(engine,args[2],total,UC_PROT_WRITE)
                                            ||uc_mem_write(engine,args[2],buf.data(),total)!=UC_ERR_OK){
                                            outcome.error=14;
                                        }else{
                                            outcome.error=0;outcome.value=0;
                                        }
                                    }
                                }
                            }
                            else outcome=handler==Handler::OpenAt?files.OpenAt(fd,path,static_cast<std::uint32_t>(args[2]))
                                :files.Open(path,static_cast<std::uint32_t>(args[1]));}
                    }else if(handler==Handler::Write){
                        const auto capacity=files.WriteCapacity(fd,args[2]);const auto count=static_cast<std::size_t>(capacity.value);
                        if(capacity.error)outcome.error=capacity.error;
                        else if(count&&!GuestAccessPermitted(engine,args[1],count,UC_PROT_READ))outcome.error=14;
                        else {std::vector<char> bytes(count);
                            if(count&&uc_mem_read(engine,args[1],bytes.data(),count)!=UC_ERR_OK){trace.reason="file_copyin_failure";uc_emu_stop(engine);return;}
                            outcome=files.Write(fd,bytes);
                        }
                    }else if(handler==Handler::Fstat){outcome=files.Fstat(fd,metadata);if(!outcome.error)files.Path(fd,metadata_path);}
                    else if(handler==Handler::FsGetPath){
                        std::array<std::uint32_t,2> fsid{};std::string path;bool copied=false;
                        if(!GuestAccessPermitted(engine,args[2],sizeof(fsid),UC_PROT_READ)
                            ||uc_mem_read(engine,args[2],fsid.data(),sizeof(fsid))!=UC_ERR_OK)outcome.error=14;
                        else {copied=true;
                            // XNU copies fsid before validating size; val[0] selects
                            // the mounted volume. val[1] is not the object selector.
                            if(!args[1]||args[1]>8192)outcome.error=22;
                            else {
                                outcome.error=trace.task.owner->mapped->FilePathByIdentity(fsid[0],args[3],path);
                                if(!outcome.error){const auto count=path.size()+1;
                                    if(count>args[1])outcome.error=28;
                                    else if(!GuestAccessPermitted(engine,args[0],count,UC_PROT_WRITE))outcome.error=14;
                                    else if(uc_mem_write(engine,args[0],path.c_str(),count)!=UC_ERR_OK){trace.reason="identity_path_copyout_failure";uc_emu_stop(engine);return;}
                                    else outcome.value=count;
                                }
                            }
                        }
                        ++trace.identity_path_calls;
                        if(trace.identity_path_prefix.size()<16)trace.identity_path_prefix.push_back({trace.last_pc,fsid,args[3],path,copied,outcome.error});
                    }else if(handler==Handler::Close)outcome=files.Close(fd);
                    else if(handler==Handler::Dup)outcome=files.Dup(fd);
                    else if(handler==Handler::Dup2)outcome=files.Dup2(fd,std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1])));
                    else if(handler==Handler::Seek)outcome=files.Seek(fd,std::bit_cast<std::int64_t>(args[1]),static_cast<std::uint32_t>(args[2]));
                    else if(handler==Handler::Ioctl){
                        if(fd<0||(!files.Contains(fd)&&fd!=0&&fd!=1&&fd!=2))outcome.error=9;
                        else outcome.error=25;
                    }else if(handler==Handler::Fcntl){
                        const auto command=static_cast<std::uint32_t>(args[1]);
                        if(command==50||command==102){std::string path;outcome=files.Path(fd,path);
                            if(!outcome.error){path.push_back('\0');
                                if(path.size()>1024)outcome.error=63;
                                else if(!GuestAccessPermitted(engine,args[2],path.size(),UC_PROT_WRITE))outcome.error=14;
                                else if(uc_mem_write(engine,args[2],path.data(),path.size())!=UC_ERR_OK){trace.reason="file_path_copyout_failure";uc_emu_stop(engine);return;}}
                        }else if(command==97){
                            std::array<std::uint64_t,3> request{};DarwinFileSignature evidence;bool copied=false;
                            outcome=files.SignatureDescriptor(fd);
                            if(!outcome.error){
                                if(!GuestAccessPermitted(engine,args[2],sizeof(request),UC_PROT_READ)
                                    ||uc_mem_read(engine,args[2],request.data(),sizeof(request))!=UC_ERR_OK)outcome.error=14;
                                else {
                                    outcome=files.RegisterSignature(fd,request[0],request[1],request[2],evidence);
                                    if(!outcome.error){
                                        std::string registered_path;
                                        if(!files.Path(fd,registered_path).error&&registered_path==trace.task.text_path)
                                            trace.task.text_signature=evidence;
                                        if(!GuestAccessPermitted(engine,args[2],8,UC_PROT_WRITE))outcome.error=14;
                                        else if(uc_mem_write(engine,args[2],&evidence.end_offset,8)!=UC_ERR_OK){trace.reason="signature_copyout_failure";uc_emu_stop(engine);return;}
                                        else {copied=true;outcome.value=0;}
                                    }
                                }
                            }
                            const std::array<std::uint64_t,4> args4{args[0],args[1],args[2],args[3]};
                            ++trace.signature_calls;if(trace.signature_prefix.size()<16)trace.signature_prefix.push_back({trace.last_pc,args4,request,evidence,outcome.error,copied});
                        }else if(command==98){
                            std::array<std::uint64_t,3> request{};JsonValue evidence=JsonValue::ObjectValue();std::string reason;std::size_t message_bytes=0;
                            outcome=files.SignatureDescriptor(fd);
                            if(!outcome.error){
                                if(!GuestAccessPermitted(engine,args[2],sizeof(request),UC_PROT_READ)
                                    ||uc_mem_read(engine,args[2],request.data(),sizeof(request))!=UC_ERR_OK)outcome.error=14;
                                else {
                                    outcome=files.CheckLibrary(fd,request[0],trace.task.code_signing.Status(),evidence,reason);
                                    // Success never touches the optional error buffer or
                                    // the request. On rejection copy a bounded real reason.
                                    if(outcome.error&&!reason.empty()&&request[1]){
                                        reason.push_back('\0');const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(request[1],reason.size()));
                                        auto bytes=reason.substr(0,count);bytes.back()='\0';reason.pop_back();
                                        if(!GuestAccessPermitted(engine,request[2],count,UC_PROT_WRITE))outcome.error=14;
                                        else if(uc_mem_write(engine,request[2],bytes.data(),count)!=UC_ERR_OK){trace.reason="library_policy_copyout_failure";uc_emu_stop(engine);return;}
                                        else message_bytes=count;
                                    }
                                }
                            }
                            const std::array<std::uint64_t,4> args4{args[0],args[1],args[2],args[3]};
                            ++trace.library_calls;if(trace.library_prefix.size()<16)trace.library_prefix.push_back({trace.last_pc,args4,request,std::move(evidence),reason,outcome.error,message_bytes});
                        }else {
                            outcome=files.Fcntl(fd,command,args[2]);
                            if(command!=1&&command!=2&&command!=3&&trace.unhandled_fcntl_prefix.size()<16){
                                std::array<std::uint64_t,3> request{};bool request_read=false;
                                // Observation only: known LP64 F_CHECK_LV input.
                                // Preserve unsupported-service errno/execution.
                                if(command==98&&GuestAccessPermitted(engine,args[2],sizeof(request),UC_PROT_READ))
                                    request_read=uc_mem_read(engine,args[2],request.data(),sizeof(request))==UC_ERR_OK;
                                const std::array<std::uint64_t,4> args4{args[0],args[1],args[2],args[3]};
                                trace.unhandled_fcntl_prefix.push_back({trace.last_pc,args4,request,request_read,outcome.error});
                            }
                        }
                    }
                    else{
                        const auto position=handler==Handler::Pread?std::optional<std::uint64_t>(args[3]):std::nullopt;
                        auto* thread=trace.task.CurrentThread();
                        if(!thread){trace.reason="pipe_read_thread_binding_failure";uc_emu_stop(engine);return;}
                        auto& request=thread->pending_read;
                        if(request.active&&request.syscall_pc!=pc-4){trace.reason="pipe_read_continuation_mismatch";uc_emu_stop(engine);return;}
                        auto capacity=request.active?files.ReadCapacity(request.lease,request.requested,request.position)
                            :files.AcquireRead(fd,args[2],position,request.lease);
                        if(!capacity.error&&!request.active){
                            request.active=true;request.requested=args[2];request.position=position;request.syscall_pc=pc-4;
                        }
                        const auto park=[&](){
                            const auto retry_pc=pc-4;
                            if(uc_reg_write(engine,UC_ARM64_REG_PC,&retry_pc)!=UC_ERR_OK
                                ||trace.task.run_queue.Block(engine,PipeReadKey(*thread),{})!=UC_ERR_OK){
                                trace.reason="pipe_read_wait_capture_failure";
                            }else{++trace.pipe_read_parks;trace.thread_lifecycle_reschedule=true;}
                            uc_emu_stop(engine);
                        };
                        if(capacity.pending){park();return;}
                        const auto count=static_cast<std::size_t>(capacity.value);
                        if(capacity.error)outcome.error=capacity.error;
                        else if(count&&!GuestAccessPermitted(engine,args[1],count,UC_PROT_WRITE))outcome.error=14;
                        else{
                            std::vector<char> bytes(count);outcome=files.Read(request.lease,bytes,position);
                            if(outcome.pending){park();return;}
                            if(!outcome.error&&outcome.value&&uc_mem_write(engine,args[1],bytes.data(),static_cast<std::size_t>(outcome.value))!=UC_ERR_OK){trace.reason="file_copyout_failure";uc_emu_stop(engine);return;}
                        }
                        request={};
                    }
                    if(handler==Handler::Stat||handler==Handler::Fstat){
                        if(!outcome.error){const auto bytes=metadata.EncodeStat64();
                            if(!GuestAccessPermitted(engine,args[1],bytes.size(),UC_PROT_WRITE))outcome.error=14;
                            else if(uc_mem_write(engine,args[1],bytes.data(),bytes.size())!=UC_ERR_OK){trace.reason="metadata_copyout_failure";uc_emu_stop(engine);return;}
                            else metadata_copied=true;
                        }
                        const std::array<std::uint64_t,4> args4{args[0],args[1],args[2],args[3]};
                        ++trace.metadata_calls;if(trace.metadata_prefix.size()<16)trace.metadata_prefix.push_back({trace.last_pc,selector,args4,metadata_path,metadata,metadata_copied,outcome.error});
                    }
                }catch(...){trace.reason="file_service_failure";uc_emu_stop(engine);return;}
                const std::uint64_t result=outcome.error?static_cast<std::uint64_t>(outcome.error):outcome.value;
                const std::array<std::uint64_t,4> args4{args[0],args[1],args[2],args[3]};
                if(trace.file_prefix_size<trace.file_prefix.size())trace.file_prefix[trace.file_prefix_size++]={trace.last_pc,selector,args4,outcome.value,outcome.error};
                auto& file_summary=trace.file_by_selector[selector];++file_summary.first;
                file_summary.second={trace.last_pc,selector,args4,outcome.value,outcome.error};
                const std::uint64_t zero=0,after=outcome.error?(flags|0x20000000ULL):(flags&~0x20000000ULL);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK
                    ||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){trace.reason="file_return_failure";uc_emu_stop(engine);}
                return;
            }
            if(handler==Handler::ThreadSelfId||handler==Handler::GetTid||handler==Handler::Crossarch||handler==Handler::Platform
                ||handler==Handler::Csrctl||handler==Handler::SharedRegion||handler==Handler::GetPid
                ||handler==Handler::ProcInfo||handler==Handler::Munmap||handler==Handler::Sigprocmask
                ||handler==Handler::MapWithLinking||handler==Handler::Mprotect||handler==Handler::BsdthreadRegister||handler==Handler::BsdthreadCtl
                ||handler==Handler::WorkqOpen||handler==Handler::WorkqKernreturn||handler==Handler::KeventQos||handler==Handler::KeventId
                ||handler==Handler::ShmOpen||handler==Handler::ShmUnlink||handler==Handler::Socket
                ||handler==Handler::Issetugid||handler==Handler::UlockWait||handler==Handler::UlockWake
                ||handler==Handler::GetUid||handler==Handler::GetEuid||handler==Handler::GetGid
                ||handler==Handler::GetEgid||handler==Handler::GetPpid||handler==Handler::GetGroups
                ||handler==Handler::GetRlimit||handler==Handler::SetRlimit||handler==Handler::Madvise
                ||handler==Handler::Mincore||handler==Handler::PsynchMutexWait||handler==Handler::PsynchMutexDrop
                ||handler==Handler::PsynchCvBroad||handler==Handler::PsynchCvSignal||handler==Handler::PsynchCvWait
                ||handler==Handler::PsynchCvClrPrepost||handler==Handler::PsynchRwLongrdlock||handler==Handler::PsynchRwYieldwrlock
                ||handler==Handler::PsynchRwDowngrade||handler==Handler::PsynchRwUpgrade||handler==Handler::PsynchRwRdlock
                ||handler==Handler::PsynchRwWrlock||handler==Handler::PsynchRwUnlock||handler==Handler::PsynchRwUnlock2
                ||handler==Handler::UlockWait2||handler==Handler::Sigaction||handler==Handler::Sigaltstack){
                if(!trace.task.owner||trace.task.owner->engine.value!=engine||selected_thread->task!=&trace.task||!selected_thread->id){
                    trace.reason="thread_binding_failure";uc_emu_stop(engine);return;}
                std::uint64_t before=0; if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&before)!=UC_ERR_OK){
                    trace.reason="thread_register_failure";uc_emu_stop(engine);return;}
                if(handler==Handler::Platform){
                    std::uint64_t code=0,input=0,readback=0,writable_before=0,writable_after=0;
                    if(uc_reg_read(engine,UC_ARM64_REG_X3,&code)!=UC_ERR_OK||uc_reg_read(engine,UC_ARM64_REG_X0,&input)!=UC_ERR_OK
                        ||uc_reg_read(engine,UC_ARM64_REG_TPIDR_EL0,&writable_before)!=UC_ERR_OK){
                        trace.reason="platform_register_failure";uc_emu_stop(engine);return;}
                    code=static_cast<std::uint32_t>(code);
                    if(code==2){
                        // Same 48-bit lower user VA policy as the engine TCR.
                        const auto base=input>0x0000ffffffffffffULL?0:input;
                        // XNU's set_tpidrro writes the base directly; alignment
                        // is not a prerequisite for this register-only service.
                        if(uc_reg_write(engine,UC_ARM64_REG_TPIDRRO_EL0,&base)!=UC_ERR_OK){
                            trace.reason="platform_register_failure";uc_emu_stop(engine);return;}
                        selected_thread->tsd_base=base;
                    }else if(code==3){
                        if(uc_reg_write(engine,UC_ARM64_REG_X0,&selected_thread->tsd_base)!=UC_ERR_OK){
                            trace.reason="platform_register_failure";uc_emu_stop(engine);return;}
                    }else if(code>1){trace.reason="unsupported_platform_syscall";uc_emu_stop(engine);return;}
                    std::uint64_t after=0;
                    if(uc_reg_read(engine,UC_ARM64_REG_TPIDRRO_EL0,&readback)!=UC_ERR_OK||readback!=selected_thread->tsd_base
                        ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK||after!=before
                        ||uc_reg_read(engine,UC_ARM64_REG_TPIDR_EL0,&writable_after)!=UC_ERR_OK||writable_before!=writable_after){
                        trace.reason="platform_readback_failure";uc_emu_stop(engine);return;}
                    ++trace.platform_calls;
                    if(trace.platform_prefix_size<trace.platform_prefix.size())
                        trace.platform_prefix[trace.platform_prefix_size++]={trace.last_pc,code,input,readback,after};
                    return;
                }
                std::uint64_t result=selected_thread->id,error=0;
                bool workqueue_reschedule=false;
                if(handler==Handler::WorkqOpen||handler==Handler::WorkqKernreturn){
                    auto& workqueue=trace.task.workqueue;
                    result=0;
                    if(!trace.task.pthread_registration.registered)error=22;
                    else if(handler==Handler::WorkqOpen){workqueue.opened=true;++workqueue.opens;}
                    else{
                        std::array<std::uint64_t,4> args{};
                        for(unsigned n=0;n<args.size();++n)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(n)+(indirect?1:0),&args[n])!=UC_ERR_OK){
                            trace.reason="workqueue_argument_read_failure";uc_emu_stop(engine);return;}
                        const auto operation=static_cast<std::uint32_t>(args[0]);
                        if(operation==0x400){
                            const auto count=DarwinWorkqueueDispatchCopyinBytes(args[2]);
                            std::array<std::uint8_t,DarwinWorkqueueDispatchConfigurationBytes> bytes{};
                            if(count&&!GuestAccessPermitted(engine,args[1],count,UC_PROT_READ))error=14;
                            else if(count&&uc_mem_read(engine,args[1],bytes.data(),count)!=UC_ERR_OK){
                                trace.reason="workqueue_configuration_copyin_failure";uc_emu_stop(engine);return;}
                            DarwinWorkqueueDispatchConfiguration decoded;
                            if(!error)error=DecodeDarwinWorkqueueDispatchConfiguration(args[2],{bytes.data(),count},decoded);
                            if(!error){
                                if(!decoded.has_label)decoded.label_offset=workqueue.configuration.label_offset;
                                workqueue.configuration=decoded;++workqueue.setups;
                            }
                        }else if(operation==0x10){
                            workqueue.configuration.serialno_offset=static_cast<std::uint64_t>(
                                static_cast<std::int64_t>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2]))));
                        }else if(operation==0x20||operation==0x30){
                            DarwinWorkqueueRequest request;
                            error=DecodeDarwinWorkqueueRequest(operation,workqueue.opened,args[2],args[3],request);
                            if(!error){
                                try{workqueue.requests.push_back(request);}catch(const std::bad_alloc&){error=12;}
                                if(!error){++workqueue.requests_received;workqueue.threads_requested+=request.count;workqueue_reschedule=true;}
                            }
                        }else if(operation==4||operation==0x40||operation==0x100){
                            const bool kevent=operation==0x40,workloop=operation==0x100;
                            const auto nevents=static_cast<std::uint32_t>(args[2]);
                            if(!workqueue.opened||!selected_thread->workqueue.member||selected_thread->workqueue.idle
                                ||kevent!=selected_thread->workqueue.kevent_bucket.has_value()
                                ||workloop!=selected_thread->workqueue.workloop.has_value())error=22;
                            else if(!kevent&&!workloop&&args[1]&&nevents)error=22; // no bound kqueue request
                            else if((kevent||workloop)&&nevents>DarwinWorkqueueKeventListLength)error=22;
                            else if(selected_thread->policy.voucher){trace.reason="unsupported_workqueue_voucher_release";uc_emu_stop(engine);return;}
                            else{
                                if(kevent){
                                    // KEVENT_RETURN applies the servicer's deferred changes,
                                    // then unbinds its bucket and parks (it never returns).
                                    const auto clock=BootstrapTrace::KeventNow();
                                    for(std::uint32_t n=0;n<nevents;++n){
                                        std::array<std::uint8_t,DarwinKeventQosBytes> bytes{};
                                        const auto address=args[1]+std::uint64_t{n}*DarwinKeventQosBytes;
                                        if(!GuestAccessPermitted(engine,address,bytes.size(),UC_PROT_READ)
                                            ||uc_mem_read(engine,address,bytes.data(),bytes.size())!=UC_ERR_OK){
                                            trace.reason="kevent_return_copyin_failure";uc_emu_stop(engine);return;}
                                        const auto change=DecodeDarwinKeventQos(bytes);
                                        trace.RecordKevent(trace.last_pc,-1,1,0,0x800,change);
                                        const auto applied=workqueue.kqueue.Apply(change,clock);
                                        if(applied.unsupported){trace.reason=applied.unsupported;uc_emu_stop(engine);return;}
                                        // An error event would be returned to a thread that cannot
                                        // resume from this call; XNU parks only after clean changes.
                                        if(applied.error){trace.reason="kevent_return_change_error";uc_emu_stop(engine);return;}
                                    }
                                    workqueue.kqueue.Unbind(*selected_thread->workqueue.kevent_bucket);
                                    selected_thread->workqueue.kevent_bucket.reset();++workqueue.kevent_returns;
                                }
                                if(workloop){
                                    // WORKLOOP_RETURN applies the servicer's deferred changes to
                                    // its bound workloop, unbinds it and parks.
                                    const auto id=*selected_thread->workqueue.workloop;
                                    auto& bound=workqueue.workloops.at(id);
                                    const auto clock=BootstrapTrace::KeventNow();
                                    const auto read=[&](std::uint64_t address,std::uint64_t& value){
                                        return GuestAccessPermitted(engine,address,8,UC_PROT_READ)&&uc_mem_read(engine,address,&value,8)==UC_ERR_OK;};
                                    for(std::uint32_t n=0;n<nevents;++n){
                                        std::array<std::uint8_t,DarwinKeventQosBytes> bytes{};
                                        const auto address=args[1]+std::uint64_t{n}*DarwinKeventQosBytes;
                                        if(!GuestAccessPermitted(engine,address,bytes.size(),UC_PROT_READ)
                                            ||uc_mem_read(engine,address,bytes.data(),bytes.size())!=UC_ERR_OK){
                                            trace.reason="workloop_return_copyin_failure";uc_emu_stop(engine);return;}
                                        const auto change=DecodeDarwinKeventQos(bytes);
                                        trace.RecordKevent(trace.last_pc,-2,1,0,0x100,change);
                                        const auto applied=bound.Apply(change,clock,read);
                                        if(applied.unsupported){trace.reason=applied.unsupported;uc_emu_stop(engine);return;}
                                        if(applied.wait){trace.reason="unsupported_workloop_return_wait";uc_emu_stop(engine);return;}
                                        if(applied.error){trace.reason="workloop_return_change_error";uc_emu_stop(engine);return;}
                                        if(applied.wake)trace.WakeWorkloopWaiter(id,*applied.wake);
                                    }
                                    bound.EndService();
                                    selected_thread->workqueue.workloop.reset();++workqueue.workloop_returns;
                                }
                                // A real return parks the worker. Its saved continuation is
                                // replaced by an upcall before waking; never resume this SVC.
                                const auto blocked=trace.task.run_queue.Block(engine,0xf400000000000000ULL|selected_thread->id,{});
                                if(blocked!=UC_ERR_OK){trace.reason="workqueue_return_capture_failure";uc_emu_stop(engine);return;}
                                selected_thread->signal_mask|=~BootstrapTrace::workqueue_thread_mask&~workqueue.allow_sigmask;
                                selected_thread->workqueue.idle=true;selected_thread->workqueue.blocked_at=0;
                                ++workqueue.returns;++workqueue.parks;
                                trace.thread_lifecycle_reschedule=true;uc_emu_stop(engine);return;
                            }
                        }else if(operation==0x80){
                            // WQOPS_SET_EVENT_MANAGER_PRIORITY keeps the highest QoS requested.
                            const auto priority=static_cast<std::uint32_t>(args[2]);
                            auto bits=(priority&0x3f00u)>>8;
                            if(!workqueue.opened)error=22;
                            else if(priority&0x20000000u){trace.reason="unsupported_event_manager_sched_priority";uc_emu_stop(engine);return;}
                            else if(!bits)error=22;
                            else{
                                std::uint8_t qos=1;while(!(bits&1u)){++qos;bits>>=1;}
                                workqueue.manager_qos=std::max(workqueue.manager_qos,qos);
                            }
                        }else{
                            // Known optional contracts have no provider/capability yet.
                            error=operation==0x100||operation==0x200?45:22;
                        }
                    }
                    result=error;
                }
                if(handler==Handler::KeventQos){
                    std::array<std::uint64_t,8> args{};
                    for(unsigned n=0;n<args.size();++n)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(n)+(indirect?1:0),&args[n])!=UC_ERR_OK){
                        trace.reason="kevent_argument_read_failure";uc_emu_stop(engine);return;}
                    auto& workqueue=trace.task.workqueue;++workqueue.kevent_calls;
                    const auto fd=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[0]));
                    const auto nchanges=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2]));
                    const auto nevents=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[4]));
                    const auto flags=static_cast<std::uint32_t>(args[7]);
                    constexpr auto known=DarwinKeventFlagImmediate|DarwinKeventFlagErrorEvents|DarwinKeventFlagStackData
                        |DarwinKeventFlagWorkq|DarwinKeventFlagWorkqManager;
                    trace.RecordKevent(trace.last_pc,fd,nchanges,nevents,flags,{});
                    // Only the process kqworkq exists; kqueue() descriptors and
                    // workloops have no provider.
                    if(fd!=-1||!(flags&DarwinKeventFlagWorkq)||(flags&~known)){
                        trace.reason="unsupported_kevent_qos";uc_emu_stop(engine);return;}
                    result=0;
                    if(!workqueue.opened||nchanges<0||nevents<0)error=22;
                    else{
                        const auto clock=BootstrapTrace::KeventNow();
                        std::vector<DarwinKeventQos> out;
                        for(std::int32_t n=0;n<nchanges&&!error;++n){
                            std::array<std::uint8_t,DarwinKeventQosBytes> bytes{};
                            const auto address=args[1]+std::uint64_t(n)*DarwinKeventQosBytes;
                            if(!GuestAccessPermitted(engine,address,bytes.size(),UC_PROT_READ)){error=14;break;}
                            if(uc_mem_read(engine,address,bytes.data(),bytes.size())!=UC_ERR_OK){
                                trace.reason="kevent_copyin_failure";uc_emu_stop(engine);return;}
                            auto change=DecodeDarwinKeventQos(bytes);
                            trace.RecordKevent(trace.last_pc,fd,nchanges,nevents,flags,change);
                            const auto applied=workqueue.kqueue.Apply(change,clock);
                            if(applied.unsupported){trace.reason=applied.unsupported;uc_emu_stop(engine);return;}
                            if(applied.error||(change.flags&DarwinEvReceipt)){
                                // kevent_register error/receipt: an EV_ERROR event while
                                // the output list has room, otherwise the call fails.
                                change.flags|=DarwinEvError;change.data=applied.error;
                                if(out.size()<static_cast<std::size_t>(nevents))out.push_back(change);
                                else if(applied.error)error=static_cast<std::uint64_t>(applied.error);
                            }
                        }
                        if(!error&&!(flags&DarwinKeventFlagErrorEvents)&&out.size()<static_cast<std::size_t>(nevents)){
                            // Event collection requires the caller to be the bucket's
                            // servicer; blocking waits on the kqworkq are not modeled.
                            const auto& bucket=selected_thread->workqueue.kevent_bucket;
                            if(!bucket||!(flags&DarwinKeventFlagImmediate)){
                                trace.reason="unsupported_kevent_workq_collection";uc_emu_stop(engine);return;}
                            for(auto& event:workqueue.kqueue.Collect(*bucket,clock,static_cast<std::size_t>(nevents)-out.size()))
                                out.push_back(event);
                        }
                        if(!error&&!out.empty()){
                            std::vector<std::uint8_t> bytes(out.size()*DarwinKeventQosBytes);
                            for(std::size_t n=0;n<out.size();++n)
                                EncodeDarwinKeventQos(out[n],std::span<std::uint8_t,DarwinKeventQosBytes>(bytes.data()+n*DarwinKeventQosBytes,DarwinKeventQosBytes));
                            if(!GuestAccessPermitted(engine,args[3],bytes.size(),UC_PROT_WRITE))error=14;
                            else if(uc_mem_write(engine,args[3],bytes.data(),bytes.size())!=UC_ERR_OK){
                                trace.reason="kevent_copyout_failure";uc_emu_stop(engine);return;}
                        }
                        if(!error)result=out.size();
                        // Newly active knotes need a servicer.
                        workqueue_reschedule=true;
                    }
                    if(error)result=error;
                }
                if(handler==Handler::KeventId){
                    std::array<std::uint64_t,8> args{};
                    for(unsigned n=0;n<args.size();++n)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(n)+(indirect?1:0),&args[n])!=UC_ERR_OK){
                        trace.reason="kevent_id_argument_read_failure";uc_emu_stop(engine);return;}
                    auto& workqueue=trace.task.workqueue;++workqueue.kevent_id_calls;
                    const auto id=args[0];
                    const auto nchanges=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2]));
                    const auto nevents=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[4]));
                    const auto flags=static_cast<std::uint32_t>(args[7]);
                    constexpr auto known=DarwinKeventFlagImmediate|DarwinKeventFlagErrorEvents|DarwinKeventFlagStackData
                        |DarwinKeventFlagWorkloop|DarwinKeventFlagDynamicKqMustExist;
                    trace.RecordKevent(trace.last_pc,-2,nchanges,nevents,flags,{});
                    // Only dynamic workloop kqueues are provided by kevent_id.
                    if(!(flags&DarwinKeventFlagWorkloop)||(flags&~known)){
                        trace.reason="unsupported_kevent_id";uc_emu_stop(engine);return;}
                    result=0;
                    auto found=workqueue.workloops.find(id);
                    if(!workqueue.opened||nchanges<0||nevents<0)error=22;
                    else if(found==workqueue.workloops.end()&&(flags&DarwinKeventFlagDynamicKqMustExist))error=2;
                    else{
                        if(found==workqueue.workloops.end())found=workqueue.workloops.emplace(id,DarwinWorkloop(id)).first;
                        auto& workloop=found->second;
                        const auto clock=BootstrapTrace::KeventNow();
                        const auto read=[&](std::uint64_t address,std::uint64_t& value){
                            return GuestAccessPermitted(engine,address,8,UC_PROT_READ)&&uc_mem_read(engine,address,&value,8)==UC_ERR_OK;};
                        std::vector<DarwinKeventQos> out;
                        for(std::int32_t n=0;n<nchanges&&!error;++n){
                            std::array<std::uint8_t,DarwinKeventQosBytes> bytes{};
                            const auto address=args[1]+std::uint64_t(n)*DarwinKeventQosBytes;
                            if(!GuestAccessPermitted(engine,address,bytes.size(),UC_PROT_READ)){error=14;break;}
                            if(uc_mem_read(engine,address,bytes.data(),bytes.size())!=UC_ERR_OK){
                                trace.reason="kevent_id_copyin_failure";uc_emu_stop(engine);return;}
                            auto change=DecodeDarwinKeventQos(bytes);
                            trace.RecordKevent(trace.last_pc,-2,nchanges,nevents,flags,change);
                            const auto applied=workloop.Apply(change,clock,read);
                            if(applied.unsupported){trace.reason=applied.unsupported;uc_emu_stop(engine);return;}
                            if(applied.wake)trace.WakeWorkloopWaiter(id,*applied.wake);
                            if(applied.wait){
                                // SYNC_WAIT parks until the owner's SYNC_WAKE (or the
                                // knote's deletion); the retried call then completes.
                                if(nchanges!=1){trace.reason="unsupported_workloop_wait_batch";uc_emu_stop(engine);return;}
                                const auto retry_pc=pc-4;
                                selected_thread->workloop_wait=std::pair{id,change.ident};
                                if(uc_reg_write(engine,UC_ARM64_REG_PC,&retry_pc)!=UC_ERR_OK
                                    ||trace.task.run_queue.Block(engine,BootstrapTrace::WorkloopWaitKey(*selected_thread),{})!=UC_ERR_OK){
                                    trace.reason="workloop_wait_capture_failure";uc_emu_stop(engine);return;}
                                ++workqueue.workloop_parks;
                                trace.thread_lifecycle_reschedule=true;uc_emu_stop(engine);return;
                            }
                            if(selected_thread->workloop_wait&&selected_thread->workloop_wait->first==id
                                &&selected_thread->workloop_wait->second==change.ident)selected_thread->workloop_wait.reset();
                            if(applied.error||(change.flags&DarwinEvReceipt)){
                                change.flags|=DarwinEvError;change.data=applied.error;
                                if(out.size()<static_cast<std::size_t>(nevents))out.push_back(change);
                                else if(applied.error)error=static_cast<std::uint64_t>(applied.error);
                            }
                        }
                        if(!error&&!(flags&DarwinKeventFlagErrorEvents)&&out.size()<static_cast<std::size_t>(nevents)){
                            // Only the bound servicer drains its workloop, without blocking.
                            if(selected_thread->workqueue.workloop!=id||!(flags&DarwinKeventFlagImmediate)){
                                trace.reason="unsupported_workloop_collection";uc_emu_stop(engine);return;}
                            for(auto& event:workloop.Collect(clock,static_cast<std::size_t>(nevents)-out.size()))out.push_back(event);
                        }
                        if(!error&&!out.empty()){
                            std::vector<std::uint8_t> bytes(out.size()*DarwinKeventQosBytes);
                            for(std::size_t n=0;n<out.size();++n)
                                EncodeDarwinKeventQos(out[n],std::span<std::uint8_t,DarwinKeventQosBytes>(bytes.data()+n*DarwinKeventQosBytes,DarwinKeventQosBytes));
                            if(!GuestAccessPermitted(engine,args[3],bytes.size(),UC_PROT_WRITE))error=14;
                            else if(uc_mem_write(engine,args[3],bytes.data(),bytes.size())!=UC_ERR_OK){
                                trace.reason="kevent_id_copyout_failure";uc_emu_stop(engine);return;}
                        }
                        if(!error)result=out.size();
                        workqueue_reschedule=true;
                    }
                    if(error)result=error;
                }
                if(handler==Handler::BsdthreadRegister){
                    ++trace.bsdthread_register_calls;trace.pthread_input_decoded=false;trace.pthread_input={};
                    trace.pthread_entries_converted=false;trace.pthread_converted_entries={};
                    trace.pthread_entry_auth_error=UC_ERR_OK;trace.pthread_registration_error=0;
                    trace.pthread_output_copied=false;trace.pthread_output_verified=false;
                    trace.pthread_features_returned=false;trace.pthread_available_features=0;
                    trace.pthread_output_readback={};
                    trace.pthread_registration_committed=trace.task.pthread_registration.registered;
                    auto& args=trace.pthread_arguments;
                    for(unsigned n=0;n<args.size();++n)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(n)+(indirect?1:0),&args[n])!=UC_ERR_OK){
                        trace.reason="pthread_registration_register_failure";uc_emu_stop(engine);return;
                    }
                    const auto size=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2]));
                    std::array<std::uint8_t,DarwinPthreadRegistrationBytes> copyin{};std::size_t copied=0;
                    if(size>=0&&size<=DarwinMaximumPthreadBytes&&args[3]&&args[4]>=8){
                        copied=static_cast<std::size_t>(std::min<std::uint64_t>(args[4],copyin.size()));
                        if(!GuestAccessPermitted(engine,args[3],copied,UC_PROT_READ))error=14;
                        else if(uc_mem_read(engine,args[3],copyin.data(),copied)!=UC_ERR_OK){
                            trace.reason="pthread_registration_copyin_failure";uc_emu_stop(engine);return;
                        }
                    }
                    if(!error)error=DecodeDarwinPthreadRegistration(size,args[3]!=0,args[4],{copyin.data(),copied},args[5],trace.pthread_input);
                    trace.pthread_decode_error=static_cast<int>(error);trace.pthread_input_decoded=error==0;
                    if(!error){
                        // No feature bits or output state can be published before
                        // the required thread-control/scheduling providers exist.
                        // Authenticating registered entries requires running the
                        // existing task-owned PAC service outside this callback.
                        // It publishes no registration state or feature mask.
                        trace.pthread_entry_auth_pending=true;
                        trace.interrupt=number;trace.syscall_selector=raw_selector;
                        uc_emu_stop(engine);return;
                    }
                    result=error;
                }

                if(handler==Handler::BsdthreadCtl){
                    ++trace.bsdthread_ctl_calls;
                    std::uint64_t raw_cmd=0,arg1=0,arg2=0,arg3=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&raw_cmd)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&arg1)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&arg2)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X4:UC_ARM64_REG_X3,&arg3)!=UC_ERR_OK){
                        trace.reason="bsdthread_ctl_register_failure";uc_emu_stop(engine);return;
                    }
                    const auto cmd=static_cast<std::uint32_t>(raw_cmd);
                    // Bind the independent stages to the actual current task,
                    // queue policy and ordinary workqueue accounting providers.
                    BootstrapTrace::PthreadPolicyBinding provider(trace,*selected_thread);
                    const auto ops=provider.Operations();
                    error=ApplyDarwinBsdthreadCtl(selected_thread->policy,cmd,arg1,arg2,arg3,
                        selected_thread->workqueue.member?DarwinPthreadPolicyKind::OrdinaryWorkqueue:DarwinPthreadPolicyKind::Ordinary,ops);
                    result=error;
                    if(trace.reason){uc_emu_stop(engine);return;}
                    workqueue_reschedule=trace.thread_lifecycle_reschedule;
                }

                if(handler==Handler::GetUid||handler==Handler::GetEuid){result=trace.task.credentials.uid;++trace.credential_calls;}
                if(handler==Handler::GetGid||handler==Handler::GetEgid){result=trace.task.credentials.gid;++trace.credential_calls;}
                if(handler==Handler::Issetugid){result=0;++trace.credential_calls;} // No set-ID transition in this immutable credential scope.
                if(handler==Handler::GetTid){++trace.credential_calls;error=3;result=error;} // XNU gettid(uidp,gidp): ESRCH when UT_SETUID is not active.
                if(handler==Handler::GetGroups){
                    ++trace.credential_calls;std::uint64_t capacity=0,pointer=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&capacity)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&pointer)!=UC_ERR_OK){trace.reason="getgroups_register_failure";uc_emu_stop(engine);return;}
                    const auto count=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(capacity));
                    const auto& groups=trace.task.credentials.groups;result=groups.size();
                    if(count<0||(count>0&&static_cast<std::size_t>(count)<groups.size()))error=22;
                    else if(count>0){
                        const auto bytes=groups.size()*sizeof(std::uint32_t);
                        if(!GuestAccessPermitted(engine,pointer,bytes,UC_PROT_WRITE))error=14;
                        else if(uc_mem_write(engine,pointer,groups.data(),bytes)!=UC_ERR_OK){trace.reason="getgroups_copyout_failure";uc_emu_stop(engine);return;}
                    }
                    if(error)result=error;
                }
                if(handler==Handler::GetPid){
                    result=trace.task.pid;
                    error=0;
                }
                if(handler==Handler::Crossarch){
                    std::uint64_t name=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&name)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    // XNU namespace argument is uint32_t; only namespace 0 is valid.
                    error=static_cast<std::uint32_t>(name)>0?22:45;result=error;
                }
                if(handler==Handler::Csrctl){
                    std::uint64_t op=0,address=0,size=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&op)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&address)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&size)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    op=static_cast<std::uint32_t>(op);
                    if(op>1)error=78;
                    else if(!address||size!=sizeof(csr_config))error=22;
                    else if(op==0){
                        std::uint32_t mask=0;
                        if(!GuestAccessPermitted(engine,address,sizeof(mask),UC_PROT_READ)
                            ||uc_mem_read(engine,address,&mask,sizeof(mask))!=UC_ERR_OK)error=14;
                        else error=(csr_config&mask)==mask?0:1;
                    }else if(!GuestAccessPermitted(engine,address,sizeof(csr_config),UC_PROT_WRITE)
                        ||uc_mem_write(engine,address,&csr_config,sizeof(csr_config))!=UC_ERR_OK)error=14;
                    result=error;
                }
                if(handler==Handler::SharedRegion){
                    std::uint64_t address=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&address)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    trace.memory_address=address;
                    const auto start=trace.task.owner->mapped->SharedRegionStart();
                    if(!start)error=22;
                    else if(!address){error=14;}
                    else {
                        const auto user_address=address&0x0000ffffffffffffULL;
                        if(!GuestAccessPermitted(engine,user_address,sizeof(start),UC_PROT_WRITE)
                            ||uc_mem_write(engine,user_address,&start,sizeof(start))!=UC_ERR_OK)error=14;
                    }
                    result=error;
                }
                if(handler==Handler::ProcInfo){
                    std::uint64_t callnum=0,pid=0,flavor=0,arg=0,buffer=0,buffersize=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&callnum)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&pid)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&flavor)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X4:UC_ARM64_REG_X3,&arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X5:UC_ARM64_REG_X4,&buffer)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X6:UC_ARM64_REG_X5,&buffersize)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    callnum=static_cast<std::uint32_t>(callnum);
                    if(callnum==15){
                        if(!buffer||!buffersize||!GuestAccessPermitted(engine,buffer,buffersize,UC_PROT_READ)){
                            error=14;
                        } else {
                            trace.all_image_info_addr=buffer;
                            trace.all_image_info_size=buffersize;
                            result=0;
                            error=0;
                        }
                    } else {
                        error=45;
                        result=error;
                    }
                }
                if(handler==Handler::Munmap){
                    std::uint64_t address=0,length=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&address)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&length)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    const auto page_size=trace.stack.PageSize();
                    const auto page_mask=page_size-1;
                    if((address&page_mask)!=0||!length||length>UINT64_MAX-page_mask||address>UINT64_MAX-length-page_mask){error=22;result=error;}
                    else {
                        const auto end=(address+length+page_mask)&~page_mask;
                        const auto code=trace.UnmapVmRange(engine,address,end);error=code==3?12:code?22:0;
                        result=error;
                    }
                }
                if(handler==Handler::Sigprocmask){
                    std::uint64_t how_arg=0,set_arg=0,oset_arg=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&how_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&set_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&oset_arg)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    const auto how=static_cast<std::uint32_t>(how_arg);
                    if(oset_arg){
                        if(!GuestAccessPermitted(engine,oset_arg,sizeof(std::uint32_t),UC_PROT_WRITE)
                            ||uc_mem_write(engine,oset_arg,&selected_thread->signal_mask,sizeof(std::uint32_t))!=UC_ERR_OK){
                            error=14;
                        }
                    }
                    if(!error&&set_arg){
                        std::uint32_t new_mask=0;
                        if(!GuestAccessPermitted(engine,set_arg,sizeof(std::uint32_t),UC_PROT_READ)
                            ||uc_mem_read(engine,set_arg,&new_mask,sizeof(std::uint32_t))!=UC_ERR_OK){
                            error=14;
                        } else {
                            constexpr std::uint32_t cant_mask=(1U << (9 - 1)) | (1U << (17 - 1));
                            new_mask &= ~cant_mask;
                            if(how==1){ // SIG_BLOCK
                                selected_thread->signal_mask |= new_mask;
                            } else if(how==2){ // SIG_UNBLOCK
                                selected_thread->signal_mask &= ~new_mask;
                            } else if(how==3){ // SIG_SETMASK
                                selected_thread->signal_mask = new_mask;
                            } else {
                                error=22;
                            }
                        }
                    }
                    if(!error){
                        result=0;
                    } else {
                        result=error;
                    }
                }
                if(handler==Handler::MapWithLinking){
                    std::uint64_t regions_arg=0,count_arg=0,blob_arg=0,size_arg=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&regions_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&count_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&blob_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X4:UC_ARM64_REG_X3,&size_arg)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    error=45;
                    result=error;
                }
                if(handler==Handler::Mprotect){
                    std::uint64_t address=0,length=0,prot_arg=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&address)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&length)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&prot_arg)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    const auto page_size=trace.stack.PageSize();
                    const auto page_mask=page_size-1;
                    if((address&page_mask)!=0||!length||length>UINT64_MAX-page_mask||address>UINT64_MAX-length-page_mask||(prot_arg&~7ULL)!=0){
                        error=22;
                        result=error;
                    } else {
                        const auto end=(address+length+page_mask)&~page_mask;
                        const auto rounded_length=end-address;
                        if(!GuestAccessPermitted(engine,address,rounded_length,0)){
                            error=12;
                            result=error;
                        } else {
                            const auto prot=static_cast<std::uint32_t>(prot_arg&7);
                            const auto code=trace.ProtectVmRange(engine,address,rounded_length,false,prot);
                            error=code==2?13:code==3?12:code?22:0;result=error;
                        }
                    }
                }
                if(handler==Handler::ShmOpen){
                    std::uint64_t name_addr=0,oflag_val=0,mode_val=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&name_addr)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&oflag_val)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&mode_val)!=UC_ERR_OK){
                        trace.reason="shm_open_register_failure";uc_emu_stop(engine);return;}
                    std::string shm_name;
                    for(std::size_t i=0;i<1024;++i){
                        char c=0;
                        if(name_addr>UINT64_MAX-i||!GuestAccessPermitted(engine,name_addr+i,1,UC_PROT_READ)
                            ||uc_mem_read(engine,name_addr+i,&c,1)!=UC_ERR_OK){error=14;break;}
                        if(!c)break;
                        shm_name.push_back(c);
                    }
                    if(!error){
                        error=2; // ENOENT
                    }
                    result=error;
                }
                if(handler==Handler::ShmUnlink){
                    std::uint64_t name_addr=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&name_addr)!=UC_ERR_OK){
                        trace.reason="shm_unlink_register_failure";uc_emu_stop(engine);return;}
                    error=2; // ENOENT
                    result=error;
                }
                if(handler==Handler::Socket){
                    std::uint64_t domain=0,type=0,protocol=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&domain)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&type)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&protocol)!=UC_ERR_OK){
                        trace.reason="socket_register_failure";uc_emu_stop(engine);return;}
                    error=47; // EAFNOSUPPORT (Address family not supported by protocol family)
                    result=error;
                }
                if(handler==Handler::GetRlimit){
                    std::uint64_t which_arg=0,rlp_arg=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&which_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&rlp_arg)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    const auto which=static_cast<std::uint32_t>(which_arg)&~0x1000U;
                    if(which>=trace.task.rlimits.size()){error=22;}
                    else if(!rlp_arg||!GuestAccessPermitted(engine,rlp_arg,16,UC_PROT_WRITE)){error=14;}
                    else {
                        const auto& rl=trace.task.rlimits[which];
                        if(uc_mem_write(engine,rlp_arg,rl.data(),sizeof(rl))!=UC_ERR_OK)error=14;
                        else error=0;
                    }
                    result=error;
                }
                if(handler==Handler::SetRlimit){
                    std::uint64_t which_arg=0,rlp_arg=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&which_arg)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&rlp_arg)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    const auto which=static_cast<std::uint32_t>(which_arg)&~0x1000U;
                    if(which>=trace.task.rlimits.size()){error=22;}
                    else if(!rlp_arg||!GuestAccessPermitted(engine,rlp_arg,16,UC_PROT_READ)){error=14;}
                    else {
                        std::array<std::uint64_t,2> requested{};
                        if(uc_mem_read(engine,rlp_arg,requested.data(),sizeof(requested))!=UC_ERR_OK)error=14;
                        else if((requested[0]&(1ULL<<63))!=0||(requested[1]&(1ULL<<63))!=0||requested[0]>requested[1])error=22;
                        else if(requested[1]>trace.task.rlimits[which][1])error=1;
                        else {
                            if(which==8){
                                requested[0]=std::min<std::uint64_t>(requested[0],4096);
                                if(trace.task.owner&&trace.task.owner->files)trace.task.owner->files->SetMaxDescriptors(requested[0]);
                            }
                            trace.task.rlimits[which]=requested;
                            error=0;
                        }
                    }
                    result=error;
                }
                if(handler==Handler::Madvise){
                    std::uint64_t address=0,length=0,advice_arg=0;
                    if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&address)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X2:UC_ARM64_REG_X1,&length)!=UC_ERR_OK
                        ||uc_reg_read(engine,indirect?UC_ARM64_REG_X3:UC_ARM64_REG_X2,&advice_arg)!=UC_ERR_OK){
                        trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                    const auto advice=static_cast<std::int32_t>(static_cast<std::uint32_t>(advice_arg));
                    const auto page_size=trace.stack.PageSize();
                    const auto page_mask=page_size-1;
                    if(advice<0||advice>11||length>UINT64_MAX-page_mask||address>UINT64_MAX-length){
                        error=22;
                    } else if(length>0){
                        const auto start=address&~page_mask;
                        const auto end=((address+length)+page_mask)&~page_mask;
                        if(end<start||!GuestAccessPermitted(engine,start,end-start,0)){
                            error=12;
                        } else if(advice==11){
                            if(!GuestAccessPermitted(engine,start,end-start,UC_PROT_WRITE)){
                                error=12;
                            } else {
                                std::vector<std::uint8_t> zeros(static_cast<std::size_t>(std::min<std::uint64_t>(end-start,65536ULL)),0);
                                for(std::uint64_t cur=start;cur<end;cur+=zeros.size()){
                                    const auto chunk=static_cast<std::size_t>(std::min<std::uint64_t>(end-cur,zeros.size()));
                                    if(uc_mem_write(engine,cur,zeros.data(),chunk)!=UC_ERR_OK){error=12;break;}
                                }
                            }
                        } else {
                            error=0;
                        }
                    } else {
                        error=0;
                    }
                    result=error;
                }
                if(handler==Handler::PsynchRwUnlock2){error=45;result=45;}
                const std::uint64_t zero=0,after=error?(before|0x20000000ULL):(before&~0x20000000ULL);
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK||uc_reg_write(engine,UC_ARM64_REG_X1,&zero)!=UC_ERR_OK
                    ||uc_reg_write(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK){
                    trace.reason="bsd_register_failure";uc_emu_stop(engine);return;}
                std::uint64_t x0=0,x1=0,actual_flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_X0,&x0)!=UC_ERR_OK||x0!=result||uc_reg_read(engine,UC_ARM64_REG_X1,&x1)!=UC_ERR_OK||x1
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&actual_flags)!=UC_ERR_OK||actual_flags!=after){
                    trace.reason="bsd_readback_failure";uc_emu_stop(engine);return;}
                if(handler==Handler::ThreadSelfId)++trace.selfid_calls;
                else if(handler==Handler::Crossarch)++trace.crossarch_calls;
                else if(handler==Handler::Csrctl)++trace.csr_calls;
                else if(handler==Handler::GetPid)++trace.getpid_calls;
                else if(handler==Handler::ProcInfo)++trace.proc_info_calls;
                else if(handler==Handler::Munmap)++trace.munmap_calls;
                else if(handler==Handler::Mprotect)++trace.mprotect_calls;
                else if(handler==Handler::Sigprocmask)++trace.sigprocmask_calls;
                else if(handler==Handler::MapWithLinking)++trace.map_with_linking_calls;
                else if(handler==Handler::ShmOpen)++trace.shm_open_calls;
                else if(handler==Handler::ShmUnlink)++trace.shm_unlink_calls;
                else ++trace.shared_region_calls;
                if(trace.bsd_prefix_size<trace.bsd_prefix.size())trace.bsd_prefix[trace.bsd_prefix_size++]={trace.last_pc,raw_selector,selector,x0,x1,before,actual_flags};
                if(workqueue_reschedule){trace.thread_lifecycle_reschedule=true;uc_emu_stop(engine);}
                return;
            }
            if(handler==Handler::ModRefs||handler==Handler::Deallocate){
                std::array<std::uint64_t,4> args{};std::uint64_t flags=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&args[i])!=UC_ERR_OK){trace.reason="mach_right_register_failure";uc_emu_stop(engine);return;}
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="mach_right_register_failure";uc_emu_stop(engine);return;}
                const auto target=static_cast<std::uint32_t>(args[0]),name=static_cast<std::uint32_t>(args[1]);
                const auto* before=trace.task.Resolve(name);const auto before_refs=before?before->send_refs+before->dead_refs:0;
                MachTask::RightResult outcome{0x10000003};
                if(trace.task.ResolveSend(target)==&trace.task)outcome=handler==Handler::ModRefs
                    ?trace.task.ModRefs(name,static_cast<std::uint32_t>(args[2]),std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[3])))
                    :trace.task.Deallocate(name);
                if(outcome.pinned_guard){trace.reason="unsupported_mach_port_guard";uc_emu_stop(engine);return;}
                const std::uint64_t value=outcome.code;std::uint64_t actual=0,after_flags=0;
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&value)!=UC_ERR_OK
                    ||uc_reg_read(engine,UC_ARM64_REG_X0,&actual)!=UC_ERR_OK
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&after_flags)!=UC_ERR_OK
                    ||actual!=value||after_flags!=flags){trace.reason="mach_right_return_failure";uc_emu_stop(engine);return;}
                for(unsigned i=1;i<args.size();++i){std::uint64_t preserved=0;
                    if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&preserved)!=UC_ERR_OK||preserved!=args[i]){
                        trace.reason="mach_right_return_failure";uc_emu_stop(engine);return;}}
                const auto* after=trace.task.Resolve(name);const auto after_refs=after?after->send_refs+after->dead_refs:0;
                if(handler==Handler::ModRefs)++trace.mod_refs_calls;else ++trace.deallocate_calls;
                if(trace.rights_prefix_size<trace.rights_prefix.size())trace.rights_prefix[trace.rights_prefix_size++]={trace.last_pc,selector,args[0],args[1],args[2],args[3],value,before_refs,after_refs,flags};
                return;
            }
            if(handler==Handler::PortConstruct){
                std::array<std::uint64_t,4> args{};std::uint64_t flags=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&args[i])!=UC_ERR_OK){trace.reason="mach_construct_register_failure";uc_emu_stop(engine);return;}
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="mach_construct_register_failure";uc_emu_stop(engine);return;}
                const auto target=static_cast<std::uint32_t>(args[0]);
                const auto options_addr=args[1];
                const auto context=args[2];
                const auto name_addr=args[3];
                std::uint64_t result=0;
                if(!trace.task.ResolveSend(target)||trace.task.ResolveSend(target)!=&trace.task){
                    result=4;
                } else if(!options_addr||!name_addr||!GuestAccessPermitted(engine,options_addr,sizeof(std::uint32_t),UC_PROT_READ)||!GuestAccessPermitted(engine,name_addr,sizeof(std::uint32_t),UC_PROT_WRITE)){
                    result=14;
                } else {
                    std::uint32_t opt_flags=0;
                    if(uc_mem_read(engine,options_addr,&opt_flags,sizeof(opt_flags))!=UC_ERR_OK){
                        result=14;
                    } else {
                        const auto port_name=trace.task.ConstructPort(opt_flags,context);
                        if(!port_name){
                            result=5;
                        } else if(uc_mem_write(engine,name_addr,&port_name,sizeof(port_name))!=UC_ERR_OK){
                            result=14;
                        } else {
                            result=0;
                        }
                    }
                }
                std::uint64_t actual=0,after_flags=0;
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK
                    ||uc_reg_read(engine,UC_ARM64_REG_X0,&actual)!=UC_ERR_OK
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&after_flags)!=UC_ERR_OK
                    ||actual!=result||after_flags!=flags){trace.reason="mach_construct_return_failure";uc_emu_stop(engine);return;}
                for(unsigned i=1;i<args.size();++i){std::uint64_t preserved=0;
                    if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&preserved)!=UC_ERR_OK||preserved!=args[i]){
                        trace.reason="mach_construct_return_failure";uc_emu_stop(engine);return;}}
                ++trace.port_construct_calls;
                return;
            }
            if(handler==Handler::MachMsg2){
                std::array<std::uint64_t,8> args{};
                for(unsigned i=0;i<8;++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&args[i])!=UC_ERR_OK){trace.reason="mach_msg2_register_failure";uc_emu_stop(engine);return;}
                const auto data=args[0];
                const auto options=args[1];
                const auto msgh_bits=static_cast<std::uint32_t>(args[2]&0xFFFFFFFF);
                const auto send_size=static_cast<std::uint32_t>(args[2]>>32);
                const auto remote_port=static_cast<std::uint32_t>(args[3]&0xFFFFFFFF);
                const auto local_port=static_cast<std::uint32_t>(args[3]>>32);
                const auto voucher_port=static_cast<std::uint32_t>(args[4]&0xFFFFFFFF);
                const auto msgh_id=static_cast<std::int32_t>(args[4]>>32);
                const auto desc_count=static_cast<std::uint32_t>(args[5]&0xFFFFFFFF);
                const auto rcv_name=static_cast<std::uint32_t>(args[5]>>32);
                const auto rcv_size=static_cast<std::uint32_t>(args[6]);
                const auto timeout=args[7];

                if(trace.mach_msg2_calls.size()<16){
                    MachMsg2Call call;
                    call.pc=trace.last_pc;call.data=data;call.options=options;call.send_size=send_size;
                    call.ports=args[3];call.id=msgh_id;call.rcv=rcv_name;call.rcv_size=rcv_size;call.timeout=timeout;
                    if((options&1)&&data&&GuestAccessPermitted(engine,data,128,UC_PROT_READ)){
                        call.bytes.resize(128,0);
                        uc_mem_read(engine,data,call.bytes.data(),128);
                    }
                    trace.mach_msg2_calls.push_back(std::move(call));
                }
                ++trace.mach_msg2_call_count;

                if(!(options&1)){ // No MACH_SEND_MSG: packed send header/id is irrelevant.
                    MachReceiveCall call{trace.last_pc,options,timeout,rcv_name,rcv_size,static_cast<std::uint32_t>(timeout)};
                    ++trace.mach_receive_calls;
                    const auto record=[&]{if(trace.mach_receive_prefix.size()<16)trace.mach_receive_prefix.push_back(call);};
                    const auto stop=[&](const char* outcome,const char* reason){
                        call.outcome=outcome;record();trace.reason=reason;uc_emu_stop(engine);
                    };
                    // XNU ipc_current_msg_options masks kernel-only flags.
                    // Receive-only calls do not require exactly one CFI class.
                    // Vector/sync/strict-reply entail additional ABI/turnstile
                    // contracts and cannot silently behave as scalar polling.
                    if(!(options&2)||(options&(0x100000000ULL|0x4000|0x8000|0x200))){
                        stop("unsupported_options","unsupported_mach_receive_options");return;
                    }
                    const auto* port=trace.task.Resolve(rcv_name);
                    if(!port||(port->type&0x100000)){
                        call.outcome="invalid_name";call.result=0x10004002;
                        ++trace.mach_receive_invalid_names;
                    }else if(!(port->type&0x20000)){
                        // XNU raises a port guard exception for a live object
                        // without a receive right. Do not pretend to deliver it.
                        stop("unsupported_guard","unsupported_mach_receive_guard");return;
                    }else if(port->object==MachTask::Object::SpecialReply){
                        stop("unsupported_special_reply","unsupported_mach_receive_special_reply");return;
                    }else if(!port->messages.empty()){
                        stop("unsupported_queue","unsupported_mach_receive_queue");return;
                    }else if(!(options&0x100)||call.normalized_timeout){
                        ++trace.mach_receive_unsupported_waits;
                        stop("unsupported_wait","unsupported_mach_receive_wait");return;
                    }else{
                        // ipc_mqueue_receive returns TIMED_OUT on an empty
                        // queue before inspecting receive memory or copying any
                        // header/trailer. timeout is a uint32 Darwin millisecond
                        // value; high priority bits in the trap argument are not
                        // part of it. Preserve X1/NZCV as the Mach ABI requires.
                        call.outcome="empty_timeout";call.result=0x10004003;
                        ++trace.mach_receive_empty_timeouts;
                    }
                    const std::uint64_t value=*call.result;record();
                    if(uc_reg_write(engine,UC_ARM64_REG_X0,&value)!=UC_ERR_OK){
                        trace.reason="mach_receive_return_failure";uc_emu_stop(engine);
                    }
                    return;
                }

                std::uint64_t result=0; // MACH_MSG_SUCCESS

                if(msgh_id==4811){ // mach_vm_map
                    if(options!=0x200000003ULL||rcv_size<44){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    if(trace.task.ResolveSend(remote_port)!=&trace.task){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size!=100||desc_count!=1||msgh_bits!=0x80001513
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,100,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,44,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
                        std::array<std::uint8_t,100> request{};
                        if(uc_mem_read(engine,data,request.data(),request.size())!=UC_ERR_OK){
                            trace.reason="mach_msg2_request_read_failure";uc_emu_stop(engine);return;
                        }
                        const auto field=[&]<class T>(std::size_t offset){T value;std::memcpy(&value,request.data()+offset,sizeof(value));return value;};
                        if(field.operator()<std::uint32_t>(0)!=msgh_bits||field.operator()<std::uint32_t>(4)!=send_size
                            ||field.operator()<std::uint32_t>(8)!=remote_port||field.operator()<std::uint32_t>(12)!=local_port
                            ||field.operator()<std::uint32_t>(16)!=voucher_port||field.operator()<std::int32_t>(20)!=msgh_id
                            ||field.operator()<std::uint32_t>(24)!=desc_count||request[38]!=19||request[39]!=0){
                            trace.reason="unsupported_mach_vm_request_layout";uc_emu_stop(engine);return;
                        }
                        if(field.operator()<std::uint32_t>(28)!=0||field.operator()<std::uint64_t>(76)!=0
                            ||field.operator()<std::uint32_t>(84)>1||field.operator()<std::uint32_t>(96)>2
                            ||field.operator()<std::uint32_t>(40)!=0||field.operator()<std::uint32_t>(44)!=1){
                            // An unimplemented memory object must never become anonymous memory.
                            trace.reason="unsupported_mach_vm_memory_object";uc_emu_stop(engine);return;
                        }
                        std::uint64_t req_address=0,req_size=0,req_mask=0;
                        std::uint32_t req_flags=0,req_cur_prot=0,req_max_prot=0;
                        uc_mem_read(engine,data+0x30,&req_address,sizeof(req_address));
                        uc_mem_read(engine,data+0x38,&req_size,sizeof(req_size));
                        uc_mem_read(engine,data+0x40,&req_mask,sizeof(req_mask));
                        uc_mem_read(engine,data+0x48,&req_flags,sizeof(req_flags));
                        uc_mem_read(engine,data+0x58,&req_cur_prot,sizeof(req_cur_prot));
                        uc_mem_read(engine,data+0x5c,&req_max_prot,sizeof(req_max_prot));

                        const auto page_size=trace.stack.PageSize();
                        const auto page_mask=page_size-1;
                        if((req_flags&~0xff000001U)!=0||(req_cur_prot&~7U)!=0||(req_max_prot&~7U)!=0
                            ||(req_cur_prot&~req_max_prot)!=0||!req_size||req_size>UINT64_MAX-page_mask
                            ||req_mask>=0x00007fffffffffffULL){
                            trace.reason="unsupported_mach_vm_map_parameters";uc_emu_stop(engine);return;
                        }
                        const auto align_mask=(req_mask>page_mask)?req_mask:page_mask;
                        const auto alloc_size=(req_size+page_mask)&~page_mask;
                        const bool anywhere=(req_flags&1)!=0;

                        std::uint64_t candidate=0;
                        bool found=false;
                        if(anywhere){
                            const auto search_start=req_address?req_address:trace.next_vm_address;
                            found=FindUnmappedGuestRange(engine,search_start,alloc_size,align_mask,candidate);
                            if(!found&&req_address){
                                found=FindUnmappedGuestRange(engine,trace.next_vm_address,alloc_size,align_mask,candidate);
                            }
                        }else{
                            if((req_address&align_mask)==0&&GuestRangeUnmapped(engine,req_address,alloc_size)){
                                candidate=req_address;
                                found=true;
                            }
                        }

                        std::int32_t ret_code=0;
                        std::uint64_t mapped_addr=0;
                        if(!found){
                            ret_code=3; // KERN_NO_SPACE
                        }else{
                            auto host_mem=trace.ReserveVmAllocation()?DarwinVmBacking::Allocate(alloc_size):nullptr;
                            if(!host_mem){
                                ret_code=3; // KERN_NO_SPACE
                            }else{
                                // NONE reserves address space without granting guest access.
                                const auto prot=static_cast<std::uint32_t>(req_cur_prot&7);
                                if(uc_mem_map_ptr(engine,candidate,alloc_size,prot,host_mem->Bytes())!=UC_ERR_OK){
                                    host_mem.reset();
                                    ret_code=14; // KERN_NO_ACCESS
                                }else{
                                    trace.vm_allocations.push_back({candidate,alloc_size,host_mem,nullptr,req_cur_prot,req_max_prot,req_flags>>24,field.operator()<std::uint32_t>(96)});
                                    trace.next_vm_address=std::max(trace.next_vm_address,candidate+alloc_size);
                                    mapped_addr=candidate;
                                    ret_code=0; // KERN_SUCCESS
                                }
                            }
                        }

                        ++trace.vm_mig_calls;if(trace.vm_mig_prefix.size()<16)trace.vm_mig_prefix.push_back({trace.last_pc,req_size,mapped_addr,req_flags,req_cur_prot,req_max_prot,req_flags>>24,static_cast<std::uint32_t>(ret_code)});

#pragma pack(push,4)
                        struct ReplyMachVmMap {
                            std::uint32_t msgh_bits=0x12;
                            std::uint32_t msgh_size=0x2c;
                            std::uint32_t msgh_remote_port=0;
                            std::uint32_t msgh_local_port=0;
                            std::uint32_t msgh_voucher_port=0;
                            std::int32_t msgh_id=4911;
                            std::uint32_t ndr[2]={0,1};
                            std::int32_t ret_code=0;
                            std::uint64_t address=0;
                        };
                        struct ReplyMachError {
                            std::uint32_t msgh_bits=0;
                            std::uint32_t msgh_size=0x24;
                            std::uint32_t msgh_remote_port=0;
                            std::uint32_t msgh_local_port=0;
                            std::uint32_t msgh_voucher_port=0;
                            std::int32_t msgh_id=4911;
                            std::uint32_t ndr[2]={0,1};
                            std::int32_t ret_code=0;
                        };
#pragma pack(pop)

                        if(ret_code==0){
                            ReplyMachVmMap reply;
                            reply.address=mapped_addr;
                            if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                                trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                            }
                        }else{
                            ReplyMachError reply;
                            reply.ret_code=ret_code;
                            if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                                trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                            }
                        }
                    }
                }else if(msgh_id==200){ // host_info
                    if(options!=0x200000003ULL||rcv_size<72){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* host_entry=trace.task.Resolve(remote_port);
                    if(!host_entry||host_entry->object!=MachTask::Object::Host||!(host_entry->type&0x10000)){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size!=40||msgh_bits!=0x1513
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,40,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,72,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
                        std::int32_t flavor=0,count=0;
                        uc_mem_read(engine,data+32,&flavor,sizeof(flavor));
                        uc_mem_read(engine,data+36,&count,sizeof(count));
                        if(flavor==5){ // HOST_PRIORITY_INFO
                            if(count<8){
#pragma pack(push,4)
                                struct ReplyError {
                                    std::uint32_t msgh_bits=0;
                                    std::uint32_t msgh_size=0x24;
                                    std::uint32_t msgh_remote_port=0;
                                    std::uint32_t msgh_local_port=0;
                                    std::uint32_t msgh_voucher_port=0;
                                    std::int32_t msgh_id=300;
                                    std::uint32_t ndr[2]={0,1};
                                    std::int32_t ret_code=5; // KERN_FAILURE
                                };
#pragma pack(pop)
                                ReplyError reply;
                                uc_mem_write(engine,data,&reply,sizeof(reply));
                            }else{
#pragma pack(push,4)
                                struct ReplyHostPriority {
                                    std::uint32_t msgh_bits=0x12;
                                    std::uint32_t msgh_size=sizeof(ReplyHostPriority);
                                    std::uint32_t msgh_remote_port=0;
                                    std::uint32_t msgh_local_port=0;
                                    std::uint32_t msgh_voucher_port=0;
                                    std::int32_t msgh_id=300;
                                    std::uint32_t ndr[2]={0,1};
                                    std::int32_t ret_code=0;
                                    std::uint32_t out_count=8;
                                    std::int32_t kernel_priority=80;
                                    std::int32_t system_priority=80;
                                    std::int32_t server_priority=64;
                                    std::int32_t user_priority=31;
                                    std::int32_t depress_priority=0;
                                    std::int32_t idle_priority=0;
                                    std::int32_t minimum_priority=0;
                                    std::int32_t maximum_priority=79;
                                };
#pragma pack(pop)
                                ReplyHostPriority reply;
                                if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                                    trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                                }
                            }
                        }else{
                            trace.reason="unsupported_host_info_flavor";uc_emu_stop(engine);return;
                        }
                    }
                }else if(msgh_id==206){ // host_get_clock_service
                    if(options!=0x200000003ULL||rcv_size<40){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* host_entry=trace.task.Resolve(remote_port);
                    if(!host_entry||host_entry->object!=MachTask::Object::Host||!(host_entry->type&0x10000)){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size!=36||msgh_bits!=0x1513
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,36,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,40,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
                        std::int32_t clock_id=0;
                        uc_mem_read(engine,data+32,&clock_id,sizeof(clock_id));
                        if(clock_id<0||clock_id>1){
#pragma pack(push,4)
                            struct ReplyError {
                                std::uint32_t msgh_bits=0;
                                std::uint32_t msgh_size=0x24;
                                std::uint32_t msgh_remote_port=0;
                                std::uint32_t msgh_local_port=0;
                                std::uint32_t msgh_voucher_port=0;
                                std::int32_t msgh_id=306;
                                std::uint32_t ndr[2]={0,1};
                                std::int32_t ret_code=5; // KERN_FAILURE
                            };
#pragma pack(pop)
                            ReplyError reply;
                            uc_mem_write(engine,data,&reply,sizeof(reply));
                        }else{
#pragma pack(push,4)
                            struct ReplyHostGetClockService {
                                std::uint32_t msgh_bits=0x80000012;
                                std::uint32_t msgh_size=sizeof(ReplyHostGetClockService);
                                std::uint32_t msgh_remote_port=0;
                                std::uint32_t msgh_local_port=0;
                                std::uint32_t msgh_voucher_port=0;
                                std::int32_t msgh_id=306;
                                std::uint32_t msgh_descriptor_count=1;
                                std::uint32_t clock_name=0;
                                std::uint32_t pad1=0;
                                std::uint16_t pad2=0;
                                std::uint8_t disposition=17; // MACH_MSG_TYPE_PORT_SEND
                                std::uint8_t type=0; // MACH_MSG_PORT_DESCRIPTOR
                            };
#pragma pack(pop)
                            static_assert(sizeof(ReplyHostGetClockService)==40);
                            const auto clock_port=trace.task.Allocate(MachTask::Object::Clock,0x10000,1);
                            ReplyHostGetClockService reply;
                            reply.clock_name=clock_port;
                            if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                                trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                            }
                        }
                    }
                }else if(msgh_id==3418){ // semaphore_create
                    if(options!=0x200000003ULL||rcv_size<40){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* task_entry=trace.task.Resolve(remote_port);
                    if(!task_entry||task_entry->object!=MachTask::Object::Task||!(task_entry->type&0x10000)){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size!=40||msgh_bits!=0x1513
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,40,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,40,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
                        std::int32_t policy=0,value=0;
                        uc_mem_read(engine,data+32,&policy,sizeof(policy));
                        uc_mem_read(engine,data+36,&value,sizeof(value));
                        if(policy<0||policy>1||value<0){
#pragma pack(push,4)
                            struct ReplyError {
                                std::uint32_t msgh_bits=0;
                                std::uint32_t msgh_size=0x24;
                                std::uint32_t msgh_remote_port=0;
                                std::uint32_t msgh_local_port=0;
                                std::uint32_t msgh_voucher_port=0;
                                std::int32_t msgh_id=3518;
                                std::uint32_t ndr[2]={0,1};
                                std::int32_t ret_code=5; // KERN_FAILURE
                            };
#pragma pack(pop)
                            ReplyError reply;
                            uc_mem_write(engine,data,&reply,sizeof(reply));
                        }else{
#pragma pack(push,4)
                            struct ReplySemaphoreCreate {
                                std::uint32_t msgh_bits=0x80000012;
                                std::uint32_t msgh_size=sizeof(ReplySemaphoreCreate);
                                std::uint32_t msgh_remote_port=0;
                                std::uint32_t msgh_local_port=0;
                                std::uint32_t msgh_voucher_port=0;
                                std::int32_t msgh_id=3518;
                                std::uint32_t msgh_descriptor_count=1;
                                std::uint32_t semaphore_name=0;
                                std::uint32_t pad1=0;
                                std::uint16_t pad2=0;
                                std::uint8_t disposition=17; // MACH_MSG_TYPE_PORT_SEND
                                std::uint8_t type=0; // MACH_MSG_PORT_DESCRIPTOR
                            };
#pragma pack(pop)
                            static_assert(sizeof(ReplySemaphoreCreate)==40);
                            const auto sem_port=trace.task.Allocate(MachTask::Object::Semaphore,0x10000,1);
                            ReplySemaphoreCreate reply;
                            reply.semaphore_name=sem_port;
                            if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                                trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                            }
                        }
                    }
                }else if(msgh_id==4822){ // mach_vm_deferred_reclamation_buffer_init
                    if(options!=0x200000003ULL||rcv_size<36){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* task_entry=trace.task.Resolve(remote_port);
                    if(!task_entry||task_entry->object!=MachTask::Object::Task||!(task_entry->type&0x10000)){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size!=40||msgh_bits!=0x1513
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,40,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,36,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
#pragma pack(push,4)
                        struct ReplyError {
                            std::uint32_t msgh_bits=0;
                            std::uint32_t msgh_size=sizeof(ReplyError);
                            std::uint32_t msgh_remote_port=0;
                            std::uint32_t msgh_local_port=0;
                            std::uint32_t msgh_voucher_port=0;
                            std::int32_t msgh_id=4922;
                            std::uint32_t ndr[2]={0,1};
                            std::int32_t ret_code=46; // KERN_NOT_SUPPORTED
                        };
#pragma pack(pop)
                        static_assert(sizeof(ReplyError)==36);
                        ReplyError reply;
                        if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                            trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                        }
                    }
                }else if(msgh_id==3412||msgh_id==3600||msgh_id==3605||msgh_id==3606){
                    const bool create=msgh_id==3412;
                    const auto request_size=create?312U:24U;
                    const auto reply_size=create?48U:44U;
                    if(options!=0x200000003ULL||timeout||rcv_size<reply_size){
                        trace.reason="unsupported_mach_thread_message_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* target_thread=create?nullptr:trace.task.ResolveThread(remote_port);
                    if(create?trace.task.ResolveSend(remote_port)!=&trace.task:!target_thread){
                        result=0x10000003;
                    }else if(send_size!=request_size||msgh_bits!=0x1513||desc_count||voucher_port
                        ||rcv_name!=local_port||!reply_port||!(reply_port->type&0x20000)){
                        result=0x10000010;
                    }else if(!data||!GuestAccessPermitted(engine,data,request_size,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,reply_size,UC_PROT_WRITE)){
                        result=0x10000002;
                    }else{
                        std::array<std::uint32_t,78> request{};
                        if(uc_mem_read(engine,data,request.data(),request_size)!=UC_ERR_OK){
                            trace.reason="mach_thread_request_read_failure";uc_emu_stop(engine);return;
                        }
                        if(request[0]!=msgh_bits||request[1]!=send_size||request[2]!=remote_port
                            ||request[3]!=local_port||request[4]||request[5]!=static_cast<std::uint32_t>(msgh_id)
                            ||(create&&(request[6]!=0||request[7]!=1))){
                            result=0x10000010;
                        }else{
                            std::uint32_t ret_code=0;
                            if(create){
                                if(request[8]!=6||request[9]!=68)ret_code=4;
                                else{
                                    // Original user representation must be authenticated outside
                                    // uc_emu_start before any context/port becomes runnable.
                                    std::copy_n(request.begin()+10,68,trace.mach_thread_create.user_state.begin());
                                    trace.mach_thread_create.reply_address=data;
                                    trace.mach_thread_create.reply_name=rcv_name;
                                    trace.mach_thread_create.receive_size=rcv_size;
                                    trace.mach_thread_create.pending=true;
                                    trace.thread_lifecycle_reschedule=true;
                                    uc_emu_stop(engine);return;
                                }
                            }else if(msgh_id==3600&&target_thread==selected_thread){
                                // The target caller never returns to the instruction after SVC.
                                ret_code=trace.task.TerminateOwnedThread(engine,remote_port);
                                if(!ret_code){trace.thread_lifecycle_reschedule=true;uc_emu_stop(engine);return;}
                            }else if(msgh_id==3600)ret_code=trace.task.TerminateOwnedThread(engine,remote_port);
                            else if(msgh_id==3606)ret_code=trace.task.ResumeOwnedThread(remote_port);
                            const std::array<std::uint32_t,11> reply{0x1200,36,0,rcv_name,0,
                                static_cast<std::uint32_t>(msgh_id+100),0,1,ret_code,0,8};
                            if(uc_mem_write(engine,data,reply.data(),sizeof(reply))!=UC_ERR_OK){
                                trace.reason="mach_thread_reply_write_failure";uc_emu_stop(engine);return;
                            }
                            if(msgh_id==3605){
                                // Produce the trap return BEFORE capturing a suspended caller.
                                // The task-owned reply is written before a running target stops.
                                const std::uint64_t success=0;
                                if(uc_reg_write(engine,UC_ARM64_REG_X0,&success)!=UC_ERR_OK){
                                    trace.reason="mach_thread_return_write_failure";uc_emu_stop(engine);return;
                                }
                                ret_code=trace.task.SuspendOwnedThread(engine,remote_port);
                                if(ret_code&&uc_mem_write(engine,data+32,&ret_code,sizeof(ret_code))!=UC_ERR_OK){
                                    trace.reason="mach_thread_reply_write_failure";uc_emu_stop(engine);return;
                                }
                                if(!ret_code&&target_thread==selected_thread){
                                    trace.thread_lifecycle_reschedule=true;uc_emu_stop(engine);return;
                                }
                            }
                        }
                    }
                }else if(msgh_id==3409||msgh_id==3410){ // task_get/set_special_port
                    const bool get=msgh_id==3409;
                    if(options!=0x200000003ULL||timeout||rcv_size<44){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const std::uint32_t expected_size=get?36:52;
                    const std::uint32_t expected_bits=get?0x1513:0x80001513;
                    if(trace.task.ResolveSend(remote_port)!=&trace.task){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size!=expected_size||msgh_bits!=expected_bits||desc_count!=(get?0U:1U)
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,send_size,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,44,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
                        std::array<std::uint8_t,52> request{};
                        if(uc_mem_read(engine,data,request.data(),send_size)!=UC_ERR_OK){
                            trace.reason="mach_msg2_request_read_failure";uc_emu_stop(engine);return;
                        }
                        const auto field=[&]<class T>(std::size_t offset){T value;std::memcpy(&value,request.data()+offset,sizeof(value));return value;};
                        if(field.operator()<std::uint32_t>(0)!=msgh_bits||field.operator()<std::uint32_t>(4)!=send_size
                            ||field.operator()<std::uint32_t>(8)!=remote_port||field.operator()<std::uint32_t>(12)!=local_port
                            ||field.operator()<std::uint32_t>(16)||field.operator()<std::int32_t>(20)!=msgh_id
                            ||field.operator()<std::uint32_t>(get?24:40)!=0||field.operator()<std::uint32_t>(get?28:44)!=1
                            ||(!get&&(field.operator()<std::uint32_t>(24)!=1||request[38]!=19||request[39]!=0))){
                            result=0x10000010; // Reject unsupported NDR/header/descriptor ABI before effects.
                        }else{
                            const auto which=field.operator()<std::int32_t>(get?32:48);
                            std::uint32_t ret_code=0,returned_port=0;
                            const auto supplied_port=get?0:field.operator()<std::uint32_t>(28);
                            if(get&&(which==3||which==5||which==6||which==11)){
                                trace.reason="unsupported_task_special_port_flavor";uc_emu_stop(engine);return;
                            }
                            if(!get&&which==11){
                                trace.reason="unsupported_task_resource_notify_port";uc_emu_stop(engine);return;
                            }
                            if(get){
                                if(which!=1&&which!=2&&which!=4&&which!=9&&which!=10)ret_code=4;
                                else {
                                    if(rcv_size<48){trace.reason="mach_msg2_reply_buffer_too_small";uc_emu_stop(engine);return;}
                                    if(!GuestAccessPermitted(engine,data,48,UC_PROT_WRITE)){
                                        result=0x10000002;
                                    }else {returned_port=trace.task.GetSpecialPort(which);if((which==1||which==2)&&!returned_port)ret_code=3;}
                                }
                            }else{
                                if(supplied_port){
                                    const auto* supplied=trace.task.Resolve(supplied_port);
                                    if(!supplied||!(supplied->type&0x10000)||!supplied->send_refs)result=0x1000000a;
                                }
                                if(!result){
                                    if(which==1||which==2)ret_code=8; // Current CSR denies kernel/host overwrite.
                                    else if(which!=4&&which!=9&&which!=10)ret_code=4;
                                    else if(supplied_port){
                                        // COPY_SEND needs independently retained kernel storage.
                                        trace.reason="unsupported_task_special_port_send_retention";uc_emu_stop(engine);return;
                                    }
                                }
                            }
                            if(!result){
                                std::array<std::uint32_t,12> reply{};
                                if(get&&!ret_code){
                                    reply={0x80001200,40,0,rcv_name,0,static_cast<std::uint32_t>(msgh_id+100),1,returned_port,0,0x00110000,0,8};
                                }else{
                                    reply={0x1200,36,0,rcv_name,0,static_cast<std::uint32_t>(msgh_id+100),0,1,ret_code,0,8,0};
                                }
                                if(uc_mem_write(engine,data,reply.data(),get&&!ret_code?48:44)!=UC_ERR_OK){
                                    trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                                }
                            }
                        }
                    }
                }else if(msgh_id==3405){ // task_info
                    if(options!=0x200000003ULL||rcv_name!=local_port){
                        trace.reason="unsupported_task_info_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* task_entry=trace.task.Resolve(remote_port);
                    if(!(msgh_bits&0x80000000u)&&desc_count){
                        // mach_msg2 validates the simple-message descriptor
                        // count before copying in the destination rights.
                        result=0x1000000e; // MACH_SEND_TOO_LARGE
                    }else if(send_size!=40){
                        trace.reason="unsupported_task_info_request_layout";uc_emu_stop(engine);return;
                    }else if(!data||!GuestAccessPermitted(engine,data,40,UC_PROT_READ)){
                        // Message copyin precedes destination-right conversion.
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else if(!task_entry||!(task_entry->type&0x10000)||!task_entry->send_refs){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000009; // MACH_SEND_INVALID_REPLY (MAKE_SEND_ONCE)
                    }else if(msgh_bits!=0x1513||voucher_port||desc_count){
                        trace.reason="unsupported_task_info_request_layout";uc_emu_stop(engine);return;
                    }else{
                        std::array<std::uint32_t,4> payload{};
                        if(uc_mem_read(engine,data+24,payload.data(),sizeof(payload))!=UC_ERR_OK){
                            trace.reason="task_info_request_read_failure";uc_emu_stop(engine);return;
                        }
                        // mach_msg2 reconstructs its header from packed trap
                        // arguments; the first24 bytes in user memory are not
                        // authoritative. The NDR and routine payload are.
                        if(payload[0]||payload[1]!=1){
                            trace.reason="unsupported_task_info_request_layout";uc_emu_stop(engine);return;
                        }
                        const auto flavor=payload[2],input_count=payload[3];
                        const auto in_count=std::min<std::uint32_t>(input_count,94);
                        TaskInfoCall call;call.pc=trace.last_pc;call.target=remote_port;call.flavor=flavor;
                        call.input_count=input_count;call.normalized_count=in_count;
                        ++trace.task_info_calls;
                        const auto record=[&]{if(trace.task_info_prefix_size<trace.task_info_prefix.size())
                            trace.task_info_prefix[trace.task_info_prefix_size++]=call;};
                        if(task_entry->object==MachTask::Object::Reply||task_entry->object==MachTask::Object::SpecialReply){
                            // Ordinary user queues are not kernel kobjects.
                            // They need a real user server, not a made-up MIG reply.
                            record();trace.reason="unsupported_task_info_user_destination";uc_emu_stop(engine);return;
                        }
                        std::array<std::uint32_t,8> info_words{};
                        std::uint32_t out_count=0,ret_code=0;
                        if(task_entry->object!=MachTask::Object::Task){
                            ret_code=4; // kernel kobject cannot convert to task
                        }else if(flavor==13){
                            if(in_count<2)ret_code=4;
                            else{const auto token=BuildDarwinSecurityToken(trace.task.credentials);
                                std::copy(token.begin(),token.end(),info_words.begin());out_count=2;}
                        }else if(flavor==15){
                            if(in_count<8)ret_code=4;
                            else{info_words=BuildDarwinAuditToken(trace.task.credentials,trace.task.pid,
                                trace.task.pid_version,trace.task.audit_session);out_count=8;}
                        }else if(flavor==17){
                            if(in_count<4)ret_code=4;
                            else{
                            const auto dyld_addr=trace.all_image_info_addr,dyld_sz=trace.all_image_info_size;
                            info_words={static_cast<std::uint32_t>(dyld_addr),static_cast<std::uint32_t>(dyld_addr>>32),
                                static_cast<std::uint32_t>(dyld_sz),static_cast<std::uint32_t>(dyld_sz>>32),1,0,0,0};
                            out_count=in_count>=5?5:4;
                            }
                        }else{
                            record();
                            trace.reason="unsupported_task_info_flavor";trace.interrupt=number;
                            trace.syscall_selector=raw_selector;uc_emu_stop(engine);return;
                        }
                        call.result_ready=true;call.kern_return=ret_code;call.output_count=out_count;
                        const std::uint32_t reply_size=ret_code?36:40+out_count*4;
                        call.reply_size=reply_size;
                        // Normal scalar receive accounts for its minimal
                        // trailer, outside msgh_size. Full TOO_LARGE discard /
                        // minimal-header copyout remains an explicit boundary.
                        if(reply_size+8>rcv_size){
                            record();
                            trace.reason="mach_msg2_reply_buffer_too_small";uc_emu_stop(engine);return;
                        }
                        std::array<std::uint32_t,20> reply{};
                        reply[0]=0x1200;reply[1]=reply_size;reply[3]=rcv_name;reply[5]=3505;
                        reply[7]=1;reply[8]=ret_code;
                        if(!ret_code){reply[9]=out_count;std::copy_n(info_words.begin(),out_count,reply.begin()+10);}
                        reply[reply_size/4+1]=8;
                        if(!GuestAccessPermitted(engine,data,reply_size+8,UC_PROT_WRITE)
                            ||uc_mem_write(engine,data,reply.data(),reply_size+8)!=UC_ERR_OK){
                            record();
                            trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                        }
                        call.copied=true;call.copyout_bytes=reply_size+8;record();
                    }
                }else if(msgh_id==8000||msgh_id==8001){ // task_restartable subsystem
                    if(options!=0x200000003ULL||rcv_size<44||timeout){
                        trace.reason="unsupported_restartable_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* target=trace.task.Resolve(remote_port);
                    if(!target||target->object!=MachTask::Object::Task||!(target->type&0x10000))result=0x10000003;
                    else if(msgh_bits!=0x1513||voucher_port||desc_count||rcv_name!=local_port
                        ||!reply_port||(reply_port->type&0x20000)==0||send_size<(msgh_id==8000?36U:24U))result=0x10000010;
                    else if(!data||!GuestAccessPermitted(engine,data,send_size,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,44,UC_PROT_WRITE))result=0x10000002;
                    else{
                        std::array<std::uint32_t,9> header{};
                        if(uc_mem_read(engine,data,header.data(),msgh_id==8000?36:24)!=UC_ERR_OK){
                            trace.reason="restartable_request_read_failure";uc_emu_stop(engine);return;
                        }
                        if(header[0]!=msgh_bits||header[1]!=send_size||header[2]!=remote_port
                            ||header[3]!=local_port||header[4]||header[5]!=static_cast<std::uint32_t>(msgh_id)
                            ||(msgh_id==8000&&(header[6]!=0||header[7]!=1))){
                            trace.reason="unsupported_restartable_request_layout";uc_emu_stop(engine);return;
                        }
                        if(!trace.task.owner||trace.task.owner->engine.value!=engine||selected_thread->task!=&trace.task||!selected_thread->id){
                            trace.reason="restartable_thread_binding_failure";uc_emu_stop(engine);return;
                        }
                        std::uint32_t ret_code=0;
                        if(msgh_id==8000){
                            const auto count=header[8];
                            if(count>64||send_size!=36+count*16){
                                trace.reason="unsupported_restartable_array_layout";uc_emu_stop(engine);return;
                            }
                            std::array<MachTask::RestartableRange,64> ranges{};
                            if(count&&uc_mem_read(engine,data+36,ranges.data(),count*16)!=UC_ERR_OK){
                                trace.reason="restartable_request_read_failure";uc_emu_stop(engine);return;
                            }
                            ++trace.task.restartable_register_calls;
                            ret_code=trace.task.LiveThreadCount()>1?46:trace.task.RegisterRestartable(ranges,count);
                        }else{
                            if(send_size!=24){trace.reason="unsupported_restartable_array_layout";uc_emu_stop(engine);return;}
                            if(trace.task.LiveThreadCount()>1&&trace.task.restartable_count){
                                trace.reason="unsupported_restartable_peer_synchronization";uc_emu_stop(engine);return;
                            }
                            // No other guest thread exists to suspend or acknowledge.
                            // Preserve caller PC, as XNU does; fence before completing.
                            std::atomic_thread_fence(std::memory_order_release);
                            ++trace.task.restartable_sync_calls;
                        }
                        std::array<std::uint32_t,11> reply{0x1200,36,0,rcv_name,0,static_cast<std::uint32_t>(msgh_id+100),0,1,ret_code,0,8};
                        if(uc_mem_write(engine,data,reply.data(),sizeof(reply))!=UC_ERR_OK){
                            trace.reason="restartable_reply_write_failure";uc_emu_stop(engine);return;
                        }
                    }
                }else if(msgh_id==400){ // bootstrap_look_up
                    if(options!=0x200000003ULL||rcv_size<36){
                        trace.reason="unsupported_mach_msg2_options";uc_emu_stop(engine);return;
                    }
                    const auto* reply_port=trace.task.Resolve(rcv_name);
                    const auto* task_entry=trace.task.Resolve(remote_port);
                    if(!task_entry||!(task_entry->type&0x10000)){
                        result=0x10000003; // MACH_SEND_INVALID_DEST
                    }else if(send_size<32||msgh_bits!=0x1513
                        ||voucher_port||rcv_name!=local_port||!reply_port||(reply_port->type&0x20000)==0){
                        result=0x10000010; // MACH_SEND_INVALID_HEADER
                    }else if(!data||!GuestAccessPermitted(engine,data,send_size,UC_PROT_READ)
                        ||!GuestAccessPermitted(engine,data,36,UC_PROT_WRITE)){
                        result=0x10000002; // MACH_SEND_INVALID_DATA
                    }else{
#pragma pack(push,4)
                        struct ReplyBootstrapLookUpError {
                            std::uint32_t msgh_bits=0;
                            std::uint32_t msgh_size=sizeof(ReplyBootstrapLookUpError);
                            std::uint32_t msgh_remote_port=0;
                            std::uint32_t msgh_local_port=0;
                            std::uint32_t msgh_voucher_port=0;
                            std::int32_t msgh_id=500;
                            std::uint32_t ndr[2]={0,1};
                            std::int32_t ret_code=1100; // BOOTSTRAP_UNKNOWN_SERVICE
                        };
#pragma pack(pop)
                        static_assert(sizeof(ReplyBootstrapLookUpError)==36);
                        ReplyBootstrapLookUpError reply;
                        if(uc_mem_write(engine,data,&reply,sizeof(reply))!=UC_ERR_OK){
                            trace.reason="mach_msg2_reply_write_failure";uc_emu_stop(engine);return;
                        }
                    }
                }else{
                    trace.reason="unsupported_mach_msg2_id";
                    uc_emu_stop(engine);
                    return;
                }

                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK){
                    trace.reason="mach_msg2_return_failure";uc_emu_stop(engine);return;
                }
                return;
            }
            if(handler==Handler::VmProtect){
                std::array<std::uint64_t,5> args{};std::uint64_t flags=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&args[i])!=UC_ERR_OK){trace.reason="vm_protect_register_failure";uc_emu_stop(engine);return;}
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="vm_protect_register_failure";uc_emu_stop(engine);return;}
                const auto target=static_cast<std::uint32_t>(args[0]);
                std::uint64_t result=0;
                if(!trace.task.ResolveSend(target)||trace.task.ResolveSend(target)!=&trace.task){
                    result=4;
                } else if(!args[2]||args[2]>UINT64_MAX-(trace.stack.PageSize()-1)||args[1]>UINT64_MAX-args[2]-(trace.stack.PageSize()-1)||(args[4]&~7ULL)!=0){
                    result=4;
                } else {
                    const auto page_size=trace.stack.PageSize();
                    const auto page_mask=page_size-1;
                    const auto start=args[1]&~page_mask;
                    const auto end=(args[1]+args[2]+page_mask)&~page_mask;
                    const auto length=end-start;
                    if(!GuestAccessPermitted(engine,start,length,0)){
                        result=1; // KERN_INVALID_ADDRESS
                    } else {
                        const auto prot=static_cast<std::uint32_t>(args[4]&7);
                        result=trace.ProtectVmRange(engine,start,length,args[3]!=0,prot);
                    }
                }
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK){trace.reason="vm_protect_return_failure";uc_emu_stop(engine);return;}
                std::uint64_t actual=0,after_flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_X0,&actual)!=UC_ERR_OK||actual!=result
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&after_flags)!=UC_ERR_OK||after_flags!=flags){trace.reason="vm_protect_return_failure";uc_emu_stop(engine);return;}
                ++trace.vm_protect_calls;
                if(trace.vm_protect_prefix_size<trace.vm_protect_prefix.size())
                    trace.vm_protect_prefix[trace.vm_protect_prefix_size++]={trace.last_pc,selector,args[0],args[1],args[2],args[3],args[4],result};
                return;
            }
            if(handler==Handler::VmMap||handler==Handler::VmAllocate){
                std::array<std::uint64_t,6> args{};std::uint64_t flags=0;
                const unsigned arg_count=handler==Handler::VmMap?6:4;
                for(unsigned i=0;i<arg_count;++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&args[i])!=UC_ERR_OK){trace.reason="vm_map_register_failure";uc_emu_stop(engine);return;}
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="vm_map_register_failure";uc_emu_stop(engine);return;}
                const auto target=static_cast<std::uint32_t>(args[0]);
                std::uint64_t result=0;
                if(!trace.task.ResolveSend(target)||trace.task.ResolveSend(target)!=&trace.task){
                    result=4;
                } else if(!args[1]||!args[2]||!GuestAccessPermitted(engine,args[1],sizeof(std::uint64_t),UC_PROT_READ|UC_PROT_WRITE)){
                    result=4;
                } else {
                    const auto raw_size=args[2];
                    const auto page_size=trace.stack.PageSize();
                    const auto page_mask=page_size-1;
                    const auto mask=handler==Handler::VmMap?args[3]:0;
                    const auto align_mask=(mask>page_mask)?mask:page_mask;
                    const auto vm_flags=handler==Handler::VmMap?args[4]:args[3];
                    const auto prot_bits=handler==Handler::VmMap?args[5]:3;
                    const auto prot=static_cast<std::uint32_t>(prot_bits&7);
                    const bool overwrite=handler==Handler::VmMap&&(vm_flags&0x4000)!=0;
                    const auto admitted_flags=handler==Handler::VmMap?0xff004001ULL:0xff000001ULL;
                    if((prot_bits&~7ULL)!=0||(vm_flags&~admitted_flags)!=0||raw_size>UINT64_MAX-page_mask){
                        result=4;
                    } else {
                        const auto alloc_size=(raw_size+page_mask)&~page_mask;
                        std::uint64_t hint=0;
                        if(uc_mem_read(engine,args[1],&hint,sizeof(hint))!=UC_ERR_OK){
                            result=14;
                        } else {
                            const bool anywhere=(vm_flags&1)!=0;
                            std::uint64_t candidate=0;
                            bool found=false;
                            if(anywhere){
                                const auto search_start=hint?hint:trace.next_vm_address;
                                found=FindUnmappedGuestRange(engine,search_start,alloc_size,align_mask,candidate);
                                if(!found&&hint){
                                    found=FindUnmappedGuestRange(engine,trace.next_vm_address,alloc_size,align_mask,candidate);
                                }
                            } else {
                                if((hint&align_mask)==0&&hint<=UINT64_MAX-alloc_size&&(overwrite?trace.CanReplaceVmRange(engine,hint,hint+alloc_size):GuestRangeUnmapped(engine,hint,alloc_size))){
                                    candidate=hint;
                                    found=true;
                                }
                            }
                            if(!found){
                                result=3;
                            } else {
                                auto host_mem=trace.ReserveVmAllocation()?DarwinVmBacking::Allocate(alloc_size):nullptr;
                                if(!host_mem){
                                    result=3;
                                } else {
                                    if(overwrite&&!anywhere){
                                        result=trace.UnmapVmRange(engine,candidate,candidate+alloc_size);
                                        if(result||!trace.ReserveVmAllocation()){trace.reason="vm_overwrite_preparation_failure";uc_emu_stop(engine);return;}
                                    }
                                    if(uc_mem_map_ptr(engine,candidate,alloc_size,prot,host_mem->Bytes())!=UC_ERR_OK){
                                        host_mem.reset();
                                        result=14;
                                    } else {
                                        // Unicorn enforces guest permissions. Its backing must
                                        // remain host-writable when guest vm_protect changes them.
                                        if(uc_mem_write(engine,args[1],&candidate,sizeof(candidate))!=UC_ERR_OK){
                                            uc_mem_unmap(engine,candidate,alloc_size);
                                            host_mem.reset();
                                            result=14;
                                        } else {
                                            trace.vm_allocations.push_back({candidate,alloc_size,host_mem,nullptr,prot,7,static_cast<std::uint32_t>(vm_flags>>24)&255});
                                            trace.next_vm_address=std::max(trace.next_vm_address,candidate+alloc_size);
                                            result=0;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK){trace.reason="vm_map_return_failure";uc_emu_stop(engine);return;}
                std::uint64_t actual=0,after_flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_X0,&actual)!=UC_ERR_OK||actual!=result
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&after_flags)!=UC_ERR_OK||after_flags!=flags){trace.reason="vm_map_return_failure";uc_emu_stop(engine);return;}
                ++trace.vm_map_calls;
                trace.vm_map_last={trace.last_pc,selector,args[0],args[1],args[2],handler==Handler::VmMap?args[4]:args[3],handler==Handler::VmMap?args[5]:3,result};
                if(!result&&uc_mem_read(engine,args[1],&trace.vm_map_last.mapped_address,sizeof(std::uint64_t))!=UC_ERR_OK){trace.reason="vm_map_address_readback_failure";uc_emu_stop(engine);return;}
                if(trace.vm_map_prefix_size<trace.vm_map_prefix.size())trace.vm_map_prefix[trace.vm_map_prefix_size++]=trace.vm_map_last;
                return;
            }
            if(handler==Handler::VmDeallocate){
                std::array<std::uint64_t,3> args{};std::uint64_t flags=0;
                for(unsigned i=0;i<args.size();++i)if(uc_reg_read(engine,UC_ARM64_REG_X0+int(i),&args[i])!=UC_ERR_OK){trace.reason="vm_deallocate_register_failure";uc_emu_stop(engine);return;}
                if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&flags)!=UC_ERR_OK){trace.reason="vm_deallocate_register_failure";uc_emu_stop(engine);return;}
                const auto target=static_cast<std::uint32_t>(args[0]);
                std::uint64_t result=0;
                if(!trace.task.ResolveSend(target)||trace.task.ResolveSend(target)!=&trace.task){
                    result=4;
                } else if(!args[2]){
                    result=0;
                } else if(args[2]>UINT64_MAX-(trace.stack.PageSize()-1)||args[1]>UINT64_MAX-args[2]-(trace.stack.PageSize()-1)){
                    result=4;
                } else {
                    const auto page_size=trace.stack.PageSize();
                    const auto page_mask=page_size-1;
                    const auto start=args[1]&~page_mask;
                    const auto end=(args[1]+args[2]+page_mask)&~page_mask;
                    result=trace.UnmapVmRange(engine,start,end);

                }
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK){trace.reason="vm_deallocate_return_failure";uc_emu_stop(engine);return;}
                std::uint64_t actual=0,after_flags=0;
                if(uc_reg_read(engine,UC_ARM64_REG_X0,&actual)!=UC_ERR_OK||actual!=result
                    ||uc_reg_read(engine,UC_ARM64_REG_NZCV,&after_flags)!=UC_ERR_OK||after_flags!=flags){trace.reason="vm_deallocate_return_failure";uc_emu_stop(engine);return;}
                ++trace.deallocate_calls;
                return;
            }
            if(handler==Handler::TimebaseInfo){
                std::uint64_t address=0,before=0;
                if(uc_reg_read(engine,UC_ARM64_REG_X0,&address)!=UC_ERR_OK||uc_reg_read(engine,UC_ARM64_REG_NZCV,&before)!=UC_ERR_OK){trace.reason="timebase_register_failure";uc_emu_stop(engine);return;}
                const auto bytes=DarwinClockTimebase::InfoBytes();
                TimebaseCall call{trace.last_pc,selector,address,false,false};
                if(GuestAccessPermitted(engine,address,bytes.size(),UC_PROT_WRITE)){
                    if(uc_mem_write(engine,address,bytes.data(),bytes.size())!=UC_ERR_OK){trace.reason="timebase_backend_copyout_failure";uc_emu_stop(engine);return;}
                    call.copied=true;std::array<std::uint8_t,8> actual{};
                    if(uc_mem_read(engine,address,actual.data(),actual.size())!=UC_ERR_OK||actual!=bytes){trace.reason="timebase_copyout_readback_failure";uc_emu_stop(engine);return;}
                    call.readback_verified=true;
                }else ++trace.timebase_copyout_failures;
                // Pinned XNU clock.c ignores copyout's error and returns KERN_SUCCESS.
                const std::uint64_t result=0;
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK){trace.reason="timebase_return_failure";uc_emu_stop(engine);return;}
                std::uint64_t after=0;if(uc_reg_read(engine,UC_ARM64_REG_NZCV,&after)!=UC_ERR_OK||after!=before){trace.reason="timebase_nzcv_failure";uc_emu_stop(engine);return;}
                ++trace.timebase_calls;if(trace.timebase_prefix_size<trace.timebase_prefix.size())trace.timebase_prefix[trace.timebase_prefix_size++]=call;
                return;
            }
            if(handler!=Handler::AbsoluteClock&&handler!=Handler::ContinuousClock){
                if(!trace.task.owner||trace.task.owner->engine.value!=engine){trace.reason="task_binding_failure";uc_emu_stop(engine);return;}
                const auto port=handler==Handler::TaskSelf?trace.task.CopySelfSend():handler==Handler::HostSelf?trace.task.CopyHostSend():handler==Handler::ThreadSelf?trace.task.CopyThreadSend():trace.task.ReplyPort(handler==Handler::SpecialReply);
                const std::uint64_t value=port;
                if(port&&!trace.task.Resolve(port)){trace.reason="task_port_binding_failure";uc_emu_stop(engine);return;}
                if(uc_reg_write(engine,UC_ARM64_REG_X0,&value)!=UC_ERR_OK){trace.reason="task_port_register_failure";uc_emu_stop(engine);return;}
                if(handler==Handler::TaskSelf){++trace.task_self_calls;
                    if(trace.task_prefix_size<trace.task_prefix.size())trace.task_prefix[trace.task_prefix_size++]={trace.last_pc,selector,port};
                }else if(handler==Handler::HostSelf){++trace.host_self_calls;
                    if(trace.task_prefix_size<trace.task_prefix.size())trace.task_prefix[trace.task_prefix_size++]={trace.last_pc,selector,port};
                }else{
                    if(handler==Handler::ThreadSelf)++trace.thread_calls;else if(handler==Handler::Reply)++trace.reply_calls;else ++trace.special_reply_calls;
                    if(trace.port_prefix_size<trace.port_prefix.size())trace.port_prefix[trace.port_prefix_size++]={trace.last_pc,selector,port};
                }
                return;
            }
            ULONGLONG value=0;
            if(low==0xfffffffd)QueryUnbiasedInterruptTimePrecise(&value);else QueryInterruptTimePrecise(&value);
            auto& calls=low==0xfffffffd?trace.absolute_calls:trace.continuous_calls;
            auto& first=low==0xfffffffd?trace.absolute_first:trace.continuous_first;
            auto& last=low==0xfffffffd?trace.absolute_last:trace.continuous_last;
            const std::uint64_t result=value;
            if(calls&&result<last){trace.reason="nonmonotonic_clock";uc_emu_stop(engine);return;}
            if(uc_reg_write(engine,UC_ARM64_REG_X0,&result)!=UC_ERR_OK){trace.reason="clock_register_failure";uc_emu_stop(engine);return;}
            if(!calls)first=result;
            last=result;++calls;
            if(trace.clock_prefix_size<trace.clock_prefix.size())trace.clock_prefix[trace.clock_prefix_size++]={trace.last_pc,selector,result};
            return;
        }
        if(selector_status==UC_ERR_OK&&pc_status==UC_ERR_OK&&number==2&&trace.last_opcode==0xd4001001
            &&pc==trace.last_pc+4&&low==5&&high==0){
            // Observe a bounded pathname without implementing or reporting success
            // for an unavailable syscall. Never read unrelated argument memory.
            std::uint64_t address=0;
            if(uc_reg_read(engine,indirect?UC_ARM64_REG_X1:UC_ARM64_REG_X0,&address)==UC_ERR_OK){
                for(std::size_t i=0;i<trace.open_path.size()&&address<=UINT64_MAX-i;++i){
                    char value=0;
                    if(!GuestAccessPermitted(engine,address+i,1,UC_PROT_READ)
                        ||uc_mem_read(engine,address+i,&value,1)!=UC_ERR_OK)break;
                    if(!value){trace.open_path_terminated=true;break;}
                    trace.open_path[trace.open_path_bytes++]=value;
                }
            }
        }
        if(number==7&&(trace.last_opcode>>21)==0x6a1){
            const auto imm16=static_cast<std::uint16_t>((trace.last_opcode>>5)&0xffff);
            if(imm16>=0xc470&&imm16<=0xc474){
                trace.reason="pointer_authentication_failure";trace.interrupt=number;
                trace.syscall_selector=raw_selector;uc_emu_stop(engine);return;
            }
        }
        trace.reason="unsupported_interrupt";trace.interrupt=number;trace.syscall_selector=raw_selector;uc_emu_stop(engine);
    }
    static bool Memory(uc_engine*,uc_mem_type type,std::uint64_t address,int size,std::int64_t,void* context){
        auto& trace=*static_cast<BootstrapTrace*>(context);trace.reason="unsupported_memory_access";
        trace.memory_type=type;trace.memory_address=address;trace.memory_size=size;return false;
    }
    static void CommpageRead(uc_engine* engine,uc_mem_type type,std::uint64_t address,int size,std::int64_t,void* context){
        auto& trace=*static_cast<BootstrapTrace*>(context);
        const bool kernel=address==commpage_address+0x37||address==commpage_ro_address+0x37;
        const bool user=address==commpage_address+0x25||address==commpage_ro_address+0x25;
        if(size==1&&(kernel||user)){
            std::uint8_t value=0;
            if(uc_mem_read(engine,address,&value,1)!=UC_ERR_OK||value!=trace.page_shift){
                trace.reason="guest_page_geometry_readback_failure";trace.memory_type=type;trace.memory_address=address;
                trace.memory_size=size;uc_emu_stop(engine);return;}
            if(kernel)++trace.kernel_page_reads;else ++trace.user_page_reads;
            if(trace.geometry_prefix_size<trace.geometry_prefix.size())trace.geometry_prefix[trace.geometry_prefix_size++]={trace.last_pc,address,value};
            return;
        }
        if(size>0&&address>=commpage_address+0x10&&address<commpage_address+0x18
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x18-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x1e&&address<commpage_address+0x20
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x20-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x20&&address<commpage_address+0x22
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x22-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x34&&address<commpage_address+0x37
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x37-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x22&&address<commpage_address+0x23
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x23-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x26&&address<commpage_address+0x28
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x28-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x2f&&address<commpage_address+0x30
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x30-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x38&&address<commpage_address+0x40
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x40-address){
            ++trace.cpu_reads;return;}
        if(size>0&&address>=commpage_address+0x80&&address<commpage_address+0x84
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x84-address){
            ++trace.cpu_reads;return;}
        // Adjacent zero backing must never masquerade as implemented Darwin state.
        if(size>0&&((address>=commpage_address+0x84&&address<commpage_address+0x88&&static_cast<std::uint64_t>(size)<=commpage_address+0x88-address)
            ||(address>=commpage_ro_address+0x84&&address<commpage_ro_address+0x88&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x88-address))){
            std::uint32_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==debugger_flags){
                ++trace.debugger_reads;
                if(trace.debugger_prefix_size<trace.debugger_prefix.size())trace.debugger_prefix[trace.debugger_prefix_size++]={trace.last_pc,address,static_cast<std::uint32_t>(size),actual};
                return;}
            trace.reason="debugger_capability_readback_failure";uc_emu_stop(engine);return;}
        if(size>0&&((address>=commpage_address+0x160&&address<commpage_address+0x168&&static_cast<std::uint64_t>(size)<=commpage_address+0x168-address)
            ||(address>=commpage_ro_address+0x160&&address<commpage_ro_address+0x168&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x168-address))){
            std::uint64_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==dyld_flags){++trace.dyld_flags_reads;return;}
            trace.reason="dyld_flags_readback_failure";uc_emu_stop(engine);return;}
        if(size>0&&((address>=commpage_address+0x92&&address<commpage_address+0x93&&static_cast<std::uint64_t>(size)<=commpage_address+0x93-address)
            ||(address>=commpage_ro_address+0x92&&address<commpage_ro_address+0x93&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x93-address))){
            std::uint8_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==dtrace_dof_enabled){++trace.dof_reads;return;}
            trace.reason="dof_readback_failure";uc_emu_stop(engine);return;}
        if(size>0&&address>=commpage_address+0x90&&address<commpage_address+0x92
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x92-address){++trace.commpage_reads;return;}
        if(size>0&&((address>=commpage_address+0x100&&address<commpage_address+0x104&&static_cast<std::uint64_t>(size)<=commpage_address+0x104-address)
            ||(address>=commpage_ro_address+0x100&&address<commpage_ro_address+0x104&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x104-address))){++trace.kdebug_reads;return;}
        // This uint32 field has no relocated RO alias in the pinned ARM ABI.
        // Check the actual little-endian backing for every admitted subword.
        if(size>0&&address>=commpage_address+0x104&&address<commpage_address+0x108
            &&static_cast<std::uint64_t>(size)<=commpage_address+0x108-address){
            std::uint32_t actual=0;
            const auto shift=static_cast<unsigned>(8*(address-(commpage_address+0x104)));
            const auto expected=(atm_diagnostic_config>>shift)&(UINT32_MAX>>(8*(4-size)));
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==expected){
                ++trace.atm_reads;
                if(trace.atm_prefix_size<trace.atm_prefix.size())trace.atm_prefix[trace.atm_prefix_size++]={trace.last_pc,address,static_cast<std::uint32_t>(size),actual};
                return;}
            trace.reason="atm_diagnostic_config_readback_failure";trace.memory_type=type;trace.memory_address=address;
            trace.memory_size=size;uc_emu_stop(engine);return;}
        if(size>0&&((address>=commpage_address+0x108&&address<commpage_address+0x10c&&static_cast<std::uint64_t>(size)<=commpage_address+0x10c-address)
            ||(address>=commpage_ro_address+0x108&&address<commpage_ro_address+0x10c&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x10c-address))){
            std::uint32_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==multiuser_config){++trace.multiuser_reads;return;}
            trace.reason="multiuser_config_readback_failure";uc_emu_stop(engine);return;}
        if(size>0&&((address>=commpage_address+0x10c&&address<commpage_address+0x110&&static_cast<std::uint64_t>(size)<=commpage_address+0x110-address)
            ||(address>=commpage_ro_address+0x10c&&address<commpage_ro_address+0x110&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x110-address))){
            std::uint32_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==aprr_support){++trace.aprr_reads;return;}
            trace.reason="aprr_readback_failure";uc_emu_stop(engine);return;}
        if(size>0&&((address>=commpage_address+0x180&&address<commpage_address+0x188&&static_cast<std::uint64_t>(size)<=commpage_address+0x188-address)
            ||(address>=commpage_ro_address+0x180&&address<commpage_ro_address+0x188&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x188-address))){
            std::uint64_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==quiescent_counter){++trace.quiescent_counter_reads;return;}
            trace.reason="quiescent_counter_readback_failure";uc_emu_stop(engine);return;}
        if(size>0&&((address>=commpage_address+0x342&&address<commpage_address+0x343&&static_cast<std::uint64_t>(size)<=commpage_address+0x343-address)
            ||(address>=commpage_ro_address+0x342&&address<commpage_ro_address+0x343&&static_cast<std::uint64_t>(size)<=commpage_ro_address+0x343-address))){
            std::uint8_t actual=0;
            if(uc_mem_read(engine,address,&actual,size)==UC_ERR_OK&&actual==0){return;}
            trace.reason="commpage_erm_active_readback_failure";trace.memory_type=type;trace.memory_address=address;trace.memory_size=size;uc_emu_stop(engine);return;}
        if(address==commpage_address+0xc8&&size==1){
            std::uint8_t actual=0xff;
            if(uc_mem_read(engine,address,&actual,1)==UC_ERR_OK&&actual==approximate_time_supported){
                ++trace.approximate_reads;
                if(trace.approximate_prefix_size<trace.approximate_prefix.size())trace.approximate_prefix[trace.approximate_prefix_size++]={trace.last_pc,address,1,actual};
                return;}
            trace.reason="approximate_clock_capability_readback_failure";trace.memory_type=type;
            trace.memory_address=address;trace.memory_size=size;uc_emu_stop(engine);return;}
        if(size>0&&address>=commpage_address+0x98&&address<commpage_address+0xa0
            &&static_cast<std::uint64_t>(size)<=commpage_address+0xa0-address){
            if(!Bias(trace.continuous_bias))trace.reason="clock_snapshot_unavailable";
            else if(uc_mem_write(engine,commpage_address+0x98,&trace.continuous_bias,8)!=UC_ERR_OK)trace.reason="clock_commpage_write_failure";
            else {++trace.timebase_reads;return;}
            trace.memory_type=type;trace.memory_address=address;trace.memory_size=size;uc_emu_stop(engine);return;
        }
        if(address==commpage_address+0xa0&&size==8){
            std::uint64_t value=0;
            if(uc_mem_read(engine,address,&value,8)==UC_ERR_OK&&value==trace.boot_epoch.boottime_usec){
                ++trace.boottime_reads;if(trace.boottime_prefix_size<trace.boottime_prefix.size())
                    trace.boottime_prefix[trace.boottime_prefix_size++]={trace.last_pc,address,value};
                return;
            }
            trace.reason="boottime_epoch_readback_failure";trace.memory_type=type;trace.memory_address=address;trace.memory_size=size;uc_emu_stop(engine);return;
        }
        if(size==8&&address>=commpage_address+0x120&&address<=commpage_address+0x140&&(address-(commpage_address+0x120))%8==0){
            std::uint64_t value=1;
            if(uc_mem_read(engine,address,&value,8)==UC_ERR_OK&&value==0){++trace.calendar_snapshot_reads;return;}
            trace.reason="inactive_calendar_snapshot_readback_failure";trace.memory_type=type;trace.memory_address=address;trace.memory_size=size;uc_emu_stop(engine);return;
        }
        trace.reason="unsupported_commpage_field";trace.memory_type=type;
        trace.memory_address=address;trace.memory_size=size;uc_emu_stop(engine);
    }
};
JsonValue ProbeBootstrap(Guest& guest,const DarwinProcessStack& stack,std::uint64_t pc,const DarwinClosureOptions& options){
    auto* engine=guest.engine.value;BootstrapTrace trace{options,*guest.task,stack};
    for(const auto& image:guest.mapped->OriginalClosure().images)for(const auto& e:image.metadata.exports){
        unsigned argument=0;
        if(e.symbol=="_abort_with_payload")argument=4;
        else if(e.symbol=="_abort_with_reason")argument=2;
        else continue;
        std::string ignored;const auto target=guest.mapped->Symbol(image.virtual_path,e.symbol,ignored);
        if(!target)continue;const auto address=reinterpret_cast<std::uint64_t>(target);
        if(std::none_of(trace.fatal_apis.begin(),trace.fatal_apis.end(),[&](const auto& known){return known.address==address;}))
            trace.fatal_apis.push_back({address,e.symbol,argument});
    }
    trace.bound_engine=engine;
    const auto page_size=stack.PageSize();
    Check(page_size&&!(page_size&(page_size-1)),"Guest VM page geometry is not a power of two.");
    for(auto size=page_size;size>1;size>>=1)++trace.page_shift;
    struct Commpage {
        uc_engine* engine;bool mapped=false,ro_mapped=false;
        explicit Commpage(uc_engine* value):engine(value){
            Uc(uc_mem_map(engine,BootstrapTrace::commpage_address,4096,UC_PROT_READ));mapped=true;
            const auto status=uc_mem_map(engine,BootstrapTrace::commpage_ro_address,4096,UC_PROT_READ);
            if(status!=UC_ERR_OK){uc_mem_unmap(engine,BootstrapTrace::commpage_address,4096);mapped=false;Uc(status);}
            ro_mapped=true;
        }
        ~Commpage(){if(ro_mapped)uc_mem_unmap(engine,BootstrapTrace::commpage_ro_address,4096);
            if(mapped)uc_mem_unmap(engine,BootstrapTrace::commpage_address,4096);}
    }commpage{engine};
    const auto epoch=DarwinClockEpoch::Capture();Check(bool(epoch),"Native boot clock epoch calibration failed.");
    trace.boot_epoch=*epoch;
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0xa0,&trace.boot_epoch.boottime_usec,8));
    // XNU's inactive snapshot: TimeStamp_tick=0 selects the original syscall
    // fallback. All five defined fields are read before that availability test.
    const std::array<std::uint64_t,5> inactive_calendar{};
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x120,inactive_calendar.data(),sizeof(inactive_calendar)));
    // USER_TIMEBASE_NONE and no continuous hardware clock: the backend does
    // not implement Darwin direct-counter semantics. These zeros
    // are explicit negative capabilities, not successful clock services.
    const std::array<std::uint8_t,2> clock_capabilities{0,0};
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x90,clock_capabilities.data(),clock_capabilities.size()));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0xc8,&BootstrapTrace::approximate_time_supported,1));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x10,&BootstrapTrace::cpu_capabilities64,sizeof(BootstrapTrace::cpu_capabilities64)));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x1e,&BootstrapTrace::commpage_version,sizeof(BootstrapTrace::commpage_version)));
    const auto cpu_caps16=static_cast<std::uint16_t>(BootstrapTrace::cpu_capabilities64);
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x20,&cpu_caps16,sizeof(cpu_caps16)));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x22,&BootstrapTrace::ncpus,1));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x26,&BootstrapTrace::cache_linesize,sizeof(BootstrapTrace::cache_linesize)));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x2f,&BootstrapTrace::cpu_clusters,1));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x34,&BootstrapTrace::active_cpus,1));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x35,&BootstrapTrace::physical_cpus,1));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x36,&BootstrapTrace::logical_cpus,1));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x38,&BootstrapTrace::commpage_memory_size,sizeof(BootstrapTrace::commpage_memory_size)));
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x80,&BootstrapTrace::cpu_family,sizeof(BootstrapTrace::cpu_family)));
    for(const auto base:{BootstrapTrace::commpage_address,BootstrapTrace::commpage_ro_address}){
        Uc(uc_mem_write(engine,base+0x25,&trace.page_shift,1));
        Uc(uc_mem_write(engine,base+0x37,&trace.page_shift,1));
        Uc(uc_mem_write(engine,base+0x84,&BootstrapTrace::debugger_flags,sizeof(BootstrapTrace::debugger_flags)));
        Uc(uc_mem_write(engine,base+0x160,&BootstrapTrace::dyld_flags,sizeof(BootstrapTrace::dyld_flags)));
        Uc(uc_mem_write(engine,base+0x92,&BootstrapTrace::dtrace_dof_enabled,sizeof(BootstrapTrace::dtrace_dof_enabled)));
        Uc(uc_mem_write(engine,base+0x100,&BootstrapTrace::kdebug_flags,sizeof(BootstrapTrace::kdebug_flags)));
        Uc(uc_mem_write(engine,base+0x108,&BootstrapTrace::multiuser_config,sizeof(BootstrapTrace::multiuser_config)));
        const std::uint32_t aprr_val=BootstrapTrace::aprr_support;
        Uc(uc_mem_write(engine,base+0x10c,&aprr_val,sizeof(aprr_val)));
        Uc(uc_mem_write(engine,base+0x180,&BootstrapTrace::quiescent_counter,sizeof(BootstrapTrace::quiescent_counter)));}
    Uc(uc_mem_write(engine,BootstrapTrace::commpage_address+0x104,&BootstrapTrace::atm_diagnostic_config,sizeof(BootstrapTrace::atm_diagnostic_config)));
    struct Hooks{uc_engine* engine;std::array<uc_hook,6> values{};~Hooks(){for(const auto hook:values)if(hook)uc_hook_del(engine,hook);}}hooks{engine};
    const std::size_t instruction_limit=options.instruction_limit?options.instruction_limit:5000000;
    Uc(uc_hook_add(engine,&hooks.values[0],UC_HOOK_CODE,reinterpret_cast<void*>(&BootstrapTrace::Code),&trace,1,0));
    Uc(uc_hook_add(engine,&hooks.values[1],UC_HOOK_INTR,reinterpret_cast<void*>(&BootstrapTrace::Interrupt),&trace,1,0));
    Uc(uc_hook_add(engine,&hooks.values[2],UC_HOOK_MEM_INVALID,reinterpret_cast<void*>(&BootstrapTrace::Memory),&trace,1,0));
    Uc(uc_hook_add(engine,&hooks.values[3],UC_HOOK_MEM_READ,reinterpret_cast<void*>(&BootstrapTrace::CommpageRead),&trace,
        BootstrapTrace::commpage_address,BootstrapTrace::commpage_address+4095));
    Uc(uc_hook_add(engine,&hooks.values[4],UC_HOOK_MEM_READ,reinterpret_cast<void*>(&BootstrapTrace::CommpageRead),&trace,
        BootstrapTrace::commpage_ro_address,BootstrapTrace::commpage_ro_address+4095));
    const std::uint64_t timeout_us=instruction_limit>5000000?std::max<std::uint64_t>(180000000ULL,static_cast<std::uint64_t>(instruction_limit)*2ULL):15000000ULL;
    Uc(uc_reg_write(engine,UC_ARM64_REG_PC,&pc));
    Uc(trace.task.thread.context.Capture(engine));
    auto& queue=trace.task.run_queue;
    Check(queue.Admit(trace.task.thread.id,trace.task.thread.context),"Main guest thread run-queue admission failed.");
    trace.task.thread.admitted=true;
    const std::size_t quantum=instruction_limit>20000000?4194304:65536;
    ULONGLONG started=0;QueryInterruptTimePrecise(&started);
    uc_err status=UC_ERR_OK;std::size_t timed_out=0;
    while(!trace.reason&&trace.callbacks<instruction_limit){
        // Host controls also apply when every guest thread is blocked on input.
        const auto operation=CurrentOperationContext();
        if(options.cancellation.Requested()||(operation&&operation->CancellationRequested())){trace.reason="cancelled";break;}
        if(std::chrono::steady_clock::now()>=options.deadline||(operation&&operation->DeadlineExceeded())){trace.reason="deadline";break;}
        const auto pending_reads=trace.PumpPipeReads();
        ULONGLONG now=0,absolute_now=0;QueryInterruptTimePrecise(&now);QueryUnbiasedInterruptTimePrecise(&absolute_now);
        const auto elapsed=now-started;
        if(elapsed>=timeout_us*10){timed_out=1;break;}
        queue.Expire(absolute_now);
        trace.PumpWorkqueue(engine,absolute_now);
        if(trace.reason)break;
        trace.UpdateScheduler(absolute_now);
        if(trace.reason)break;
        std::uint64_t selected=0;trace.host_context_operation=true;
        const auto dispatch_error=queue.Dispatch(engine,absolute_now,selected);trace.host_context_operation=false;Uc(dispatch_error);
        if(!selected){
            if(pending_reads||(trace.workqueue_retry_deadline&&!trace.task.workqueue.requests.empty())
                ||trace.NextKeventDeadline()){
                // Poll native byte-pipe readiness only while idle; guest peers
                // continue via Dispatch. No protocol-specific wait timeout.
                Sleep(1);continue;
            }
            trace.reason="no_runnable_guest_thread";break;
        }
        // Additional threads require real MachTask thread/port bindings before
        // their interrupts may execute. Queue support alone declares no pthread capability.
        Check(trace.task.SelectOwnedThread(selected),"Selected thread lacks a guest task binding.");
        std::uint64_t next_pc=0;Uc(uc_reg_read(engine,UC_ARM64_REG_PC,&next_pc));
        auto* selected_thread=trace.task.CurrentThread();
        const auto* dispatched=queue.Lookup(selected);
        if(dispatched&&dispatched->wake_generation!=selected_thread->last_wake_generation){
            selected_thread->remaining_quantum=quantum;
            selected_thread->last_wake_generation=dispatched->wake_generation;
        }
        if(!selected_thread->remaining_quantum)selected_thread->remaining_quantum=quantum;
        const auto starting_priority=dispatched?dispatched->effective_priority:0;
        if(instruction_limit>20000000&&hooks.values[0]&&trace.prefix_size>=trace.prefix.size()){
            Uc(uc_hook_del(engine,hooks.values[0]));hooks.values[0]=0;
            Uc(uc_hook_add(engine,&hooks.values[5],UC_HOOK_BLOCK,reinterpret_cast<void*>(&BootstrapTrace::Block),&trace,1,0));
            // Translated blocks carry the hooks present when they were generated.
            Uc(uc_ctl_flush_tb(engine));
        }
        // Block accounting runs without Unicorn's instruction count (itself a
        // per-instruction hook). The block hook ends the same instruction
        // quantum synchronously at a block boundary, never from a timer thread.
        const bool block_accounting=hooks.values[5]!=0;
        const auto before=trace.callbacks;
        const auto slice=block_accounting?std::size_t(0):(instruction_limit>20000000&&hooks.values[0]&&trace.prefix_size<trace.prefix.size())
            ?std::min<std::size_t>(16,instruction_limit-before)
            :std::min(selected_thread->remaining_quantum,instruction_limit-before);
        std::uint64_t cpu_before=0;
        if(!BootstrapTrace::ReadCpuTime(cpu_before)){trace.reason="scheduler_cpu_clock_failure";break;}
        trace.scheduler_clock_ready=true;
        trace.cpu_segment_id=selected;trace.cpu_segment_stamp=cpu_before;
        // Keep every scheduling quantum bounded, independently of trace detail.
        // Zero timeout/count would allow a guest loop to evade all host controls.
        const auto emu_timeout=(timeout_us*10-elapsed+9)/10;
        trace.block_quantum_end=block_accounting?before+std::min(selected_thread->remaining_quantum,instruction_limit-before):0;
        status=uc_emu_start(engine,next_pc,0,emu_timeout,slice);
        trace.block_quantum_end=0;
        trace.ChargeCpuSegment();trace.cpu_segment_id=0;
        const auto consumed=std::min<std::size_t>(trace.callbacks-before,selected_thread->remaining_quantum);
        selected_thread->remaining_quantum-=consumed;
        if(trace.mach_thread_create.pending){
            auto& request=trace.mach_thread_create;request.pending=false;
            trace.pointer_auth_sign_pc=queue.ExclusiveClearPC()-8;
            trace.pointer_auth_pc=trace.pointer_auth_sign_pc+12;
            trace.host_auth_operation=true;
            std::array<std::uint32_t,68> converted{};
            const auto conversion=ConvertDarwinThreadStateArm64(engine,trace.pointer_auth_pc,
                trace.pointer_auth_sign_pc+16,trace.pointer_auth_sign_pc+20,request.user_state,converted);
            trace.host_auth_operation=false;
            if(conversion!=UC_ERR_OK){trace.reason="mach_thread_state_conversion_backend_failure";status=conversion;}
            else{
                // XNU NO_PTRAUTH describes the userspace representation, not
                // a PSTATE bit. Consume it at the internal context boundary;
                // the raw PC/LR/SP/FP and inherited task PAC controls stay intact.
                Check(converted[67]==(guest.jop_enabled?0u:1u),"Converted ARM64 task state has inconsistent PAC representation.");
                converted[67]=0;
                std::uint32_t name=0;std::uint64_t id=0;
                auto ret_code=trace.task.PrepareOwnedThread(engine,converted,0,name,id);
                if(!ret_code){
                    const std::array<std::uint32_t,12> reply{0x80001200,40,0,request.reply_name,0,3512,1,name,0,0x00110000,0,8};
                    const auto copied=uc_mem_write(engine,request.reply_address,reply.data(),sizeof(reply));
                    if(copied!=UC_ERR_OK){
                        trace.task.RollbackPreparedThread(name);trace.reason="mach_thread_create_reply_write_failure";status=copied;
                    }else{
                        bool published=false;
                        try{published=trace.task.PublishOwnedThread(name,false);}catch(const std::bad_alloc&){}
                        if(!published){trace.task.RollbackPreparedThread(name);ret_code=3;}
                    }
                }
                if(ret_code&&!trace.reason){
                    const std::array<std::uint32_t,11> reply{0x1200,36,0,request.reply_name,0,3512,0,1,ret_code,0,8};
                    const auto copied=uc_mem_write(engine,request.reply_address,reply.data(),sizeof(reply));
                    if(copied!=UC_ERR_OK){trace.reason="mach_thread_create_reply_write_failure";status=copied;}
                }
                if(!trace.reason){const std::uint64_t success=0;status=uc_reg_write(engine,UC_ARM64_REG_X0,&success);}
            }
        }
        if(trace.pthread_entry_auth_pending){
            trace.pthread_entry_auth_pending=false;
            trace.pointer_auth_sign_pc=trace.task.run_queue.ExclusiveClearPC()-8;
            trace.pointer_auth_pc=trace.pointer_auth_sign_pc+12;
            trace.host_auth_operation=true;
            const std::array<std::uint64_t,2> entries{trace.pthread_arguments[0],trace.pthread_arguments[1]};
            const auto auth_error=ConvertDarwinFunctionPointersFromUser(engine,trace.pointer_auth_pc,
                entries,trace.pthread_converted_entries);
            trace.host_auth_operation=false;trace.pthread_entry_auth_error=auth_error;
            trace.pthread_entries_converted=auth_error==UC_ERR_OK;
            if(auth_error!=UC_ERR_OK)trace.reason="pthread_entry_conversion_backend_failure";
            else{
                const auto stack_range=trace.stack.Range();
                const auto stack_hint=(stack_range.address+stack_range.size)&~(trace.stack.PageSize()-1);
                auto& registered=trace.task.pthread_registration;
                auto error=CommitDarwinPthreadRegistration(registered,trace.pthread_input,
                    std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(trace.pthread_arguments[2])),
                    trace.pthread_converted_entries[0],trace.pthread_converted_entries[1],stack_hint);
                trace.pthread_registration_committed=registered.registered;
                trace.pthread_available_features=trace.AvailablePthreadFeatures();
                trace.pthread_output_copied=false;trace.pthread_output_verified=false;
                if(!error&&trace.pthread_input.copied_bytes){
                    DarwinPthreadRegistrationOutput output;output.stack_addr_hint=registered.stack_addr_hint;
                    // Kernel default policy is the original zero (psynch), not
                    // USE_ULOCK. No default is inferred from a codec/test mask.
                    output.mutex_default_policy=0;
                    auto* selected=trace.task.CurrentThread();
                    if(!selected)trace.reason="pthread_registration_thread_binding_failure";
                    else{
                        DarwinPthreadRunQueuePolicyProvider provider(trace.task.run_queue,selected->id);
                        const auto qos=selected->policy.qos.tier?selected->policy.qos:DarwinPthreadQos{4,0};
                        if(provider.ApplyQos(qos)!=0)trace.reason="pthread_registration_priority_provider_failure";
                        else{
                            selected->policy.qos=qos;
                            std::uint32_t main_qos=0;
                            if(!EncodeDarwinPthreadQos({qos.tier,0},main_qos))trace.reason="pthread_registration_priority_encode_failure";
                            else output.main_qos=main_qos;
                        }
                    }
                    std::array<std::uint8_t,DarwinPthreadRegistrationBytes> outgoing{};
                    const auto count=trace.pthread_input.copied_bytes;
                    if(!trace.reason){
                        const auto encoded=EncodeDarwinPthreadRegistration(trace.pthread_input,output,outgoing);
                        if(encoded)trace.reason="pthread_registration_output_encode_failure";
                        // Apple publishes registration before copyout and maps
                        // copyout failure to EINVAL; it does not roll it back.
                        else if(!GuestAccessPermitted(engine,trace.pthread_arguments[3],count,UC_PROT_WRITE))error=22;
                        else if(uc_mem_write(engine,trace.pthread_arguments[3],outgoing.data(),count)!=UC_ERR_OK)
                            trace.reason="pthread_registration_copyout_backend_failure";
                        else{
                            trace.pthread_output_copied=true;
                            const auto readback=uc_mem_read(engine,trace.pthread_arguments[3],trace.pthread_output_readback.data(),count);
                            trace.pthread_output_verified=readback==UC_ERR_OK
                                &&std::equal(outgoing.begin(),outgoing.begin()+count,trace.pthread_output_readback.begin());
                            if(!trace.pthread_output_verified)trace.reason="pthread_registration_copyout_readback_failure";
                        }
                    }
                }
                trace.pthread_registration_error=error;
                if(!trace.reason&&error){
                    std::uint64_t before=0;Uc(uc_reg_read(engine,UC_ARM64_REG_NZCV,&before));
                    const std::uint64_t value=error,zero=0,after=before|0x20000000ULL;
                    Uc(uc_reg_write(engine,UC_ARM64_REG_X0,&value));Uc(uc_reg_write(engine,UC_ARM64_REG_X1,&zero));
                    Uc(uc_reg_write(engine,UC_ARM64_REG_NZCV,&after));
                    trace.thread_lifecycle_reschedule=true;
                }else if(!trace.reason){
                    if(!trace.pthread_available_features)trace.reason="unsupported_pthread_capabilities";
                    else{
                        std::uint64_t before=0;Uc(uc_reg_read(engine,UC_ARM64_REG_NZCV,&before));
                        const std::uint64_t value=trace.pthread_available_features,zero=0,after=before&~0x20000000ULL;
                        Uc(uc_reg_write(engine,UC_ARM64_REG_X0,&value));Uc(uc_reg_write(engine,UC_ARM64_REG_X1,&zero));
                        Uc(uc_reg_write(engine,UC_ARM64_REG_NZCV,&after));
                        trace.pthread_features_returned=true;trace.thread_lifecycle_reschedule=true;
                    }
                }
            }
        }
        Uc(uc_query(engine,UC_QUERY_TIMEOUT,&timed_out));
        if(queue.Running()){
            const auto* current=queue.Lookup(selected);
            const auto expired=selected_thread->remaining_quantum==0
                ||(current&&current->effective_priority<starting_priority);
            if(expired)selected_thread->remaining_quantum=quantum;
            Uc(queue.PreemptCurrent(engine,expired));
        }
        const bool lifecycle_reschedule=trace.thread_lifecycle_reschedule;
        trace.thread_lifecycle_reschedule=false;
        if(trace.reason||status!=UC_ERR_OK||timed_out||(hooks.values[0]&&trace.callbacks-before<slice&&!lifecycle_reschedule))break;
    }
    if(!trace.reason)trace.reason=timed_out?"timeout":status!=UC_ERR_OK?"backend_error":trace.callbacks>=instruction_limit?"instruction_budget":"backend_stop";
    std::uint64_t stop_pc=0;Uc(uc_reg_read(engine,UC_ARM64_REG_PC,&stop_pc));
    auto result=JsonValue::ObjectValue(),prefix=JsonValue::ArrayValue();
    auto authentication=JsonValue::ObjectValue();
    uc_arm64_cp_reg actual_control{1,0,3,0,0,0};Uc(uc_reg_read(engine,UC_ARM64_REG_CP_REG,&actual_control));
    authentication.Set("main_cpu_subtype",JsonValue::Number(std::to_string(guest.main_subtype)));
    authentication.Set("jop_enabled",JsonValue::Boolean(guest.jop_enabled));
    authentication.Set("sctlr",JsonValue::Number(std::to_string(actual_control.val)));
    authentication.Set("ia_enabled",JsonValue::Boolean((actual_control.val&(1ULL<<31))!=0));
    authentication.Set("ib_enabled",JsonValue::Boolean((actual_control.val&(1ULL<<30))!=0));
    authentication.Set("da_enabled",JsonValue::Boolean((actual_control.val&(1ULL<<27))!=0));
    authentication.Set("db_enabled",JsonValue::Boolean((actual_control.val&(1ULL<<13))!=0));
    authentication.Set("scope",JsonValue::String("main ARM64 ABI; ARM64e v0 enabled; code-signing plugin-host exceptions not classified"));
    result.Set("pointer_authentication_policy",std::move(authentication));
    for(std::size_t i=0;i<trace.prefix_size;++i){auto item=JsonValue::ObjectValue();item.Set("pc",JsonValue::Number(std::to_string(trace.prefix[i].first)));
        item.Set("opcode",JsonValue::Number(std::to_string(trace.prefix[i].second)));prefix.ArrayItems().push_back(std::move(item));}
    result.Set("instruction_prefix",std::move(prefix));result.Set("entered",JsonValue::Boolean(trace.callbacks!=0));
    auto contexts=JsonValue::ObjectValue();
    contexts.Set("current_thread_id",JsonValue::Number(std::to_string(trace.task.CurrentThread()?trace.task.CurrentThread()->id:0)));
    contexts.Set("saved",JsonValue::Boolean(trace.task.thread.context.Saved()));
    contexts.Set("captures",JsonValue::Number(std::to_string(trace.task.thread.context.Captures())));
    contexts.Set("shared_task_memory",JsonValue::Boolean(true));
    contexts.Set("guest_thread_count",JsonValue::Number(std::to_string(1+trace.task.peers.size())));
    contexts.Set("live_guest_thread_count",JsonValue::Number(std::to_string(trace.task.LiveThreadCount())));
    contexts.Set("multithread_scheduler_available",JsonValue::Boolean(false));
    contexts.Set("run_queue_threads",JsonValue::Number(std::to_string(queue.Size())));
    contexts.Set("run_queue_dispatches",JsonValue::Number(std::to_string(queue.Dispatches())));
    contexts.Set("exclusive_monitor_clears",JsonValue::Number(std::to_string(queue.ExclusiveClears())));
    contexts.Set("instruction_quantum",JsonValue::Number(std::to_string(quantum)));
    result.Set("thread_context",std::move(contexts));
    auto accounting=JsonValue::ObjectValue();
    accounting.Set("scope",JsonValue::String("one modeled CPU; non-clutch timeshare; native thread CPU charge; sampled load"));
    accounting.Set("cpu_clock",JsonValue::String("GetThreadTimes kernel+user, 100ns units; uc_emu_start interval only"));
    accounting.Set("cpu_charged_100ns",JsonValue::Number(std::to_string(trace.cpu_charged)));
    accounting.Set("load_samples",JsonValue::Number(std::to_string(trace.load_samples)));
    accounting.Set("priority_ticks",JsonValue::Number(std::to_string(trace.priority_ticks)));
    auto scheduler_policies=JsonValue::ArrayValue();
    const auto append_policy=[&](const MachTask::Thread& thread){
        const auto* entry=queue.Lookup(thread.id);if(!entry)return;
        auto policy=JsonValue::ObjectValue();
        for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
            {"id",thread.id},{"base_priority",static_cast<std::uint64_t>(entry->base_priority)},
            {"effective_priority",static_cast<std::uint64_t>(entry->effective_priority)},
            {"sched_usage",entry->sched_usage},{"pri_shift",entry->pri_shift},{"voucher",thread.policy.voucher}})
            policy.Set(key,JsonValue::Number(std::to_string(value)));
        policy.Set("timeshare",JsonValue::Boolean(entry->timeshare));scheduler_policies.ArrayItems().push_back(std::move(policy));
    };
    append_policy(trace.task.thread);for(const auto& peer:trace.task.peers)append_policy(*peer);
    accounting.Set("threads",std::move(scheduler_policies));result.Set("scheduler_accounting",std::move(accounting));
    auto workqueue=JsonValue::ObjectValue();
    const auto& wq=trace.task.workqueue;
    workqueue.Set("opened",JsonValue::Boolean(wq.opened));
    workqueue.Set("semantic_scope",JsonValue::String("ordinary-workqueue, kqworkq and workloop kevent delivery (user/timer/memorystatus filters, workloop thread requests and sync waits); cooperative provider absent"));
    for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
        {"opens",wq.opens},{"setups",wq.setups},{"requests_received",wq.requests_received},
        {"threads_requested",wq.threads_requested},{"admissions",wq.admissions},
        {"returns",wq.returns},{"reuses",wq.reuses},{"parks",wq.parks},
        {"policy_updates",wq.policy_updates},
        {"dispatch_serialno_offset",wq.configuration.serialno_offset},
        {"dispatch_label_offset",wq.configuration.label_offset},
        {"dispatch_version",wq.configuration.version},{"modeled_cpu_count",1}})
        workqueue.Set(key,JsonValue::Number(std::to_string(value)));
    std::uint64_t pending_count=0;
    for(const auto& request:wq.requests)pending_count+=request.count;
    workqueue.Set("pending_thread_count",JsonValue::Number(std::to_string(pending_count)));
    workqueue.Set("main_signal_mask",JsonValue::Number(std::to_string(trace.task.thread.signal_mask)));
    {
        auto kevent=JsonValue::ObjectValue(),calls=JsonValue::ArrayValue();
        for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
            {"calls",wq.kevent_calls},{"returns",wq.kevent_returns},{"upcalls",wq.kevent_upcalls},
            {"knotes",wq.kqueue.Size()},{"registrations",wq.kqueue.registrations},
            {"deliveries",wq.kqueue.deliveries},{"manager_qos",wq.manager_qos},
            {"kevent_id_calls",wq.kevent_id_calls},{"workloops",wq.workloops.size()},
            {"workloop_upcalls",wq.workloop_upcalls},{"workloop_returns",wq.workloop_returns},
            {"workloop_parks",wq.workloop_parks}})
            kevent.Set(key,JsonValue::Number(std::to_string(value)));
        for(const auto& call:trace.kevent_prefix){auto row=JsonValue::ObjectValue();
            for(const auto& [key,value]:std::vector<std::pair<const char*,std::int64_t>>{
                {"pc",static_cast<std::int64_t>(call.pc)},{"fd",call.fd},{"nchanges",call.nchanges},{"nevents",call.nevents},
                {"flags",call.flags},{"ident",static_cast<std::int64_t>(call.change.ident)},{"filter",call.change.filter},
                {"change_flags",call.change.flags},{"qos",call.change.qos},{"fflags",call.change.fflags},{"data",call.change.data}})
                row.Set(key,JsonValue::Number(std::to_string(value)));
            calls.ArrayItems().push_back(std::move(row));}
        kevent.Set("call_suffix",std::move(calls));
        workqueue.Set("kevent",std::move(kevent));
    }
    auto workers=JsonValue::ArrayValue();
    for(const auto& peer:trace.task.peers){const auto& binding=peer->workqueue;
        if(!binding.member)continue;
        auto worker=JsonValue::ObjectValue();
        for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{
            {"id",peer->id},{"control_name",peer->control_name},{"self",binding.self},
            {"stack_bottom",binding.stack_bottom},{"allocation",binding.allocation},
            {"allocation_size",binding.allocation_size},{"tsd_base",peer->tsd_base},
            {"signal_mask",peer->signal_mask},{"qos",binding.qos},{"upcalls",binding.upcalls}})
            worker.Set(key,JsonValue::Number(std::to_string(value)));
        worker.Set("idle",JsonValue::Boolean(binding.idle));
        worker.Set("alive",JsonValue::Boolean(peer->alive));
        worker.Set("overcommit",JsonValue::Boolean(binding.overcommit));
        const auto* port=trace.task.Resolve(peer->control_name);
        worker.Set("pinned_control_port",JsonValue::Boolean(port&&port->pinned));
        workers.ArrayItems().push_back(std::move(worker));
    }
    workqueue.Set("workers",std::move(workers));result.Set("workqueue",std::move(workqueue));
    auto recent=JsonValue::ArrayValue();
    for(std::size_t i=trace.recent_count>trace.recent.size()?trace.recent_count-trace.recent.size():0;i<trace.recent_count;++i){
        const auto& instruction=trace.recent[i%trace.recent.size()];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(instruction.pc)));item.Set("opcode",JsonValue::Number(std::to_string(instruction.opcode)));
        auto registers=JsonValue::ArrayValue();for(const auto value:instruction.registers)registers.ArrayItems().push_back(JsonValue::Number(std::to_string(value)));
        item.Set("registers",std::move(registers));
        item.Set("register_snapshot_before_instruction",JsonValue::Boolean(true));
        const bool observed=instruction.load_observed&&GuestAccessPermitted(engine,instruction.load_address,8,UC_PROT_READ);
        item.Set("load_observed",JsonValue::Boolean(observed));
        item.Set("load_address",JsonValue::Number(std::to_string(instruction.load_address)));
        item.Set("load_value",JsonValue::Number(std::to_string(observed?instruction.load_value:0)));
        recent.ArrayItems().push_back(std::move(item));}
    result.Set("last_instructions",std::move(recent));
    std::uint64_t current_fp = 0;
    uc_reg_read(engine, UC_ARM64_REG_X29, &current_fp);
    auto stack_frames = JsonValue::ArrayValue();
    for(int frame = 0; frame < 32 && current_fp && current_fp < 0x0000ffffffffffffULL; ++frame) {
        std::uint64_t next_fp = 0, lr = 0;
        if(uc_mem_read(engine, current_fp, &next_fp, 8) != UC_ERR_OK || uc_mem_read(engine, current_fp + 8, &lr, 8) != UC_ERR_OK) break;
        auto f = JsonValue::ObjectValue();
        f.Set("frame", JsonValue::Number(std::to_string(frame)));
        f.Set("fp", JsonValue::Number(std::to_string(current_fp)));
        f.Set("lr", JsonValue::Number(std::to_string(lr & 0x0000ffffffffffffULL)));
        stack_frames.ArrayItems().push_back(std::move(f));
        if(next_fp <= current_fp) break;
        current_fp = next_fp;
    }
    if(trace.last_pc&&trace.options.instruction_limit>20000000)uc_mem_read(engine,trace.last_pc,&trace.last_opcode,4);
    result.Set("callstack", std::move(stack_frames));
    result.Set("exited",JsonValue::Boolean(trace.exited));
    result.Set("exit_status",JsonValue::Number(std::to_string(trace.exit_status)));
    auto pipe_waits=JsonValue::ObjectValue();
    pipe_waits.Set("parks",JsonValue::Number(std::to_string(trace.pipe_read_parks)));
    pipe_waits.Set("wakes",JsonValue::Number(std::to_string(trace.pipe_read_wakes)));
    std::size_t pending_read_count=trace.task.thread.pending_read.active?1:0;
    for(const auto& peer:trace.task.peers)if(peer->pending_read.active)++pending_read_count;
    pipe_waits.Set("pending",JsonValue::Number(std::to_string(pending_read_count)));
    result.Set("native_pipe_waits",std::move(pipe_waits));
    result.Set("stop_reason",JsonValue::String(trace.reason));result.Set("backend_status",JsonValue::String(uc_strerror(status)));
    result.Set("open_path",JsonValue::String(std::string(trace.open_path.data(),trace.open_path_bytes)));
    result.Set("open_path_terminated",JsonValue::Boolean(trace.open_path_terminated));
    auto sandbox=JsonValue::ObjectValue();sandbox.Set("pid",JsonValue::Number(std::to_string(guest.task->pid)));
    sandbox.Set("profile_state",JsonValue::String("none"));sandbox.Set("profile_installation_supported",JsonValue::Boolean(false));
    auto policies=JsonValue::ArrayValue();policies.ArrayItems().push_back(JsonValue::String("Sandbox"));policies.ArrayItems().push_back(JsonValue::String("AMFI"));
    sandbox.Set("registered_policies",std::move(policies));
    auto sandbox_calls=JsonValue::ArrayValue();for(const auto& call:trace.sandbox_prefix){auto item=JsonValue::ObjectValue(),request=JsonValue::ArrayValue();
        for(auto field:call.request)request.ArrayItems().push_back(JsonValue::Number(std::to_string(field)));
        auto args=JsonValue::ArrayValue();for(auto field:call.arguments)args.ArrayItems().push_back(JsonValue::Number(std::to_string(field)));
        item.Set("arguments",std::move(args));item.Set("policy_registered",JsonValue::Boolean(call.policy=="Sandbox"||call.policy=="AMFI"));
        item.Set("decision_produced",JsonValue::Boolean(call.decision_written));
        item.Set("request",std::move(request));item.Set("pc",JsonValue::Number(std::to_string(call.pc)));
        item.Set("call",JsonValue::Number(std::to_string(call.call)));item.Set("policy",JsonValue::String(call.policy));
        item.Set("operation",JsonValue::String(call.operation));item.Set("decision",JsonValue::Number(std::to_string(call.decision)));
        item.Set("errno",JsonValue::Number(std::to_string(call.error)));sandbox_calls.ArrayItems().push_back(std::move(item));}
    sandbox.Set("call_prefix",std::move(sandbox_calls));result.Set("sandbox",std::move(sandbox));
    result.Set("loader_policy",trace.task.loader_policy.ToJson());
    auto sysctl=JsonValue::ObjectValue(),sysctl_calls=JsonValue::ArrayValue();
    sysctl.Set("calls",JsonValue::Number(std::to_string(trace.sysctl_calls)));sysctl.Set("guest_page_size",JsonValue::Number(std::to_string(stack.PageSize())));
    auto nodes=JsonValue::ArrayValue();nodes.ArrayItems().push_back(JsonValue::String("hw.pagesize"));sysctl.Set("value_nodes",std::move(nodes));
    for(const auto& call:trace.sysctl_prefix){auto item=JsonValue::ObjectValue(),mib=JsonValue::ArrayValue(),args=JsonValue::ArrayValue();
        for(auto field:call.mib)mib.ArrayItems().push_back(JsonValue::Number(std::to_string(field)));
        for(auto field:call.arguments)args.ArrayItems().push_back(JsonValue::Number(std::to_string(field)));
        item.Set("mib",std::move(mib));item.Set("arguments",std::move(args));item.Set("name_input",JsonValue::String(call.name));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("errno",JsonValue::Number(std::to_string(call.error)));
        item.Set("capacity",JsonValue::Number(std::to_string(call.capacity)));item.Set("output_length",JsonValue::Number(std::to_string(call.output_length)));
        item.Set("mib_copied",JsonValue::Boolean(call.mib_copied));item.Set("length_copied",JsonValue::Boolean(call.length_copied));
        sysctl_calls.ArrayItems().push_back(std::move(item));}
    sysctl.Set("call_prefix",std::move(sysctl_calls));result.Set("sysctl",std::move(sysctl));
    auto fatal=JsonValue::ObjectValue(),fatal_entries=JsonValue::ArrayValue(),fatal_calls=JsonValue::ArrayValue();
    for(const auto& api:trace.fatal_apis){auto item=JsonValue::ObjectValue();item.Set("pc",JsonValue::Number(std::to_string(api.address)));
        item.Set("symbol",JsonValue::String(api.symbol));fatal_entries.ArrayItems().push_back(std::move(item));}
    for(const auto& call:trace.fatal_observations){auto item=JsonValue::ObjectValue(),args=JsonValue::ArrayValue();
        for(auto field:call.arguments)args.ArrayItems().push_back(JsonValue::Number(std::to_string(field)));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("symbol",JsonValue::String(call.symbol));
        item.Set("arguments",std::move(args));item.Set("reason",JsonValue::String(call.reason));item.Set("terminated",JsonValue::Boolean(call.terminated));
        item.Set("readable",JsonValue::Boolean(call.readable));fatal_calls.ArrayItems().push_back(std::move(item));}
    fatal.Set("entrypoints",std::move(fatal_entries));fatal.Set("calls",std::move(fatal_calls));
    fatal.Set("capture_failed",JsonValue::Boolean(trace.fatal_capture_failed));fatal.Set("observational_only",JsonValue::Boolean(true));
    result.Set("fatal_api_observations",std::move(fatal));
    // Internal runtime wrappers need not be exported. Preserve bounded printable
    // strings still addressed by registers at the stop, without guessing an ABI
    // or changing the guest. An empty result does not imply absence of a reason.
    auto stopped_strings=JsonValue::ArrayValue();
    if(trace.recent_count){const auto& stopped=trace.recent[(trace.recent_count-1)%trace.recent.size()];
        for(unsigned reg=0;reg<31;++reg){const auto pointer=stopped.registers[reg];if(!pointer)continue;
            std::string text;bool terminated=false,printable=true;
            for(std::size_t i=0;i<1024;++i){unsigned char c=0;
                if(pointer>UINT64_MAX-i||!GuestAccessPermitted(engine,pointer+i,1,UC_PROT_READ)
                    ||uc_mem_read(engine,pointer+i,&c,1)!=UC_ERR_OK)break;
                if(!c){terminated=true;break;}
                if((c<32&&c!='\n'&&c!='\r'&&c!='\t')||c>126){printable=false;break;}
                text.push_back(static_cast<char>(c));
            }
            if(terminated&&printable&&!text.empty()){auto item=JsonValue::ObjectValue();
                item.Set("register",JsonValue::Number(std::to_string(reg)));item.Set("address",JsonValue::Number(std::to_string(pointer)));
                item.Set("text",JsonValue::String(text));stopped_strings.ArrayItems().push_back(std::move(item));}
        }
    }
    result.Set("stop_register_strings",std::move(stopped_strings));
    auto code_sign=JsonValue::ObjectValue(),code_sign_calls=JsonValue::ArrayValue();
    const auto& security=trace.task.code_signing;
    code_sign.Set("source",JsonValue::String("native-task-code-signing-state"));
    code_sign.Set("validation_state",JsonValue::String("not-performed"));
    code_sign.Set("signature_validated",JsonValue::Boolean(security.signature_validated));
    code_sign.Set("enforcement",JsonValue::Boolean(security.enforcement));
    code_sign.Set("platform_binary",JsonValue::Boolean(security.platform_binary));code_sign.Set("platform_path",JsonValue::Boolean(security.platform_path));
    code_sign.Set("flags",JsonValue::Number(std::to_string(security.Status())));code_sign.Set("pid",JsonValue::Number(std::to_string(trace.task.pid)));
    code_sign.Set("calls",JsonValue::Number(std::to_string(trace.code_sign_calls)));
    for(const auto& call:trace.code_sign_prefix){auto item=JsonValue::ObjectValue(),args=JsonValue::ArrayValue();
        for(auto arg:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(arg)));
        item.Set("arguments",std::move(args));item.Set("pc",JsonValue::Number(std::to_string(call.pc)));
        item.Set("status",JsonValue::Number(std::to_string(call.status)));item.Set("copied",JsonValue::Boolean(call.copied));
        item.Set("audit_token_pointer",JsonValue::Number(std::to_string(call.audit_token_pointer)));
        item.Set("audited",JsonValue::Boolean(call.audited));
        item.Set("audit_token_copied",JsonValue::Boolean(call.audit_token_copied));item.Set("audit_token_matches",JsonValue::Boolean(call.audit_token_matches));
        auto token=JsonValue::ArrayValue();if(call.audit_token_copied)for(auto word:call.audit_token)token.ArrayItems().push_back(JsonValue::Number(std::to_string(word)));
        item.Set("audit_token",std::move(token));
        item.Set("errno",JsonValue::Number(std::to_string(call.error)));code_sign_calls.ArrayItems().push_back(std::move(item));}
    code_sign.Set("call_prefix",std::move(code_sign_calls));result.Set("code_signing",std::move(code_sign));
    auto identities=JsonValue::ObjectValue(),identity_calls=JsonValue::ArrayValue();
    identities.Set("calls",JsonValue::Number(std::to_string(trace.identity_path_calls)));
    for(const auto& call:trace.identity_path_prefix){auto item=JsonValue::ObjectValue(),fsid=JsonValue::ArrayValue();
        for(auto value:call.fsid)fsid.ArrayItems().push_back(JsonValue::Number(std::to_string(value)));
        item.Set("fsid",std::move(fsid));item.Set("fsid_copied",JsonValue::Boolean(call.copied));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("object",JsonValue::Number(std::to_string(call.object)));
        item.Set("path",JsonValue::String(call.path));item.Set("errno",JsonValue::Number(std::to_string(call.error)));identity_calls.ArrayItems().push_back(std::move(item));}
    identities.Set("call_prefix",std::move(identity_calls));result.Set("identity_paths",std::move(identities));
    auto metadata=JsonValue::ObjectValue(),metadata_calls=JsonValue::ArrayValue();
    metadata.Set("calls",JsonValue::Number(std::to_string(trace.metadata_calls)));
    for(const auto& call:trace.metadata_prefix){auto item=JsonValue::ObjectValue(),args=JsonValue::ArrayValue();
        for(auto arg:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(arg)));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("selector",JsonValue::Number(std::to_string(call.selector)));
        item.Set("arguments",std::move(args));item.Set("path",JsonValue::String(call.path));item.Set("copied",JsonValue::Boolean(call.copied));
        item.Set("errno",JsonValue::Number(std::to_string(call.error)));item.Set("metadata",call.metadata.ToJson());metadata_calls.ArrayItems().push_back(std::move(item));}
    metadata.Set("call_prefix",std::move(metadata_calls));result.Set("file_metadata",std::move(metadata));
    auto mmap=JsonValue::ObjectValue(),mmap_calls=JsonValue::ArrayValue();mmap.Set("calls",JsonValue::Number(std::to_string(trace.mmap_calls)));
    for(const auto& call:trace.mmap_prefix){auto item=JsonValue::ObjectValue(),args=JsonValue::ArrayValue();for(auto arg:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(arg)));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("arguments",std::move(args));item.Set("address",JsonValue::Number(std::to_string(call.address)));
        item.Set("errno",JsonValue::Number(std::to_string(call.error)));item.Set("source",call.source);mmap_calls.ArrayItems().push_back(std::move(item));}
    mmap.Set("call_prefix",std::move(mmap_calls));result.Set("file_mappings",std::move(mmap));
    result.Set("original_files",guest.files->ToJson());
    auto signatures=JsonValue::ObjectValue(),signature_calls=JsonValue::ArrayValue();
    signatures.Set("calls",JsonValue::Number(std::to_string(trace.signature_calls)));
    for(const auto& call:trace.signature_prefix){auto item=call.evidence.ToJson(),args=JsonValue::ArrayValue(),request=JsonValue::ArrayValue();
        for(auto v:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(v)));
        for(auto v:call.request)request.ArrayItems().push_back(JsonValue::Number(std::to_string(v)));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("arguments",std::move(args));item.Set("request",std::move(request));
        item.Set("errno",JsonValue::Number(std::to_string(call.error)));item.Set("copied",JsonValue::Boolean(call.copied));signature_calls.ArrayItems().push_back(std::move(item));}
    signatures.Set("call_prefix",std::move(signature_calls));result.Set("file_signatures",std::move(signatures));
    auto libraries=JsonValue::ObjectValue(),library_calls=JsonValue::ArrayValue();libraries.Set("calls",JsonValue::Number(std::to_string(trace.library_calls)));
    for(const auto& call:trace.library_prefix){auto item=call.evidence,args=JsonValue::ArrayValue(),request=JsonValue::ArrayValue();
        for(auto v:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(v)));
        for(auto v:call.request)request.ArrayItems().push_back(JsonValue::Number(std::to_string(v)));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("arguments",std::move(args));item.Set("request",std::move(request));
        item.Set("errno",JsonValue::Number(std::to_string(call.error)));item.Set("reason",JsonValue::String(call.reason));
        item.Set("message_bytes",JsonValue::Number(std::to_string(call.message_bytes)));library_calls.ArrayItems().push_back(std::move(item));}
    libraries.Set("call_prefix",std::move(library_calls));result.Set("library_validation",std::move(libraries));
    auto unhandled_fcntls=JsonValue::ArrayValue();for(const auto& call:trace.unhandled_fcntl_prefix){auto item=JsonValue::ObjectValue(),args=JsonValue::ArrayValue(),request=JsonValue::ArrayValue();
        for(auto v:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(v)));
        for(auto v:call.request)request.ArrayItems().push_back(JsonValue::Number(std::to_string(v)));
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("arguments",std::move(args));item.Set("request",std::move(request));
        item.Set("request_read",JsonValue::Boolean(call.request_read));item.Set("errno",JsonValue::Number(std::to_string(call.error)));
        item.Set("observational_only",JsonValue::Boolean(true));unhandled_fcntls.ArrayItems().push_back(std::move(item));}
    result.Set("unhandled_fcntl_prefix",std::move(unhandled_fcntls));
    const auto file_call_json=[](const BootstrapTrace::FileCall& call){auto item=JsonValue::ObjectValue(),args=JsonValue::ArrayValue();
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("selector",JsonValue::Number(std::to_string(call.selector)));
        for(const auto value:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(value)));item.Set("arguments",std::move(args));
        item.Set("value",JsonValue::Number(std::to_string(call.value)));item.Set("errno",JsonValue::Number(std::to_string(call.error)));return item;};
    auto file_calls=JsonValue::ArrayValue();for(std::size_t i=0;i<trace.file_prefix_size;++i)file_calls.ArrayItems().push_back(file_call_json(trace.file_prefix[i]));
    result.Set("file_call_prefix",std::move(file_calls));
    auto file_summary=JsonValue::ArrayValue();for(const auto& [selector,entry]:trace.file_by_selector){auto item=file_call_json(entry.second);
        item.Set("calls",JsonValue::Number(std::to_string(entry.first)));file_summary.ArrayItems().push_back(std::move(item));}
    result.Set("file_call_summary",std::move(file_summary));
    for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{{"instruction_callbacks",trace.callbacks},{"instruction_limit",instruction_limit},
        {"stop_pc",stop_pc},{"last_instruction_pc",trace.last_pc},{"last_instruction_opcode",trace.last_opcode},{"interrupt",trace.interrupt},
        {"memory_type",static_cast<std::uint64_t>(trace.memory_type)},{"memory_address",trace.memory_address},{"memory_size",static_cast<std::uint64_t>(trace.memory_size)},
        {"syscall_selector",trace.syscall_selector}})result.Set(key,JsonValue::Number(std::to_string(value)));
    auto capabilities=JsonValue::ObjectValue();
    capabilities.Set("address",JsonValue::Number(std::to_string(BootstrapTrace::commpage_address)));
    capabilities.Set("user_timebase",JsonValue::Number("0"));capabilities.Set("continuous_hardware_clock",JsonValue::Boolean(false));
    capabilities.Set("approximate_shared_time",JsonValue::Boolean(BootstrapTrace::approximate_time_supported!=0));
    capabilities.Set("cpu_capabilities64",JsonValue::Number(std::to_string(BootstrapTrace::cpu_capabilities64)));
    capabilities.Set("dit_supported",JsonValue::Boolean(false));
    capabilities.Set("read_only",JsonValue::Boolean(true));capabilities.Set("unknown_fields_rejected",JsonValue::Boolean(true));
    capabilities.Set("validated_reads",JsonValue::Number(std::to_string(trace.commpage_reads)));result.Set("commpage",std::move(capabilities));
    auto geometry=JsonValue::ObjectValue();
    geometry.Set("ro_address",JsonValue::Number(std::to_string(BootstrapTrace::commpage_ro_address)));
    geometry.Set("page_size",JsonValue::Number(std::to_string(page_size)));
    geometry.Set("kernel_page_shift",JsonValue::Number(std::to_string(trace.page_shift)));
    geometry.Set("user_page_shift",JsonValue::Number(std::to_string(trace.page_shift)));
    geometry.Set("derived_from_owned_stack",JsonValue::Boolean((1ULL<<trace.page_shift)==trace.stack.PageSize()));
    geometry.Set("kernel_reads",JsonValue::Number(std::to_string(trace.kernel_page_reads)));
    geometry.Set("user_reads",JsonValue::Number(std::to_string(trace.user_page_reads)));
    geometry.Set("legacy_aliases_published",JsonValue::Boolean(true));
    auto geometry_reads=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.geometry_prefix_size;++i){const auto& read=trace.geometry_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(read.pc)));item.Set("address",JsonValue::Number(std::to_string(read.address)));
        item.Set("value",JsonValue::Number(std::to_string(read.value)));geometry_reads.ArrayItems().push_back(std::move(item));}
    geometry.Set("read_prefix",std::move(geometry_reads));
    result.Set("commpage_geometry",std::move(geometry));
    auto debugger=JsonValue::ObjectValue(),debugger_reads=JsonValue::ArrayValue();
    debugger.Set("kernel_debugger_available",JsonValue::Boolean(false));
    debugger.Set("flags",JsonValue::Number(std::to_string(BootstrapTrace::debugger_flags)));
    debugger.Set("source",JsonValue::String("native-runtime-debugger-policy"));
    debugger.Set("legacy_address",JsonValue::Number(std::to_string(BootstrapTrace::commpage_address+0x84)));
    debugger.Set("ro_address",JsonValue::Number(std::to_string(BootstrapTrace::commpage_ro_address+0x84)));
    debugger.Set("reads",JsonValue::Number(std::to_string(trace.debugger_reads)));
    for(std::size_t i=0;i<trace.debugger_prefix_size;++i){const auto& read=trace.debugger_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(read.pc)));item.Set("address",JsonValue::Number(std::to_string(read.address)));
        item.Set("size",JsonValue::Number(std::to_string(read.size)));item.Set("value",JsonValue::Number(std::to_string(read.value)));
        debugger_reads.ArrayItems().push_back(std::move(item));}
    debugger.Set("read_prefix",std::move(debugger_reads));result.Set("debugger_capability",std::move(debugger));
    auto kdebug=JsonValue::ObjectValue();kdebug.Set("flags",JsonValue::Number(std::to_string(BootstrapTrace::kdebug_flags)));
    kdebug.Set("validated_reads",JsonValue::Number(std::to_string(trace.kdebug_reads)));
    kdebug.Set("collector_registered",JsonValue::Boolean(false));result.Set("kdebug",std::move(kdebug));
    auto atm=JsonValue::ObjectValue(),atm_reads=JsonValue::ArrayValue();
    atm.Set("diagnostic_config",JsonValue::Number(std::to_string(BootstrapTrace::atm_diagnostic_config)));
    atm.Set("source",JsonValue::String("native-provider-disabled; XNU ATM_TRACE_DISABLE"));
    atm.Set("collector_registered",JsonValue::Boolean(false));atm.Set("configuration_mutation_supported",JsonValue::Boolean(false));
    atm.Set("legacy_mapping_only",JsonValue::Boolean(true));atm.Set("validated_reads",JsonValue::Number(std::to_string(trace.atm_reads)));
    for(std::size_t i=0;i<trace.atm_prefix_size;++i){const auto& read=trace.atm_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(read.pc)));item.Set("address",JsonValue::Number(std::to_string(read.address)));
        item.Set("size",JsonValue::Number(std::to_string(read.size)));item.Set("value",JsonValue::Number(std::to_string(read.value)));atm_reads.ArrayItems().push_back(std::move(item));}
    atm.Set("read_prefix",std::move(atm_reads));result.Set("atm_logging",std::move(atm));
    auto dof=JsonValue::ObjectValue();dof.Set("enabled",JsonValue::Boolean(BootstrapTrace::dtrace_dof_enabled!=0));
    dof.Set("validated_reads",JsonValue::Number(std::to_string(trace.dof_reads)));result.Set("dtrace_dof",std::move(dof));
    auto aprr=JsonValue::ObjectValue();aprr.Set("supported",JsonValue::Boolean(BootstrapTrace::aprr_support!=0));
    aprr.Set("validated_reads",JsonValue::Number(std::to_string(trace.aprr_reads)));result.Set("aprr",std::move(aprr));
    auto multiuser=JsonValue::ObjectValue();multiuser.Set("config",JsonValue::Number(std::to_string(BootstrapTrace::multiuser_config)));
    multiuser.Set("validated_reads",JsonValue::Number(std::to_string(trace.multiuser_reads)));result.Set("multiuser",std::move(multiuser));
    auto quiescent=JsonValue::ObjectValue();quiescent.Set("counter",JsonValue::Number(std::to_string(BootstrapTrace::quiescent_counter)));
    quiescent.Set("validated_reads",JsonValue::Number(std::to_string(trace.quiescent_counter_reads)));result.Set("quiescent_counter",std::move(quiescent));
    auto clocks=JsonValue::ObjectValue();clocks.Set("tick_nanoseconds",JsonValue::Number("100"));
    clocks.Set("approximate_counter_publisher_registered",JsonValue::Boolean(false));
    clocks.Set("approximate_capability_reads",JsonValue::Number(std::to_string(trace.approximate_reads)));
    auto approximate_reads=JsonValue::ArrayValue();for(std::size_t i=0;i<trace.approximate_prefix_size;++i){
        const auto& read=trace.approximate_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(read.pc)));item.Set("address",JsonValue::Number(std::to_string(read.address)));
        item.Set("size",JsonValue::Number(std::to_string(read.size)));item.Set("value",JsonValue::Number(std::to_string(read.value)));approximate_reads.ArrayItems().push_back(std::move(item));}
    clocks.Set("approximate_capability_read_prefix",std::move(approximate_reads));
    auto boot_epoch=trace.boot_epoch.ToJson();boot_epoch.Set("reads",JsonValue::Number(std::to_string(trace.boottime_reads)));
    auto boot_reads=JsonValue::ArrayValue();for(std::size_t i=0;i<trace.boottime_prefix_size;++i){const auto& read=trace.boottime_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(read.pc)));item.Set("address",JsonValue::Number(std::to_string(read.address)));item.Set("value",JsonValue::Number(std::to_string(read.value)));boot_reads.ArrayItems().push_back(std::move(item));}
    boot_epoch.Set("read_prefix",std::move(boot_reads));result.Set("boot_clock_epoch",std::move(boot_epoch));
    auto entropy=JsonValue::ObjectValue();entropy.Set("source",JsonValue::String("Windows-BCryptGenRandom-system-preferred"));entropy.Set("calls",JsonValue::Number(std::to_string(trace.entropy_calls)));
    auto entropy_calls=JsonValue::ArrayValue();for(const auto& call:trace.entropy_prefix){auto item=JsonValue::ObjectValue();
        item.Set("pc", JsonValue::Number(std::to_string(call.pc)));
        item.Set("address", JsonValue::Number(std::to_string(call.address)));
        item.Set("size", JsonValue::Number(std::to_string(call.size)));
        item.Set("errno", JsonValue::Number(std::to_string(call.error)));
        item.Set("generated", JsonValue::Boolean(call.generated));
        item.Set("copied", JsonValue::Boolean(call.copied));
        entropy_calls.ArrayItems().push_back(std::move(item));
    }
    entropy.Set("call_prefix",std::move(entropy_calls));result.Set("entropy",std::move(entropy));
    auto calendar=JsonValue::ObjectValue();calendar.Set("snapshot_active",JsonValue::Boolean(false));calendar.Set("snapshot_reads",JsonValue::Number(std::to_string(trace.calendar_snapshot_reads)));
    calendar.Set("calls",JsonValue::Number(std::to_string(trace.calendar_calls)));calendar.Set("timezone_supported",JsonValue::Boolean(false));calendar.Set("calendar_adjustment_tracking",JsonValue::Boolean(false));
    auto calendar_calls=JsonValue::ArrayValue();for(const auto& call:trace.calendar_prefix){auto item=call.sample.ToJson();auto args=JsonValue::ArrayValue();for(auto arg:call.args)args.ArrayItems().push_back(JsonValue::Number(std::to_string(arg)));
        item.Set("arguments", std::move(args));
        item.Set("pc", JsonValue::Number(std::to_string(call.pc)));
        item.Set("errno", JsonValue::Number(std::to_string(call.error)));
        item.Set("timeval_copied", JsonValue::Boolean(call.timeval_copied));
        item.Set("absolute_copied", JsonValue::Boolean(call.absolute_copied));
        calendar_calls.ArrayItems().push_back(std::move(item));
    }
    calendar.Set("call_prefix",std::move(calendar_calls));result.Set("calendar",std::move(calendar));
    for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{{"timebase_reads",trace.timebase_reads},
        {"continuous_bias",trace.continuous_bias},{"absolute_calls",trace.absolute_calls},{"continuous_calls",trace.continuous_calls},
        {"absolute_first",trace.absolute_first},{"absolute_last",trace.absolute_last},
        {"continuous_first",trace.continuous_first},{"continuous_last",trace.continuous_last}})clocks.Set(key,JsonValue::Number(std::to_string(value)));
    clocks.Set("timebase_info_service_implemented",JsonValue::Boolean(true));result.Set("clocks",std::move(clocks));
    auto timebase=JsonValue::ObjectValue(),timebase_calls=JsonValue::ArrayValue();
    timebase.Set("numerator",JsonValue::Number(std::to_string(DarwinClockTimebase::Numerator)));timebase.Set("denominator",JsonValue::Number(std::to_string(DarwinClockTimebase::Denominator)));
    timebase.Set("calls",JsonValue::Number(std::to_string(trace.timebase_calls)));timebase.Set("copyout_failures",JsonValue::Number(std::to_string(trace.timebase_copyout_failures)));
    timebase.Set("copyout_error_return",JsonValue::String("XNU-pinned-KERN_SUCCESS; copied=false remains explicit"));
    for(std::size_t n=0;n<trace.timebase_prefix_size;++n){const auto& call=trace.timebase_prefix[n];auto row=JsonValue::ObjectValue();
        row.Set("pc",JsonValue::Number(std::to_string(call.pc)));row.Set("selector",JsonValue::Number(std::to_string(call.selector)));row.Set("address",JsonValue::Number(std::to_string(call.address)));
        row.Set("copied",JsonValue::Boolean(call.copied));row.Set("readback_verified",JsonValue::Boolean(call.readback_verified));row.Set("result",JsonValue::Number("0"));timebase_calls.ArrayItems().push_back(std::move(row));}
    timebase.Set("call_prefix",std::move(timebase_calls));result.Set("timebase_info",std::move(timebase));
    auto clock_prefix=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.clock_prefix_size;++i){const auto& call=trace.clock_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("selector",JsonValue::Number(std::to_string(call.selector)));
        item.Set("ticks",JsonValue::Number(std::to_string(call.ticks)));clock_prefix.ArrayItems().push_back(std::move(item));}
    result.Set("clock_call_prefix",std::move(clock_prefix));
    auto vm_regions=JsonValue::ObjectValue(),vm_region_prefix=JsonValue::ArrayValue(),vm_mig_calls=JsonValue::ArrayValue();
    std::size_t overlap_count=0;for(std::size_t n=0;n<trace.vm_allocations.size();++n)for(std::size_t k=n+1;k<trace.vm_allocations.size();++k){
        const auto& a=trace.vm_allocations[n];const auto& b=trace.vm_allocations[k];if(a.address<b.address+b.size&&b.address<a.address+a.size)++overlap_count;}
    vm_regions.Set("overlap_count",JsonValue::Number(std::to_string(overlap_count)));vm_regions.Set("overlap_audit_scope",JsonValue::String("all-tracked-logical-regions; untracked-image/stack/cache-mappings-excluded"));
    vm_regions.Set("region_count",JsonValue::Number(std::to_string(trace.vm_allocations.size())));
    vm_regions.Set("mig_calls",JsonValue::Number(std::to_string(trace.vm_mig_calls)));
    for(std::size_t n=0;n<std::min<std::size_t>(32,trace.vm_allocations.size());++n){const auto& region=trace.vm_allocations[n];auto item=JsonValue::ObjectValue();
        for (const auto& [key, value] :
             std::array<std::pair<const char*, std::uint64_t>, 7>{{{"address", region.address},
                                                                   {"size", region.size},
                                                                   {"current_protection", region.current_protection},
                                                                   {"maximum_protection", region.maximum_protection},
                                                                   {"tag", region.tag},
                                                                   {"inheritance", region.inheritance},
                                                                   {"backing_offset", region.backing_offset}}})
            item.Set(key, JsonValue::Number(std::to_string(value)));
        item.Set("anonymous_backing_lease",JsonValue::Boolean(bool(region.host_memory)));item.Set("file_backing_lease",JsonValue::Boolean(bool(region.file_mapping)));vm_region_prefix.ArrayItems().push_back(std::move(item));}
    for(const auto& call:trace.vm_mig_prefix){auto item=JsonValue::ObjectValue();
        for (const auto& [key, value] :
             std::array<std::pair<const char*, std::uint64_t>, 8>{{{"pc", call.pc},
                                                                   {"size", call.size},
                                                                   {"address", call.address},
                                                                   {"flags", call.flags},
                                                                   {"current_protection", call.current},
                                                                   {"maximum_protection", call.maximum},
                                                                   {"tag", call.tag},
                                                                   {"result", call.result}}})
            item.Set(key, JsonValue::Number(std::to_string(value)));
        vm_mig_calls.ArrayItems().push_back(std::move(item));}
    vm_regions.Set("region_prefix",std::move(vm_region_prefix));vm_regions.Set("mig_call_prefix",std::move(vm_mig_calls));result.Set("vm_regions",std::move(vm_regions));
    auto task_state=JsonValue::ObjectValue();const auto& task=*guest.task;const auto& entry=task.ports[task.self_name>>8];
    const auto* resolved=task.ResolveSend(task.self_name);
    task_state.Set("self_name",JsonValue::Number(std::to_string(task.self_name)));
    task_state.Set("self_calls",JsonValue::Number(std::to_string(trace.task_self_calls)));
    task_state.Set("host_self_calls",JsonValue::Number(std::to_string(trace.host_self_calls)));
    task_state.Set("vm_protect_calls",JsonValue::Number(std::to_string(trace.vm_protect_calls)));
    task_state.Set("vm_map_calls",JsonValue::Number(std::to_string(trace.vm_map_calls)));
    task_state.Set("send_user_refs",JsonValue::Number(std::to_string(entry.send_refs)));
    task_state.Set("port_type",JsonValue::Number(std::to_string(entry.type)));task_state.Set("pinned",JsonValue::Boolean(entry.pinned));
    task_state.Set("resolves_to_guest",JsonValue::Boolean(resolved&&resolved->owner==&guest&&resolved->owner->engine.value==engine));
    task_state.Set("invalid_names_rejected",JsonValue::Boolean(!task.ResolveSend(0)&&!task.ResolveSend(0xffffffff)
        &&!task.ResolveSend(task.self_name^1)&&!task.ResolveSend(task.self_name+0x100)));
    task_state.Set("mapped_images",JsonValue::Number(std::to_string(resolved?resolved->owner->mapped->ImageCount():0)));
    auto task_prefix=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.task_prefix_size;++i){const auto& call=trace.task_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("selector",JsonValue::Number(std::to_string(call.selector)));
        item.Set("port",JsonValue::Number(std::to_string(call.port)));task_prefix.ArrayItems().push_back(std::move(item));}
    task_state.Set("call_prefix",std::move(task_prefix));
    auto vm_protect_calls=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.vm_protect_prefix_size;++i){const auto& call=trace.vm_protect_prefix[i];auto item=JsonValue::ObjectValue();
        for (const auto& [key, value] :
             std::array<std::pair<const char*, std::uint64_t>, 8>{{{"pc", call.pc},
                                                                   {"selector", call.selector},
                                                                   {"target", call.target},
                                                                   {"address", call.address},
                                                                   {"size", call.size},
                                                                   {"set_max", call.set_max},
                                                                   {"prot", call.prot},
                                                                   {"result", call.result}}})
            item.Set(key, JsonValue::Number(std::to_string(value)));
        vm_protect_calls.ArrayItems().push_back(std::move(item));}
    task_state.Set("vm_protect_prefix",std::move(vm_protect_calls));
    auto vm_map_calls=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.vm_map_prefix_size;++i){const auto& call=trace.vm_map_prefix[i];auto item=JsonValue::ObjectValue();
        for (const auto& [key, value] :
             std::array<std::pair<const char*, std::uint64_t>, 8>{{{"pc", call.pc},
                                                                   {"selector", call.selector},
                                                                   {"target", call.target},
                                                                   {"address", call.address},
                                                                   {"size", call.size},
                                                                   {"flags", call.flags},
                                                                   {"prot", call.prot},
                                                                   {"result", call.result}}})
            item.Set(key, JsonValue::Number(std::to_string(value)));
        vm_map_calls.ArrayItems().push_back(std::move(item));}
    auto last_vm_map=JsonValue::ObjectValue();if(trace.vm_map_calls){const auto& call=trace.vm_map_last;
        for (const auto& [key, value] :
             std::array<std::pair<const char*, std::uint64_t>, 9>{{{"pc", call.pc},
                                                                   {"selector", call.selector},
                                                                   {"target", call.target},
                                                                   {"address", call.address},
                                                                   {"mapped_address", call.mapped_address},
                                                                   {"size", call.size},
                                                                   {"flags", call.flags},
                                                                   {"prot", call.prot},
                                                                   {"result", call.result}}})
            last_vm_map.Set(key, JsonValue::Number(std::to_string(value)));
    }
    task_state.Set("vm_map_last",std::move(last_vm_map));
    task_state.Set("vm_map_prefix",std::move(vm_map_calls));
    auto restartable=JsonValue::ObjectValue(),ranges=JsonValue::ArrayValue();
    restartable.Set("register_calls",JsonValue::Number(std::to_string(task.restartable_register_calls)));
    restartable.Set("synchronize_calls",JsonValue::Number(std::to_string(task.restartable_sync_calls)));
    restartable.Set("guest_threads",JsonValue::Number(std::to_string(task.LiveThreadCount())));
    restartable.Set("multithread_synchronization_supported",JsonValue::Boolean(false));
    restartable.Set("policy",JsonValue::String("release-XNU-single-registration; calling-thread-excluded-from-synchronization"));
    for(std::size_t i=0;i<task.restartable_count;++i){const auto& r=task.restartable_ranges[i];auto row=JsonValue::ObjectValue();
        row.Set("location",JsonValue::Number(std::to_string(r.location)));row.Set("length",JsonValue::Number(std::to_string(r.length)));
        row.Set("recovery_offset",JsonValue::Number(std::to_string(r.recovery)));row.Set("flags",JsonValue::Number(std::to_string(r.flags)));ranges.ArrayItems().push_back(std::move(row));}
    restartable.Set("ranges",std::move(ranges));result.Set("restartable_ranges",std::move(restartable));
    result.Set("mach_task",std::move(task_state));
    auto port_state=JsonValue::ObjectValue();
    port_state.Set("reply_calls",JsonValue::Number(std::to_string(trace.reply_calls)));
    port_state.Set("mod_refs_calls",JsonValue::Number(std::to_string(trace.mod_refs_calls)));
    port_state.Set("deallocate_calls",JsonValue::Number(std::to_string(trace.deallocate_calls)));
    port_state.Set("guard_delivery_implemented",JsonValue::Boolean(false));
    auto rights_calls=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.rights_prefix_size;++i){const auto& call=trace.rights_prefix[i];auto item=JsonValue::ObjectValue();
        for (const auto& [key, value] :
             std::array<std::pair<const char*, std::uint64_t>, 10>{{{"pc", call.pc},
                                                                    {"selector", call.selector},
                                                                    {"target", call.target},
                                                                    {"name", call.name},
                                                                    {"right", call.right},
                                                                    {"delta", call.delta},
                                                                    {"result", call.result},
                                                                    {"before_refs", call.before_refs},
                                                                    {"after_refs", call.after_refs},
                                                                    {"nzcv", call.nzcv}}})
            item.Set(key, JsonValue::Number(std::to_string(value)));
        rights_calls.ArrayItems().push_back(std::move(item));}
    port_state.Set("rights_call_prefix",std::move(rights_calls));
    port_state.Set("thread_calls",JsonValue::Number(std::to_string(trace.thread_calls)));
    port_state.Set("special_reply_calls",JsonValue::Number(std::to_string(trace.special_reply_calls)));
    port_state.Set("port_construct_calls",JsonValue::Number(std::to_string(trace.port_construct_calls)));
    port_state.Set("namespace_entries",JsonValue::Number(std::to_string(task.ports.size()-1)));
    const auto* current_thread=task.CurrentThread();
    port_state.Set("thread_self_name",JsonValue::Number(std::to_string(current_thread?current_thread->control_name:0)));
    port_state.Set("thread_binding_agrees",JsonValue::Boolean(current_thread&&current_thread->task==&task&&task.owner==&guest&&task.owner->engine.value==engine));
    port_state.Set("special_reply_name",JsonValue::Number(std::to_string(current_thread?current_thread->special_reply_name:0)));
    port_state.Set("ipc_service_implemented",JsonValue::Boolean(false));
    auto port_prefix=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.port_prefix_size;++i){const auto& call=trace.port_prefix[i];auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(call.pc)));item.Set("selector",JsonValue::Number(std::to_string(call.selector)));
        item.Set("port",JsonValue::Number(std::to_string(call.port)));port_prefix.ArrayItems().push_back(std::move(item));}
    port_state.Set("call_prefix",std::move(port_prefix));
    auto port_entries=JsonValue::ArrayValue();std::size_t receives=0,bound_special=0;
    for(std::size_t i=1;i<task.ports.size();++i){const auto& port=task.ports[i];
        if(port.type&0x20000)++receives;
        if(port.thread_bound)++bound_special;
        if(i>32)continue;
        const auto name=(static_cast<std::uint32_t>(i)<<8)|port.generation;
        auto item=JsonValue::ObjectValue();item.Set("name",JsonValue::Number(std::to_string(name)));
        item.Set("dead_refs",JsonValue::Number(std::to_string(port.dead_refs)));
        item.Set("type",JsonValue::Number(std::to_string(port.type)));item.Set("send_refs",JsonValue::Number(std::to_string(port.send_refs)));
        const char* kind = port.object == MachTask::Object::Task        ? "task"
                           : port.object == MachTask::Object::Thread    ? "thread"
                           : port.object == MachTask::Object::Reply     ? "reply"
                           : port.object == MachTask::Object::Host      ? "host"
                           : port.object == MachTask::Object::Clock     ? "clock"
                           : port.object == MachTask::Object::Semaphore ? "semaphore"
                                                                        : "special_reply";
        item.Set("object",JsonValue::String(kind));item.Set("pinned",JsonValue::Boolean(port.pinned));
        item.Set("bound_to_thread",JsonValue::Boolean(port.thread_bound));item.Set("queue_size",JsonValue::Number(std::to_string(port.messages.size())));
        item.Set("bound_thread_id",JsonValue::Number(std::to_string(port.thread_object&&port.thread_object->task==&task?port.thread_object->id:0)));
        item.Set("resolves_actual_owner",JsonValue::Boolean(task.Resolve(name)==&port&&port.task->owner==&guest));
        item.Set("invalid_generation_rejected",JsonValue::Boolean(!task.Resolve(name^1)));
        item.Set("resolves_as_task_send",JsonValue::Boolean(task.ResolveSend(name)==&task));
        item.Set("resolves_as_thread_send",JsonValue::Boolean(task.ResolveThread(name)&&task.ResolveThread(name)==port.thread_object));
        port_entries.ArrayItems().push_back(std::move(item));}
    port_state.Set("receive_rights",JsonValue::Number(std::to_string(receives)));
    port_state.Set("bound_special_replies",JsonValue::Number(std::to_string(bound_special)));
    port_state.Set("entry_prefix",std::move(port_entries));result.Set("mach_ports",std::move(port_state));
    auto identity=JsonValue::ObjectValue();
    identity.Set("thread_id",JsonValue::Number(std::to_string(current_thread?current_thread->id:0)));
    identity.Set("tsd_base",JsonValue::Number(std::to_string(current_thread?current_thread->tsd_base:0)));
    identity.Set("selfid_calls",JsonValue::Number(std::to_string(trace.selfid_calls)));
    identity.Set("crossarch_calls",JsonValue::Number(std::to_string(trace.crossarch_calls)));
    identity.Set("csrctl_calls",JsonValue::Number(std::to_string(trace.csr_calls)));
    identity.Set("shared_region_calls",JsonValue::Number(std::to_string(trace.shared_region_calls)));
    identity.Set("getpid_calls",JsonValue::Number(std::to_string(trace.getpid_calls)));
    identity.Set("proc_info_calls",JsonValue::Number(std::to_string(trace.proc_info_calls)));
    identity.Set("munmap_calls",JsonValue::Number(std::to_string(trace.munmap_calls)));
    identity.Set("mprotect_calls",JsonValue::Number(std::to_string(trace.mprotect_calls)));
    identity.Set("sigprocmask_calls",JsonValue::Number(std::to_string(trace.sigprocmask_calls)));
    auto credentials=JsonValue::ObjectValue();credentials.Set("source",JsonValue::String("Windows-effective-token; existing-native-stat64-SID-realm"));
    credentials.Set("uid",JsonValue::Number(std::to_string(task.credentials.uid)));credentials.Set("euid",JsonValue::Number(std::to_string(task.credentials.uid)));
    credentials.Set("gid",JsonValue::Number(std::to_string(task.credentials.gid)));credentials.Set("egid",JsonValue::Number(std::to_string(task.credentials.gid)));
    auto groups=JsonValue::ArrayValue();for(const auto id:task.credentials.groups)groups.ArrayItems().push_back(JsonValue::Number(std::to_string(id)));
    credentials.Set("groups",std::move(groups));credentials.Set("calls",JsonValue::Number(std::to_string(trace.credential_calls)));
    credentials.Set("set_id_transitions_supported",JsonValue::Boolean(false));result.Set("credentials",std::move(credentials));
    identity.Set("bsdthread_register_calls",JsonValue::Number(std::to_string(trace.bsdthread_register_calls)));
    auto registration=JsonValue::ObjectValue(),registration_args=JsonValue::ArrayValue();
    for(const auto arg:trace.pthread_arguments)registration_args.ArrayItems().push_back(JsonValue::Number(std::to_string(arg)));
    registration.Set("arguments",std::move(registration_args));registration.Set("calls",JsonValue::Number(std::to_string(trace.bsdthread_register_calls)));
    registration.Set("input_decoded",JsonValue::Boolean(trace.pthread_input_decoded));
    registration.Set("entries_converted",JsonValue::Boolean(trace.pthread_entries_converted));
    registration.Set("entry_conversion_backend_error",JsonValue::Number(std::to_string(trace.pthread_entry_auth_error)));
    registration.Set("converted_thread_start",JsonValue::Number(std::to_string(trace.pthread_converted_entries[0])));
    registration.Set("converted_wqthread",JsonValue::Number(std::to_string(trace.pthread_converted_entries[1])));
    registration.Set("conversion_certifies_authentication",JsonValue::Boolean(false));
    registration.Set("decode_errno",JsonValue::Number(std::to_string(trace.pthread_decode_error)));
    registration.Set("known_wire_bytes",JsonValue::Number(std::to_string(DarwinPthreadRegistrationBytes)));
    registration.Set("input_version",JsonValue::Number(std::to_string(trace.pthread_input.input_version)));
    registration.Set("copyin_bytes",JsonValue::Number(std::to_string(trace.pthread_input.copied_bytes)));
    registration.Set("unknown_tail_bytes",JsonValue::Number(std::to_string(trace.pthread_input.unknown_tail_bytes)));
    registration.Set("registration_committed",JsonValue::Boolean(trace.pthread_registration_committed));
    registration.Set("output_copied",JsonValue::Boolean(trace.pthread_output_copied));
    registration.Set("output_readback_verified",JsonValue::Boolean(trace.pthread_output_verified));
    registration.Set("registration_errno",JsonValue::Number(std::to_string(trace.pthread_registration_error)));
    auto output_prefix=JsonValue::ArrayValue();
    if(trace.pthread_output_verified)for(std::size_t n=0;n<trace.pthread_input.copied_bytes;++n)
        output_prefix.ArrayItems().push_back(JsonValue::Number(std::to_string(trace.pthread_output_readback[n])));
    registration.Set("output_wire_prefix",std::move(output_prefix));
    registration.Set("capabilities_available",JsonValue::Number(std::to_string(trace.pthread_available_features)));
    registration.Set("feature_return_completed",JsonValue::Boolean(trace.pthread_features_returned));
    if(!trace.pthread_available_features){
        registration.Set("missing_capabilities",JsonValue::ArrayValue({JsonValue::String("FINEPRIO"),JsonValue::String("BSDTHREADCTL"),
            JsonValue::String("SETSELF"),JsonValue::String("QOS_MAINTENANCE"),JsonValue::String("QOS_DEFAULT")}));
    }else{
        registration.Set("missing_capabilities",JsonValue::ArrayValue());
    }
    auto offsets=JsonValue::ObjectValue();
    offsets.Set("tsd",JsonValue::Number(std::to_string(trace.pthread_input.tsd_offset)));
    offsets.Set("maximum_tsd_offset",JsonValue::Number(std::to_string(trace.pthread_input.max_tsd_offset)));
    offsets.Set("dispatch_queue",JsonValue::Number(std::to_string(trace.pthread_input.dispatch_queue_offset)));
    offsets.Set("return_to_kernel",JsonValue::Number(std::to_string(trace.pthread_input.return_to_kernel_offset)));
    offsets.Set("mach_thread_self",JsonValue::Number(std::to_string(trace.pthread_input.mach_thread_self_offset)));
    offsets.Set("workqueue_quantum_expiry",JsonValue::Number(std::to_string(trace.pthread_input.wq_quantum_expiry_offset)));
    registration.Set("normalized_offsets",std::move(offsets));result.Set("pthread_registration",std::move(registration));

    identity.Set("shm_open_calls",JsonValue::Number(std::to_string(trace.shm_open_calls)));
    identity.Set("shm_unlink_calls",JsonValue::Number(std::to_string(trace.shm_unlink_calls)));
    identity.Set("threadstart",JsonValue::Number(std::to_string(task.pthread_registration.thread_start)));
    identity.Set("wqthread",JsonValue::Number(std::to_string(task.pthread_registration.workqueue_start)));
    identity.Set("thread_flags",JsonValue::Number("0"));
    identity.Set("stack_addr_hint",JsonValue::Number(std::to_string(task.pthread_registration.stack_addr_hint)));
    identity.Set("targetconc_ptr",JsonValue::Number("0"));
    identity.Set("dispatchqueue_offset",JsonValue::Number(std::to_string(task.pthread_registration.input.dispatch_queue_offset)));
    identity.Set("tsd_offset",JsonValue::Number(std::to_string(task.pthread_registration.input.tsd_offset)));
    identity.Set("all_image_info_addr",JsonValue::Number(std::to_string(trace.all_image_info_addr)));
    identity.Set("all_image_info_size",JsonValue::Number(std::to_string(trace.all_image_info_size)));
    identity.Set("shared_region_start",JsonValue::Number(std::to_string(guest.mapped->SharedRegionStart())));
    identity.Set("csr_config",JsonValue::Number(std::to_string(BootstrapTrace::csr_config)));
    identity.Set("platform_calls",JsonValue::Number(std::to_string(trace.platform_calls)));
    identity.Set("thread_binding_agrees",JsonValue::Boolean(current_thread&&current_thread->task==&task&&task.owner==&guest&&task.owner->engine.value==engine));
    std::uint64_t tpidrro=0;Uc(uc_reg_read(engine,UC_ARM64_REG_TPIDRRO_EL0,&tpidrro));
    identity.Set("tpidrro_agrees",JsonValue::Boolean(current_thread&&tpidrro==current_thread->tsd_base));
    auto bsd=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.bsd_prefix_size;++i){const auto& c=trace.bsd_prefix[i];auto item=JsonValue::ObjectValue();
        for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{{"pc",c.pc},{"raw_selector",c.raw_selector},
            {"selector",c.selector},{"x0",c.x0},{"x1",c.x1},{"nzcv_before",c.nzcv_before},{"nzcv_after",c.nzcv_after}})
            item.Set(key,JsonValue::Number(std::to_string(value)));
        bsd.ArrayItems().push_back(std::move(item));}
    identity.Set("call_prefix",std::move(bsd));
    auto platform=JsonValue::ArrayValue();
    for(std::size_t i=0;i<trace.platform_prefix_size;++i){const auto& c=trace.platform_prefix[i];auto item=JsonValue::ObjectValue();
        for(const auto& [key,value]:std::vector<std::pair<const char*,std::uint64_t>>{{"pc",c.pc},{"code",c.code},{"input",c.input},{"base",c.base},{"nzcv",c.nzcv}})
            item.Set(key,JsonValue::Number(std::to_string(value)));
        platform.ArrayItems().push_back(std::move(item));}
    identity.Set("platform_prefix",std::move(platform));result.Set("thread_identity",std::move(identity));
    auto flags=JsonValue::ObjectValue();flags.Set("flags",JsonValue::Number(std::to_string(BootstrapTrace::dyld_flags)));
    flags.Set("validated_reads",JsonValue::Number(std::to_string(trace.dyld_flags_reads)));result.Set("dyld_flags",std::move(flags));
    auto registers=JsonValue::ArrayValue();
    for(std::size_t i=0;i<31;++i){const auto reg=i<29?UC_ARM64_REG_X0+static_cast<int>(i):i==29?UC_ARM64_REG_X29:UC_ARM64_REG_X30;
        std::uint64_t actual=0;Uc(uc_reg_read(engine,reg,&actual));registers.ArrayItems().push_back(JsonValue::Number(std::to_string(actual)));}
    result.Set("registers",std::move(registers));
    auto handlers=JsonValue::ArrayValue();
    for(const auto& registration:BootstrapTrace::registrations){auto item=JsonValue::ObjectValue();
        item.Set("selector_id",JsonValue::Number(std::to_string(static_cast<std::int32_t>(registration.selector))));
        item.Set("name",JsonValue::String(registration.name));handlers.ArrayItems().push_back(std::move(item));}
    result.Set("service_manifest",std::move(handlers));
    auto msg2=JsonValue::ArrayValue();
    for(const auto& c:trace.mach_msg2_calls){
        auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(c.pc)));
        item.Set("data",JsonValue::Number(std::to_string(c.data)));
        item.Set("options",JsonValue::Number(std::to_string(c.options)));
        item.Set("send_requested",JsonValue::Boolean((c.options&1)!=0));
        item.Set("receive_requested",JsonValue::Boolean((c.options&2)!=0));
        item.Set("send_size",JsonValue::Number(std::to_string(c.send_size)));
        item.Set("ports",JsonValue::Number(std::to_string(c.ports)));
        item.Set("id",JsonValue::Number(std::to_string(c.id)));
        item.Set("rcv",JsonValue::Number(std::to_string(c.rcv)));
        item.Set("rcv_size",JsonValue::Number(std::to_string(c.rcv_size)));
        item.Set("timeout",JsonValue::Number(std::to_string(c.timeout)));
        auto hex_bytes=JsonValue::ArrayValue();
        for(auto b:c.bytes)hex_bytes.ArrayItems().push_back(JsonValue::Number(std::to_string(b)));
        item.Set("bytes",std::move(hex_bytes));
        msg2.ArrayItems().push_back(std::move(item));
    }
    result.Set("mach_msg2_calls",std::move(msg2));
    result.Set("mach_msg2_call_count",JsonValue::Number(std::to_string(trace.mach_msg2_call_count)));
    auto receive=JsonValue::ObjectValue(),receive_prefix=JsonValue::ArrayValue();
    receive.Set("calls",JsonValue::Number(std::to_string(trace.mach_receive_calls)));
    receive.Set("empty_timeouts",JsonValue::Number(std::to_string(trace.mach_receive_empty_timeouts)));
    receive.Set("invalid_names",JsonValue::Number(std::to_string(trace.mach_receive_invalid_names)));
    receive.Set("unsupported_waits",JsonValue::Number(std::to_string(trace.mach_receive_unsupported_waits)));
    receive.Set("message_delivery_supported",JsonValue::Boolean(false));
    receive.Set("blocking_receive_supported",JsonValue::Boolean(false));
    for(const auto& c:trace.mach_receive_prefix){auto item=JsonValue::ObjectValue();
        item.Set("pc",JsonValue::Number(std::to_string(c.pc)));
        item.Set("options",JsonValue::Number(std::to_string(c.options)));
        item.Set("receive_name",JsonValue::Number(std::to_string(c.receive_name)));
        item.Set("receive_size",JsonValue::Number(std::to_string(c.receive_size)));
        item.Set("timeout",JsonValue::Number(std::to_string(c.timeout)));
        item.Set("normalized_timeout",JsonValue::Number(std::to_string(c.normalized_timeout)));
        item.Set("outcome",JsonValue::String(c.outcome?c.outcome:"unknown"));
        item.Set("result",c.result?JsonValue::Number(std::to_string(*c.result)):JsonValue::Null());
        receive_prefix.ArrayItems().push_back(std::move(item));
    }
    receive.Set("call_prefix",std::move(receive_prefix));result.Set("mach_receive",std::move(receive));
    auto audit=JsonValue::ObjectValue(),security_token=JsonValue::ArrayValue(),audit_token=JsonValue::ArrayValue();
    audit.Set("pid",JsonValue::Number(std::to_string(task.pid)));
    audit.Set("pid_version",JsonValue::Number(std::to_string(task.pid_version)));
    audit.Set("audit_user_id",JsonValue::Number(std::to_string(task.audit_session.auid)));
    audit.Set("audit_session_id",JsonValue::Number(std::to_string(task.audit_session.asid)));
    audit.Set("source",JsonValue::String("task-lifetime generation; immutable Windows SID credentials; XNU default non-login audit session"));
    audit.Set("session_mutation_supported",JsonValue::Boolean(false));
    for(const auto word:BuildDarwinSecurityToken(task.credentials))security_token.ArrayItems().push_back(JsonValue::Number(std::to_string(word)));
    for(const auto word:BuildDarwinAuditToken(task.credentials,task.pid,task.pid_version,task.audit_session))audit_token.ArrayItems().push_back(JsonValue::Number(std::to_string(word)));
    audit.Set("security_token",std::move(security_token));audit.Set("audit_token",std::move(audit_token));
    result.Set("audit_identity",std::move(audit));
    auto task_info=JsonValue::ObjectValue(),task_info_calls=JsonValue::ArrayValue();
    task_info.Set("calls",JsonValue::Number(std::to_string(trace.task_info_calls)));
    task_info.Set("mig_max_words",JsonValue::Number("94"));
    task_info.Set("scope",JsonValue::String("task control identity/security/audit and dyld info; bounded scalar replies; insufficient receive capacity remains an explicit diagnostic"));
    for(std::size_t i=0;i<trace.task_info_prefix_size;++i){const auto& call=trace.task_info_prefix[i];auto row=JsonValue::ObjectValue();
        row.Set("pc",JsonValue::Number(std::to_string(call.pc)));row.Set("target",JsonValue::Number(std::to_string(call.target)));
        row.Set("flavor",JsonValue::Number(std::to_string(call.flavor)));row.Set("input_count",JsonValue::Number(std::to_string(call.input_count)));
        row.Set("normalized_count",JsonValue::Number(std::to_string(call.normalized_count)));row.Set("output_count",JsonValue::Number(std::to_string(call.output_count)));
        row.Set("kern_return",call.result_ready?JsonValue::Number(std::to_string(call.kern_return)):JsonValue::Null());
        row.Set("reply_size",JsonValue::Number(std::to_string(call.reply_size)));row.Set("copyout_bytes",JsonValue::Number(std::to_string(call.copyout_bytes)));
        row.Set("copied",JsonValue::Boolean(call.copied));task_info_calls.ArrayItems().push_back(std::move(row));
    }
    task_info.Set("call_prefix",std::move(task_info_calls));result.Set("task_info",std::move(task_info));
    result.Set("runtime_initialized",JsonValue::Boolean(false));result.Set("execution_validated",JsonValue::Boolean(false));return result;
}
}
DarwinArm64MappingResult MapDarwinArm64Images(const std::string& executable,
    const std::vector<std::filesystem::path>& trees, const DarwinClosureOptions& options, const std::vector<std::string>& plugins,bool prepare_arguments,bool probe_bootstrap,const DarwinProcessStreams& streams) {
    DarwinArm64MappingResult result;
    try {
        std::unique_ptr<DarwinProcessStack> stack;
        Guest guest(executable,trees,options,plugins,streams);
        if(prepare_arguments||probe_bootstrap){
            std::string error;stack=guest.mapped->ProcessStack(executable,{executable},{},{"executable_path="+executable},error);
            Check(bool(stack),error.c_str());
            const auto& frame=stack->Arguments();const auto range=stack->Range();
            Uc(uc_mem_map_ptr(guest.engine.value,range.address,range.size,range.protection,range.host_bytes));
            DarwinProcessThread thread;if(!guest.mapped->ProcessThread(executable,*stack,thread,error))throw std::runtime_error(error);
            Check(thread.cpu==0x0100000c&&thread.original.flavor==6&&thread.original.state_words.size()==68,"Unsupported ARM64 initial thread state.");
            const auto& words=thread.original.state_words;
            const auto pstate=words[66];Check((pstate&~0xf0000000u)==0&&words[67]==0,"Unsupported ARM64 startup status or authenticated thread-state flags.");
            auto initial_words=words;
            const auto initial_sp=frame.kernel_args;
            initial_words[62]=static_cast<std::uint32_t>(initial_sp);initial_words[63]=static_cast<std::uint32_t>(initial_sp>>32);
            initial_words[64]=static_cast<std::uint32_t>(thread.pc);initial_words[65]=static_cast<std::uint32_t>(thread.pc>>32);
            DarwinThreadContext initial_context;Uc(initial_context.InitializeArm64(guest.engine.value,initial_words,0));
            Uc(initial_context.Restore(guest.engine.value));
            auto registers=JsonValue::ArrayValue();
            for(std::size_t i=0;i<31;++i){
                const auto reg=i<29?UC_ARM64_REG_X0+static_cast<int>(i):i==29?UC_ARM64_REG_X29:UC_ARM64_REG_X30;
                const auto value=std::uint64_t(words[i*2])|(std::uint64_t(words[i*2+1])<<32);
                std::uint64_t actual=0;Uc(uc_reg_read(guest.engine.value,reg,&actual));
                Check(actual==value,"ARM64 initial general register readback differs.");registers.ArrayItems().push_back(JsonValue::Number(std::to_string(actual)));
            }

            std::uint32_t actual_pstate=0;std::uint64_t actual_pc=0;
            Uc(uc_reg_read(guest.engine.value,UC_ARM64_REG_PSTATE,&actual_pstate));Uc(uc_reg_read(guest.engine.value,UC_ARM64_REG_PC,&actual_pc));
            Check(actual_pstate==pstate&&actual_pc==thread.pc,"ARM64 startup PC/status readback differs.");
            result.process_thread=thread.ToJson();result.process_thread.Set("general_register_readback",std::move(registers));
            result.process_thread.Set("pc_readback",JsonValue::Number(std::to_string(actual_pc)));
            result.process_thread.Set("pstate_readback",JsonValue::Number(std::to_string(actual_pstate)));
            result.process_thread.Set("register_readback_agrees",JsonValue::Boolean(true));
            const auto sp=frame.kernel_args;
            std::uint64_t readback=0;Uc(uc_reg_read(guest.engine.value,UC_ARM64_REG_SP,&readback));Check(readback==sp&&sp%16==0,"Guest Darwin stack pointer readback differs.");
            std::array<std::uint64_t,2> header{};Uc(uc_mem_read(guest.engine.value,frame.kernel_args,header.data(),sizeof(header)));
            Check(header[0]==frame.main_header&&header[1]==frame.argc,"Guest Darwin argument block readback differs.");
            std::uint8_t guard=0;
            Check(uc_mem_read(guest.engine.value,range.address-1,&guard,1)==UC_ERR_READ_UNMAPPED
                &&uc_mem_read(guest.engine.value,range.address+range.size,&guard,1)==UC_ERR_READ_UNMAPPED,"Guest Darwin stack guard is accessible.");
            result.process_arguments=frame.ToJson();result.process_stack=stack->ToJson();
            result.process_stack.Set("sp_readback",JsonValue::Number(std::to_string(readback)));
            result.process_thread.Set("sp_readback",JsonValue::Number(std::to_string(readback)));
            result.process_stack.Set("guest_guards_unmapped",JsonValue::Boolean(true));
            const auto* apple=reinterpret_cast<const std::uint64_t*>(frame.apple);
            for(std::size_t i=0;i<frame.apple_count;++i){
                std::uint64_t address=0;Uc(uc_mem_read(guest.engine.value,frame.apple+i*8,&address,8));
                Check(address==apple[i],"Guest Darwin Apple-vector pointer differs.");
                const auto* value=reinterpret_cast<const char*>(apple[i]);
                const auto length=std::strlen(value)+1;std::string readback(length,'\0');
                Uc(uc_mem_read(guest.engine.value,address,readback.data(),length));
                Check(std::memcmp(value,readback.data(),length)==0,"Guest Darwin startup string readback differs.");
            }
            result.process_stack.Set("startup_parameter_readback_agrees",JsonValue::Boolean(true));
            if(probe_bootstrap){
                std::string prepare_error;
                Check(guest.mapped->PrepareForDynamicLinkerBootstrap(executable,prepare_error),prepare_error.c_str());
                result.bootstrap=ProbeBootstrap(guest,*stack,thread.pc,options);
                result.diagnostic="Darwin bootstrap stopped: "+result.bootstrap.GetString("stop_reason");}
        }
        result.images=guest.mapped->ImageCount();
        result.ranges=guest.mapped->Ranges().size();
        result.applied_fixups=guest.mapped->AppliedFixups();
        result.weak_bindings=guest.mapped->WeakBindings();
        result.initializers=guest.mapped->Initializers();
        result.initialization_order=guest.mapped->EagerInitializationOrder();
        result.mapped=true;
    } catch(const std::exception& failure) {result.diagnostic=failure.what();}
    return result;
}
DarwinArm64Result RunDarwinArm64Function(const std::string& executable,
    const std::vector<std::filesystem::path>& trees, const std::string& symbol,
    const std::vector<std::uint64_t>& arguments, const DarwinClosureOptions& options, const std::vector<std::string>& plugins) {
    DarwinArm64Result result;
    try {
        Check(arguments.size() <= 8, "ARM64 integer argument register limit exceeded.");
        std::string error;
        Allocation stack;
        Guest guest(executable, trees, options,plugins);
        auto& engine=guest.engine;
        auto& mapped=guest.mapped;
        const auto entry=reinterpret_cast<std::uint64_t>(mapped->Symbol(executable,symbol,error));
        Check(error.empty()&&entry,error.empty()?"ARM64 entry symbol is absent.":error.c_str());
        const auto ranges=mapped->Ranges();
        Check(std::any_of(ranges.begin(),ranges.end(),[&](const auto& range){
            return (range.protection&4)&&entry>=range.address&&entry-range.address<range.size;
        }), "ARM64 function entry is not executable original code.");
        constexpr std::size_t stack_size = 4 * 1024 * 1024;
        stack.value=VirtualAlloc(nullptr,stack_size+4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        Check(stack.value, "ARM64 stack allocation failed.");
        const auto stack_begin = reinterpret_cast<std::uint64_t>(stack.value), sentinel = stack_begin + stack_size;
        Uc(uc_mem_map(engine.value, stack_begin, stack_size, UC_PROT_READ | UC_PROT_WRITE));
        Uc(uc_mem_map(engine.value, sentinel, 4096, UC_PROT_READ | UC_PROT_EXEC));
        auto sp = sentinel - 16; Uc(uc_reg_write(engine.value, UC_ARM64_REG_SP, &sp));
        Uc(uc_reg_write(engine.value, UC_ARM64_REG_X30, &sentinel));
        for (std::size_t i = 0; i < 8; ++i) {
            const std::uint64_t value = i < arguments.size() ? arguments[i] : 0;
            Uc(uc_reg_write(engine.value, UC_ARM64_REG_X0 + static_cast<int>(i), &value));
        }
        Control control{options}; uc_hook code = 0, interrupt = 0;
        Uc(uc_hook_add(engine.value, &code, UC_HOOK_CODE, reinterpret_cast<void*>(Control::Code), &control, 1, 0));
        Uc(uc_hook_add(engine.value, &interrupt, UC_HOOK_INTR, reinterpret_cast<void*>(Control::Interrupt), &control, 1, 0));
        // Bounded CPU primitive: one million instructions / two seconds maximum.
        const auto status = uc_emu_start(engine.value, entry, sentinel, 2000000, 1000000);
        Check(!control.rejected, control.diagnostic);
        Uc(status);
        std::uint64_t pc = 0; Uc(uc_reg_read(engine.value, UC_ARM64_REG_PC, &pc));
        Check(pc == sentinel, "ARM64 function did not return within execution budget.");
        Uc(uc_reg_read(engine.value, UC_ARM64_REG_X0, &result.value)); result.returned = true;
    } catch (const std::exception& failure) { result.diagnostic = failure.what(); }
    return result;
}
}
