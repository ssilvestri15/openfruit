#include "darwin_pthread_policy.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <string_view>
using namespace OpenFruit;
namespace {
void Require(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
struct Backend {
    DarwinPthreadPolicyState consumed{{4,0},true,0};
    DarwinPthreadQos workqueue_qos{4,0};bool overcommit=false;
    int qos_error=0,voucher_error=0,timeshare_error=0,workqueue_error=0;
    std::array<char,8> order{};std::size_t calls=0;
    void Reset(){order={};calls=0;}
    bool Order(std::string_view expected)const{return std::string_view(order.data(),calls)==expected;}
    static int Qos(void* context,DarwinPthreadQos qos)noexcept {
        auto& b=*static_cast<Backend*>(context);b.order[b.calls++]='Q';
        if(!b.qos_error)b.consumed.qos=qos;return b.qos_error;
    }
    static int Voucher(void* context,std::uint32_t voucher)noexcept {
        auto& b=*static_cast<Backend*>(context);b.order[b.calls++]='V';
        if(!b.voucher_error)b.consumed.voucher=voucher;return b.voucher_error;
    }
    static int Timeshare(void* context,bool timeshare)noexcept {
        auto& b=*static_cast<Backend*>(context);b.order[b.calls++]='T';
        if(!b.timeshare_error)b.consumed.timeshare=timeshare;return b.timeshare_error;
    }
    static int Workqueue(void* context,DarwinPthreadQos qos,bool overcommit)noexcept {
        auto& b=*static_cast<Backend*>(context);b.order[b.calls++]='W';
        if(!b.workqueue_error){b.workqueue_qos=qos;b.overcommit=overcommit;}
        return b.workqueue_error;
    }
    DarwinPthreadPolicyOperations Operations(){return {this,Qos,Voucher,Timeshare,Workqueue};}
};
std::uint32_t Priority(std::uint8_t tier,int relative){std::uint32_t value=0;Require(EncodeDarwinPthreadQos({tier,relative},value),"Encode fixture inputs failed");return value;}
}
int main(){try{
    constexpr int expected[6][16]={
        {4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1},
        {4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1},
        {20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5},
        {31,31,30,29,29,28,27,27,26,25,25,24,23,23,22,21},
        {37,37,37,36,36,36,35,35,34,34,34,33,33,33,32,32},
        {46,46,45,45,44,44,43,43,42,41,41,40,40,39,39,38}};
    for(std::uint8_t tier=1;tier<=6;++tier)for(int magnitude=0;magnitude<16;++magnitude){
        int base=-1;Require(ResolveDarwinPthreadBasePriority({tier,-magnitude},base)
            &&base==expected[tier-1][magnitude],"XNU ordinary QoS band scaling differs");
    }
    for(const auto invalid: {DarwinPthreadQos{0,0},{7,0},{1,1},{1,-16}}){
        int base=99;Require(!ResolveDarwinPthreadBasePriority(invalid,base)&&base==99,"Invalid QoS changed priority output");
    }
    for(std::uint8_t tier=1;tier<=6;++tier)for(int relative=-15;relative<=0;++relative){
        DarwinPthreadQos qos;const auto priority=Priority(tier,relative);
        Require(DecodeDarwinPthreadQos(priority,qos)&&qos==DarwinPthreadQos{tier,relative},"QoS/relative signed encoding mismatch");
    }
    DarwinPthreadQos output{4,-2};const auto preserved=output;
    Require(!DecodeDarwinPthreadQos(0,output)&&output==preserved,"Unspecified became valid QoS");
    for(unsigned byte=0;byte<=255;++byte){
        const auto valid=byte>=240;
        Require(DecodeDarwinPthreadQos(0x100|byte,output)==valid,"Signed relative priority boundary differs");
    }
    Require(DecodeDarwinPthreadQos(0x2100|0xff,output)&&output==DarwinPthreadQos{1,0},"XNU lowest-set QoS bit changed");
    Require(!DecodeDarwinPthreadQos(Priority(4,0)|0x20000000,output)
        &&!DecodeDarwinPthreadQos(Priority(4,0)|0x02000000,output),"Scheduling/manager encoding accepted as QoS");
    std::uint32_t encoded=123;
    Require(!EncodeDarwinPthreadQos({0,0},encoded)&&encoded==123
        &&!EncodeDarwinPthreadQos({7,0},encoded)&&!EncodeDarwinPthreadQos({1,-16},encoded)
        &&!EncodeDarwinPthreadQos({1,1},encoded),"Invalid encode changed output");
    Backend backend;auto operations=backend.Operations();auto state=backend.consumed;
    constexpr auto ordinary=DarwinPthreadPolicyKind::Ordinary;
    constexpr auto all=DarwinSetSelfQos|DarwinSetSelfVoucher|DarwinSetSelfFixedPriority;
    const auto apply=[&](std::uint64_t priority,std::uint32_t voucher,std::uint32_t flags){
        backend.Reset();return ApplyDarwinPthreadSetSelf(state,priority,voucher,flags,ordinary,operations);
    };
    Require(!apply(Priority(1,-15),1799,all)&&backend.Order("QVT")
        &&state.qos==DarwinPthreadQos{1,-15}&&state.voucher==1799&&!state.timeshare
        &&state.qos==backend.consumed.qos&&state.voucher==backend.consumed.voucher,
        "Requested stages did not reach provider/state in order");
    Require(!apply(Priority(4,0),0,DarwinSetSelfQos|DarwinSetSelfTimeshare)
        &&backend.Order("QT")&&state.timeshare&&state.qos==DarwinPthreadQos{4,0},"Legacy/default or timeshare state lost");
    Require(!apply(0,0,DarwinSetSelfFixedPriority|DarwinSetSelfTimeshare)&&!state.timeshare&&backend.Order("T"),"Fixed bit precedence differs");
    for(const int failure:{1,4,37,49}){
        backend.qos_error=failure;backend.voucher_error=0;
        Require(apply(Priority(6,-3),42,all)==22&&backend.Order("QV")
            &&state.qos==DarwinPthreadQos{4,0}&&state.voucher==42,"QoS failure mapping/independent voucher effect differs");
        backend.qos_error=0;backend.voucher_error=failure;
        Require(apply(Priority(6,-3),99,all)==2&&backend.Order("QVT")
            &&state.qos==DarwinPthreadQos{6,-3}&&state.voucher==42,"Voucher failure mapping/independent QoS effect differs");
        backend.qos_error=failure;
        Require(apply(Priority(4,0),99,all)==94&&backend.Order("QV"),"Dual-stage error was not Darwin EBADMSG");
        backend.qos_error=0;backend.voucher_error=0;backend.timeshare_error=failure;
        Require(apply(Priority(4,0),7,all)==22&&backend.Order("QVT")&&state.voucher==7,"Fixed policy kernel error mapping differs");
        backend.timeshare_error=0;
    }
    Require(apply(Priority(2,0),11,all|DarwinSetSelfUnbind)==22&&backend.Order("QVT")
        &&state.voucher==11&&state.qos.tier==2,"Ordinary unbind error suppressed later effects");
    backend.qos_error=4;backend.voucher_error=4;
    Require(apply(Priority(4,0),0,all|DarwinSetSelfUnbind)==94,"Combined failure must precede unbind error");
    backend.qos_error=0;backend.voucher_error=0;
    state.qos={};Require(apply(Priority(4,0),12,all)==1&&backend.Order("V")&&state.voucher==12,"Opted-out thread gained QoS or lost voucher stage");
    state.qos={4,0};
    const DarwinPthreadPolicyOperations missing{};
    Require(ApplyDarwinPthreadSetSelf(state,Priority(1,0),0,DarwinSetSelfQos,ordinary,missing)==45,
        "Missing real QoS provider silently succeeded");
    Require(ApplyDarwinPthreadSetSelf(state,0,0,DarwinSetSelfVoucher,ordinary,missing)==45
        &&ApplyDarwinPthreadSetSelf(state,0,0,DarwinSetSelfTimeshare,ordinary,missing)==45,
        "Missing voucher/scheduling provider silently succeeded");
    Require(ApplyDarwinPthreadSetSelf(state,Priority(1,0),0,DarwinSetSelfQos|DarwinSetSelfVoucher,ordinary,missing)==94,
        "Missing independent providers lost combined error");
    Require(apply(Priority(4,0),0,0x20)==45&&backend.Order(""),"Unsupported input flag silently accepted");
    Require(apply(Priority(4,0),0,DarwinSetSelfQosOverride)==22&&backend.Order(""),"Override without QoS flag admitted");
    const auto overridden=Priority(4,0)|0x00800000|0x08000000|0x4000;
    Require(apply(overridden,0,DarwinSetSelfQos)==22
        &&!apply(overridden,0,DarwinSetSelfQos|DarwinSetSelfQosOverride)
        &&backend.Order("Q")&&state.qos==DarwinPthreadQos{4,0},
        "Ordinary override validation or requested QoS source behavior differs");
    backend.Reset();Require(ApplyDarwinPthreadSetSelf(state,Priority(4,0),18,all,
        DarwinPthreadPolicyKind::WorkqueueUnsupported,operations)==45&&backend.Order("V")&&state.voucher==18,
        "Workqueue state fabricated policy success or lost independent voucher stage");

    // Isolated owner callbacks establish source stage ordering; actual task
    // accounting, scheduler effects and original guest execution are Main gates.
    constexpr auto worker=DarwinPthreadPolicyKind::OrdinaryWorkqueue;
    auto work_state=backend.consumed;
    const auto work_apply=[&](std::uint64_t priority,std::uint32_t voucher,std::uint32_t flags){
        backend.Reset();return ApplyDarwinPthreadSetSelf(work_state,priority,voucher,flags,worker,operations);
    };
    for(std::uint8_t tier=1;tier<=6;++tier)for(int relative=-15;relative<=0;++relative)for(const bool oc:{false,true}){
        Require(!work_apply(Priority(tier,relative)|(oc?0x80000000u:0),0,DarwinSetSelfQos)
            &&backend.Order("WQ")&&backend.workqueue_qos==DarwinPthreadQos{tier,relative}
            &&backend.overcommit==oc&&work_state.qos==DarwinPthreadQos{tier,relative}
            &&work_state.qos==backend.consumed.qos,"Workqueue QoS/type transition did not reach both owner stages");
    }
    for(unsigned byte=0;byte<240;++byte){
        Require(work_apply(0x800|byte,0,DarwinSetSelfQos)==22&&backend.Order(""),
            "Invalid SET_SELF relative priority reached workqueue or CPU owner");
    }
    Require(work_apply(Priority(4,0)|0x08000000u,0,DarwinSetSelfQos)==22&&backend.Order("")
        &&work_apply(Priority(4,0)|0x88000000u,0,DarwinSetSelfQos)==22&&backend.Order(""),
        "Ordinary workqueue transitioned to cooperative pool");
    Require(work_apply(overridden,0,DarwinSetSelfQos|DarwinSetSelfQosOverride)==22&&backend.Order("")
        &&work_apply(overridden,0,DarwinSetSelfQos)==22&&backend.Order(""),
        "Cooperative override request changed ordinary worker bucket");
    Require(work_apply(0,0,DarwinSetSelfUnbind)==37&&backend.Order(""),
        "Unbound ordinary worker did not return EALREADY");
    Require(work_apply(0,0,DarwinSetSelfFixedPriority|DarwinSetSelfTimeshare)==45&&backend.Order(""),
        "Workqueue changed extended scheduling policy");
    Require(work_apply(Priority(3,-4),19,all|DarwinSetSelfUnbind)==37&&backend.Order("WQV")
        &&work_state.qos==DarwinPthreadQos{3,-4}&&work_state.voucher==19,
        "Worker unbind failure suppressed independent QoS/voucher or lost error precedence");
    for(const int failure:{1,4,37,49}){
        backend.workqueue_error=failure;const auto before_qos=work_state.qos;
        const auto before_bucket=backend.workqueue_qos;const auto before_oc=backend.overcommit;
        Require(work_apply(Priority(2,-3)|0x80000000u,21,all)==22&&backend.Order("WV")
            &&work_state.qos==before_qos&&backend.workqueue_qos==before_bucket
            &&backend.overcommit==before_oc&&work_state.voucher==21,
            "Failed workqueue owner stage continued CPU policy or suppressed voucher");
        backend.workqueue_error=0;backend.qos_error=failure;
        Require(work_apply(Priority(1,-5)|0x80000000u,22,all)==22&&backend.Order("WQV")
            &&backend.workqueue_qos==DarwinPthreadQos{1,-5}&&backend.overcommit
            &&work_state.qos==before_qos&&work_state.voucher==22,
            "CPU policy failure rolled back prior workqueue accounting or suppressed voucher");
        backend.voucher_error=failure;
        Require(work_apply(Priority(4,0),23,all|DarwinSetSelfUnbind)==94&&backend.Order("WQV")
            &&backend.workqueue_qos==DarwinPthreadQos{4,0}&&!backend.overcommit
            &&work_state.qos==before_qos&&work_state.voucher==22,
            "Worker combined QoS/voucher failure lost EBADMSG precedence or prior bucket effects");
        backend.qos_error=0;backend.voucher_error=0;
    }
    auto no_worker_owner=operations;no_worker_owner.update_workqueue=nullptr;
    backend.Reset();
    Require(ApplyDarwinPthreadSetSelf(work_state,Priority(4,0),0,DarwinSetSelfQos,worker,no_worker_owner)==45
        &&backend.Order(""),"Workqueue owner absence silently applied CPU-only policy");
    auto no_cpu_owner=operations;no_cpu_owner.apply_qos=nullptr;
    backend.Reset();const auto before_cpu=work_state.qos;
    Require(ApplyDarwinPthreadSetSelf(work_state,Priority(2,-7),0,DarwinSetSelfQos,worker,no_cpu_owner)==45
        &&backend.Order("W")&&backend.workqueue_qos==DarwinPthreadQos{2,-7}
        &&work_state.qos==before_cpu,"Missing CPU owner erased source partial update or claimed success");
    Require(ApplyDarwinPthreadSetSelf(work_state,Priority(4,0),0,DarwinSetSelfQos,worker,missing)==45,
        "Missing workqueue policy providers fabricated success");
    work_state.qos={};
    Require(!work_apply(Priority(4,0),0,DarwinSetSelfQos)&&backend.Order("WQ")
        &&work_state.qos==DarwinPthreadQos{4,0},"Worker incorrectly used ordinary thread opt-out gate");
    Backend other;auto other_state=other.consumed;
    Require(!ApplyDarwinPthreadSetSelf(other_state,Priority(3,-2),13,DarwinSetSelfQos|DarwinSetSelfVoucher,
        ordinary,other.Operations())&&other_state.qos.tier==3&&state.qos.tier!=3,"Per-owner state crossed threads");
    for(auto command:{0x10u,0x401u,0x402u,0x40u,0x80u,0x200u,0x400u,0x800u,0x1000u,0x2000u,0x4000u})
        Require(ApplyDarwinBsdthreadCtl(state,command,0,0,0,ordinary,operations)==45,"Unsupported/discontinued command succeeded");
    Require(ApplyDarwinBsdthreadCtl(state,0x20,0,0,0,ordinary,operations)==22
        &&ApplyDarwinBsdthreadCtl(state,0x800,0,0,1,ordinary,operations)==22
        &&ApplyDarwinBsdthreadCtl(state,0x1000,0,1,0,ordinary,operations)==22,"Unknown/reserved command error differs");
    Require(!ApplyDarwinBsdthreadCtl(state,0x100,Priority(4,-1),14,DarwinSetSelfQos|DarwinSetSelfVoucher,
        ordinary,operations)&&state.qos==DarwinPthreadQos{4,-1}&&state.voucher==14,"SET_SELF ABI forwarding differs");
    Require(!ApplyDarwinBsdthreadCtl(state,0x100,0,0,0,ordinary,missing),"Source no-operation flags request failed");
    std::cout<<"Darwin pthread QoS encoding and provider-driven SET_SELF state/error stages PASS\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
