#include "darwin_kevent.hpp"
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* text){if(!ok)throw std::runtime_error(text);}
DarwinKeventQos Kev(std::int16_t filter,std::uint64_t ident,std::uint16_t flags,std::uint32_t fflags=0,
    std::int64_t data=0,std::int32_t qos=0,std::uint64_t udata=0){
    DarwinKeventQos kev;kev.filter=filter;kev.ident=ident;kev.flags=flags;kev.fflags=fflags;
    kev.data=data;kev.qos=qos;kev.udata=udata;return kev;
}
void TestCodec(){
    auto kev=Kev(DarwinEvfiltTimer,0x1122334455667788ULL,0x1234,0xdeadbeef,-5,0x02000000,0x99);
    kev.xflags=7;kev.ext={1,2,3,4};
    std::array<std::uint8_t,DarwinKeventQosBytes> bytes{};
    EncodeDarwinKeventQos(kev,bytes);
    Require(bytes[8]==0xf9&&bytes[9]==0xff&&bytes[0]==0x88,"kevent_qos_s layout wrong");
    Require(DecodeDarwinKeventQos(bytes)==kev,"kevent_qos_s round trip failed");
}
void TestUser(){
    DarwinWorkqKqueue kq;const DarwinKeventClock clock{1000,5000};
    constexpr std::int32_t manager=DarwinPthreadPriorityEventManager;
    // libdispatch's manager wakeup knote: EV_ADD|EV_CLEAR, then NOTE_TRIGGER.
    Require(!kq.Apply(Kev(DarwinEvfiltUser,1,DarwinEvAdd|DarwinEvClear,0,0,manager),clock).error,"user add failed");
    Require(!kq.PendingBucket(clock),"untriggered user knote pending");
    Require(!kq.Apply(Kev(DarwinEvfiltUser,1,0,0x01000000|0xc0000000|0x5),clock).error,"user trigger failed");
    Require(kq.PendingBucket(clock)==DarwinWorkqKqueue::ManagerBucket,"trigger did not reach manager bucket");
    Require(kq.Bind(DarwinWorkqKqueue::ManagerBucket)&&!kq.PendingBucket(clock),"bound bucket still pending");
    const auto events=kq.Collect(DarwinWorkqKqueue::ManagerBucket,clock,16);
    Require(events.size()==1&&events[0].ident==1&&events[0].fflags==5&&!(events[0].flags&DarwinEvAdd)
        &&(events[0].flags&DarwinEvClear),"user delivery wrong");
    kq.Unbind(DarwinWorkqKqueue::ManagerBucket);
    Require(!kq.PendingBucket(clock),"EV_CLEAR knote redelivered");
    Require(kq.Apply(Kev(DarwinEvfiltUser,2,DarwinEvDelete),clock).error==2,"missing delete not ENOENT");
    Require(kq.Apply(Kev(DarwinEvfiltUser,2,DarwinEvEnable),clock).error==2,"missing enable not ENOENT");
    Require(!kq.Apply(Kev(DarwinEvfiltUser,1,DarwinEvDelete),clock).error&&!kq.Size(),"delete failed");
    // QoS-bucketed, udata-specific, EV_DISPATCH knote.
    const std::int32_t utility=0x400|0xff; // QOS_CLASS_UTILITY -> thread QoS 3
    Require(!kq.Apply(Kev(DarwinEvfiltUser,9,DarwinEvAdd|DarwinEvUdataSpecific|DarwinEvDispatch|DarwinEvClear,0x01000000,0,utility,0xa),clock).error
        &&!kq.Apply(Kev(DarwinEvfiltUser,9,DarwinEvAdd|DarwinEvUdataSpecific,0,0,utility,0xb),clock).error&&kq.Size()==2,
        "udata-specific knotes collided");
    Require(kq.PendingBucket(clock)==3&&kq.Collect(3,clock,16).size()==1,"QoS bucket delivery wrong");
    Require(!kq.Apply(Kev(DarwinEvfiltUser,9,DarwinEvUdataSpecific,0x01000000,0,0,0xa),clock).error&&!kq.PendingBucket(clock),
        "EV_DISPATCH knote delivered while disabled");
    Require(!kq.Apply(Kev(DarwinEvfiltUser,9,DarwinEvUdataSpecific|DarwinEvEnable,0,0,0,0xa),clock).error&&kq.PendingBucket(clock)==3,
        "EV_ENABLE did not rearm the dispatched knote");
}
void TestTimer(){
    DarwinWorkqKqueue kq;
    // Relative milliseconds, periodic: two expirations reported as data=2.
    Require(!kq.Apply(Kev(DarwinEvfiltTimer,1,DarwinEvAdd,0,5),{0,0}).error&&kq.NextDeadline()==50000,"ms timer deadline wrong");
    Require(!kq.PendingBucket({49999,0}),"timer fired early");
    auto events=kq.Collect(4,{100000,0},16);
    Require(events.size()==1&&events[0].data==2&&(events[0].flags&DarwinEvClear),"periodic timer count wrong");
    Require(kq.NextDeadline()==150000&&!kq.PendingBucket({100000,0}),"periodic timer not rearmed");
    // Absolute mach time, oneshot: deleted after delivery.
    constexpr std::uint32_t machtime=0x100,absolute=0x8,continuous=0x80;
    Require(!kq.Apply(Kev(DarwinEvfiltTimer,2,DarwinEvAdd|DarwinEvOneshot,machtime|absolute,700),{0,0}).error,"absolute timer failed");
    events=kq.Collect(4,{700,0},16);
    Require(events.size()==1&&events[0].ident==2&&events[0].data==1&&kq.Size()==1,"oneshot absolute timer wrong");
    // Continuous deadline maps by the continuous/absolute offset.
    Require(!kq.Apply(Kev(DarwinEvfiltTimer,3,DarwinEvAdd|DarwinEvOneshot,machtime|absolute|continuous,9000),{1000,8000}).error
        &&kq.NextDeadline()==2000,"continuous timer mapping wrong");
    Require(!kq.Apply(Kev(DarwinEvfiltTimer,4,DarwinEvAdd,0x4,250),{0,0}).error,"ns timer failed");
    Require(kq.Apply(Kev(DarwinEvfiltTimer,5,DarwinEvAdd,0,-1),{0,0}).error==22,"negative timer accepted");
    Require(kq.Apply(Kev(DarwinEvfiltTimer,6,DarwinEvAdd,absolute,1),{0,0}).unsupported,"calendar timer accepted");
}
void TestUnsupported(){
    DarwinWorkqKqueue kq;
    Require(kq.Apply(Kev(-8,1,DarwinEvAdd),{}).unsupported&&!kq.Size(),"unmodeled filter accepted");
    // Memory pressure is registrable but has no activation provider.
    Require(!kq.Apply(Kev(DarwinEvfiltMemorystatus,0,DarwinEvAdd,0x37),{}).error&&kq.Size()==1&&!kq.PendingBucket({}),
        "memorystatus registration wrong");
}
}
void TestWorkloop(){
    constexpr std::uint64_t wl=0x34a10,state=0x9000;
    std::uint64_t word=0x00000000'00000a07ULL; // owner port 0xa04 in the low bits
    const auto read=[&](std::uint64_t address,std::uint64_t& value){if(address!=state)return false;value=word;return true;};
    DarwinWorkloop loop(wl);const DarwinKeventClock clock{};
    const std::int32_t utility=0x400|0xff;
    // libdispatch poke: THREAD_REQUEST|UPDATE_QOS|IGNORE_ESTALE, EV_ADD|EV_ENABLE.
    auto poke=Kev(DarwinEvfiltWorkloop,wl,DarwinEvAdd|DarwinEvEnable,0x111,0,utility,wl);
    poke.ext[DarwinWlExtAddress]=state;poke.ext[DarwinWlExtMask]=0x37'00000001ULL;poke.ext[DarwinWlExtValue]=0x1234;
    Require(!loop.Apply(poke,clock,read).error,"thread request rejected despite IGNORE_ESTALE");
    Require(loop.ServicerPriority(clock)==static_cast<std::uint32_t>(utility),"thread request did not request a servicer");
    auto events=loop.BeginService(clock,16);
    Require(events.size()==1&&events[0].filter==DarwinEvfiltWorkloop&&events[0].ident==wl&&!(events[0].flags&DarwinEvAdd)
        &&loop.Serviced()&&!loop.ServicerPriority(clock),"thread request delivery wrong");
    loop.EndService();
    Require(!loop.ServicerPriority(clock),"delivered thread request redelivered without EV_ENABLE");
    // Without IGNORE_ESTALE a stale owner word is ESTALE; a match discovers the owner.
    auto discover=poke;discover.fflags=0x91;discover.ext[DarwinWlExtValue]=0x1234;
    Require(loop.Apply(discover,clock,read).error==70,"stale state not ESTALE");
    discover.ext[DarwinWlExtValue]=word;
    Require(!loop.Apply(discover,clock,read).error&&loop.Owner()==0xa04,"owner not discovered");
    Require(!loop.ServicerPriority(clock),"owned workloop requested a servicer");
    auto wait=Kev(DarwinEvfiltWorkloop,0x707,DarwinEvAdd|DarwinEvDisable,DarwinNoteWlSyncWait,0,utility,wl);
    const auto waited=loop.Apply(wait,clock,read);
    Require(waited.wait&&!waited.error&&loop.HasWaiter(0x707),"sync wait did not block on an owned workloop");
    auto wake=Kev(DarwinEvfiltWorkloop,0x707,DarwinEvAdd|DarwinEvDisable,DarwinNoteWlSyncWake);
    Require(loop.Apply(wake,clock,read).wake==0x707u,"sync wake did not release the waiter");
    Require(!loop.Apply(wait,clock,read).wait,"woken waiter blocked again on retry");
    auto cleanup=Kev(DarwinEvfiltWorkloop,0x707,DarwinEvDelete|DarwinEvEnable,DarwinNoteWlEndOwnership|DarwinNoteWlSyncWake);
    Require(!loop.Apply(cleanup,clock,read).error&&!loop.HasWaiter(0x707)&&!loop.Owner(),"waiter cleanup/end ownership wrong");
    Require(loop.ServicerPriority(clock)==static_cast<std::uint32_t>(utility),"ended ownership did not request the servicer");
    // Delete of the thread request (THREAD_REQUEST|IGNORE_ESTALE, EV_ADD|EV_DELETE|EV_ENABLE).
    Require(!loop.Apply(Kev(DarwinEvfiltWorkloop,wl,DarwinEvAdd|DarwinEvDelete|DarwinEvEnable,0x101),clock,read).error
        &&!loop.ServicerPriority(clock),"thread request deletion wrong");
    Require(!loop.Apply(Kev(DarwinEvfiltWorkloop,wl,DarwinEvAdd|DarwinEvDelete|DarwinEvEnable,0x101),clock,read).error,
        "EV_ADD|EV_DELETE of an absent request failed");
    // Unowned sync wait returns at once; ordinary knotes request the servicer.
    Require(!loop.Apply(Kev(DarwinEvfiltWorkloop,0x808,DarwinEvAdd,DarwinNoteWlSyncWait),clock,read).wait,"unowned wait blocked");
    Require(!loop.Apply(Kev(DarwinEvfiltUser,5,DarwinEvAdd|DarwinEvClear,0x01000000,0,utility),clock,read).error
        &&loop.ServicerPriority(clock)==(0x400u|0xffu|0x80000000u),"workloop knote did not request a servicer");
    Require(loop.BeginService(clock,16).size()==1,"workloop knote not delivered");
    Require(loop.Apply(Kev(DarwinEvfiltWorkloop,wl,DarwinEvAdd,0x200),clock,read).unsupported,"unknown workloop command accepted");
    Require(loop.Apply(Kev(DarwinEvfiltWorkloop,wl,DarwinEvAdd,0x5),clock,read).unsupported,"combined commands accepted");
}
int main(){try{
    TestCodec();TestUser();TestTimer();TestUnsupported();TestWorkloop();
    std::cout<<"PASS: Darwin kqworkq kevent model\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<"\n";return 1;}}
