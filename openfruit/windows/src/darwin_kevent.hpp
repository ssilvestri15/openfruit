#pragma once
#include <array>
#include <functional>
#include <map>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace OpenFruit {
// XNU bsd/sys/event.h / event_private.h kevent_qos_s, 64 bytes little-endian.
inline constexpr std::size_t DarwinKeventQosBytes=64;
struct DarwinKeventQos {
    std::uint64_t ident=0;
    std::int16_t filter=0;
    std::uint16_t flags=0;
    std::int32_t qos=0;
    std::uint64_t udata=0;
    std::uint32_t fflags=0,xflags=0;
    std::int64_t data=0;
    std::array<std::uint64_t,4> ext{};
    bool operator==(const DarwinKeventQos&) const=default;
};
DarwinKeventQos DecodeDarwinKeventQos(std::span<const std::uint8_t,DarwinKeventQosBytes>) noexcept;
void EncodeDarwinKeventQos(const DarwinKeventQos&,std::span<std::uint8_t,DarwinKeventQosBytes>) noexcept;

inline constexpr std::int16_t DarwinEvfiltTimer=-7,DarwinEvfiltUser=-10,DarwinEvfiltMemorystatus=-14,
    DarwinEvfiltWorkloop=-17;
inline constexpr std::uint16_t DarwinEvAdd=0x1,DarwinEvDelete=0x2,DarwinEvEnable=0x4,DarwinEvDisable=0x8,
    DarwinEvOneshot=0x10,DarwinEvClear=0x20,DarwinEvReceipt=0x40,DarwinEvDispatch=0x80,
    DarwinEvUdataSpecific=0x100,DarwinEvError=0x4000;
inline constexpr std::uint32_t DarwinKeventFlagImmediate=0x1,DarwinKeventFlagErrorEvents=0x2,
    DarwinKeventFlagStackData=0x4,DarwinKeventFlagWorkq=0x20,DarwinKeventFlagWorkqManager=0x200,
    DarwinKeventFlagWorkloop=0x400,DarwinKeventFlagDynamicKqMustExist=0x20000;
// _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG routes a knote to the event manager.
inline constexpr std::uint32_t DarwinPthreadPriorityEventManager=0x02000000;

// Guest clocks of the existing provider: mach absolute and continuous time in
// 100ns ticks (DarwinClockTimebase).
struct DarwinKeventClock { std::uint64_t absolute=0,continuous=0; };

// The process workqueue kqueue (kevent_qos with KEVENT_FLAG_WORKQ). Knotes are
// serviced by kevent workqueue threads per QoS bucket, one servicer per bucket
// as XNU kqworkq requests. Implemented filters: EVFILT_USER, relative and
// mach-time EVFILT_TIMER, and EVFILT_MEMORYSTATUS registration (this provider
// models no memory pressure, so such knotes never activate). Anything else is
// reported unsupported rather than answered with a fabricated errno.
class DarwinWorkqKqueue {
public:
    static constexpr std::uint8_t ManagerBucket=7; // after thread QoS 1..6
    struct Change {
        int error=0;              // per-change errno (EV_ERROR data)
        const char* unsupported=nullptr;
    };
    Change Apply(const DarwinKeventQos&,const DarwinKeventClock&);
    // Highest bucket with an active, enabled knote that has no bound servicer.
    std::optional<std::uint8_t> PendingBucket(const DarwinKeventClock&);
    // Delivers up to maximum active knotes of a bucket (EV_CLEAR/ONESHOT/DISPATCH).
    std::vector<DarwinKeventQos> Collect(std::uint8_t bucket,const DarwinKeventClock&,std::size_t maximum);
    // A workloop's knotes are delivered to its servicer whatever their QoS.
    std::vector<DarwinKeventQos> CollectAll(const DarwinKeventClock&,std::size_t maximum);
    // Earliest armed timer deadline in mach absolute ticks.
    std::optional<std::uint64_t> NextDeadline() const noexcept;
    bool Bind(std::uint8_t bucket) noexcept;
    void Unbind(std::uint8_t bucket) noexcept;
    bool Bound(std::uint8_t bucket) const noexcept{return bucket<bound_.size()&&bound_[bucket];}
    std::size_t Size() const noexcept{return knotes_.size();}
    std::uint64_t registrations=0,deliveries=0;
private:
    struct Knote {
        DarwinKeventQos kev;
        std::uint8_t bucket=4;
        bool enabled=true,active=false;
        std::uint32_t user_fflags=0;
        std::optional<std::uint64_t> deadline; // mach absolute
        std::uint64_t interval=0,fired=0;      // periodic interval in ticks
    };
    std::vector<Knote> knotes_;
    std::array<bool,8> bound_{};
    Knote* Find(const DarwinKeventQos&) noexcept;
    void Refresh(const DarwinKeventClock&) noexcept;
    std::vector<DarwinKeventQos> Deliver(std::optional<std::uint8_t> bucket,const DarwinKeventClock&,std::size_t maximum);
};

// XNU EVFILT_WORKLOOP commands (event_private.h) as libdispatch issues them.
inline constexpr std::uint32_t DarwinNoteWlThreadRequest=0x1,DarwinNoteWlSyncWait=0x4,DarwinNoteWlSyncWake=0x8,
    DarwinNoteWlUpdateQos=0x10,DarwinNoteWlEndOwnership=0x20,DarwinNoteWlDiscoverOwner=0x80,
    DarwinNoteWlIgnoreEstale=0x100;
inline constexpr std::size_t DarwinWlExtAddress=1,DarwinWlExtMask=2,DarwinWlExtValue=3;

// One dynamic workloop kqueue (kevent_id with KEVENT_FLAG_WORKLOOP). It owns
// ordinary knotes, at most one thread request (ident = workloop id), sync
// waiters (ident = waiting thread) and its ownership state. A servicer is
// needed when an enabled thread request has no owner, or a knote is active,
// and none is bound. Commands outside the implemented set are unsupported.
class DarwinWorkloop {
public:
    // Reads the guest word named by ext[ADDR]; false is EFAULT.
    using ReadWord=std::function<bool(std::uint64_t address,std::uint64_t& value)>;
    struct Change {
        int error=0;
        const char* unsupported=nullptr;
        bool wait=false;                      // SYNC_WAIT: the caller must block
        std::optional<std::uint64_t> wake;    // sync waiter ident to release
    };
    explicit DarwinWorkloop(std::uint64_t id):id_(id){}
    std::uint64_t Id() const noexcept{return id_;}
    Change Apply(const DarwinKeventQos&,const DarwinKeventClock&,const ReadWord&);
    // Pthread priority of the needed servicer request, if one is needed now.
    std::optional<std::uint32_t> ServicerPriority(const DarwinKeventClock&);
    // Binds a servicer and delivers the thread request event and active knotes.
    std::vector<DarwinKeventQos> BeginService(const DarwinKeventClock&,std::size_t maximum);
    std::vector<DarwinKeventQos> Collect(const DarwinKeventClock& clock,std::size_t maximum){return knotes_.CollectAll(clock,maximum);}
    void EndService() noexcept{serviced_=false;}
    bool Serviced() const noexcept{return serviced_;}
    std::uint32_t Owner() const noexcept{return owner_;}
    bool HasWaiter(std::uint64_t ident) const{return waiters_.contains(ident);}
    std::optional<std::uint64_t> NextDeadline() const noexcept{return knotes_.NextDeadline();}
    std::uint64_t services=0,sync_waits=0,sync_wakes=0;
private:
    std::uint64_t id_;
    DarwinWorkqKqueue knotes_;
    struct ThreadRequest {DarwinKeventQos kev;bool enabled=true;};
    std::optional<ThreadRequest> request_;
    std::uint32_t owner_=0;            // discovered owner thread port name
    bool serviced_=false;
    std::map<std::uint64_t,bool> waiters_; // ident -> woken
};
}
