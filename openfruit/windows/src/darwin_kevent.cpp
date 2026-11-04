#include "darwin_kevent.hpp"
#include <algorithm>
#include <limits>

namespace OpenFruit {
namespace {
std::uint64_t Read(std::span<const std::uint8_t,DarwinKeventQosBytes> bytes,std::size_t at,unsigned width){
    std::uint64_t value=0;for(unsigned n=0;n<width;++n)value|=std::uint64_t(bytes[at+n])<<(8*n);return value;
}
void Put(std::span<std::uint8_t,DarwinKeventQosBytes> bytes,std::size_t at,std::uint64_t value,unsigned width){
    for(unsigned n=0;n<width;++n)bytes[at+n]=static_cast<std::uint8_t>(value>>(8*n));
}
// XNU filt_timer fflags.
constexpr std::uint32_t NoteSeconds=0x1,NoteUseconds=0x2,NoteNseconds=0x4,NoteAbsolute=0x8,
    NoteMachContinuous=0x80,NoteMachtime=0x100;
// XNU filt_user fflags.
constexpr std::uint32_t NoteTrigger=0x01000000,NoteFfAnd=0x40000000,NoteFfOr=0x80000000,
    NoteFfCtrlMask=0xc0000000,NoteFfFlagsMask=0x00ffffff;
// Registration flags a knote keeps; the action bits apply to one change only.
constexpr std::uint16_t PersistentFlags=static_cast<std::uint16_t>(~(DarwinEvAdd|DarwinEvDelete|DarwinEvEnable
    |DarwinEvDisable|DarwinEvReceipt|DarwinEvError));

std::uint64_t Saturating(std::uint64_t value,std::uint64_t scale){
    return value>std::numeric_limits<std::uint64_t>::max()/scale?std::numeric_limits<std::uint64_t>::max():value*scale;
}
// Relative timer amount in 100ns mach ticks.
std::uint64_t Ticks(std::uint64_t amount,std::uint32_t fflags){
    if(fflags&NoteMachtime)return amount;
    if(fflags&NoteNseconds)return amount/100+(amount%100?1:0);
    if(fflags&NoteUseconds)return Saturating(amount,10);
    if(fflags&NoteSeconds)return Saturating(amount,10000000);
    return Saturating(amount,10000); // milliseconds
}
std::uint8_t BucketOf(std::int32_t qos){
    const auto priority=static_cast<std::uint32_t>(qos);
    if(priority&DarwinPthreadPriorityEventManager)return DarwinWorkqKqueue::ManagerBucket;
    auto bits=(priority&0x3f00u)>>8;
    if(!bits)return 4; // THREAD_QOS_LEGACY for an unspecified knote QoS
    std::uint8_t tier=1;while(!(bits&1u)){++tier;bits>>=1;}
    return tier;
}
}

DarwinKeventQos DecodeDarwinKeventQos(std::span<const std::uint8_t,DarwinKeventQosBytes> bytes) noexcept {
    DarwinKeventQos kev;
    kev.ident=Read(bytes,0,8);
    kev.filter=static_cast<std::int16_t>(Read(bytes,8,2));
    kev.flags=static_cast<std::uint16_t>(Read(bytes,10,2));
    kev.qos=static_cast<std::int32_t>(Read(bytes,12,4));
    kev.udata=Read(bytes,16,8);
    kev.fflags=static_cast<std::uint32_t>(Read(bytes,24,4));
    kev.xflags=static_cast<std::uint32_t>(Read(bytes,28,4));
    kev.data=static_cast<std::int64_t>(Read(bytes,32,8));
    for(unsigned n=0;n<4;++n)kev.ext[n]=Read(bytes,40+8*n,8);
    return kev;
}
void EncodeDarwinKeventQos(const DarwinKeventQos& kev,std::span<std::uint8_t,DarwinKeventQosBytes> bytes) noexcept {
    Put(bytes,0,kev.ident,8);Put(bytes,8,static_cast<std::uint16_t>(kev.filter),2);Put(bytes,10,kev.flags,2);
    Put(bytes,12,static_cast<std::uint32_t>(kev.qos),4);Put(bytes,16,kev.udata,8);Put(bytes,24,kev.fflags,4);
    Put(bytes,28,kev.xflags,4);Put(bytes,32,static_cast<std::uint64_t>(kev.data),8);
    for(unsigned n=0;n<4;++n)Put(bytes,40+8*n,kev.ext[n],8);
}

DarwinWorkqKqueue::Knote* DarwinWorkqKqueue::Find(const DarwinKeventQos& kev) noexcept {
    const bool specific=(kev.flags&DarwinEvUdataSpecific)!=0;
    for(auto& knote:knotes_)if(knote.kev.filter==kev.filter&&knote.kev.ident==kev.ident
        &&((knote.kev.flags&DarwinEvUdataSpecific)!=0)==specific&&(!specific||knote.kev.udata==kev.udata))return &knote;
    return nullptr;
}

DarwinWorkqKqueue::Change DarwinWorkqKqueue::Apply(const DarwinKeventQos& kev,const DarwinKeventClock& clock){
    if(kev.filter!=DarwinEvfiltTimer&&kev.filter!=DarwinEvfiltUser&&kev.filter!=DarwinEvfiltMemorystatus)
        return {0,"unsupported_kevent_filter"};
    auto* knote=Find(kev);
    if(kev.flags&DarwinEvDelete){
        if(!knote)return {2}; // ENOENT
        knotes_.erase(knotes_.begin()+(knote-knotes_.data()));return {};
    }
    if(kev.filter==DarwinEvfiltTimer&&(kev.flags&DarwinEvAdd)){
        if((kev.fflags&NoteAbsolute)&&!(kev.fflags&NoteMachtime))return {0,"unsupported_kevent_calendar_timer"};
        if(kev.data<0)return {22};
    }
    const bool created=!knote;
    if(!knote){
        if(!(kev.flags&DarwinEvAdd))return {2};
        knotes_.emplace_back();knote=&knotes_.back();
        knote->kev=kev;knote->enabled=!(kev.flags&DarwinEvDisable);
        ++registrations;
    }else if(kev.flags&DarwinEvAdd){
        // Reregistration updates the knote's QoS, udata and filter state.
        knote->kev.qos=kev.qos;knote->kev.udata=kev.udata;knote->kev.ext=kev.ext;
        knote->kev.flags=kev.flags;
    }
    if(kev.flags&DarwinEvAdd){
        knote->kev.flags&=PersistentFlags;
        knote->bucket=BucketOf(kev.qos);
        if(kev.filter==DarwinEvfiltTimer){
            // filt_timerattach: timers are always EV_CLEAR; reprogramming
            // discards an undelivered expiration count.
            knote->kev.flags|=DarwinEvClear;knote->kev.fflags=kev.fflags;knote->kev.data=kev.data;
            const auto amount=static_cast<std::uint64_t>(kev.data);
            knote->active=false;knote->fired=0;knote->interval=0;
            if(kev.fflags&NoteAbsolute){
                if(kev.fflags&NoteMachContinuous)
                    knote->deadline=amount>clock.continuous?clock.absolute+(amount-clock.continuous):clock.absolute;
                else knote->deadline=amount;
            }else{
                const auto ticks=Ticks(amount,kev.fflags);
                knote->deadline=ticks>std::numeric_limits<std::uint64_t>::max()-clock.absolute
                    ?std::numeric_limits<std::uint64_t>::max():clock.absolute+ticks;
                if(!(kev.flags&DarwinEvOneshot))knote->interval=ticks;
            }
        }
    }
    if(kev.filter==DarwinEvfiltUser){
        // filt_userattach saves the flags; filt_usertouch combines them by the
        // control bits and copies data. NOTE_TRIGGER activates the knote.
        const auto value=kev.fflags&NoteFfFlagsMask;
        if(created)knote->user_fflags=value;
        else switch(kev.fflags&NoteFfCtrlMask){
            case NoteFfAnd:knote->user_fflags&=value;break;
            case NoteFfOr:knote->user_fflags|=value;break;
            case NoteFfCtrlMask:knote->user_fflags=value;break;
            default:break;
        }
        knote->kev.data=kev.data;
        if(kev.fflags&NoteTrigger)knote->active=true;
    }
    if(kev.flags&DarwinEvEnable)knote->enabled=true;
    if(kev.flags&DarwinEvDisable)knote->enabled=false;
    return {};
}

void DarwinWorkqKqueue::Refresh(const DarwinKeventClock& clock) noexcept {
    for(auto& knote:knotes_){
        if(!knote.deadline||*knote.deadline>clock.absolute)continue;
        if(knote.interval){
            const auto count=1+(clock.absolute-*knote.deadline)/knote.interval;
            knote.fired+=count;
            *knote.deadline=Saturating(count,knote.interval)>std::numeric_limits<std::uint64_t>::max()-*knote.deadline
                ?std::numeric_limits<std::uint64_t>::max():*knote.deadline+count*knote.interval;
        }else{++knote.fired;knote.deadline.reset();}
        knote.active=true;
    }
}

std::optional<std::uint8_t> DarwinWorkqKqueue::PendingBucket(const DarwinKeventClock& clock){
    Refresh(clock);
    std::optional<std::uint8_t> best;
    for(const auto& knote:knotes_)if(knote.active&&knote.enabled&&!bound_[knote.bucket]
        &&(!best||knote.bucket>*best))best=knote.bucket;
    return best;
}

std::vector<DarwinKeventQos> DarwinWorkqKqueue::Deliver(std::optional<std::uint8_t> bucket,const DarwinKeventClock& clock,std::size_t maximum){
    Refresh(clock);
    std::vector<DarwinKeventQos> events;
    for(std::size_t index=0;index<knotes_.size()&&events.size()<maximum;){
        auto& knote=knotes_[index];
        if(!knote.active||!knote.enabled||(bucket&&knote.bucket!=*bucket)){++index;continue;}
        auto event=knote.kev;
        if(knote.kev.filter==DarwinEvfiltTimer){event.data=static_cast<std::int64_t>(knote.fired);knote.fired=0;}
        else if(knote.kev.filter==DarwinEvfiltUser)event.fflags=knote.user_fflags;
        events.push_back(event);++deliveries;
        if(knote.kev.flags&DarwinEvOneshot){knotes_.erase(knotes_.begin()+index);continue;}
        if(knote.kev.flags&DarwinEvDispatch)knote.enabled=false;
        if(knote.kev.flags&DarwinEvClear){
            knote.active=false;
            if(knote.kev.filter==DarwinEvfiltUser){knote.user_fflags=0;knote.kev.data=0;}
        }
        ++index;
    }
    return events;
}

std::vector<DarwinKeventQos> DarwinWorkqKqueue::Collect(std::uint8_t bucket,const DarwinKeventClock& clock,std::size_t maximum){
    return Deliver(bucket,clock,maximum);
}
std::vector<DarwinKeventQos> DarwinWorkqKqueue::CollectAll(const DarwinKeventClock& clock,std::size_t maximum){
    return Deliver(std::nullopt,clock,maximum);
}

std::optional<std::uint64_t> DarwinWorkqKqueue::NextDeadline() const noexcept {
    std::optional<std::uint64_t> next;
    for(const auto& knote:knotes_)if(knote.deadline&&knote.enabled&&(!next||*knote.deadline<*next))next=knote.deadline;
    return next;
}
bool DarwinWorkqKqueue::Bind(std::uint8_t bucket) noexcept {
    if(bucket>=bound_.size()||bound_[bucket])return false;
    bound_[bucket]=true;return true;
}
void DarwinWorkqKqueue::Unbind(std::uint8_t bucket) noexcept {if(bucket<bound_.size())bound_[bucket]=false;}

DarwinWorkloop::Change DarwinWorkloop::Apply(const DarwinKeventQos& kev,const DarwinKeventClock& clock,const ReadWord& read){
    if(kev.filter!=DarwinEvfiltWorkloop){
        const auto change=knotes_.Apply(kev,clock);
        return {change.error,change.unsupported};
    }
    constexpr auto known=DarwinNoteWlThreadRequest|DarwinNoteWlSyncWait|DarwinNoteWlSyncWake|DarwinNoteWlUpdateQos
        |DarwinNoteWlEndOwnership|DarwinNoteWlDiscoverOwner|DarwinNoteWlIgnoreEstale;
    if(kev.fflags&~known)return {0,"unsupported_workloop_command"};
    const auto command=kev.fflags&(DarwinNoteWlThreadRequest|DarwinNoteWlSyncWait|DarwinNoteWlSyncWake);
    if(command&(command-1))return {0,"unsupported_workloop_command"};
    if(command==DarwinNoteWlThreadRequest&&kev.ident!=id_)return {0,"unsupported_workloop_thread_request_ident"};
    // filt_wlupdate: the owner's state word is compared under the mask; a
    // mismatch is ESTALE unless ignored, and then no owner is discovered.
    const auto mask=kev.ext[DarwinWlExtMask];
    const bool discover=(kev.fflags&DarwinNoteWlDiscoverOwner)!=0;
    std::uint64_t word=0;bool stale=false;
    if(mask||discover){
        if(!read(kev.ext[DarwinWlExtAddress],word))return {14};
        stale=(word&mask)!=(kev.ext[DarwinWlExtValue]&mask);
        if(stale&&!(kev.fflags&DarwinNoteWlIgnoreEstale))return {70}; // Darwin ESTALE
    }
    if(discover&&!stale)owner_=static_cast<std::uint32_t>(word)&~3u; // dispatch lock owner port name
    if(kev.fflags&DarwinNoteWlEndOwnership)owner_=0;
    Change change;
    const bool remove=(kev.flags&DarwinEvDelete)!=0;
    if(command==DarwinNoteWlThreadRequest){
        if(remove){
            if(!request_&&!(kev.flags&DarwinEvAdd))return {2};
            request_.reset();
        }else if(kev.flags&DarwinEvAdd){
            if(!request_)request_=ThreadRequest{kev,!(kev.flags&DarwinEvDisable)};
            else{request_->kev.qos=kev.qos;request_->kev.udata=kev.udata;request_->kev.ext=kev.ext;}
            if(kev.flags&DarwinEvEnable)request_->enabled=true;
            if(kev.flags&DarwinEvDisable)request_->enabled=false;
        }else if(!request_)return {2};
        else{
            if(kev.fflags&DarwinNoteWlUpdateQos)request_->kev.qos=kev.qos;
            if(kev.flags&DarwinEvEnable)request_->enabled=true;
            if(kev.flags&DarwinEvDisable)request_->enabled=false;
        }
    }else if(command==DarwinNoteWlSyncWait){
        if(remove){
            if(!waiters_.erase(kev.ident)&&!(kev.flags&DarwinEvAdd))return {2};
            change.wake=kev.ident;
        }else{
            auto [entry,inserted]=waiters_.try_emplace(kev.ident,false);
            // Without an owner or servicer nobody holds the workloop: the
            // waiter returns at once and retries its acquisition.
            if(inserted&&!owner_&&!serviced_)entry->second=true;
            change.wait=!entry->second;
            if(inserted)++sync_waits;
        }
    }else if(command==DarwinNoteWlSyncWake){
        const auto waiter=waiters_.find(kev.ident);
        if(remove){
            if(waiter==waiters_.end()&&!(kev.flags&DarwinEvAdd))return {2};
            if(waiter!=waiters_.end())waiters_.erase(waiter);
        }else{
            if(waiter==waiters_.end())return {0,"unsupported_workloop_wake_without_waiter"};
            waiter->second=true;
        }
        change.wake=kev.ident;++sync_wakes;
    }
    return change;
}

std::optional<std::uint32_t> DarwinWorkloop::ServicerPriority(const DarwinKeventClock& clock){
    if(serviced_)return std::nullopt;
    std::optional<std::uint32_t> priority;
    if(request_&&request_->enabled&&!owner_)priority=static_cast<std::uint32_t>(request_->kev.qos);
    if(const auto bucket=knotes_.PendingBucket(clock)){
        const auto tier=std::min<std::uint8_t>(*bucket,6);
        const std::uint32_t knote=(0x100u<<(tier-1))|0xffu;
        if(!priority||(knote&0x3f00u)>(*priority&0x3f00u))priority=knote|(priority?*priority&0x80000000u:0x80000000u);
    }
    return priority;
}

std::vector<DarwinKeventQos> DarwinWorkloop::BeginService(const DarwinKeventClock& clock,std::size_t maximum){
    serviced_=true;++services;
    std::vector<DarwinKeventQos> events;
    if(request_&&request_->enabled&&!owner_&&maximum){
        // The thread request is delivered once per service, like EV_DISPATCH.
        auto event=request_->kev;
        event.flags&=static_cast<std::uint16_t>(~(DarwinEvAdd|DarwinEvDelete|DarwinEvEnable|DarwinEvDisable|DarwinEvReceipt));
        events.push_back(event);request_->enabled=false;
    }
    for(auto& event:knotes_.CollectAll(clock,maximum-events.size()))events.push_back(event);
    return events;
}
}
