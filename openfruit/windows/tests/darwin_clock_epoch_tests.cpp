#include "darwin_clock_epoch.hpp"
#include <iostream>
#include <stdexcept>
#include <limits>
#include <array>
using namespace OpenFruit;
void Require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
int main(){try{
    constexpr std::uint64_t origin=116444736000000000ULL;
    const auto sample=DarwinClockEpoch::FromSamples(origin+123456789000ULL,1000000,1000020);
    Require(sample&&sample->boottime_usec==12345578899ULL,"100ns/Unix epoch conversion or midpoint differs");
    for(const auto& args:{std::array<std::uint64_t,3>{origin-1,0,0},{origin+10,11,12},{origin+10,2,1}})
        Require(!DarwinClockEpoch::FromSamples(args[0],args[1],args[2]),"Invalid or reversed clock sample fabricated epoch");
    const auto large=DarwinClockEpoch::FromSamples(UINT64_MAX,0,UINT64_MAX-origin);
    Require(bool(large),"Valid wide clock bracket overflowed midpoint arithmetic");
    const auto native=DarwinClockEpoch::Capture();Require(bool(native),"Native clock calibration failed");
    const auto calendar=native->utc_filetime-origin;const auto lower=(calendar-native->continuous_after)/10,upper=(calendar-native->continuous_before)/10;
    Require(lower<=native->boottime_usec&&native->boottime_usec<=upper,"Native epoch escapes recorded bracket");
    const auto report=native->ToJson();Require(report.Get("epoch_stable_for_task")->Bool()&&!report.Get("calendar_adjustment_tracking")->Bool(),"Unsupported adjustment capability advertised");
    const auto info=DarwinClockTimebase::InfoBytes();
    Require(info==std::array<std::uint8_t,8>{100,0,0,0,1,0,0,0},"Mach uint32 timebase wire layout differs from Windows100ns provider");
    const auto calendar_time=DarwinCalendarTime::FromSamples(origin+123456789,100,120);
    Require(calendar_time&&calendar_time->seconds==12&&calendar_time->microseconds==345678&&calendar_time->AbsoluteTime()==110,"Calendar conversion differs from Darwin microsecond ABI");
    const auto encoded=calendar_time->Timeval64();Require(encoded[0]==12&&encoded[8]==0x4e&&encoded[9]==0x46&&encoded[10]==5&&encoded[11]==0&&encoded[12]==0&&encoded[15]==0,"Timeval64 layout/zero padding differs");
    Require(!DarwinCalendarTime::FromSamples(origin-1,0,0)&&!DarwinCalendarTime::FromSamples(origin,2,1),"Invalid calendar samples admitted");
    const auto wrapped=DarwinCalendarTime::FromSamples(origin+(0x100000000ULL+7)*10000000ULL,0,0);Require(wrapped&&wrapped->seconds==7,"XNU seconds cast lost");
    Require(bool(DarwinCalendarTime::Capture()),"Native UTC calendar sample unavailable");
    std::cout<<"Native boot/calendar epoch arithmetic and real Windows clock bracket PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
