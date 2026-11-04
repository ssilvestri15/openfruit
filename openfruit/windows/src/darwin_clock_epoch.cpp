#include "darwin_clock_epoch.hpp"
#include <windows.h>
#include <realtimeapiset.h>
#include <utility>
namespace OpenFruit {
std::array<std::uint8_t,8> DarwinClockTimebase::InfoBytes(){
    std::array<std::uint8_t,8> bytes{};
    for(unsigned n=0;n<4;++n){bytes[n]=static_cast<std::uint8_t>(Numerator>>(8*n));bytes[n+4]=static_cast<std::uint8_t>(Denominator>>(8*n));}
    return bytes;
}
std::optional<DarwinClockEpoch> DarwinClockEpoch::FromSamples(std::uint64_t utc,std::uint64_t before,std::uint64_t after){
    constexpr std::uint64_t unix_origin=116444736000000000ULL;
    if(after<before||utc<unix_origin||utc-unix_origin<after)return {};
    const auto midpoint=before+(after-before)/2;
    return DarwinClockEpoch{utc,before,after,(utc-unix_origin-midpoint)/10};
}
std::optional<DarwinClockEpoch> DarwinClockEpoch::Capture(){
    ULONGLONG before=0,after=0;FILETIME utc{};
    QueryInterruptTimePrecise(&before);GetSystemTimePreciseAsFileTime(&utc);QueryInterruptTimePrecise(&after);
    return FromSamples((static_cast<std::uint64_t>(utc.dwHighDateTime)<<32)|utc.dwLowDateTime,before,after);
}
JsonValue DarwinClockEpoch::ToJson() const{
    auto result=JsonValue::ObjectValue();result.Set("source",JsonValue::String("Windows-UTC-and-continuous-interrupt-clock-calibration"));
    result.Set("unit",JsonValue::String("Unix-epoch-microseconds"));
    result.Set("boottime_usec",JsonValue::Number(std::to_string(boottime_usec)));
    result.Set("utc_filetime_100ns",JsonValue::Number(std::to_string(utc_filetime)));
    result.Set("continuous_before_100ns",JsonValue::Number(std::to_string(continuous_before)));
    result.Set("continuous_after_100ns",JsonValue::Number(std::to_string(continuous_after)));
    result.Set("sample_span_100ns",JsonValue::Number(std::to_string(continuous_after-continuous_before)));
    result.Set("epoch_stable_for_task",JsonValue::Boolean(true));
    result.Set("calendar_adjustment_tracking",JsonValue::Boolean(false));return result;
}
std::optional<DarwinCalendarTime> DarwinCalendarTime::FromSamples(std::uint64_t utc,std::uint64_t before,std::uint64_t after){
    constexpr std::uint64_t origin=116444736000000000ULL;
    if(utc<origin||after<before)return {};
    const auto ticks=utc-origin;
    // XNU gettimeofday casts seconds through uint32_t for the ARM64 ABI.
    return DarwinCalendarTime{utc,before,after,static_cast<std::uint32_t>(ticks/10000000ULL),static_cast<std::uint32_t>((ticks%10000000ULL)/10)};
}
std::optional<DarwinCalendarTime> DarwinCalendarTime::Capture(){
    ULONGLONG before=0,after=0;FILETIME utc{};
    QueryUnbiasedInterruptTimePrecise(&before);GetSystemTimePreciseAsFileTime(&utc);QueryUnbiasedInterruptTimePrecise(&after);
    return FromSamples((static_cast<std::uint64_t>(utc.dwHighDateTime)<<32)|utc.dwLowDateTime,before,after);
}
std::uint64_t DarwinCalendarTime::AbsoluteTime() const{return absolute_before+(absolute_after-absolute_before)/2;}
std::array<std::uint8_t,16> DarwinCalendarTime::Timeval64() const{
    std::array<std::uint8_t,16> bytes{};
    for(unsigned n=0;n<8;++n)bytes[n]=static_cast<std::uint8_t>(static_cast<std::uint64_t>(seconds)>>(8*n));
    for(unsigned n=0;n<4;++n)bytes[8+n]=static_cast<std::uint8_t>(microseconds>>(8*n));
    return bytes;
}
JsonValue DarwinCalendarTime::ToJson() const{
    auto report=JsonValue::ObjectValue();report.Set("source",JsonValue::String("Windows-precise-UTC-and-unbiased-interrupt-clock"));
    for(const auto& [key,value]:std::array<std::pair<const char*,std::uint64_t>,6>{{{"utc_filetime_100ns",utc_filetime},{"absolute_before_100ns",absolute_before},{"absolute_after_100ns",absolute_after},{"absolute_time_100ns",AbsoluteTime()},{"seconds",seconds},{"microseconds",microseconds}}})report.Set(key,JsonValue::Number(std::to_string(value)));
    return report;
}
}
