#pragma once
#include "json_value.hpp"
#include <cstdint>
#include <optional>
#include <array>
namespace OpenFruit {
// The Windows interrupt-time APIs used by both guest clocks report 100ns ticks.
struct DarwinClockTimebase {
    static constexpr std::uint32_t Numerator=100,Denominator=1;
    static std::array<std::uint8_t,8> InfoBytes();
};
// Calendar origin for the existing 100ns Windows interrupt clock. This is a
// calibrated provider epoch, not a reconstructed Apple or historical Windows boot.
struct DarwinClockEpoch {
    std::uint64_t utc_filetime=0,continuous_before=0,continuous_after=0,boottime_usec=0;
    static std::optional<DarwinClockEpoch> FromSamples(std::uint64_t utc_filetime,
        std::uint64_t continuous_before,std::uint64_t continuous_after);
    static std::optional<DarwinClockEpoch> Capture();
    JsonValue ToJson() const;
};
struct DarwinCalendarTime {
    std::uint64_t utc_filetime=0,absolute_before=0,absolute_after=0;
    std::uint32_t seconds=0,microseconds=0;
    static std::optional<DarwinCalendarTime> FromSamples(std::uint64_t utc,
        std::uint64_t absolute_before,std::uint64_t absolute_after);
    static std::optional<DarwinCalendarTime> Capture();
    std::array<std::uint8_t,16> Timeval64() const;
    std::uint64_t AbsoluteTime() const;
    JsonValue ToJson() const;
};
}
