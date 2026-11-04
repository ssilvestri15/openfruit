#include "darwin_sysctl.hpp"
#include <array>
#include <cstring>
#include <stdexcept>

namespace OpenFruit {
namespace {
template<class T> DarwinSysctlResult Bytes(std::span<const T> values) {
    DarwinSysctlResult result;result.bytes.resize(values.size_bytes());
    if(!result.bytes.empty())std::memcpy(result.bytes.data(),values.data(),values.size_bytes());
    return result;
}
}
DarwinSysctl::DarwinSysctl(std::uint64_t page_size) {
    if(!page_size||(page_size&(page_size-1))||page_size>INT32_MAX)
        throw std::invalid_argument("Invalid native guest sysctl page geometry.");
    page_size_=static_cast<std::uint32_t>(page_size);
}
DarwinSysctlResult DarwinSysctl::NameToOid(std::string_view input)const {
    if(input.empty())return {{},2};
    if(input.size()>=1024)return {{},63};
    // XNU copies exactly newlen bytes, terminates, then uses C-string lookup.
    auto name=input.substr(0,input.find('\0'));
    if(!name.empty()&&name.back()=='.')name.remove_suffix(1);
    const std::array<std::int32_t,2> pagesize{6,7},name2oid{0,3};
    if(name=="hw.pagesize")return Bytes<std::int32_t>(pagesize);
    if(name=="sysctl.name2oid")return Bytes<std::int32_t>(name2oid);
    if(name=="hw"){const std::array<std::int32_t,1> root{6};return Bytes<std::int32_t>(root);}
    if(name=="sysctl"){const std::array<std::int32_t,1> root{0};return Bytes<std::int32_t>(root);}
    return {{},2};
}
DarwinSysctlResult DarwinSysctl::Read(std::span<const std::int32_t> mib)const {
    if(mib.size()<2||mib.size()>12)return {{},22};
    if(mib.size()==2&&mib[0]==6&&mib[1]==7){
        const std::array<std::uint32_t,1> value{page_size_};return Bytes<std::uint32_t>(value);
    }
    return {{},2};
}
}
