#include "darwin_file_signature.hpp"
#include "macho_code_directory.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <map>
#include <algorithm>
#include <vector>
namespace OpenFruit {
namespace {
std::uint64_t Read(std::string_view bytes,std::size_t p,unsigned n=4){std::uint64_t v=0;for(unsigned i=0;i<n;++i)v=v*256+static_cast<unsigned char>(bytes[p+i]);return v;}
bool Cms(std::string_view cms,std::string_view directory){
    CRYPT_VERIFY_MESSAGE_PARA parameters{};parameters.cbSize=sizeof(parameters);
    parameters.dwMsgAndCertEncodingType=X509_ASN_ENCODING|PKCS_7_ASN_ENCODING;
    const BYTE* content=reinterpret_cast<const BYTE*>(directory.data());DWORD size=static_cast<DWORD>(directory.size());
    struct Certificate {PCCERT_CONTEXT value=nullptr;~Certificate(){if(value)CertFreeCertificateContext(value);}} signer;
    return CryptVerifyDetachedMessageSignature(&parameters,0,reinterpret_cast<const BYTE*>(cms.data()),
        static_cast<DWORD>(cms.size()),1,&content,&size,&signer.value)&&signer.value;
}
}
JsonValue DarwinFileSignature::ToJson() const {
    auto r=JsonValue::ObjectValue();r.Set("source",JsonValue::String("original-CodeDirectory-pages-and-native-CMS-verifier"));
    r.Set("code_limit",JsonValue::Number(std::to_string(code_limit)));r.Set("end_offset",JsonValue::Number(std::to_string(end_offset)));
    r.Set("code_pages",JsonValue::Number(std::to_string(code_pages)));r.Set("cms_present",JsonValue::Boolean(cms_present));
    r.Set("cms_verified",JsonValue::Boolean(cms_verified));r.Set("ad_hoc",JsonValue::Boolean(ad_hoc));
    r.Set("identifier",JsonValue::String(identifier));
    std::string hash;constexpr char hex[]="0123456789abcdef";for(auto byte:cdhash){hash+=hex[byte>>4];hash+=hex[byte&15];}
    r.Set("cdhash",JsonValue::String(hash));
    r.Set("certificate_chain_trusted",JsonValue::Boolean(false));r.Set("platform_authority",JsonValue::Boolean(false));return r;
}
int VerifyDarwinFileSignature(std::string_view image,std::uint64_t offset,std::uint64_t size,DarwinFileSignature& output,std::string& error){
    output={};error.clear();auto Fail=[&](const char* message,int code=80){error=message;return code;};
    MachOSigningLayout layout;
    if(!InspectMachOSigningLayout(image,layout,error))return 80;
    if(size>40ULL*1024*1024)return Fail("Signature exceeds native registration limit.",7);
    if(offset!=layout.signature_offset||size!=layout.signature_size)return Fail("Signature request disagrees with original Mach-O command.");
    const auto signature=image.substr(static_cast<std::size_t>(offset),static_cast<std::size_t>(size));
    if(signature.size()<12||Read(signature,0)!=0xfade0cc0)return Fail("Missing embedded signature SuperBlob.");
    const auto length=Read(signature,4),count=Read(signature,8);
    if(length<12||length>signature.size()||count>(length-12)/8||count>64)return Fail("Signature index exceeds original blob.");
    std::map<std::uint32_t,std::string_view> blobs;std::vector<std::pair<std::uint64_t,std::uint64_t>> intervals;
    for(std::uint64_t i=0;i<count;++i){
        const auto slot=static_cast<std::uint32_t>(Read(signature,12+i*8));const auto at=Read(signature,16+i*8);
        if(at<12+count*8||at>length||length-at<8)return Fail("Signature slot header outside blob.");
        const auto n=Read(signature,at+4);if(n<8||n>length-at||!blobs.emplace(slot,signature.substr(at,n)).second)return Fail("Duplicate or truncated signature slot.");
        intervals.emplace_back(at,at+n);
    }
    std::sort(intervals.begin(),intervals.end());for(std::size_t i=1;i<intervals.size();++i)if(intervals[i].first<intervals[i-1].second)return Fail("Overlapping signature slots.");
    const auto cd=blobs.find(0);if(cd==blobs.end()||cd->second.size()<44)return Fail("Missing CodeDirectory.");
    // Alternate directories need CMS hash-agility binding/selection, not an
    // arbitrary choice of primary. Leave that contract explicitly unsupported.
    for(const auto& [slot,blob]:blobs)if(slot>=0x1000&&slot<0x1005)return Fail("Alternate CodeDirectory selection is not implemented.",45);
    CodeDirectorySpecialSlots specials;
    for(const auto& [slot,blob]:blobs){
        if(slot==0||slot==0x10000)continue;
        const auto magic=Read(blob,0);
        if((slot==2&&magic==0xfade0c01)||(slot==5&&magic==0xfade7171)||(slot==7&&magic==0xfade7172)
            ||(slot>=8&&slot<=11&&magic==0xfade8181))specials.emplace(slot,std::string(blob));
        else return Fail("Unsupported embedded signature slot.",45);
    }
    if(!VerifyMachOCodeDirectory(image,cd->second,specials,error))return 80;
    DarwinFileSignature result;result.code_limit=layout.signature_offset;result.code_pages=Read(cd->second,28);
    const auto ident_offset=static_cast<std::size_t>(Read(cd->second,20));
    if(ident_offset<cd->second.size()){
        const auto end_pos=cd->second.find('\0',ident_offset);
        result.identifier=std::string(cd->second.substr(ident_offset,end_pos!=std::string_view::npos?end_pos-ident_offset:std::string_view::npos));
    }
    const auto shift=static_cast<unsigned char>(cd->second[39]);
    const std::uint64_t mask=shift?(std::uint64_t(1)<<shift)-1:0;
    result.end_offset=(result.code_limit+mask)&~mask;result.ad_hoc=(Read(cd->second,12)&2)!=0;
    const auto cms=blobs.find(0x10000);result.cms_present=cms!=blobs.end()&&cms->second.size()>8;
    if(cms!=blobs.end()&&Read(cms->second,0)!=0xfade0b01)return Fail("CMS wrapper has invalid magic.");
    if(result.cms_present){if(!Cms(cms->second.substr(8),cd->second))return Fail("Original CMS signature does not authenticate CodeDirectory.");result.cms_verified=true;}
    else if(!result.ad_hoc)return Fail("Non-ad-hoc CodeDirectory has no CMS authenticator.");
    if(!ComputeMachOCodeDirectoryHash(cd->second,result.cdhash,error))return 5;
    output=result;return 0;
}
}
