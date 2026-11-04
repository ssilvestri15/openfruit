#include "zip_member.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <zlib.h>
#include <algorithm>
#include <array>
#include <stdexcept>
#include <windows.h>
#include <bcrypt.h>
namespace OpenFruit {
namespace {
std::uint64_t U(const std::string& bytes, std::size_t offset, unsigned count) {
    if (offset > bytes.size() || count > bytes.size()-offset) throw std::runtime_error("Truncated ZIP local metadata.");
    std::uint64_t value = 0;
    for (unsigned i=0;i<count;++i) value |= std::uint64_t(static_cast<unsigned char>(bytes[offset+i])) << (i*8);
    return value;
}
struct InflateState {
    z_stream stream{};
    bool initialized = false;
    ~InflateState() { if (initialized) inflateEnd(&stream); }
};
struct StreamHash {
    BCRYPT_ALG_HANDLE algorithm=nullptr; BCRYPT_HASH_HANDLE handle=nullptr; unsigned size=0;
    explicit StreamHash(bool sha384):size(sha384?48:32){
        if(BCryptOpenAlgorithmProvider(&algorithm,sha384?BCRYPT_SHA384_ALGORITHM:BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0)
            BCryptCreateHash(algorithm,&handle,nullptr,0,nullptr,0,0);
    }
    ~StreamHash(){if(handle)BCryptDestroyHash(handle);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);}
    bool Add(std::string_view bytes){return handle&&BCryptHashData(handle,reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),static_cast<ULONG>(bytes.size()),0)>=0;}
    std::string Finish(){std::array<UCHAR,48> bytes{};if(!handle||BCryptFinishHash(handle,bytes.data(),size,0)<0)throw std::runtime_error("ZIP stream hashing failed.");
        constexpr char hex[]="0123456789abcdef";std::string out;for(unsigned n=0;n<size;++n){out.push_back(hex[bytes[n]>>4]);out.push_back(hex[bytes[n]&15]);}return out;}
};
}
ZipMemberResult StreamZipMember(const ZipInventoryResult& inventory, const std::string& name,
    const ZipInventoryRead& reader, const ZipMemberSink& sink, CancellationToken cancellation, std::chrono::steady_clock::time_point deadline) {
    ZipMemberResult result;
    try {
        const auto context=CurrentOperationContext();
        auto check = [&] {
            if (cancellation.Requested()||(context&&context->CancellationRequested())) throw std::runtime_error("ZIP member read cancelled.");
            if (std::chrono::steady_clock::now() >= deadline||(context&&context->DeadlineExceeded())) throw std::runtime_error("ZIP member deadline exceeded.");
        };
        check();
        if (!inventory.directory_validated || !reader || !sink) throw std::runtime_error("Validated original ZIP directory and sink required.");
        const ZipInventoryMember* member = nullptr;
        for (const auto& m : inventory.members) if (m.name == name) {
            if (member) throw std::runtime_error("Ambiguous original ZIP member.");
            member = &m;
        }
        if (!member) throw std::runtime_error("Original ZIP member missing.");
        if (member->compressed > 128ULL*1024*1024*1024 || member->uncompressed > 128ULL*1024*1024*1024)
            throw std::runtime_error("ZIP stream byte budget exceeded.");
        if (member->flags & ~std::uint16_t(0x806) || (member->method != 0 && member->method != 8))
            throw std::runtime_error("ZIP member encoding or data descriptor unsupported.");
        std::uint64_t boundary = inventory.directory_offset;
        if (inventory.archive_bytes > 128ULL*1024*1024*1024 || boundary > inventory.archive_bytes || member->local_offset >= boundary) throw std::runtime_error("ZIP member offset invalid.");
        for (const auto& m : inventory.members) {
            if (&m != member && m.local_offset == member->local_offset) throw std::runtime_error("ZIP member header aliases another entry.");
            if (m.local_offset > member->local_offset) boundary = std::min(boundary,m.local_offset);
        }
        auto read = [&](std::uint64_t offset,std::uint64_t count) {
            check();
            if (offset > boundary || count > boundary-offset || count > 64ULL*1024*1024) throw std::runtime_error("ZIP member overlaps another archive region.");
            if (!count) return std::string{};
            auto bytes = reader(offset,count);
            if (!bytes || bytes->size()!=count) throw std::runtime_error("Original ZIP member acquisition failed.");
            check(); return std::move(*bytes);
        };
        const auto header = read(member->local_offset,30);
        if (U(header,0,4)!=0x04034b50 || U(header,6,2)!=member->flags || U(header,8,2)!=member->method || U(header,14,4)!=member->crc32)
            throw std::runtime_error("Original local ZIP header differs from directory.");
        const auto n=U(header,26,2), x=U(header,28,2);
        const auto variable = read(member->local_offset+30,n+x);
        if (variable.substr(0,static_cast<std::size_t>(n))!=member->name) throw std::runtime_error("Original local ZIP name differs from directory.");
        auto compressed=U(header,18,4), uncompressed=U(header,22,4);
        const bool nc=compressed==0xffffffff, nu=uncompressed==0xffffffff;
        std::size_t pos=static_cast<std::size_t>(n);
        bool zip64=false;
        while (pos<variable.size()) {
            if(variable.size()-pos<4)throw std::runtime_error("Truncated ZIP local extra header.");
            const auto id=U(variable,pos,2), count=U(variable,pos+2,2);pos+=4;
            if(count>variable.size()-pos)throw std::runtime_error("Truncated ZIP local extra data.");
            if(id==1) {
                if(zip64)throw std::runtime_error("Duplicate ZIP64 local metadata.");
                zip64=true;std::size_t field=pos;
                auto next=[&]{if(pos+count-field<8)throw std::runtime_error("Missing ZIP64 local size.");auto value=U(variable,field,8);field+=8;return value;};
                if(nu)uncompressed=next();if(nc)compressed=next();
            }
            pos+=static_cast<std::size_t>(count);
        }
        if(((nc||nu)&&!zip64)||compressed!=member->compressed||uncompressed!=member->uncompressed)
            throw std::runtime_error("Original ZIP member sizes disagree.");
        const auto payload_offset=member->local_offset+30+n+x;
        if(payload_offset>boundary||compressed>boundary-payload_offset)throw std::runtime_error("ZIP member overlaps another archive region.");
        StreamHash sha256(false),sha384(true);uLong crc=0;std::uint64_t decoded=0;
        auto emit=[&](std::string_view bytes){
            check();if(bytes.size()>uncompressed-decoded)throw std::runtime_error("ZIP member decoded size exceeded.");
            if(!sha256.Add(bytes)||!sha384.Add(bytes))throw std::runtime_error("ZIP stream hashing failed.");
            crc=crc32(crc,reinterpret_cast<const Bytef*>(bytes.data()),static_cast<uInt>(bytes.size()));
            if(!sink(bytes))throw std::runtime_error("ZIP member quarantine write failed.");decoded+=bytes.size();
        };
        if(member->method==0) {
            if(compressed!=uncompressed)throw std::runtime_error("Stored ZIP member sizes disagree.");
            for(std::uint64_t offset=0;offset<compressed;){
                const auto packed=read(payload_offset+offset,std::min<std::uint64_t>(16ULL*1024*1024,compressed-offset));
                emit(packed);offset+=packed.size();
            }
        } else {
            InflateState state;
            if(inflateInit2(&state.stream,-MAX_WBITS)!=Z_OK)throw std::runtime_error("Native ZIP decoder initialization failed.");
            state.initialized=true;
            std::array<char,65536> output{};std::string packed;std::uint64_t offset=0;
            for(;;) {
                if(!state.stream.avail_in&&offset<compressed){packed=read(payload_offset+offset,std::min<std::uint64_t>(16ULL*1024*1024,compressed-offset));offset+=packed.size();
                    state.stream.next_in=reinterpret_cast<Bytef*>(packed.data());state.stream.avail_in=static_cast<uInt>(packed.size());}
                check();state.stream.next_out=reinterpret_cast<Bytef*>(output.data());state.stream.avail_out=static_cast<uInt>(output.size());
                const auto before=state.stream.avail_in;
                const auto code=inflate(&state.stream,Z_NO_FLUSH);
                const auto produced=output.size()-state.stream.avail_out;
                if(produced)emit(std::string_view(output.data(),produced));
                if(code==Z_STREAM_END) {
                    if(state.stream.avail_in||offset!=compressed)throw std::runtime_error("ZIP member has trailing compressed bytes.");
                    break;
                }
                if(code!=Z_OK || (!produced && state.stream.avail_in==before))throw std::runtime_error("ZIP DEFLATE stream is incomplete or invalid.");
            }
        }
        check();
        if(decoded!=uncompressed || crc!=member->crc32)
            throw std::runtime_error("Original ZIP member size or CRC32 verification failed.");
        result.sha256=sha256.Finish();result.sha384=sha384.Finish();check();result.compressed_bytes=compressed;result.decoded_bytes=decoded;result.stream_verified=true;
    } catch(const std::exception& e) { result={};result.error=e.what(); }
    catch(...) { result={};result.error="Original ZIP member read failed."; }
    return result;
}
ZipMemberResult ReadZipMember(const ZipInventoryResult& inventory,const std::string& name,const ZipInventoryRead& reader,
    CancellationToken cancellation,std::chrono::steady_clock::time_point deadline){
    for(const auto& m:inventory.members)if(m.name==name&&(m.compressed>64ULL*1024*1024||m.uncompressed>64ULL*1024*1024)){
        ZipMemberResult r;r.error="ZIP metadata-member memory budget exceeded.";return r;}
    std::string body;auto result=StreamZipMember(inventory,name,reader,[&](std::string_view bytes){
        if(bytes.size()>64ULL*1024*1024-body.size())return false;body.append(bytes);return true;
    },cancellation,deadline);
    if(result.stream_verified)result.body=std::move(body);return result;
}
ZipMemberResult ReadRemoteZipMember(const RangeTransferRequest& options,const std::string& name) {
    auto inventory=InspectRemoteZip(options);
    return ReadRemoteZipMember(inventory,name,options);
}
ZipMemberResult ReadRemoteZipMember(const ZipInventoryResult& inventory,const std::string& name,const RangeTransferRequest& options) {
    if(!inventory.directory_validated) { ZipMemberResult result;result.error=inventory.error;return result; }
    if(inventory.source_url.empty() || inventory.source_etag.empty() ||
        (!options.url.empty()&&options.url!=inventory.source_url) ||
        (options.expected_total&&options.expected_total!=inventory.archive_bytes) ||
        (!options.expected_etag.empty()&&options.expected_etag!=inventory.source_etag)) {
        ZipMemberResult result;result.error="Original ZIP source identity mismatch.";return result;
    }
    auto request=options;request.url=inventory.source_url;request.expected_total=inventory.archive_bytes;request.expected_etag=inventory.source_etag;
    return ReadZipMember(inventory,name,[&](std::uint64_t offset,std::uint64_t count)->std::optional<std::string>{
        request.offset=offset;request.bytes=count;auto result=HttpTransfer::ReadRange(request);
        if(!result.Succeeded())return {};return std::move(result.body);
    },options.cancellation,options.deadline);
}
JsonValue ZipMemberResult::ToJson() const {
    auto out=JsonValue::ObjectValue();out.Set("stream_verified",JsonValue::Boolean(stream_verified));
    out.Set("decoded_bytes",JsonValue::Number(std::to_string(decoded_bytes)));out.Set("compressed_bytes",JsonValue::Number(std::to_string(compressed_bytes)));
    out.Set("sha256",JsonValue::String(sha256));out.Set("error",JsonValue::String(error));
    out.Set("sha384",JsonValue::String(sha384));
    out.Set("publisher_verified",JsonValue::Boolean(false));out.Set("provider_registered",JsonValue::Boolean(false));
    out.Set("published",JsonValue::Boolean(false));return out;
}
}
