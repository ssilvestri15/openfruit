#include "aea_root.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <zlib.h>
#include <array>
#include <algorithm>
extern "C" int openfruit_lzfse_decode_exact(const unsigned char*,std::size_t,unsigned char*,std::size_t);
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <stdexcept>
namespace OpenFruit {
namespace {
void Check(bool ok,const char* error){if(!ok)throw std::runtime_error(error);}
void Cng(NTSTATUS status,const char* error){Check(status>=0,error);}
struct Alg{BCRYPT_ALG_HANDLE value=nullptr;~Alg(){if(value)BCryptCloseAlgorithmProvider(value,0);}};
struct Hash{BCRYPT_HASH_HANDLE value=nullptr;~Hash(){if(value)BCryptDestroyHash(value);}};
struct Key{BCRYPT_KEY_HANDLE value=nullptr;~Key(){if(value)BCryptDestroyKey(value);}};
std::unique_ptr<SecretBytes> Hmac(std::string_view key,std::string_view data){
    Alg alg;Cng(BCryptOpenAlgorithmProvider(&alg.value,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG),"Native AEA HMAC provider unavailable.");
    Hash hash;Cng(BCryptCreateHash(alg.value,&hash.value,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),static_cast<ULONG>(key.size()),0),"Native AEA HMAC setup failed.");
    Cng(BCryptHashData(hash.value,reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),static_cast<ULONG>(data.size()),0),"Native AEA HMAC input failed.");
    auto out=std::make_unique<SecretBytes>(32);Cng(BCryptFinishHash(hash.value,out->Data(),32,0),"Native AEA HMAC finish failed.");return out;
}
std::unique_ptr<SecretBytes> Hkdf(std::string_view key,std::string_view salt,std::string_view info,std::size_t count){
    const std::string zeros(32,'\0');auto prk=Hmac(salt.empty()?std::string_view(zeros):salt,key);auto out=std::make_unique<SecretBytes>(count);
    std::unique_ptr<SecretBytes> previous;std::size_t offset=0;unsigned block=1;
    while(offset<count){const auto previous_size=previous?32:0;auto input=std::make_unique<SecretBytes>(previous_size+info.size()+1);
        if(previous)std::memcpy(input->Data(),previous->Data(),32);std::memcpy(input->Data()+previous_size,info.data(),info.size());input->Data()[previous_size+info.size()]=static_cast<unsigned char>(block++);
        previous=Hmac(prk->View(),input->View());const auto take=(count-offset)>32?32:count-offset;std::memcpy(out->Data()+offset,previous->Data(),take);offset+=take;
    }return out;
}
std::unique_ptr<SecretBytes> AesCtr(std::string_view encrypted,std::string_view key,std::string_view iv){
    const auto count=((encrypted.size()+15)/16)*16;Check(count&&count<=16*1024*1024,"Native AEA CTR byte budget exceeded.");
    auto counters=std::make_unique<SecretBytes>(count);std::memcpy(counters->Data(),iv.data(),16);
    for(std::size_t block=1;block<count/16;++block){auto target=counters->Data()+16*block;std::memcpy(target,target-16,16);bool carry=true;
        for(int n=15;n>=0&&carry;--n){target[n]+=1;carry=target[n]==0;}Check(!carry,"Native AEA root CTR counter overflow.");}
    Alg alg;Cng(BCryptOpenAlgorithmProvider(&alg.value,BCRYPT_AES_ALGORITHM,nullptr,0),"Native AEA AES provider unavailable.");
    Cng(BCryptSetProperty(alg.value,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),sizeof(BCRYPT_CHAIN_MODE_ECB),0),"Native AEA AES counter mode setup failed.");
    Key symmetric;Cng(BCryptGenerateSymmetricKey(alg.value,&symmetric.value,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),32,0),"Native AEA AES key setup failed.");
    auto stream = std::make_unique<SecretBytes>(count);
    ULONG written = 0;
    Cng(BCryptEncrypt(symmetric.value, counters->Data(), static_cast<ULONG>(count), nullptr, nullptr, 0, stream->Data(),
                      static_cast<ULONG>(count), &written, 0),
        "Native AEA AES counter encryption failed.");
    Check(written == count, "Native AEA counter size invalid.");
    auto plain=std::make_unique<SecretBytes>(encrypted.size());for(std::size_t n=0;n<encrypted.size();++n)plain->Data()[n]=stream->Data()[n]^static_cast<unsigned char>(encrypted[n]);return plain;
}
std::uint64_t U(std::string_view bytes,std::size_t offset,unsigned count){std::uint64_t value=0;for(unsigned n=0;n<count;++n)value|=std::uint64_t(static_cast<unsigned char>(bytes[offset+n]))<<(8*n);return value;}
std::unique_ptr<SecretBytes> FramedMac(std::string_view key,std::string_view data,std::string_view salt){
    auto message=std::make_unique<SecretBytes>(salt.size()+data.size()+8);if(!salt.empty())std::memcpy(message->Data(),salt.data(),salt.size());if(!data.empty())std::memcpy(message->Data()+salt.size(),data.data(),data.size());
    for(unsigned n=0;n<8;++n)message->Data()[salt.size()+data.size()+n]=static_cast<unsigned char>(std::uint64_t(salt.size())>>(8*n));return Hmac(key,message->View());
}
bool Equal(std::string_view a,std::string_view b){if(a.size()!=b.size())return false;unsigned difference=0;for(std::size_t n=0;n<a.size();++n)difference|=static_cast<unsigned char>(a[n])^static_cast<unsigned char>(b[n]);return difference==0;}
std::string LeIndex(std::string label,std::uint32_t index){for(unsigned n=0;n<4;++n)label+=static_cast<char>(index>>(8*n));return label;}
struct StreamHash {
    Alg algorithm;Hash hash;unsigned size=0;
    StreamHash(bool sha384,std::string_view key={}):size(sha384?48:32){
        Cng(BCryptOpenAlgorithmProvider(&algorithm.value,sha384?BCRYPT_SHA384_ALGORITHM:BCRYPT_SHA256_ALGORITHM,nullptr,key.empty()?0:BCRYPT_ALG_HANDLE_HMAC_FLAG),"Native AEA stream hash provider failed.");
        Cng(BCryptCreateHash(algorithm.value,&hash.value,nullptr,0,key.empty()?nullptr:reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),static_cast<ULONG>(key.size()),0),"Native AEA stream hash setup failed.");
    }
    void Add(std::string_view data){Cng(BCryptHashData(hash.value,reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),static_cast<ULONG>(data.size()),0),"Native AEA stream hash input failed.");}
    std::unique_ptr<SecretBytes> FinishRaw(){auto raw=std::make_unique<SecretBytes>(size);Cng(BCryptFinishHash(hash.value,raw->Data(),size,0),"Native AEA stream hash finish failed.");return raw;}
    std::string Finish(){auto raw=FinishRaw();constexpr char hex[]="0123456789abcdef";std::string out;for(auto c:raw->View()){const auto byte=static_cast<unsigned char>(c);out+=hex[byte>>4];out+=hex[byte&15];}return out;}
};
std::string Hex(std::string_view raw){constexpr char hex[]="0123456789abcdef";std::string out;for(unsigned char c:raw){out+=hex[c>>4];out+=hex[c&15];}return out;}
struct Inflate {z_stream stream{};bool ready=false;~Inflate(){if(ready)inflateEnd(&stream);}};

}
struct AeaRoot::Impl {
    std::unique_ptr<SecretBytes> main_key;std::string first_cluster_hmac;
    std::uint64_t file_size=0,encrypted_size=0,body_offset=0;std::uint32_t segment_size=0,segments_per_cluster=0;unsigned compression=0,checksum=0;
    ~Impl(){if(!first_cluster_hmac.empty())SecureZeroMemory(first_cluster_hmac.data(),first_cluster_hmac.size());}
};
AeaRoot::AeaRoot(std::unique_ptr<Impl> value):impl_(std::move(value)){}
AeaRoot::~AeaRoot()=default;
std::unique_ptr<AeaRoot> AeaRoot::Open(std::uint32_t profile,std::string_view auth,std::string_view master,std::string_view salt,std::string_view encrypted,std::uint64_t input_bytes,std::string& error){
    error.clear();try{
        Check(profile==1&&auth.size()<=65536&&master.size()==32&&salt.size()==32&&encrypted.size()==112,"Native AEA root input shape invalid.");
        Check(input_bytes>=12+auth.size()+144&&input_bytes<=128ULL*1024*1024*1024,"Native AEA original input size invalid.");
        auto state=std::make_unique<Impl>();state->body_offset=156+auth.size();std::string main_info="AEA_AMK";for(unsigned n=0;n<4;++n)main_info.push_back(static_cast<char>(profile>>(8*n)));
        state->main_key=Hkdf(master,salt,main_info,32);auto root_keys=Hkdf(state->main_key->View(),{},"AEA_RHEK",80);
        const auto salt_size=32+auth.size();auto message=std::make_unique<SecretBytes>(salt_size+48+8);std::memcpy(message->Data(),encrypted.data()+80,32);if(!auth.empty())std::memcpy(message->Data()+32,auth.data(),auth.size());std::memcpy(message->Data()+salt_size,encrypted.data()+32,48);
        for(unsigned n=0;n<8;++n)message->Data()[salt_size+48+n]=static_cast<unsigned char>(std::uint64_t(salt_size)>>(8*n));
        auto mac=Hmac(root_keys->View().substr(0,32),message->View());unsigned difference=0;for(unsigned n=0;n<32;++n)difference|=mac->Data()[n]^static_cast<unsigned char>(encrypted[n]);Check(!difference,"Original AEA root HMAC authentication failed.");
        auto plain=AesCtr(encrypted.substr(32,48),root_keys->View().substr(32,32),root_keys->View().substr(64,16));const auto bytes=plain->View();
        state->file_size = U(bytes, 0, 8);
        state->encrypted_size = U(bytes, 8, 8);
        state->segment_size = static_cast<std::uint32_t>(U(bytes, 16, 4));
        state->segments_per_cluster = static_cast<std::uint32_t>(U(bytes, 20, 4));
        state->compression = static_cast<unsigned char>(bytes[24]);
        state->checksum = static_cast<unsigned char>(bytes[25]);
        Check(state->file_size&&state->file_size<=128ULL*1024*1024*1024&&state->encrypted_size==input_bytes,"Authenticated AEA root file-size contract invalid.");
        Check(state->segment_size&&state->segment_size<=16*1024*1024&&state->segments_per_cluster&&state->segments_per_cluster<=65536,"Authenticated AEA segment/cluster bounds invalid.");
        Check(state->checksum<=2&&std::string("-4befxz").find(static_cast<char>(state->compression))!=std::string::npos,"Authenticated AEA root codec/checksum metadata unsupported.");
        state->first_cluster_hmac=std::string(encrypted.substr(80,32));return std::unique_ptr<AeaRoot>(new AeaRoot(std::move(state)));
    }catch(const std::exception& e){error=e.what();}catch(...){error="Native AEA root verification failed.";}return {};
}
AeaDecodeResult AeaRoot::Decode(const AeaRead& reader,const AeaSink& sink,CancellationToken cancellation,std::chrono::steady_clock::time_point deadline) const {
    OperationSpan span("runtime.aea_decode");AeaDecodeResult result;
    try{
        const auto context = span.Context();
        auto check = [&] {
            if (cancellation.Requested() || (context && context->CancellationRequested()))
                throw std::runtime_error("Native AEA decode cancelled.");
            if (std::chrono::steady_clock::now() >= deadline || (context && context->DeadlineExceeded()))
                throw std::runtime_error("Native AEA decode deadline exceeded.");
        };
        check();
        Check(reader && sink, "Native AEA stable reader and quarantine sink required.");
        Check(impl_->checksum == 0 || impl_->checksum == 2, "Native AEA segment checksum backend unavailable.");
        Check(impl_->compression == '-' || impl_->compression == 'e' || impl_->compression == 'z',
              "Native AEA segment codec backend unavailable.");
        std::uint64_t input=impl_->body_offset,output=0,clusters=0,segments=0,last_progress=0;std::string cluster_mac=impl_->first_cluster_hmac;
        StreamHash sha256(false),sha384(true);
        auto read = [&](std::uint64_t bytes) {
            check();
            Check(bytes <= 16ULL * 1024 * 1024 && input <= impl_->encrypted_size &&
                      bytes <= impl_->encrypted_size - input,
                  "Original AEA encoded range exceeds input bounds.");
            auto data = reader(input, bytes);
            Check(data && data->size() == bytes, "Original AEA encoded range read failed.");
            input += bytes;
            check();
            return std::move(*data);
        };
        const auto header_size=8+(impl_->checksum==2?32:0);const auto table_size=std::uint64_t(header_size)*impl_->segments_per_cluster;
        while(output<impl_->file_size){
            check();Check(clusters<=UINT32_MAX,"AEA cluster ordinal exceeds key domain.");auto cluster_key=Hkdf(impl_->main_key->View(),{},LeIndex("AEA_CK",static_cast<std::uint32_t>(clusters)),32);auto header_keys=Hkdf(cluster_key->View(),{},"AEA_CHEK",80);
            const auto encrypted_table=read(table_size),next_mac=read(32),segment_macs=read(32ULL*impl_->segments_per_cluster);auto table_mac=FramedMac(header_keys->View().substr(0,32),encrypted_table,next_mac+segment_macs);
            Check(Equal(cluster_mac,table_mac->View()),"Original AEA cluster header HMAC authentication failed.");auto table=AesCtr(encrypted_table,header_keys->View().substr(32,32),header_keys->View().substr(64,16));
            for(std::uint32_t index=0;index<impl_->segments_per_cluster;++index){
                check();const auto record=table->View().substr(std::size_t(index)*header_size,header_size);const auto decoded=U(record,0,4),encoded=U(record,4,4);
                if(output==impl_->file_size){Check(decoded==0&&encoded==0,"Authenticated AEA segment follows decoded EOF.");continue;}
                Check(decoded==std::min<std::uint64_t>(impl_->segment_size,impl_->file_size-output)&&encoded&&encoded<=16ULL*1024*1024,"Authenticated AEA segment size/position invalid.");
                auto segment_keys=Hkdf(cluster_key->View(),{},LeIndex("AEA_SK",index),80);const auto encrypted=read(encoded);auto mac=FramedMac(segment_keys->View().substr(0,32),encrypted,{});
                Check(Equal(std::string_view(segment_macs).substr(std::size_t(index)*32,32),mac->View()),"Original AEA segment HMAC authentication failed.");auto compressed=AesCtr(encrypted,segment_keys->View().substr(32,32),segment_keys->View().substr(64,16));std::unique_ptr<SecretBytes> expanded;
                if(encoded!=decoded){expanded=std::make_unique<SecretBytes>(decoded);
                    if(impl_->compression=='e')Check(openfruit_lzfse_decode_exact(compressed->Data(),static_cast<std::size_t>(encoded),expanded->Data(),static_cast<std::size_t>(decoded))!=0,"Native original LZFSE segment decode failed exact EOF/size.");
                    else if (impl_->compression == 'z') {
                        Inflate state;
                        Check(inflateInit(&state.stream) == Z_OK, "Native AEA zlib setup failed.");
                        state.ready = true;
                        auto guarded = std::make_unique<SecretBytes>(decoded + 1);
                        state.stream.next_in = compressed->Data();
                        state.stream.avail_in = static_cast<uInt>(encoded);
                        state.stream.next_out = guarded->Data();
                        state.stream.avail_out = static_cast<uInt>(decoded + 1);
                        const auto status = inflate(&state.stream, Z_FINISH);
                        Check(status == Z_STREAM_END && state.stream.avail_in == 0 && state.stream.total_out == decoded,
                              "Native AEA zlib exact EOF/size failed.");
                        std::memcpy(expanded->Data(), guarded->Data(), static_cast<std::size_t>(decoded));
                    } else
                        throw std::runtime_error("Uncompressed AEA segment has inconsistent sizes.");
                }
                const auto data=expanded?expanded->View():compressed->View();if(impl_->checksum==2)Check(Sha256(data).value_or("")==Hex(record.substr(8,32)),"Original AEA decoded segment SHA256 mismatch.");
                sha256.Add(data);sha384.Add(data);check();Check(sink(data),"Native AEA quarantine sink failed.");output+=decoded;++segments;
                if (context && (output - last_progress >= 16ULL * 1024 * 1024 || output == impl_->file_size)) {
                    last_progress = output;
                    auto progress = JsonValue::ObjectValue();
                    progress.Set("bytes", JsonValue::Number(std::to_string(output)));
                    progress.Set("total_bytes", JsonValue::Number(std::to_string(impl_->file_size)));
                    progress.Set("basis", JsonValue::String("bytes"));
                    context->Emit("task.progress", std::move(progress));
                }
            }cluster_mac=next_mac;++clusters;
        }
        const auto padding_bytes=impl_->encrypted_size-input;auto padding_keys=Hkdf(impl_->main_key->View(),{},"AEA_PAK",80);StreamHash padding(false,padding_keys->View().substr(0,32));
        while(input<impl_->encrypted_size){auto bytes=read(std::min<std::uint64_t>(1024*1024,impl_->encrypted_size-input));padding.Add(bytes);}
        auto terminal=padding.FinishRaw();Check(Equal(cluster_mac,terminal->View())||(!padding_bytes&&Equal(cluster_mac,std::string(32,'\0'))),"Original AEA terminal padding HMAC authentication failed.");check();
        result.authenticated=true;result.decoded_bytes=output;result.input_bytes=input;result.clusters=clusters;result.segments=segments;result.padding_bytes=padding_bytes;result.sha256=sha256.Finish();result.sha384=sha384.Finish();
    }catch(const std::exception& e){result={};result.error=e.what();}catch(...){result={};result.error="Native AEA full decode failed.";}
    auto completion=result.ToJson();span.Complete(std::move(completion),result.authenticated);return result;
}
JsonValue AeaDecodeResult::ToJson() const {
    auto out = JsonValue::ObjectValue();
    out.Set("authentication_verified", JsonValue::Boolean(authenticated));
    out.Set("all_clusters_authenticated", JsonValue::Boolean(authenticated));
    out.Set("decryption_complete", JsonValue::Boolean(authenticated));
    out.Set("decoded_bytes", JsonValue::Number(std::to_string(decoded_bytes)));
    out.Set("input_bytes", JsonValue::Number(std::to_string(input_bytes)));
    out.Set("clusters", JsonValue::Number(std::to_string(clusters)));
    out.Set("segments", JsonValue::Number(std::to_string(segments)));
    out.Set("padding_bytes", JsonValue::Number(std::to_string(padding_bytes)));
    out.Set("sha256", JsonValue::String(sha256));
    out.Set("sha384", JsonValue::String(sha384));
    out.Set("error", JsonValue::String(error));
    out.Set("publisher_verified", JsonValue::Boolean(false));
    out.Set("component_digest_verified", JsonValue::Boolean(false));
    return out;
}
JsonValue AeaRoot::ToJson() const {
    auto out = JsonValue::ObjectValue();
    out.Set("aea_root_authenticated", JsonValue::Boolean(true));
    out.Set("decoded_file_bytes", JsonValue::Number(std::to_string(impl_->file_size)));
    out.Set("encrypted_file_bytes", JsonValue::Number(std::to_string(impl_->encrypted_size)));
    out.Set("segment_bytes", JsonValue::Number(std::to_string(impl_->segment_size)));
    out.Set("segments_per_cluster", JsonValue::Number(std::to_string(impl_->segments_per_cluster)));
    out.Set("compression", JsonValue::String(std::string(1, static_cast<char>(impl_->compression))));
    out.Set("checksum_type", JsonValue::Number(std::to_string(impl_->checksum)));
    out.Set("all_clusters_authenticated", JsonValue::Boolean(false));
    out.Set("authentication_verified", JsonValue::Boolean(false));
    out.Set("decryption_complete", JsonValue::Boolean(false));
    out.Set("component_digest_verified", JsonValue::Boolean(false));
    return out;
}
}
