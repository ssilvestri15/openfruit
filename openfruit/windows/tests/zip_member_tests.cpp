#include "zip_member.hpp"
#include "content_hash.hpp"
#include "zip_stage.hpp"
#include "operation_events.hpp"
#include <zlib.h>
#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <random>
using namespace OpenFruit;
namespace {
void Require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
void Put(std::string& b,std::uint64_t value,unsigned n){for(unsigned i=0;i<n;++i)b.push_back(static_cast<char>(value>>(i*8)));}
void Set(std::string& b,std::size_t pos,std::uint64_t value,unsigned n){for(unsigned i=0;i<n;++i)b.at(pos+i)=static_cast<char>(value>>(i*8));}
std::string Pack(const std::string& original){
    z_stream s{};Require(deflateInit2(&s,Z_DEFAULT_COMPRESSION,Z_DEFLATED,-MAX_WBITS,8,Z_DEFAULT_STRATEGY)==Z_OK,"Owned DEFLATE initialization failed");
    std::string packed(deflateBound(&s,static_cast<uLong>(original.size())),'\0');
    s.next_in=reinterpret_cast<Bytef*>(const_cast<char*>(original.data()));s.avail_in=static_cast<uInt>(original.size());
    s.next_out=reinterpret_cast<Bytef*>(packed.data());s.avail_out=static_cast<uInt>(packed.size());
    const auto code=deflate(&s,Z_FINISH);const auto size=s.total_out;deflateEnd(&s);Require(code==Z_STREAM_END,"Owned DEFLATE failed");packed.resize(size);return packed;
}
struct OriginalArchive {
    std::string bytes, name="Original.plist", body="owned unchanged original input bytes";
    std::size_t central=0;
    explicit OriginalArchive(bool compressed,bool zip64=false,std::string content="owned unchanged original input bytes") : body(std::move(content)){
        const auto packed=compressed?Pack(body):body;
        const auto crc=crc32(0,reinterpret_cast<const Bytef*>(body.data()),static_cast<uInt>(body.size()));
        std::string extra;
        if(zip64){Put(extra,1,2);Put(extra,16,2);Put(extra,body.size(),8);Put(extra,packed.size(),8);}
        bytes.resize(30,'\0');Set(bytes,0,0x04034b50,4);Set(bytes,4,zip64?45:20,2);Set(bytes,8,compressed?8:0,2);Set(bytes,14,crc,4);
        Set(bytes,18,zip64?0xffffffff:packed.size(),4);Set(bytes,22,zip64?0xffffffff:body.size(),4);Set(bytes,26,name.size(),2);Set(bytes,28,extra.size(),2);
        bytes+=name+extra+packed;central=bytes.size();
        std::string directory(46,'\0');Set(directory,0,0x02014b50,4);Set(directory,6,zip64?45:20,2);Set(directory,10,compressed?8:0,2);Set(directory,16,crc,4);
        Set(directory,20,zip64?0xffffffff:packed.size(),4);Set(directory,24,zip64?0xffffffff:body.size(),4);Set(directory,28,name.size(),2);Set(directory,30,extra.size(),2);
        directory+=name+extra;bytes+=directory;
        Put(bytes,0x06054b50,4);Put(bytes,0,2);Put(bytes,0,2);Put(bytes,1,2);Put(bytes,1,2);Put(bytes,directory.size(),4);Put(bytes,central,4);Put(bytes,0,2);
    }
    ZipInventoryRead Reader(){return [this](std::uint64_t offset,std::uint64_t count)->std::optional<std::string>{if(offset>bytes.size()||count>bytes.size()-offset)return {};return bytes.substr(static_cast<std::size_t>(offset),static_cast<std::size_t>(count));};}
    ZipInventoryResult Inventory(){return InspectZipInventory(bytes.size(),Reader());}
    ZipMemberResult Read(){return ReadZipMember(Inventory(),name,Reader());}
    // Rebuild sizes/offsets consistently, leaving stream semantics as the only
    // negative control. This helper is for non-ZIP64 owned fixtures.
    void Payload(const std::string& packed){
        const auto start=30+name.size();bytes.replace(start,central-start,packed);central=start+packed.size();
        Set(bytes,18,packed.size(),4);Set(bytes,central+20,packed.size(),4);Set(bytes,bytes.size()-6,central,4);
    }
};
void Fail(OriginalArchive archive){auto result=archive.Read();Require(!result.stream_verified&&result.body.empty()&&result.sha256.empty()&&!result.error.empty(),"Corrupt ZIP member accepted or partial bytes exposed");}
}
int main(){try{
    for(bool compressed:{false,true})for(bool zip64:{false,true}){
        OriginalArchive archive(compressed,zip64);const auto original=archive.bytes;auto r=archive.Read();
        Require(r.stream_verified&&r.body==archive.body&&r.sha256==Sha256(archive.body)&&archive.bytes==original,"Original stored/DEFLATE/ZIP64 member did not round trip unchanged");
        auto report=r.ToJson();Require(!report.Get("publisher_verified")->Bool(true)&&!report.Get("provider_registered")->Bool(true)&&!report.Get("published")->Bool(true),"Stream verification claims publication/trust");
    }
    OriginalArchive stored(false), deflated(true), local64(true,true);
    auto bad=stored;bad.bytes[30]='X';Fail(bad);
    bad=stored;Set(bad.bytes,8,8,2);Fail(bad);
    bad=stored;Set(bad.bytes,14,1,4);Fail(bad);
    bad=stored;Set(bad.bytes,22,999,4);Fail(bad);
    bad=stored;bad.bytes[bad.central-1]^=1;Fail(bad);
    bad=deflated;bad.bytes[30+bad.name.size()]^=255;Fail(bad);
    bad=local64;Set(bad.bytes,30+bad.name.size()+2,15,2);Fail(bad);
    auto packed=Pack(deflated.body);bad=deflated;bad.Payload(packed+"X");
    Require(bad.Read().error=="ZIP member has trailing compressed bytes.","Trailing compressed bytes were not detected at stream boundary");Fail(bad);
    packed.pop_back();bad=deflated;bad.Payload(packed);
    Require(bad.Read().error=="ZIP DEFLATE stream is incomplete or invalid.","Truncated DEFLATE stream was not detected before CRC");Fail(bad);
    auto inventory=stored.Inventory();Require(inventory.directory_validated,"Owned inventory failed");
    Require(!ReadZipMember(inventory,"missing",stored.Reader()).stream_verified,"Missing original member accepted");
    auto metadata=inventory;metadata.members[0].uncompressed=65ULL*1024*1024;
    Require(!ReadZipMember(metadata,stored.name,stored.Reader()).stream_verified,"Decoded memory budget ignored");
    metadata=inventory;metadata.members[0].flags|=8;
    Require(!ReadZipMember(metadata,stored.name,stored.Reader()).stream_verified,"Unsupported descriptor accepted");
    metadata=inventory;auto next=metadata.members[0];next.name="other";next.local_offset=1;metadata.members.push_back(next);
    Require(!ReadZipMember(metadata,stored.name,stored.Reader()).stream_verified,"Local header overlaps another member");
    bool called=false;auto inactive=[&](auto,auto)->std::optional<std::string>{called=true;return {};};CancellationSource source;source.Cancel();
    auto interrupted=ReadZipMember(inventory,stored.name,inactive,source.Token());Require(!called&&interrupted.error=="ZIP member read cancelled.","Cancellation did not stop acquisition");
    interrupted=ReadZipMember(inventory,stored.name,inactive,{},std::chrono::steady_clock::now());Require(!called&&interrupted.error=="ZIP member deadline exceeded.","Deadline did not stop acquisition");
    int calls=0;interrupted=ReadZipMember(inventory,stored.name,[&](auto offset,auto count)->std::optional<std::string>{++calls;if(calls==3)return {};return stored.bytes.substr(static_cast<std::size_t>(offset),static_cast<std::size_t>(count));});
    Require(!interrupted.stream_verified&&interrupted.body.empty()&&calls==3,"Payload acquisition failure ignored");
    OriginalArchive abc(true,false,"abc");auto abc_result=abc.Read();
    Require(abc_result.sha384=="cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7","Native SHA384 known vector failed");
    OriginalArchive large(true,false,std::string(70*1024*1024,'x'));std::uint64_t emitted=0;
    auto streamed=StreamZipMember(large.Inventory(),large.name,large.Reader(),[&](std::string_view bytes){emitted+=bytes.size();return true;});
    Require(streamed.stream_verified&&streamed.body.empty()&&streamed.decoded_bytes==large.body.size()&&emitted==large.body.size()&&streamed.sha256==Sha256(large.body),"Large member did not stream independently of metadata memory budget");
    Require(!large.Read().stream_verified,"Metadata memory cap removed by streaming support");
    std::mt19937 random(1234);std::string noise(17*1024*1024,'\0');for(auto& c:noise)c=static_cast<char>(random());
    OriginalArchive chunks(true,false,noise);std::size_t maximum=0;calls=0;
    streamed=StreamZipMember(chunks.Inventory(),chunks.name,[&](auto offset,auto count)->std::optional<std::string>{maximum=std::max(maximum,static_cast<std::size_t>(count));++calls;return chunks.bytes.substr(static_cast<std::size_t>(offset),static_cast<std::size_t>(count));},[](auto){return true;});
    Require(streamed.stream_verified&&streamed.sha256==Sha256(noise)&&calls>=4&&maximum<=16*1024*1024,"DEFLATE input did not refill across bounded chunks");
    const auto root=std::filesystem::temp_directory_path()/("OPENFRUIT-zip-stage-"+NewOperationId());std::filesystem::create_directory(root);
    auto staged=StageZipMember(abc.Inventory(),abc.name,abc.Reader(),root/"success","sha2-384",abc_result.sha384);
    Require(staged.digest_matched&&std::filesystem::file_size(staged.path)==3&&Sha256File(staged.path)==Sha256("abc"),"Native file stage did not preserve original content/digest");
    staged=StageZipMember(abc.Inventory(),abc.name,abc.Reader(),root/"bad-digest","sha2-384",std::string(96,'0'));
    Require(!staged.digest_matched&&staged.path.empty()&&std::filesystem::is_empty(root/"bad-digest"),"Failed stage exposed partial file");
    staged=StageZipMember(abc.Inventory(),abc.name,abc.Reader(),root/"success","sha2-384",abc_result.sha384);
    Require(!staged.digest_matched&&!std::filesystem::is_empty(root/"success"),"Existing quarantine directory was overwritten");
    std::string frame="AEA1";Put(frame,1,4);Put(frame,0,4);frame+="owned encrypted-input fixture";
    OriginalArchive encrypted(false,false,frame);
    staged=StageZipMember(encrypted.Inventory(),encrypted.name,encrypted.Reader(),root/"encrypted-input","sha2-384",std::string(96,'0'));
    Require(!staged.digest_matched&&staged.encrypted_input_retained&&staged.stream.stream_verified&&!staged.path.empty()&&Sha256File(staged.path)==Sha256(frame),"ZIP-verified encrypted input was lost or falsely approved");
    Require(!staged.ToJson().Get("component_digest_scope_verified")->Bool(true)&&!staged.ToJson().Get("publisher_verified")->Bool(true),"Unverified AEA digest scope elevated trust");
    std::filesystem::remove_all(root); // Unique owned fixture only.
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
