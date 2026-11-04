#include "apfs_compression.hpp"
#include <fstream>
#include <iterator>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
void Put(std::string& s,std::size_t p,std::size_t v,unsigned n){for(unsigned i=0;i<n;++i)s.at(p+i)=char((v>>(8*i))&255);}
std::string Frame(bool rle){
    const std::size_t packed=rle?43:42;std::string s="ZBM\x09";s.resize(4+packed+6,0);
    Put(s,4,packed,3);Put(s,7,rle?40:8,3);Put(s,10,23,3);Put(s,13,23,3);Put(s,16,24,3);
    s.replace(19,8,"ABCDEFGH");s[27]=char(255);if(rle){s[28]=char(0x30);s[29]=char(0x0f);}Put(s,4+packed,6,3);return s;
}
}
int main(int argc,char** argv){try{
    std::string error;
    for(bool rle:{false,true}){const auto frame=Frame(rle);auto out=DecodeApfsLzBitmap(frame,rle?40:8,error);Require(out.has_value(),error.c_str());std::string expected;for(int i=0;i<(rle?5:1);++i)expected+="ABCDEFGH";Require(*out==expected,"Literal/back-reference bytes differ.");
        for(std::size_t i=0;i<frame.size();++i)Require(!DecodeApfsLzBitmap(std::string_view(frame).substr(0,i),expected.size(),error),"Truncated frame accepted.");}
    const std::string raw=std::string(1,char(255))+"raw-data";Require(DecodeApfsLzBitmap(raw,8,error)==std::optional<std::string>("raw-data"),"Raw marker failed.");
    Require(DecodeApfsLzBitmap(Frame(false)+"unused-slot-bytes",8,error)==std::optional<std::string>("ABCDEFGH"),"Bounded slot tail rejected.");
    auto retained_distance=Frame(true);retained_distance[31]=3;
    Require(DecodeApfsLzBitmap(retained_distance,40,error)==std::optional<std::string>("ABCDEFGHABCDEFGHABCDEFGHABCDEFGHABCDEFGH"),"Dictionary distance mode 3 did not retain distance.");
    std::string padded="ZBM\x09";padded.resize(4+179+6,0);Put(padded,4,179,3);Put(padded,7,32768,3);Put(padded,10,23,3);Put(padded,13,23,3);Put(padded,16,24,3);padded.replace(19,8,"ABCDEFGH");padded[27]=char(255);padded[28]=char(0x30);for(std::size_t i=29;i<166;++i)padded[i]=char(255);padded[165]=char(0xcf);Put(padded,183,6,3);
    std::string large_expected;for(int i=0;i<4096;++i)large_expected+="ABCDEFGH";
    Require(DecodeApfsLzBitmap(padded,32768,error)==std::optional<std::string>(large_expected),"4097-token block padding rejected.");
    Require(!DecodeApfsLzBitmap(raw,7,error),"Incorrect raw length accepted.");
    std::string full="ZBM\x09";for(int i=0;i<2;++i){const auto start=full.size();full.resize(start+32774,'x');Put(full,start,32774,3);Put(full,start+3,32768,3);}const auto tail=full.size();full.resize(tail+6,0);Put(full,tail,6,3);
    Require(DecodeApfsLzBitmap(full,65536,error)==std::optional<std::string>(std::string(65536,'x')),"Full raw-block frame failed.");
    auto invalid=Frame(false);invalid[28]=char(15);Require(!DecodeApfsLzBitmap(invalid,8,error),"RLE without predecessor accepted.");
    invalid=Frame(false);invalid[27]=0;Require(!DecodeApfsLzBitmap(invalid,8,error),"Back-reference before output accepted.");
    invalid=Frame(false);Put(invalid,10,500,3);Require(!DecodeApfsLzBitmap(invalid,8,error),"Out-of-range section accepted.");
    std::string fork(8,0);Put(fork,0,8,4);fork+=Frame(false);Put(fork,4,fork.size(),4);
    Require(DecodeApfsLzBitmapResourceFork(fork,8,error)==std::optional<std::string>("ABCDEFGH"),"Resource-fork table decode failed.");
    invalid=fork;Put(invalid,0,7,4);Require(!DecodeApfsLzBitmapResourceFork(invalid,8,error),"Invalid table start accepted.");
    invalid=fork;Put(invalid,4,fork.size()-1,4);Require(!DecodeApfsLzBitmapResourceFork(invalid,8,error),"Trailing fork bytes accepted.");
    Require(!DecodeApfsLzBitmapResourceFork(fork,0,error),"Empty declared output accepted.");
    const std::string raw_lzvn=std::string(1,char(6))+"raw-lzvn-data";
    Require(DecodeApfsLzvn(raw_lzvn,13,error)==std::optional<std::string>("raw-lzvn-data"),"Raw LZVN marker failed.");
    Require(!DecodeApfsLzvn(raw_lzvn,12,error),"Incorrect raw LZVN length accepted.");
    Require(!DecodeApfsLzvn("",10,error),"Empty LZVN input accepted.");
    Require(!DecodeApfsLzvn(raw_lzvn,0,error),"Zero LZVN expected accepted.");
    Require(!DecodeApfsLzvn(raw_lzvn,70000,error),"Oversized LZVN block budget accepted.");
    const std::string lzvn_block=std::string("\xe8\x41\x42\x43\x44\x45\x46\x47\x48\x38\x08\xfb\xe3\x46\x47\x48\x06\x00\x00\x00\x00\x00\x00\x00",24);
    Require(DecodeApfsLzvn(lzvn_block,32,error)==std::optional<std::string>("ABCDEFGHABCDEFGHABCDEFGHABCDEFGH"),"Valid LZVN block decode failed.");
    Require(!DecodeApfsLzvn(lzvn_block.substr(0,10),32,error),"Truncated LZVN block accepted.");
    // Reaching the output size does not prove a complete compressed stream.
    for(std::size_t n=16;n<lzvn_block.size();++n)
        Require(!DecodeApfsLzvn(std::string_view(lzvn_block).substr(0,n),32,error),"LZVN accepted a missing/truncated end marker.");
    Require(DecodeApfsLzvn(lzvn_block+"tail",32,error)==std::optional<std::string>("ABCDEFGHABCDEFGHABCDEFGHABCDEFGH"),"Bounded LZVN slot tail rejected.");
    Require(!DecodeApfsLzvn(lzvn_block,31,error),"LZVN accepted an output buffer filled by a partial match.");
    std::string lzvn_fork(8,0);Put(lzvn_fork,0,8,4);lzvn_fork+=lzvn_block;Put(lzvn_fork,4,lzvn_fork.size(),4);
    Require(DecodeApfsLzvnResourceFork(lzvn_fork,32,error)==std::optional<std::string>("ABCDEFGHABCDEFGHABCDEFGHABCDEFGH"),"LZVN resource-fork decode failed.");
    invalid=lzvn_fork;Put(invalid,0,7,4);Require(!DecodeApfsLzvnResourceFork(invalid,32,error),"Invalid LZVN table start accepted.");
    invalid=lzvn_fork;Put(invalid,4,lzvn_fork.size()-1,4);Require(!DecodeApfsLzvnResourceFork(invalid,32,error),"Trailing LZVN fork bytes accepted.");
    Require(!DecodeApfsLzvnResourceFork(lzvn_fork,0,error),"Empty declared LZVN fork output accepted.");
    // Optional diagnostic mode: supplied fork bytes do not prove production derivation.
    if(argc==4){std::ifstream input(argv[1],std::ios::binary);Require(bool(input),"Diagnostic input unavailable.");std::string bytes((std::istreambuf_iterator<char>(input)),{});auto out=DecodeApfsLzBitmapResourceFork(bytes,std::stoull(argv[3]),error);Require(out.has_value(),error.c_str());std::ofstream output(argv[2],std::ios::binary);output.write(out->data(),out->size());Require(bool(output),"Diagnostic output failed.");std::cout<<"Diagnostic decoded bytes: "<<out->size()<<'\n';}
    else Require(argc==1,"Expected no arguments or diagnostic input/output/size.");
    std::cout<<"PASS: bounded LZBITMAP/LZVN decoding and malformed resource forks.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
