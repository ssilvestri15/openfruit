#include "apfs_metadata.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
void Require(bool ok,const char* e){if(!ok)throw std::runtime_error(e);}
using U64=std::uint64_t;
void Put(std::string& s,std::size_t p,U64 v,unsigned n=8){for(unsigned i=0;i<n;++i)s.at(p+i)=static_cast<char>(v>>(8*i));}
U64 Get(const std::string& s,std::size_t p,unsigned n=8){U64 v=0;for(unsigned i=0;i<n;++i)v|=U64(static_cast<unsigned char>(s.at(p+i)))<<(8*i);return v;}
void Sign(std::string& b){constexpr U64 m=0xffffffff;U64 a=0,c=0;for(std::size_t i=8;i<b.size();i+=4){a=(a+Get(b,i,4))%m;c=(c+a)%m;}const auto x=m-(a+c)%m,y=m-(a+x)%m;Put(b,0,x|(y<<32));}
std::string Object(U64 oid,U64 xid,unsigned type,unsigned sub=0){std::string b(4096,'\0');Put(b,8,oid);Put(b,16,xid);Put(b,24,type,4);Put(b,28,sub,4);return b;}
std::string NX(U64 xid,bool latest){auto b=Object(1,xid,0x80000001);b.replace(32,4,"NXSB");Put(b,36,4096,4);Put(b,40,24);Put(b,64,2);b.replace(72,16,"owned-uuid-01234");Put(b,104,4,4);Put(b,108,4,4);Put(b,112,1);Put(b,120,8);Put(b,128,latest?0:2,4);Put(b,132,latest?0:2,4);Put(b,136,latest?2:0,4);Put(b,140,2,4);Put(b,144,latest?2:0,4);Put(b,148,2,4);Put(b,152,1025);Put(b,160,latest?12:15);Put(b,168,1027);Put(b,180,100,4);Put(b,184,1026);Sign(b);return b;}
std::string Map(U64 p,U64 xid,U64 data){auto b=Object(p,xid,0x4000000c);Put(b,32,1,4);Put(b,36,2,4);for(unsigned i=0;i<2;++i){const auto off=40+i*40;Put(b,off,i?0x80000011:0x80000005,4);Put(b,off+8,4096,4);Put(b,off+24,i?1027:1025);Put(b,off+32,data+i);}Sign(b);return b;}
std::string Omap(U64 p,U64 xid,U64 tree){auto b=Object(p,xid,0x4000000b);Put(b,40,0x40000002,4);Put(b,48,tree);Sign(b);return b;}
std::string Tree(U64 p,U64 xid,U64 volume){auto b=Object(p,xid,0x40000002,11);Put(b,32,7,2);Put(b,36,1,4);Put(b,42,64,2);Put(b,56,0,2);Put(b,58,16,2);Put(b,120,1026);Put(b,128,xid);Put(b,4044,4096,4);Put(b,4048,volume);Put(b,4056,18,4);Put(b,4060,4096,4);Put(b,4064,16,4);Put(b,4068,16,4);Put(b,4072,16,4);Put(b,4076,16,4);Put(b,4080,1);Put(b,4088,1);Sign(b);return b;}
std::string Volume(U64 xid){auto b=Object(1026,xid,13);b.replace(32,4,"APSB");Put(b,56,33);Put(b,116,2,4);Put(b,128,18);Put(b,136,2000);Put(b,264,1);b.replace(704,5,"Owned");Sign(b);return b;}
std::string Image(){std::string s(24*4096,'\0');auto set=[&](unsigned p,std::string b){s.replace(p*4096,4096,b);};set(0,NX(1,false));set(1,Map(1,2,8));set(2,NX(2,false));set(3,Map(3,3,10));set(4,NX(3,true));for(unsigned i=8;i<12;++i){auto b=Object(i%2?1027:1025,i<10?2:3,i%2?0x80000011:0x80000005);Sign(b);set(i,b);}set(12,Omap(12,3,13));set(13,Tree(13,3,14));set(14,Volume(3));set(15,Omap(15,2,16));set(16,Tree(16,2,17));set(17,Volume(2));return s;}
JsonValue Inspect(const std::string& s){return InspectApfsMetadata([&](U64 p,U64 n){return s.substr(static_cast<std::size_t>(p),static_cast<std::size_t>(n));},s.size());}
void Bad(const std::string& s){const auto r=Inspect(s);Require(!r.Get("complete")->Bool()&&!r.Get("metadata_verified")->Bool()&&!r.Get("volumes"),"Malformed metadata approved or partial volumes leaked");}
void Mutate(std::string& s,unsigned p,const std::function<void(std::string&)>& fn){auto b=s.substr(p*4096,4096);fn(b);Sign(b);s.replace(p*4096,4096,b);}
void Write(const std::filesystem::path& p,const std::string& s){std::ofstream f(p,std::ios::binary);f.write(s.data(),static_cast<std::streamsize>(s.size()));Require(bool(f),"Owned fixture write failed");}
std::string RawHash(const std::string& data){const auto hex=*Sha256(data);std::string b;for(std::size_t i=0;i<hex.size();i+=2)b+=static_cast<char>(std::stoi(hex.substr(i,2),nullptr,16));return b;}
std::string FsKey(U64 id,unsigned type){std::string key(8,'\0');Put(key,0,id|(U64(type)<<60));return key;}
std::string FsNode(bool root,unsigned level,const std::vector<std::pair<std::string,std::string>>& entries,U64 keys,U64 nodes){
    std::string b(4096,'\0');Put(b,32,24|(root?1:0)|(level?0:2),2);Put(b,34,level,2);Put(b,36,entries.size(),4);const auto len=entries.size()*8;Put(b,42,len,2);std::size_t kp=56+len,used_values=0;const auto end=root?4056U:4096U;
    for(std::size_t i=0;i<entries.size();++i){const auto& [k,v]=entries[i];used_values+=v.size();Put(b,56+i*8,kp-56-len,2);Put(b,58+i*8,k.size(),2);Put(b,60+i*8,used_values,2);Put(b,62+i*8,v.size(),2);b.replace(kp,k.size(),k);b.replace(end-used_values,v.size(),v);kp+=k.size();}
    if(root){Put(b,4056,0x1c2,4);Put(b,4060,4096,4);Put(b,4080,keys);Put(b,4088,nodes);}return b;
}
std::string TreesImage(){
    auto s=Image();auto set=[&](unsigned p,const std::string& b){s.replace(p*4096,4096,b);};auto v=s.substr(14*4096,4096);Put(v,1024,1999);Put(v,1032,22);Put(v,1040,0x40000002,4);Sign(v);set(14,v);
    auto omap=Omap(18,3,19);set(18,omap);auto t=Tree(19,3,21);Put(t,36,3,4);Put(t,120,1999);Put(t,128,3);
    for(unsigned i=0;i<3;++i){Put(t,56+i*4,i*16,2);Put(t,58+i*4,(i+1)*16,2);Put(t,120+i*16,1999+i);Put(t,128+i*16,3);Put(t,4040-i*16,i?8:0,4);Put(t,4044-i*16,4096,4);Put(t,4048-i*16,i==0?21:i==1?20:23);}Put(t,4080,3);Sign(t);set(19,t);
    auto dir=std::string(92,'\0');Put(dir,0,1);Put(dir,8,2);Put(dir,80,0x4000,2);auto file=dir;Put(file,0,2);Put(file,8,16);Put(file,80,0x8000,2);
    auto name=FsKey(2,9);name.resize(12,'\0');const std::string leaf_name="owned.txt";Put(name,8,leaf_name.size()+1,4);name+=leaf_name;name+='\0';std::string entry(18,'\0');Put(entry,0,16);Put(entry,16,8,2);
    const auto child=FsNode(false,0,{{FsKey(2,3),dir},{name,entry},{FsKey(16,3),file}},0,0);set(23,child);std::string link(40,'\0');Put(link,0,1);link.replace(8,32,RawHash(child));const auto fsroot=FsNode(true,1,{{FsKey(2,3),link}},3,2);set(20,fsroot);
    auto integrity=Object(1999,3,30);Put(integrity,32,2,4);Put(integrity,40,1,4);Put(integrity,44,128,4);integrity.replace(128,32,RawHash(fsroot));Sign(integrity);set(21,integrity);
    auto ext=Tree(22,3,7);Put(ext,28,31,4);Put(ext,120,16);Put(ext,128,0);Put(ext,4040,4096);Put(ext,4048,7);Sign(ext);set(22,ext);return s;
}
JsonValue InspectTrees(const std::string& s){return InspectApfsMetadata([&](U64 p,U64 n){return s.substr(static_cast<std::size_t>(p),static_cast<std::size_t>(n));},s.size(),true);}
void BadTrees(const std::string& s){const auto r=InspectTrees(s);Require(!r.Get("complete")->Bool()&&!r.Get("volumes"),"Malformed sealed tree approved or partial paths leaked");}
void Reseal(std::string& s){const auto child=s.substr(23*4096,4096);auto root=s.substr(20*4096,4096);root.replace(4024,32,RawHash(child));s.replace(20*4096,4096,root);Mutate(s,21,[&](std::string& b){b.replace(128,32,RawHash(root));});}
std::string FileImage(bool compressed,unsigned codec=14,bool omit_hash=false,std::size_t logical_size=4096){
    auto s=TreesImage();std::string data;for(unsigned i=0;i<4096;++i)data+=char(i%251);
    std::string dir(92,'\0');Put(dir,0,1);Put(dir,8,2);Put(dir,80,0x4000,2);auto file=dir;Put(file,0,2);Put(file,8,16);Put(file,80,0x8000,2);
    auto name=FsKey(2,9);name.resize(12,'\0');Put(name,8,10,4);name+="owned.txt";name+='\0';std::string entry(18,'\0');Put(entry,0,16);Put(entry,16,8,2);
    std::vector<std::pair<std::string,std::string>> records{{FsKey(2,3),dir},{name,entry}};
    U64 owner=16;
    if(compressed){Put(file,68,32,4);records.emplace_back(FsKey(16,3),file);owner=17;auto xattr=[&](const std::string& label,unsigned flags,const std::string& bytes){auto key=FsKey(16,4);key.resize(10,'\0');Put(key,8,label.size()+1,2);key+=label;key+='\0';std::string value(4,'\0');Put(value,0,flags,2);Put(value,2,bytes.size(),2);value+=bytes;records.emplace_back(key,value);};
        std::string fork(8,'\0');Put(fork,0,8,4);fork+=char(255);fork+=data;Put(fork,4,fork.size(),4);s.replace(6*4096,fork.size(),fork);std::string stream(48,'\0');Put(stream,0,owner);Put(stream,8,fork.size());Put(stream,16,8192);xattr("com.apple.ResourceFork",1,stream);
        std::string header="fpmc";header.resize(16,'\0');Put(header,4,codec,4);Put(header,8,data.size());xattr("com.apple.decmpfs",2,header);Mutate(s,22,[&](std::string& b){Put(b,120,owner);Put(b,4040,8192);Put(b,4048,6);});
    }else{file.resize(140,'\0');Put(file,92,1,2);Put(file,94,40,2);Put(file,96,8,1);Put(file,98,40,2);Put(file,100,logical_size);Put(file,108,4096);records.emplace_back(FsKey(16,3),file);s.replace(7*4096,data.size(),data);}
    if(!omit_hash){auto key=FsKey(owner,13);key.resize(16,'\0');Put(key,8,U64(1)<<56);std::string value(3,'\0');Put(value,0,1,2);Put(value,2,32,1);value+=RawHash(data);records.emplace_back(key,value);}
    s.replace(23*4096,4096,FsNode(false,0,records,0,0));Put(s,20*4096+4080,records.size());Reseal(s);return s;
}
ApfsFileResult ReadOwnedFile(const std::string& s,const std::string& path="/owned.txt"){return ReadApfsFile([&](U64 p,U64 n){return s.substr(static_cast<std::size_t>(p),static_cast<std::size_t>(n));},s.size(),path);}
std::string OrdinaryImage(){
    auto s=FileImage(false,14,true);const auto sealed_leaf=s.substr(23*4096,4096);
    std::vector<std::pair<std::string,std::string>> records;const auto keybase=56+Get(sealed_leaf,42,2);
    for(U64 i=0;i<Get(sealed_leaf,36,4);++i)records.emplace_back(
        sealed_leaf.substr(keybase+Get(sealed_leaf,56+i*8,2),Get(sealed_leaf,58+i*8,2)),
        sealed_leaf.substr(4096-Get(sealed_leaf,60+i*8,2),Get(sealed_leaf,62+i*8,2)));
    auto extent=FsKey(16,8);extent.resize(16,'\0');std::string value(24,'\0');Put(value,0,4096);Put(value,8,7);Put(value,16,16);records.emplace_back(extent,value);
    auto leaf=FsNode(false,0,records,0,0);Put(leaf,8,2001);Put(leaf,16,3);Put(leaf,24,3,4);Put(leaf,28,14,4);Put(leaf,32,2,2);Sign(leaf);s.replace(23*4096,4096,leaf);
    std::string link(8,'\0');Put(link,0,2001);auto root=FsNode(true,1,{{FsKey(2,3),link}},records.size(),2);
    Put(root,8,2000);Put(root,16,3);Put(root,24,2,4);Put(root,28,14,4);Put(root,32,1,2);Put(root,4056,0x42,4);Sign(root);s.replace(20*4096,4096,root);
    Mutate(s,14,[](std::string& b){Put(b,56,1);Put(b,1024,0);Put(b,1032,0);});
    Mutate(s,19,[](std::string& b){Put(b,4024,0,4);Put(b,4008,0,4);});return s;
}
std::string StreamingImage(bool shared_hash=false){
    auto s=FileImage(true);s.resize(64*4096,'\0');for(unsigned p:{0U,2U,4U})Mutate(s,p,[](std::string& b){Put(b,40,64);});
    const auto first=std::string(65536,'A'),second=std::string(65536,'B');std::string fork(12,'\0');Put(fork,0,12,4);fork+=char(255);fork+=first;Put(fork,4,fork.size(),4);fork+=char(255);fork+=second;Put(fork,8,fork.size(),4);s.replace(24*4096,fork.size(),fork);
    const auto leaf=s.substr(23*4096,4096);std::vector<std::pair<std::string,std::string>> records;const auto n=Get(leaf,36,4),keybase=56+Get(leaf,42,2);
    for(U64 i=0;i<n;++i){auto key=leaf.substr(keybase+Get(leaf,56+i*8,2),Get(leaf,58+i*8,2));auto value=leaf.substr(4096-Get(leaf,60+i*8,2),Get(leaf,62+i*8,2));const auto kind=Get(key,0)>>60;if(kind==13)continue;if(kind==4){const auto name=key.substr(10);if(name.starts_with("com.apple.ResourceFork")){Put(value,12,fork.size());Put(value,20,33*4096);}else if(name.starts_with("com.apple.decmpfs"))Put(value,12,131072);}records.emplace_back(std::move(key),std::move(value));}
    auto hash=[&](U64 offset,const std::string& data){auto key=FsKey(17,13);key.resize(16,'\0');Put(key,8,(U64(1)<<56)|offset);std::string value(3,'\0');Put(value,0,data.size()/4096,2);Put(value,2,32,1);value+=RawHash(data);records.emplace_back(key,value);};if(shared_hash)hash(0,first+second);else{hash(0,first);hash(65536,second);}
    s.replace(23*4096,4096,FsNode(false,0,records,0,0));Put(s,20*4096+4080,records.size());Reseal(s);Mutate(s,22,[](std::string& b){Put(b,4040,33*4096);Put(b,4048,24);});return s;
}
}
int main(int argc,char** argv){try{
    const auto original=Image();auto r=Inspect(original);Require(r.Get("complete")->Bool()&&r.Get("checkpoint_xid")->Serialize()=="3"&&r.Get("checkpoint_physical_block")->Serialize()=="4"&&r.Get("checkpoint_object_headers_verified")->Serialize()=="2","Latest checkpoint not derived from descriptor ring");Require(r.Get("volumes")->ArrayItems().size()==1&&r.Get("volumes")->ArrayItems()[0].GetString("name")=="Owned"&&!r.Get("filesystem_verified")->Bool()&&!r.Get("provider_registered")->Bool(),"Volume metadata scope incorrect");
    auto s=original;s[10*4096+100]^=1;r=Inspect(s);Require(r.Get("complete")->Bool()&&r.Get("checkpoint_xid")->Serialize()=="2"&&r.Get("rejected_checkpoints")->Serialize()=="1","Interrupted newest checkpoint did not fall back to older valid checkpoint");
    s[8*4096+100]^=1;Bad(s);
    s=original;s[0]^=1;Bad(s);s=original;s[14*4096+100]^=1;Bad(s);
    for(auto change:{0,1,2,3,4,5,6,7,8}){s=original;Mutate(s,13,[&](std::string& b){switch(change){case 0:Put(b,58,0,2);break;case 1:Put(b,56,65535,2);break;case 2:Put(b,4040,4,4);break;case 3:Put(b,4040,1,4);break;case 4:Put(b,4044,8192,4);break;case 5:Put(b,4048,99);break;case 6:Put(b,32,15,2);break;case 7:Put(b,4064,8,4);break;case 8:Put(b,36,1000,4);break;}});Bad(s);}
    s=original;Mutate(s,0,[](std::string& b){Put(b,104,0x80000004,4);});Bad(s);
    s=original;Mutate(s,14,[](std::string& b){Put(b,8,1028);});Bad(s);
    s=original;Mutate(s,14,[](std::string& b){Put(b,36,1,4);});Bad(s);
    s=original;Mutate(s,14,[](std::string& b){b.replace(704,256,std::string(256,'x'));});Bad(s);
    // Physical internal node plus non-root leaf, with authoritative footer counts.
    s=original;auto leaf=Tree(19,3,14);const auto value=leaf.substr(4040,16);Put(leaf,24,0x40000003,4);Put(leaf,32,6,2);Put(leaf,58,16,2);leaf.replace(4056,40,std::string(40,'\0'));leaf.replace(4080,16,value);Sign(leaf);s.replace(19*4096,4096,leaf);
    Mutate(s,13,[](std::string& b){Put(b,32,5,2);Put(b,34,1,2);Put(b,58,8,2);b.replace(4040,16,std::string(16,'\0'));Put(b,4048,19);Put(b,4088,2);});r=Inspect(s);Require(r.Get("complete")->Bool(),"Physical object-map child traversal failed");
    auto nested=s;Mutate(s,13,[](std::string& b){Put(b,4048,13);});Bad(s);s=nested;Mutate(s,13,[](std::string& b){Put(b,128,2);});Bad(s);
    // A newest tombstone must not revive an older valid version of the same OID.
    s=original;Mutate(s,13,[](std::string& b){Put(b,36,2,4);Put(b,60,16,2);Put(b,62,32,2);Put(b,128,2);Put(b,136,1026);Put(b,144,3);Put(b,4048,17);Put(b,4024,1,4);Put(b,4028,4096,4);Put(b,4032,14);Put(b,4080,2);});Bad(s);
    // A valid but unsupported latest checkpoint is an error, not a rollback.
    s=original;Mutate(s,3,[](std::string& b){Put(b,48,8192,4);});Bad(s);
    Require(!InspectApfsMetadata([](U64,U64){return std::string();},original.size()).Get("complete")->Bool(),"Short input read accepted");
    const auto trees_original=TreesImage();r=InspectTrees(trees_original);if(!r.Get("complete")->Bool())std::cerr<<r.Serialize(true)<<'\n';Require(r.Get("complete")->Bool()&&r.Get("volume_trees_verified")->Bool(),"Original metadata did not derive volume OMAP/seal/extents");const auto& trees=*r.Get("volumes")->ArrayItems()[0].Get("trees");Require(trees.Get("filesystem_nodes")->Serialize()=="2"&&trees.Get("filesystem_records")->Serialize()=="3"&&trees.Get("file_extents")->Serialize()=="1"&&trees.Get("paths")->ArrayItems().size()==1&&trees.Get("paths")->ArrayItems()[0].GetString("path")=="/owned.txt"&&!trees.Get("file_contents_verified")->Bool(),"Sealed path/extent inventory incorrect");
    const auto ordinary=OrdinaryImage();r=InspectTrees(ordinary);if(!r.Get("complete")->Bool())std::cerr<<r.Serialize(true)<<'\n';Require(r.Get("complete")->Bool(),"Ordinary virtual tree inventory failed.");
    const auto& ordinary_tree=*r.Get("volumes")->ArrayItems()[0].Get("trees");
    Require(!ordinary_tree.Get("sealed_metadata_hashes_verified")->Bool()&&ordinary_tree.Get("filesystem_metadata_checksums_verified")->Bool()
        &&ordinary_tree.Get("filesystem_nodes")->Serialize()=="2"&&ordinary_tree.Get("filesystem_records")->Serialize()=="4"
        &&ordinary_tree.Get("file_extents")->Serialize()=="1"&&ordinary_tree.Get("paths")->ArrayItems()[0].Get("extent_count")->Serialize()=="1"
        &&!ordinary_tree.Get("file_contents_verified")->Bool(),"Ordinary checksum/extent/seal scope incorrect.");
    Require(!ReadOwnedFile(ordinary).report.Get("complete")->Bool(),"Ordinary file approved using unavailable sealed hashes.");
    const auto ordinary_bound=ReadApfsFile([&](U64 p,U64 n){return ordinary.substr(p,n);},ordinary.size(),"/owned.txt",{},true);
    std::string ordinary_expected;for(unsigned i=0;i<4096;++i)ordinary_expected+=char(i%251);
    Require(ordinary_bound.report.Get("complete")->Bool()&&!ordinary_bound.report.Get("file_contents_verified")->Bool()
        &&ordinary_bound.bytes==ordinary_expected&&ordinary_bound.report.GetString("scope")=="selected-original-apfs-file-source-bound-decoded","Source-bound ordinary extraction failed.");
    s=ordinary;s[23*4096+200]^=1;BadTrees(s);
    // Valid checksums cannot excuse an OMAP transaction, type or partition mismatch.
    for(unsigned change:{0U,1U,2U,3U,4U,5U,6U,7U,8U,9U,10U}){
        s=ordinary;Mutate(s,20,[&](std::string& b){switch(change){
            case 0:Put(b,4088,1);break;case 1:Put(b,4080,3);break;case 2:Put(b,4056,0x142,4);break;
            case 3:Put(b,4056,0x52,4);break;case 4:Put(b,4048,2000);break;case 5:Put(b,4048,9999);break;
            case 6:Put(b,16,2);break;case 7:Put(b,32,0x8001,2);break;case 8:Put(b,28,11,4);break;
            case 9:Put(b,64,3);break;case 10:Put(b,60,0,2);break;}});BadTrees(s);
    }
    for(unsigned change:{0U,1U,2U,3U,4U,5U}){
        s=ordinary;Mutate(s,23,[&](std::string& b){const auto vp=4096-Get(b,60+3*8,2),kp=56+Get(b,42,2)+Get(b,56+3*8,2);
            switch(change){case 0:Put(b,vp,4095);break;case 1:Put(b,vp+8,24);break;case 2:Put(b,vp,U64(1)<<56);break;
                case 3:Put(b,kp+8,1);break;case 4:Put(b,16,2);break;case 5:Put(b,24,2,4);break;}});BadTrees(s);
    }
    for(bool compressed:{false,true}){s=FileImage(compressed);auto result=ReadOwnedFile(s);if(!result.report.Get("complete")->Bool())std::cerr<<result.report.Serialize(true)<<'\n';Require(result.report.Get("complete")->Bool()&&result.bytes.size()==4096&&result.report.GetString("sha256")==*Sha256(result.bytes)&&result.report.Get("file_contents_verified")->Bool()&&!result.report.Get("provider_registered")->Bool(),"File metadata did not derive and verify original content.");s[(compressed?6:7)*4096+(compressed?9:0)]^=1;result=ReadOwnedFile(s);Require(!result.report.Get("complete")->Bool()&&result.bytes.empty(),"Corrupt file data leaked or approved.");}
    Require(!ReadOwnedFile(FileImage(true),"/missing").report.Get("complete")->Bool(),"Missing file approved.");
    Require(!ReadOwnedFile(FileImage(true,12)).report.Get("complete")->Bool(),"Unsupported compression approved.");
    Require(!ReadOwnedFile(FileImage(true,14,true)).report.Get("complete")->Bool(),"Missing data hashes approved.");
    s=FileImage(false,14,false,604);auto partial=ReadOwnedFile(s);Require(partial.report.Get("complete")->Bool()&&partial.bytes.size()==604&&partial.report.Get("hash_covered_bytes")->Serialize()=="4096", "Uncompressed file padding not verified or leaked into logical content.");s[7*4096+1000]^=1;Require(!ReadOwnedFile(s).report.Get("complete")->Bool(),"Corrupt physical EOF padding approved.");
    s=FileImage(false);const auto inode_value_offset=Get(s,23*4096+56+2*8+4,2);Put(s,23*4096+4096-inode_value_offset+94,0,2);Reseal(s);Require(!ReadOwnedFile(s).report.Get("complete")->Bool(),"Inode dstream outside declared xfield bytes approved.");
    for(bool shared:{false,true}){s=StreamingImage(shared);std::string emitted;std::size_t calls=0;const auto streamed=StreamApfsFile([&](U64 p,U64 n){return s.substr(p,n);},s.size(),"/owned.txt",[&](std::string_view piece){Require(piece.size()<=65536,"Streaming emitted oversized chunk.");emitted+=piece;++calls;});if(!streamed.Get("complete")->Bool())std::cerr<<streamed.Serialize(true)<<'\n';Require(streamed.Get("complete")->Bool()&&streamed.Get("streaming")->Bool()&&calls==2&&emitted==std::string(65536,'A')+std::string(65536,'B')&&streamed.GetString("sha256")==*Sha256(emitted),"Streamed file/hash boundary propagation failed.");}
    for(unsigned block:{19U,20U,21U,22U,23U}){s=trees_original;s[block*4096+200]^=1;BadTrees(s);}
    s=trees_original;Mutate(s,19,[](std::string& b){Put(b,4024,0,4);});BadTrees(s);
    s=trees_original;Mutate(s,21,[](std::string& b){Put(b,36,1,4);});BadTrees(s);s=trees_original;Mutate(s,21,[](std::string& b){Put(b,40,3,4);});BadTrees(s);s=trees_original;Mutate(s,21,[](std::string& b){Put(b,44,4090,4);});BadTrees(s);
    s=trees_original;Mutate(s,22,[](std::string& b){Put(b,4048,24);});BadTrees(s);s=trees_original;Mutate(s,22,[](std::string& b){Put(b,4040,4095);});BadTrees(s);
    s=trees_original;s[23*4096+32]=30;Reseal(s);BadTrees(s);s=trees_original;Put(s,23*4096+60,0,2);Reseal(s);BadTrees(s);
    s=trees_original;Put(s,23*4096+36,2000,4);Reseal(s);BadTrees(s);
    // Correct hashes do not approve a directory entry that references no inode.
    s=trees_original;Put(s,23*4096+4096-92-18,99);Reseal(s);BadTrees(s);
    s=trees_original;s[23*4096+100]='/';Reseal(s);BadTrees(s);
    // A directory cycle is invalid even when every node hash is authentic.
    s=trees_original;auto root_inode=std::string(92,'\0');Put(root_inode,0,1);Put(root_inode,8,2);Put(root_inode,80,0x4000,2);auto next_inode=root_inode;Put(next_inode,0,2);Put(next_inode,8,16);auto edge=[](U64 parent,const std::string& name,U64 target){auto key=FsKey(parent,9);key.resize(12,'\0');Put(key,8,name.size()+1,4);key+=name;key+='\0';std::string value(18,'\0');Put(value,0,target);Put(value,16,4,2);return std::make_pair(key,value);};const auto cycle=FsNode(false,0,{{FsKey(2,3),root_inode},edge(2,"child",16),{FsKey(16,3),next_inode},edge(16,"back",2)},0,0);s.replace(23*4096,4096,cycle);Put(s,20*4096+4080,4);Reseal(s);BadTrees(s);
    const auto root=std::filesystem::temp_directory_path()/("openfruit-apfs-owned-"+NewOperationId());std::filesystem::create_directory(root);const auto image=root/"owned.raw",report=root/"decoded.json";Write(image,original);auto input=JsonValue::ObjectValue();for(const char* k:{"complete","authentication_verified","all_clusters_authenticated","decryption_complete","component_digest_verified","component_digest_scope_verified","quarantined"})input.Set(k,JsonValue::Boolean(true));input.Set("digest_scope",JsonValue::String("decoded-aea-payload"));input.Set("sha256",JsonValue::String(*Sha256(original)));input.Set("path",JsonValue::String(image.generic_string()));input.Set("decoded_bytes",JsonValue::Number(std::to_string(original.size())));Write(report,input.Serialize());
    r=InspectApfsStage(report);Require(r.Get("complete")->Bool()&&r.GetString("source_sha256")==*Sha256(original),"Report-derived native input failed");
    Require(!InspectApfsStage(report,{},std::chrono::steady_clock::now()).Get("complete")->Bool(),"APFS deadline ignored");
    input.Set("component_digest_verified",JsonValue::Boolean(false));Write(report,input.Serialize());Require(!InspectApfsStage(report).Get("complete")->Bool(),"Unverified decoded input accepted");input.Set("component_digest_verified",JsonValue::Boolean(true));Write(report,input.Serialize());
    s=original;s.back()^=1;Write(image,s);Require(!InspectApfsStage(report).Get("complete")->Bool(),"Mutated original snapshot accepted");Write(image,original);
    HANDLE writer=CreateFileW(image.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);Require(writer!=INVALID_HANDLE_VALUE,"Owned writer fixture failed");Require(!InspectApfsStage(report).Get("complete")->Bool(),"Concurrent mutation lease accepted");CloseHandle(writer);
    CancellationSource cancellation;cancellation.Cancel();Require(!InspectApfsStage(report,cancellation.Token()).Get("complete")->Bool(),"APFS cancellation ignored");
    if(argc>1){const auto executable=Win32Process::ToWide(argv[1]);const auto child=Win32Process::Run(executable,{executable,L"runtime",L"inspect-apfs",report.wstring()});Require(child.exit_code==0&&child.std_out.find("container-checkpoint-object-headers-omap-volume-superblocks")!=std::string::npos,"Native CLI propagation failed");}
    Write(image,trees_original);input.Set("sha256",JsonValue::String(*Sha256(trees_original)));Write(report,input.Serialize());Require(InspectApfsStage(report,{},std::chrono::steady_clock::time_point::max(),true).Get("complete")->Bool(),"Sealed tree report propagation failed");
    if(argc>1){const auto executable=Win32Process::ToWide(argv[1]);const auto child=Win32Process::Run(executable,{executable,L"runtime",L"inspect-apfs-trees",report.wstring()});const auto result=JsonValue::Parse(child.std_out);Require(child.exit_code==0&&result&&result->Get("volume_trees_verified")->Bool(),"Sealed tree native CLI propagation failed");}
    const auto file_original=FileImage(true);Write(image,file_original);input.Set("sha256",JsonValue::String(*Sha256(file_original)));Write(report,input.Serialize());const auto output=root/"extracted";
    r=ExtractApfsStage(report,"/owned.txt",output);if(!r.Get("complete")->Bool())std::cerr<<r.Serialize(true)<<'\n';Require(r.Get("complete")->Bool()&&r.Get("file_contents_verified")->Bool()&&r.Get("quarantined")->Bool()&&r.GetString("source_sha256")==*Sha256(file_original),"Native report-derived extraction failed.");Require(Sha256File(output/"file.decoded-quarantined")==std::optional<std::string>(r.GetString("sha256")),"Retained output digest differs.");
    Require(!ExtractApfsStage(report,"/owned.txt",output).Get("complete")->Bool(),"Existing output directory reused.");
    const auto failed=root/"failed";Require(!ExtractApfsStage(report,"",failed).Get("complete")->Bool()&&!std::filesystem::exists(failed),"Empty path accepted.");Require(!ExtractApfsStage(report,"/missing",failed).Get("complete")->Bool()&&!std::filesystem::exists(failed),"Missing file left output.");
    Require(!ExtractApfsStage(report,"/owned.txt",failed,cancellation.Token()).Get("complete")->Bool()&&!std::filesystem::exists(failed),"Cancelled extraction left output.");
    s=file_original;s[6*4096+9]^=1;Write(image,s);input.Set("sha256",JsonValue::String(*Sha256(s)));Write(report,input.Serialize());r=ExtractApfsStage(report,"/owned.txt",failed);Require(!r.Get("complete")->Bool()&&r.GetString("error").find("data-hash mismatch")!=std::string::npos&&!std::filesystem::exists(failed),"Corrupt authenticated file data approved or retained.");Write(image,file_original);input.Set("sha256",JsonValue::String(*Sha256(file_original)));Write(report,input.Serialize());
    if(argc>1){const auto executable=Win32Process::ToWide(argv[1]);const auto cli_output=root/"extracted-cli";const auto child=Win32Process::Run(executable,{executable,L"runtime",L"extract-apfs-file",report.wstring(),L"/owned.txt",cli_output.wstring()});const auto result=JsonValue::Parse(child.std_out);Require(child.exit_code==0&&result&&result->Get("file_contents_verified")->Bool()&&Sha256File(cli_output/"file.decoded-quarantined")==Sha256File(output/"file.decoded-quarantined"),"Native CLI file extraction propagation failed.");std::filesystem::remove(cli_output/"file.decoded-quarantined");std::filesystem::remove(cli_output);}
    std::filesystem::remove(output/"file.decoded-quarantined");std::filesystem::remove(output);
    s=StreamingImage();s[24*4096+65550]^=1;Write(image,s);input.Set("sha256",JsonValue::String(*Sha256(s)));input.Set("decoded_bytes",JsonValue::Number(std::to_string(s.size())));Write(report,input.Serialize());r=ExtractApfsStage(report,"/owned.txt",failed);Require(!r.Get("complete")->Bool()&&r.GetString("error").find("data-hash mismatch")!=std::string::npos&&!std::filesystem::exists(failed),"Late corrupt chunk left partial output or directory.");
    // Fresh test-owned directory; remove only the exact known fixture files.
    std::filesystem::remove(report);std::filesystem::remove(image);std::filesystem::remove(root);std::cout<<"APFS metadata verified with original input binding, checkpoint fallback and malformed-object rejection.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
