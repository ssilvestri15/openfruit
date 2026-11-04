#include "apfs_metadata.hpp"
#include "apfs_compression.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <array>
#include <tuple>
namespace OpenFruit {
namespace {
using U64 = std::uint64_t;
U64 U(std::string_view b, std::size_t p, unsigned n) {
    if(p>b.size() || n>b.size()-p) throw std::runtime_error("Truncated APFS field.");
    U64 v=0; for(unsigned i=0;i<n;++i) v|=U64(static_cast<unsigned char>(b[p+i]))<<(8*i); return v;
}
void Require(bool ok, const char* e) { if(!ok) throw std::runtime_error(e); }
void Supported(bool ok, const char* e) { if(!ok) throw std::logic_error(e); }
void Checksum(std::string_view b) {
    Require(b.size()>=32 && b.size()%4==0,"Invalid APFS object size.");
    constexpr U64 m=0xffffffff; U64 a=0,c=0;
    for(std::size_t p=8;p<b.size();p+=4){a=(a+U(b,p,4))%m;c=(c+a)%m;}
    const auto lo=m-(a+c)%m,hi=m-(a+lo)%m;
    Require(U(b,0,8)==(lo|(hi<<32)),"APFS object Fletcher64 mismatch.");
}
std::string Hex(std::string_view b) {static constexpr char d[]="0123456789abcdef";std::string s;for(unsigned char c:b){s+=d[c>>4];s+=d[c&15];}return s;}
JsonValue Num(U64 v){return JsonValue::Number(std::to_string(v));}
JsonValue Empty(){auto r=JsonValue::ObjectValue();for(const char* k:{"complete","metadata_verified","filesystem_verified","publisher_verified","provider_registered","published"})r.Set(k,JsonValue::Boolean(false));return r;}
struct Record {U64 oid,xid;std::uint32_t flags,size;U64 paddr;};
using Key=std::pair<U64,U64>;
using Extents=std::map<Key,std::pair<U64,U64>>;
struct Inode {U64 parent,private_id,mode,bsd_flags;std::string original;};
struct DirectoryEntry {U64 id,type;};
struct FileTree {
    std::set<U64> nodes;
    std::array<U64,16> kinds{};
    U64 records=0;
    std::map<U64,Inode> inodes;
    std::map<std::pair<U64,std::string>,DirectoryEntry> directories;
    std::map<std::pair<U64,std::string>,std::string> xattrs;
    std::map<Key,std::string> hashes;
    Extents extents;
};
struct Parser {
    const ApfsRead& read;U64 bytes,blocks=0;std::uint32_t bs=0;U64 reads=0,record_count=0;
    std::string requested_path,file_data;JsonValue selected_file;U64 selected_count=0;
    std::function<void()> control;
    ApfsWrite sink;
    bool memory_mode=true;
    bool source_bound=false;
    std::string At(U64 off,U64 n){if(control)control();Require(off<=bytes&&n<=bytes-off&&n<=16ULL*1024*1024,"APFS read bounds exceeded.");auto b=read(off,n);Require(b.size()==n,"Short APFS read.");return b;}
    std::string Block(U64 n){Require(n<blocks && ++reads<=65536,"APFS block address or read budget exceeded.");return At(n*bs,bs);}
    void Object(std::string_view b,U64 oid,U64 xid,std::uint32_t type,std::uint32_t subtype=0){
        Checksum(b);Require(U(b,8,8)==oid && U(b,16,8)>0 && U(b,16,8)<=xid && U(b,24,4)==type && U(b,28,4)==subtype,"APFS object identity/type/transaction mismatch.");
    }
    void NX(std::string_view b){
        Object(b,1,U(b,16,8),0x80000001);Require(b.substr(32,4)=="NXSB"&&U(b,36,4)==bs&&U(b,40,8)==blocks,"APFS container geometry mismatch.");
        Supported(U(b,64,8)==2,"Unsupported APFS container incompatible features.");
        Require(U(b,180,4)>0&&U(b,180,4)<=100,"APFS volume count bounds invalid.");
        Supported(!(U(b,104,4)&0x80000000)&&!(U(b,108,4)&0x80000000),"Noncontiguous APFS checkpoint areas unsupported.");
        for(auto p:{104,108}){const auto count=U(b,p,4),base=U(b,112+(p-104)*2,8);Require(count>0&&count<=65536&&base>0&&base<blocks&&count<=blocks-base,"APFS checkpoint area bounds invalid.");}
        Require(U(b,128,4)<U(b,104,4)&&U(b,132,4)<U(b,108,4),"APFS checkpoint next index invalid.");
        Require(U(b,136,4)<U(b,104,4)&&U(b,140,4)>=2&&U(b,140,4)<=U(b,104,4)&&U(b,144,4)<U(b,108,4)&&U(b,148,4)<=U(b,108,4),"APFS checkpoint ring bounds invalid.");
    }
    U64 Checkpoint(std::string_view b,U64 address){
        NX(b);const auto xid=U(b,16,8),base=U(b,112,8),count=U(b,104,4),index=U(b,136,4),length=U(b,140,4);
        Require(base+(index+length-1)%count==address,"APFS checkpoint descriptor membership mismatch.");
        U64 objects=0;std::set<Key> identities;std::set<U64> addresses;
        for(U64 i=0;i<length-1;++i){
            const auto p=base+(index+i)%count;const auto map=Block(p);Object(map,p,xid,0x4000000c);
            Require(U(map,16,8)==xid&&U(map,32,4)==(i==length-2?1:0),"APFS checkpoint map transaction/last flag invalid.");
            const auto n=U(map,36,4);Require(n<=(bs-40)/40,"APFS checkpoint mapping count invalid.");
            for(U64 j=0;j<n;++j){const auto off=40+j*40,type=U(map,off,4),sub=U(map,off+4,4),size=U(map,off+8,4),fs=U(map,off+16,8),oid=U(map,off+24,8),pa=U(map,off+32,8);
                Supported((type&0xc0000000)==0x80000000&&size==bs,"Unsupported APFS ephemeral object storage/size.");Require(U(map,off+12,4)==0,"Invalid APFS checkpoint mapping padding.");
                Require(identities.emplace(fs,oid).second&&addresses.insert(pa).second,"Duplicate APFS checkpoint object mapping.");
                const auto data_base=U(b,120,8),data_count=U(b,108,4),data_index=U(b,144,4),data_len=U(b,148,4);
                Require(pa>=data_base&&pa-data_base<data_count&&((pa-data_base+data_count-data_index)%data_count)<data_len,"APFS ephemeral object outside active checkpoint data.");
                const auto object=Block(pa);Object(object,oid,xid,static_cast<std::uint32_t>(type),static_cast<std::uint32_t>(sub));++objects;
            }
        }
        Require(identities.contains({0,U(b,152,8)})&&identities.contains({0,U(b,168,8)}),"APFS checkpoint missing space manager or reaper.");return objects;
    }
    std::pair<Key,Key> Tree(U64 address,U64 xid,unsigned depth,int expected_level,bool root,std::set<U64>& visited,std::map<Key,Record>& records){
        Require(depth<=32&&visited.size()<4096&&visited.insert(address).second,"APFS object-map tree cycle/depth/node budget exceeded.");
        const auto b=Block(address);Object(b,address,xid,root?0x40000002:0x40000003,11);
        const auto flags=U(b,32,2),level=U(b,34,2),n=U(b,36,4),toff=U(b,40,2),tlen=U(b,42,2);
        Require((flags&~7ULL)==0&&(flags&4)&&bool(flags&1)==root&&bool(flags&2)==(level==0)&&level<=32&&(expected_level<0||level==expected_level),"Unsupported APFS object-map node flags/level.");
        const U64 end=bs-(root?40:0),table=56+toff,keybase=table+tlen;
        Require(n>0&&n<=16384&&table<=end&&tlen<=end-table&&n*4<=tlen,"APFS object-map table bounds invalid.");
        if(root){Require(U(b,end+4,4)==bs&&U(b,end+8,4)==16&&U(b,end+12,4)==16&&(U(b,end,4)&0x10)&&!(U(b,end,4)&~0x53ULL),"Unsupported APFS object-map tree geometry/flags.");}
        std::vector<std::pair<U64,U64>> spans;std::vector<std::pair<Key,U64>> children;Key last{},minimum{};bool first=true;
        for(U64 i=0;i<n;++i){
            const auto ko=U(b,table+i*4,2),vo=U(b,table+i*4+2,2),kp=keybase+ko,vs=level?8ULL:16ULL;
            Require(ko!=65535&&vo!=65535&&kp<=end&&16<=end-kp&&vo<=end&&vo>=vs,"APFS object-map record bounds invalid.");const auto vp=end-vo;
            Require(vp>=keybase,"APFS object-map value overlaps table.");spans.emplace_back(kp,kp+16);spans.emplace_back(vp,vp+vs);
            const Key key{U(b,kp,8),U(b,kp+8,8)};Require(key.first>0&&key.second>0&&(first||last<key),"APFS object-map keys not strictly ordered.");if(first)minimum=key;first=false;last=key;
            if(level){children.emplace_back(key,U(b,vp,8));}
            else {Require(++record_count<=1000000,"APFS object-map record budget exceeded.");Record r{key.first,key.second,static_cast<std::uint32_t>(U(b,vp,4)),static_cast<std::uint32_t>(U(b,vp+4,4)),U(b,vp+8,8)};
                Require(!(r.flags&~31U)&&records.emplace(key,r).second,"Duplicate APFS object-map record or unknown flags.");}
        }
        std::sort(spans.begin(),spans.end());for(std::size_t i=1;i<spans.size();++i)Require(spans[i-1].second<=spans[i].first,"Overlapping APFS object-map key/value ranges.");
        for (std::size_t i = 0; i < children.size(); ++i) {
            const auto range =
                Tree(children[i].second, xid, depth + 1, static_cast<int>(level - 1), false, visited, records);
            Require(range.first == children[i].first &&
                        (i + 1 == children.size() || range.second < children[i + 1].first),
                    "APFS object-map child keys violate parent partition.");
            last = range.second;
        }
        if(root)Require(U(b,end+24,8)==records.size()&&U(b,end+32,8)==visited.size(),"APFS object-map footer record/node counts disagree.");
        return {minimum,last};
    }
    std::map<Key, Record> Omap(U64 address, U64 xid) {
        const auto b = Block(address);
        Object(b, address, xid, 0x4000000b);
        Require(!(U(b, 32, 4) & ~31ULL) && U(b, 40, 4) == 0x40000002, "Unsupported APFS object-map flags/tree type.");
        std::set<U64> visited;
        std::map<Key, Record> records;
        Tree(U(b, 48, 8), xid, 0, -1, true, visited, records);
        return records;
    }
    Record Lookup(const std::map<Key, Record>& records, U64 oid, U64 xid, bool headerless = false) {
        auto p = records.upper_bound({oid, xid});
        Require(p != records.begin(), "APFS virtual object unavailable at checkpoint.");
        --p;
        Require(p->first.first == oid && !(p->second.flags & 1),
                "APFS virtual object missing or deleted at checkpoint.");
        Require(!(p->second.flags & 4) && ((p->second.flags & 8) == (headerless ? 8U : 0U)) && p->second.size == bs,
                "Encrypted/headerless/multiblock APFS metadata storage mismatch.");
        return p->second;
    }
    void FilesystemRecord(std::string_view key,std::string_view value,bool hashed_names,FileTree& tree){
        Require(key.size()>=8&&key.size()<=832&&value.size()<=3808,"APFS filesystem record size invalid.");const auto raw=U(key,0,8),id=raw&0x0fffffffffffffff,kind=raw>>60;
        Require(id>0&&kind>0&&kind<=13&&++tree.records<=4000000,"APFS filesystem record kind/count invalid.");++tree.kinds[kind];
        if (kind == 3) {
            Require(key.size() == 8 && value.size() >= 92 && tree.inodes.size() < 1000000,
                    "APFS inode size/count invalid.");
            Require(tree.inodes
                        .emplace(id, Inode{U(value, 0, 8), U(value, 8, 8), U(value, 80, 2), U(value, 68, 4),
                                           requested_path.empty() ? std::string{} : std::string(value)})
                        .second,
                    "Duplicate APFS inode.");
        }
        if(kind==8){
            Require(key.size()==16&&value.size()==24,"APFS filesystem extent record size invalid.");
            const Key extent{id,U(key,8,8)};const auto lf=U(value,0,8),length=lf&0x00ffffffffffffff,physical=U(value,8,8);
            Supported(!(lf>>56),"Unsupported APFS filesystem extent flags.");
            Require(tree.extents.size()<1000000&&extent.second%bs==0&&length>0&&length%bs==0&&extent.second<=UINT64_MAX-length
                &&(!physical||(physical<blocks&&length/bs<=blocks-physical))
                &&tree.extents.emplace(extent,std::make_pair(length,physical)).second,"APFS filesystem extent length/address/duplicate invalid.");
            // crypto_id is an encryption key/tweak identifier. The enclosing
            // ordinary-volume contract requires unencrypted storage; it is
            // not a physical address or a reason to transform original bytes.
        }
        if (!requested_path.empty() && kind == 4) {
            const auto n = U(key, 8, 2);
            Require(n > 1 && key.size() == 10 + n && key.back() == '\0' && value.size() >= 4 &&
                        U(value, 2, 2) == value.size() - 4,
                    "APFS xattr bounds invalid.");
            const auto name = key.substr(10, n - 1);
            Require(name.find('\0') == std::string_view::npos &&
                        tree.xattrs.emplace(std::make_pair(id, std::string(name)), value).second,
                    "Duplicate/invalid APFS xattr.");
        }
        if (!requested_path.empty() && kind == 13) {
            Require(key.size() == 16, "APFS file-info key size invalid.");
            const auto info = U(key, 8, 8);
            if ((info >> 56) == 1) {
                Require(value.size() == 35 && U(value, 0, 2) > 0 && U(value, 2, 1) == 32,
                        "APFS data-hash record invalid.");
                Require(tree.hashes.emplace(Key{id, info & 0x00ffffffffffffff}, value).second,
                        "Duplicate APFS data hash.");
            }
        }
        if (kind == 9) {
            const auto prefix = hashed_names ? 12U : 10U;
            Require(tree.directories.size() < 1000000, "APFS directory record count budget exceeded.");
            if (key.size() < prefix || value.size() < 18)
                throw std::runtime_error("APFS directory record size invalid: key=" + std::to_string(key.size()) +
                                         ", value=" + std::to_string(value.size()) + ", inode=" + std::to_string(id) +
                                         ".");
            const auto n = hashed_names ? U(key, 8, 4) & 1023 : U(key, 8, 2);
            Require(n > 1 && key.size() == prefix + n && key.back() == '\0', "APFS directory name bounds invalid.");
            const auto name = key.substr(prefix, n - 1);
            Require(name.find('\0')==std::string_view::npos&&name.find('/')==std::string_view::npos&&name!="."&&name!=".."&&MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name.data(),static_cast<int>(name.size()),nullptr,0)>0,"APFS directory name encoding/path invalid.");
            const auto target=U(value,0,8),type=U(value,16,2)&15;Require(target>0&&tree.directories.emplace(std::make_pair(id,std::string(name)),DirectoryEntry{target,type}).second,"Duplicate or invalid APFS directory entry.");
        }
    }
    std::string SealedTree(U64 oid,U64 root_oid,U64 xid,const std::map<Key,Record>& omap,const std::string& expected,bool root,int expected_level,unsigned depth,bool hashed_names,FileTree& tree){
        Require(depth <= 32 && tree.nodes.size() < 16384 && tree.nodes.insert(oid).second,
                "APFS sealed tree cycle/depth/node budget exceeded.");
        const auto r = Lookup(omap, oid, xid, true);
        const auto b = Block(r.paddr);
        Require(std::all_of(b.begin(), b.begin() + 32, [](char c) { return c == 0; }),
                "APFS headerless node has nonzero object header.");
        const auto hash = Sha256(b);
        Require(hash && *hash == expected, "APFS sealed tree SHA256 mismatch.");
        const auto flags=U(b,32,2),level=U(b,34,2),n=U(b,36,4),table=56+U(b,40,2),tlen=U(b,42,2),end=U64(bs)-(root?40:0),keybase=table+tlen;
        Supported(flags==(24|(root?1:0)|(level==0?2:0))&&level<=32&&(expected_level<0||level==expected_level),"Unsupported APFS sealed node flags/level.");Require(n>0&&table<=end&&tlen<=end-table&&n<=tlen/8,"APFS sealed node table bounds invalid.");
        if(root){Supported((U(b,end,4)&0x180)==0x180&&!(U(b,end,4)&~0x1c3ULL)&&U(b,end+4,4)==bs&&U(b,end+8,4)==0&&U(b,end+12,4)==0,"Unsupported APFS sealed root geometry/flags.");}
        std::vector<std::pair<U64,U64>> spans;std::vector<std::tuple<U64,std::string,std::string>> children;std::string first_key;
        for(U64 i=0;i<n;++i){const auto off=table+i*8,ko=U(b,off,2),kl=U(b,off+2,2),vo=U(b,off+4,2),vl=U(b,off+6,2),kp=keybase+ko;
            Require(ko != 65535 && vo != 65535 && kl >= 8 && kl <= 832 && kp <= end && kl <= end - kp && vo <= end &&
                        vl <= vo && end - vo >= keybase,
                    "APFS sealed record bounds invalid.");
            const auto vp = end - vo;
            spans.emplace_back(kp, kp + kl);
            spans.emplace_back(vp, vp + vl);
            const auto key = std::string_view(b).substr(kp, kl), value = std::string_view(b).substr(vp, vl);
            if (!i) first_key = std::string(key);
            if (level) {
                Supported(vl >= 40 && vl <= 72, "Unsupported APFS sealed child hash encoding.");
                const auto relative = U(value, 0, 8);
                Require(relative > 0 && relative <= UINT64_MAX - root_oid,
                        "APFS sealed relative child identifier overflow.");
                children.emplace_back(root_oid + relative, Hex(value.substr(8, 32)), std::string(key));
            } else
                FilesystemRecord(key, value, hashed_names, tree);
        }
        std::sort(spans.begin(),spans.end());for(std::size_t i=1;i<spans.size();++i)Require(spans[i-1].second<=spans[i].first,"Overlapping APFS sealed key/value ranges.");
        for(const auto& [child,hash,key]:children)Require(SealedTree(child,root_oid,xid,omap,hash,false,static_cast<int>(level-1),depth+1,hashed_names,tree)==key,"APFS sealed parent/child minimum key mismatch.");
        if(root)Require(U(b,end+24,8)==tree.records&&U(b,end+32,8)==tree.nodes.size(),"APFS sealed footer record/node counts disagree.");return first_key;
    }
    std::string OrdinaryTree(U64 oid,U64 xid,const std::map<Key,Record>& omap,bool root,int expected_level,unsigned depth,bool hashed_names,FileTree& tree){
        Require(depth<=32&&tree.nodes.size()<65536&&tree.nodes.insert(oid).second,"APFS ordinary tree cycle/depth/node budget exceeded.");
        const auto mapping=Lookup(omap,oid,xid);const auto b=Block(mapping.paddr);
        Object(b,oid,mapping.xid,root?2:3,14);
        Require(U(b,16,8)==mapping.xid,"APFS ordinary node transaction differs from selected object-map version.");
        const auto flags=U(b,32,2),level=U(b,34,2),n=U(b,36,4),table=56+U(b,40,2),tlen=U(b,42,2),end=U64(bs)-(root?40:0),keybase=table+tlen;
        Supported(flags==((root?1U:0U)|(level==0?2U:0U))&&level<=32&&(expected_level<0||level==expected_level),"Unsupported APFS ordinary node flags/level.");
        Require(n>0&&table<=end&&tlen<=end-table&&n<=tlen/8,"APFS ordinary node table bounds invalid.");
        if(root){Supported(!(U(b,end,4)&~0x43ULL)&&U(b,end+4,4)==bs&&U(b,end+8,4)==0&&U(b,end+12,4)==0,"Unsupported APFS ordinary virtual root geometry/flags.");
            Require(U(b,end+24,8)<=4000000&&U(b,end+32,8)<=65536,"APFS ordinary declared record/node budget exceeded.");}
        std::vector<std::pair<U64,U64>> spans;std::vector<std::pair<U64,std::string>> children;std::string first_key;
        for(U64 i=0;i<n;++i){
            const auto off=table+i*8,ko=U(b,off,2),kl=U(b,off+2,2),vo=U(b,off+4,2),vl=U(b,off+6,2),kp=keybase+ko;
            Require(ko!=65535&&vo!=65535&&kl>=8&&kl<=832&&kp<=end&&kl<=end-kp&&vo<=end&&vl<=vo&&end-vo>=keybase,"APFS ordinary record bounds invalid.");
            const auto vp=end-vo;spans.emplace_back(kp,kp+kl);spans.emplace_back(vp,vp+vl);
            const auto key=std::string_view(b).substr(kp,kl),value=std::string_view(b).substr(vp,vl);if(!i)first_key=std::string(key);
            if(level){Require(vl==8&&U(value,0,8)>0,"APFS ordinary virtual child identifier invalid.");children.emplace_back(U(value,0,8),std::string(key));}
            else FilesystemRecord(key,value,hashed_names,tree);
        }
        std::sort(spans.begin(),spans.end());for(std::size_t i=1;i<spans.size();++i)Require(spans[i-1].second<=spans[i].first,"Overlapping APFS ordinary key/value ranges.");
        for(const auto& [child,key]:children)Require(OrdinaryTree(child,xid,omap,false,static_cast<int>(level-1),depth+1,hashed_names,tree)==key,"APFS ordinary parent/child minimum key mismatch.");
        if(root)Require(U(b,end+24,8)==tree.records&&U(b,end+32,8)==tree.nodes.size(),"APFS ordinary footer record/node counts disagree.");
        return first_key;
    }
    std::pair<Key,Key> ExtentTree(U64 p,U64 xid,bool root,int expected_level,unsigned depth,std::set<U64>& nodes,Extents& extents){
        Require(depth <= 32 && nodes.size() < 4096 && nodes.insert(p).second,
                "APFS file extent tree cycle/depth/node budget exceeded.");
        const auto b = Block(p);
        Object(b, p, xid, root ? 0x40000002 : 0x40000003, 31);
        const auto flags = U(b, 32, 2), level = U(b, 34, 2), n = U(b, 36, 4), table = 56 + U(b, 40, 2),
                   tlen = U(b, 42, 2), end = U64(bs) - (root ? 40 : 0), keybase = table + tlen;
        Require(flags==(4|(root?1:0)|(level==0?2:0))&&level<=32&&(expected_level<0||level==expected_level)&&table<=end&&tlen<=end-table&&n>0&&n<=tlen/4,"APFS file extent node geometry invalid.");
        if(root)Require((U(b,end,4)&16)&&!(U(b,end,4)&~0x53ULL)&&U(b,end+4,4)==bs&&U(b,end+8,4)==16&&U(b,end+12,4)==16,"APFS file extent root geometry invalid.");
        std::vector<std::pair<U64,U64>> spans;std::vector<std::pair<Key,U64>> children;Key first{},last{};
        for (U64 i = 0; i < n; ++i) {
            const auto ko = U(b, table + i * 4, 2), vo = U(b, table + i * 4 + 2, 2), kp = keybase + ko,
                       vl = level ? 8ULL : 16ULL;
            Require(ko != 65535 && vo != 65535 && kp <= end && 16 <= end - kp && vo <= end && vo >= vl &&
                        end - vo >= keybase,
                    "APFS file extent record bounds invalid.");
            const auto vp = end - vo;
            spans.emplace_back(kp, kp + 16);
            spans.emplace_back(vp, vp + vl);
            const Key key{U(b, kp, 8), U(b, kp + 8, 8)};
            Require(key.first > 0 && key.second % bs == 0 && (!i || last < key),
                    "APFS file extent key ordering/alignment invalid.");
            if (!i) first = key;
            last = key;
            if (level)
                children.emplace_back(key, U(b, vp, 8));
            else {
                const auto lf = U(b, vp, 8), len = lf & 0x00ffffffffffffff, pa = U(b, vp + 8, 8);
                Supported(!(lf >> 56), "Unsupported APFS file extent flags.");
                Require(extents.size() < 1000000 && len > 0 && len % bs == 0 && key.second <= UINT64_MAX - len &&
                            (!pa || (pa < blocks && len / bs <= blocks - pa)) &&
                            extents.emplace(key, std::make_pair(len, pa)).second,
                        "APFS file extent length/address/duplicate invalid.");
            }
        }
        std::sort(spans.begin(),spans.end());for(std::size_t i=1;i<spans.size();++i)Require(spans[i-1].second<=spans[i].first,"Overlapping APFS file extent metadata ranges.");
        for (std::size_t i = 0; i < children.size(); ++i) {
            const auto range =
                ExtentTree(children[i].second, xid, false, static_cast<int>(level - 1), depth + 1, nodes, extents);
            Require(range.first == children[i].first &&
                        (i + 1 == children.size() || range.second < children[i + 1].first),
                    "APFS file extent child partition invalid.");
            last = range.second;
        }
        if(root)Require(U(b,end+24,8)==extents.size()&&U(b,end+32,8)==nodes.size(),"APFS file extent footer counts disagree.");return {first,last};
    }
    std::string Stream(U64 owner,U64 size,const Extents& extents){
        Supported(size<=512ULL*1024*1024,"APFS stream exceeds current whole-file read budget.");std::string data;data.reserve(static_cast<std::size_t>(size));U64 cursor=0;
        for(auto p=extents.lower_bound({owner,0});p!=extents.end()&&p->first.first==owner&&cursor<size;++p){Require(p->first.second==cursor,"APFS file extent coverage gap.");const auto [length,physical]=p->second;const auto take=std::min(length,size-cursor);
            for(U64 off=0;off<take;){if(control)control();const auto n=std::min<U64>(1024*1024,take-off);if(physical)data+=At(physical*bs+off,n);else data.append(static_cast<std::size_t>(n),'\0');off+=n;}cursor+=take;}
        Require(cursor==size,"APFS file stream has incomplete extent coverage.");return data;
    }
    std::string StreamRange(U64 owner,U64 size,U64 offset,U64 count,const Extents& extents){
        Require(size<=64ULL*1024*1024*1024&&offset<=size&&count<=size-offset&&count<=16ULL*1024*1024,"APFS bounded stream range invalid.");std::string out;out.reserve(static_cast<std::size_t>(count));U64 cursor=offset;auto p=extents.upper_bound({owner,cursor});if(p!=extents.begin())--p;
        while (out.size() < count) {
            Require(p != extents.end() && p->first.first == owner && p->first.second <= cursor &&
                        cursor - p->first.second < p->second.first,
                    "APFS file extent coverage gap.");
            const auto within = cursor - p->first.second,
                       take = std::min<U64>(count - out.size(), p->second.first - within), physical = p->second.second;
            for(U64 off=0;off<take;){if(control)control();const auto n=std::min<U64>(1024*1024,take-off);if(physical)out+=At(physical*bs+within+off,n);else out.append(static_cast<std::size_t>(n),'\0');off+=n;}cursor+=take;++p;
        }
        return out;
    }
    std::string Attribute(const FileTree& tree,U64 inode,const std::string& name,U64& owner,const Extents& extents){
        const auto p=tree.xattrs.find({inode,name});Require(p!=tree.xattrs.end(),"Required original APFS xattr missing.");const auto& v=p->second;const auto flags=U(v,0,2);Supported(!(flags&~15ULL)&&((flags&3)==1||(flags&3)==2),"Unsupported APFS xattr storage flags.");
        if (flags & 2) {
            owner = 0;
            return v.substr(4);
        }
        Require(v.size() == 52, "APFS xattr dstream size invalid.");
        owner = U(v, 4, 8);
        const auto size = U(v, 12, 8), allocated = U(v, 20, 8);
        Require(owner > 0 && allocated >= size && allocated % bs == 0, "APFS xattr stream allocation invalid.");
        Supported(!U(v, 28, 8), "Encrypted APFS xattr streams unsupported.");
        return Stream(owner, size, extents);
    }
    U64 InodeSize(const Inode& inode) {
        const auto& v = inode.original;
        Require(v.size() >= 96, "APFS regular inode dstream unavailable.");
        const auto n = U(v, 92, 2), used = U(v, 94, 2), start = 96 + n * 4;
        Require(n <= 64 && start <= v.size() && used <= v.size() - start, "APFS inode extended-field bounds invalid.");
        U64 at = start;
        std::optional<U64> size;
        const auto end = start + used;
        for (U64 i = 0; i < n; ++i) {
            const auto kind = U(v, 96 + i * 4, 1), length = U(v, 98 + i * 4, 2);
            Require(at <= end && length <= end - at, "APFS inode extended-field payload truncated.");
            if (kind == 8) {
                Require(!size && length == 40, "APFS inode dstream duplicate/size invalid.");
                size = U(v, at, 8);
                Require(U(v, at + 8, 8) >= *size, "APFS inode allocated size invalid.");
                Supported(!U(v, at + 16, 8), "Encrypted APFS inode stream unsupported.");
            }
            const auto aligned = (length + 7) & ~7ULL;
            Require(aligned <= end - at, "APFS inode extended-field padding truncated.");
            at += aligned;
        }
        Require(at == end, "APFS inode extended-field used size mismatch.");
        Require(size.has_value(),"APFS regular inode dstream missing.");return *size;
    }
    void SelectFile(const FileTree& tree,const Extents& extents,const JsonValue& paths,bool sealed){
        for(const auto& path:paths.ArrayItems()){
            if(path.GetString("path")!=requested_path)continue;
            Require(++selected_count==1,"Requested APFS path is ambiguous across volumes.");
            const auto id=std::stoull(path.Get("inode")->Serialize());const auto& inode=tree.inodes.at(id);
            Supported((inode.mode>>12)==8,"Requested APFS path is not a regular file.");
            U64 owner=inode.private_id,type=0,logical_size=0;std::string header;
            if (inode.bsd_flags & 32) {
                U64 metadata_owner = 0;
                header = Attribute(tree, id, "com.apple.decmpfs", metadata_owner, extents);
                Require(header.size() >= 16 && header.substr(0, 4) == "fpmc", "APFS decmpfs header invalid.");
                type = U(header, 4, 4);
                logical_size = U(header, 8, 8);
                Supported(type == 7 || type == 8 || type == 13 || type == 14,
                          "Unsupported original APFS decmpfs compression type.");
            } else
                logical_size = InodeSize(inode);
            Supported(logical_size<=(memory_mode?512ULL*1024*1024:64ULL*1024*1024*1024),"APFS decoded file budget exceeded.");
            const auto available=type?logical_size:((logical_size+bs-1)/bs)*bs;
            U64 fork_size=0;std::string offsets;
            if(type==14||type==8){Require(header.size()==16,"APFS resource-fork compression header length invalid.");const auto attr=tree.xattrs.find({id,"com.apple.ResourceFork"});Require(attr!=tree.xattrs.end(),"Required original APFS resource-fork attribute missing.");const auto& v=attr->second;
                Supported(v.size() == 52 && !(U(v, 0, 2) & ~15ULL) && (U(v, 0, 2) & 3) == 1,
                          "Unsupported APFS resource-fork stream storage.");
                owner = U(v, 4, 8);
                fork_size = U(v, 12, 8);
                Require(owner > 0 && fork_size <= UINT32_MAX && U(v, 20, 8) >= fork_size && U(v, 20, 8) % bs == 0,
                        "APFS resource-fork allocation/offset-width invalid.");
                Supported(!U(v, 28, 8), "Encrypted APFS resource fork unsupported.");
                const auto chunks = (logical_size + 65535) / 65536, table_size = (chunks + 1) * 4;
                Require(logical_size > 0 && table_size <= fork_size, "APFS resource-fork index size invalid.");
                offsets = StreamRange(owner, fork_size, 0, table_size, extents);
                Require(U(offsets, 0, 4) == table_size && U(offsets, chunks * 4, 4) == fork_size,
                        "APFS resource-fork offset table bounds invalid.");
            }
            auto record=tree.hashes.lower_bound({owner,0});std::unique_ptr<Sha256Stream> range_hash;Sha256Stream whole;
            U64 covered=0,emitted=0,window_size=0,window_used=0,hashes=0,maximum_chunk=0;std::string expected;
            auto consume=[&](std::string_view chunk){
                if(control)control();Require(covered<=available&&chunk.size()<=available-covered,"APFS streamed output exceeds declared size.");maximum_chunk=std::max<U64>(maximum_chunk,chunk.size());
                if(sealed){
                    for(std::size_t p=0;p<chunk.size();){
                        if (!range_hash) {
                            Require(record != tree.hashes.end() && record->first.first == owner &&
                                        record->first.second == covered,
                                    "APFS file data-hash coverage gap/overlap.");
                            window_size = U(record->second, 0, 2) * bs;
                            Supported(window_size <= available - covered,
                                      "APFS file hash extends beyond available original stream blocks.");
                            window_used = 0;
                            expected = Hex(std::string_view(record->second).substr(3, 32));
                            range_hash = std::make_unique<Sha256Stream>();
                        }
                        const auto count=std::min<U64>(chunk.size()-p,window_size-window_used);Require(range_hash->Update(chunk.substr(p,static_cast<std::size_t>(count))),"APFS streamed range SHA256 failed.");p+=count;covered+=count;window_used+=count;
                        if(window_used==window_size){const auto digest=range_hash->Finish();Require(digest&&*digest==expected,"APFS decoded file data-hash mismatch.");range_hash.reset();++record;++hashes;}
                    }
                }else covered+=chunk.size();
                const auto logical = std::min<U64>(chunk.size(), logical_size - emitted);
                if (logical) {
                    const auto piece = chunk.substr(0, static_cast<std::size_t>(logical));
                    Require(whole.Update(piece), "APFS streamed file SHA256 failed.");
                    if (memory_mode)
                        file_data.append(piece);
                    else {
                        Require(bool(sink), "APFS streaming sink missing.");
                        sink(piece);
                    }
                    emitted += logical;
                }
            };
            if(type==14||type==8){const auto chunks=(logical_size+65535)/65536;U64 decoded=0;
                for (U64 i = 0; i < chunks; ++i) {
                    if (control) control();
                    const auto begin = U(offsets, i * 4, 4), end = U(offsets, (i + 1) * 4, 4);
                    Require(begin >= offsets.size() && end > begin && end <= fork_size && end - begin <= 131072,
                            "APFS resource-fork block offset/size invalid.");
                    const auto packed = StreamRange(owner, fork_size, begin, end - begin, extents);
                    maximum_chunk = std::max<U64>(maximum_chunk, packed.size());
                    std::string error;
                    const auto expected_len = static_cast<std::size_t>(std::min<U64>(65536, logical_size - decoded));
                    auto block = (type == 14) ? DecodeApfsLzBitmap(packed, expected_len, error)
                                              : DecodeApfsLzvn(packed, expected_len, error);
                    Require(block.has_value(), error.c_str());
                    decoded += block->size();
                    consume(*block);
                }
            }else if(type==13){Supported(logical_size<=65536,"APFS inline compression output budget exceeded.");std::string error;auto block=DecodeApfsLzBitmap(std::string_view(header).substr(16),static_cast<std::size_t>(logical_size),error);Require(block.has_value(),error.c_str());consume(*block);
            }else if(type==7){Supported(logical_size<=65536,"APFS inline compression output budget exceeded.");std::string error;auto block=DecodeApfsLzvn(std::string_view(header).substr(16),static_cast<std::size_t>(logical_size),error);Require(block.has_value(),error.c_str());consume(*block);
            }else for(U64 p=0;p<available;){const auto count=std::min<U64>(65536,available-p);const auto block=StreamRange(owner,available,p,count,extents);consume(block);p+=count;}
            Require(covered==available&&emitted==logical_size,"APFS decoded file size mismatch.");
            if(sealed)Require(!range_hash&&(record==tree.hashes.end()||record->first.first!=owner)&&(logical_size==0||hashes>0),"APFS decoded file data hashes incomplete.");
            const auto digest=whole.Finish();Require(digest.has_value(),"APFS decoded file SHA256 unavailable.");
            selected_file = JsonValue::ObjectValue();
            selected_file.Set("virtual_path", JsonValue::String(requested_path));
            selected_file.Set("inode", Num(id));
            selected_file.Set("hash_stream_id", Num(owner));
            selected_file.Set("compression_type", Num(type));
            selected_file.Set("decoded_bytes", Num(logical_size));
            selected_file.Set("sha256", JsonValue::String(*digest));
            selected_file.Set("data_hash_records_verified", Num(hashes));
            selected_file.Set("data_hash_scope",
                              JsonValue::String(sealed ? (type ? "decoded-file-data" : "original-file-stream-blocks")
                                                       : "none-ordinary-source-bound"));
            selected_file.Set("hash_covered_bytes", Num(covered));
            selected_file.Set("file_contents_verified", JsonValue::Boolean(sealed));
            selected_file.Set("streaming", JsonValue::Boolean(!memory_mode));
            selected_file.Set("maximum_payload_chunk_bytes", Num(maximum_chunk));
            selected_file.Set("resource_fork_index_bytes", Num(offsets.size()));
        }
    }
    JsonValue Paths(const FileTree& tree,const Extents& extents){
        const auto root=tree.inodes.find(2);Require(root!=tree.inodes.end()&&(root->second.mode>>12)==4,"APFS filesystem root inode missing or not directory.");std::map<U64,U64> extent_counts;std::optional<std::pair<Key,U64>> previous;
        for(const auto& [key,value]:extents){Require(!previous||previous->first.first!=key.first||previous->first.second+previous->second<=key.second,"Overlapping APFS logical file extents.");previous=std::make_pair(key,value.first);++extent_counts[key.first];}
        auto paths=JsonValue::ArrayValue();std::set<U64> directories;U64 path_bytes=0;
        std::function<void(U64, const std::string&, unsigned)> visit = [&](U64 parent, const std::string& prefix,
                                                                           unsigned depth) {
            Require(depth <= 256 && directories.insert(parent).second, "APFS directory graph cycle/depth exceeded.");
            auto p = tree.directories.lower_bound({parent, {}});
            for (; p != tree.directories.end() && p->first.first == parent; ++p) {
                const auto inode = tree.inodes.find(p->second.id);
                Require(inode != tree.inodes.end(), "APFS directory entry references missing inode.");
                const auto type = inode->second.mode >> 12;
                Require(!p->second.type || p->second.type == type, "APFS directory entry/inode type mismatch.");
                const auto path = prefix + "/" + p->first.second;
                path_bytes += path.size();
                Require(paths.ArrayItems().size() < 1000000 && path_bytes <= 64ULL * 1024 * 1024,
                        "APFS path inventory byte/count budget exceeded.");
                auto v = JsonValue::ObjectValue();
                v.Set("path", JsonValue::String(path));
                v.Set("inode", Num(p->second.id));
                v.Set("private_id", Num(inode->second.private_id));
                v.Set("type", Num(type));
                v.Set("bsd_flags", Num(inode->second.bsd_flags));
                v.Set("extent_count", Num(extent_counts[inode->second.private_id]));
                paths.ArrayItems().push_back(std::move(v));
                if (type == 4) visit(p->second.id, path, depth + 1);
            }
        };
        visit(2, "", 0);
        return paths;
    }
    JsonValue VolumeTrees(std::string_view volume,U64 xid){
        const auto incompatible=U(volume,56,8);const bool sealed=(incompatible&32)!=0;
        Supported(!(incompatible&~0x29ULL)&&(U(volume,264,8)&1)&&U(volume,116,4)==2,"Unsupported APFS volume tree features/storage.");
        Require(!U(volume,160,8)&&!U(volume,168,8),"APFS volume snapshot reversion requires separate selection.");
        const auto omap=Omap(U(volume,128,8),xid);const auto root_oid=U(volume,136,8),integrity_oid=U(volume,1024,8);
        FileTree tree;Extents extents;std::set<U64> nodes;auto out=JsonValue::ObjectValue();
        if(sealed){
            Supported(U(volume,1040,4)==0x40000002,"Unsupported APFS sealed extent storage.");
            const auto im=Lookup(omap,integrity_oid,xid);const auto integrity=Block(im.paddr);Object(integrity,integrity_oid,im.xid,30);
            Require(U(integrity,16,8)==im.xid,"APFS integrity object transaction mismatch.");
            Supported((U(integrity,32,4)==1||U(integrity,32,4)==2)&&!U(integrity,36,4)&&U(integrity,40,4)==1&&!U(integrity,48,8),"Unsupported/broken APFS integrity seal or hash algorithm.");
            const auto offset=U(integrity,44,4);Require(offset>=(U(integrity,32,4)==2?128:56)&&offset<=bs-32,"APFS integrity root hash offset invalid.");
            const auto hash=Hex(std::string_view(integrity).substr(offset,32));
            SealedTree(root_oid,root_oid,xid,omap,hash,true,-1,0,(incompatible&9)!=0,tree);
            Supported(tree.extents.empty(),"Unsupported mixed sealed/ordinary APFS extent storage.");
            ExtentTree(U(volume,1032,8),xid,true,-1,0,nodes,extents);
            out.Set("integrity_physical_block",Num(im.paddr));out.Set("integrity_version",Num(U(integrity,32,4)));out.Set("root_sha256",JsonValue::String(hash));
        }else{
            Supported(!integrity_oid&&!U(volume,1032,8),"Unsupported integrity/extent tree on ordinary APFS volume.");
            OrdinaryTree(root_oid,xid,omap,true,-1,0,(incompatible&9)!=0,tree);
            extents=std::move(tree.extents);
        }
        out.Set("volume_omap_records",Num(omap.size()));out.Set("integrity_oid",Num(integrity_oid));
        out.Set("root_physical_block",Num(Lookup(omap,root_oid,xid,sealed).paddr));
        out.Set("sealed_metadata_hashes_verified",JsonValue::Boolean(sealed));out.Set("filesystem_metadata_checksums_verified",JsonValue::Boolean(!sealed));
        out.Set("filesystem_tree_storage",JsonValue::String(sealed?"sealed-headerless-virtual":"ordinary-checksummed-virtual"));
        out.Set("filesystem_nodes",Num(tree.nodes.size()));out.Set("filesystem_records",Num(tree.records));
        auto kinds=JsonValue::ArrayValue();for(auto n:tree.kinds)kinds.ArrayItems().push_back(Num(n));out.Set("record_kinds",std::move(kinds));
        out.Set("file_extent_nodes",Num(nodes.size()));out.Set("file_extents",Num(extents.size()));out.Set("inodes",Num(tree.inodes.size()));out.Set("directory_entries",Num(tree.directories.size()));
        auto paths=Paths(tree,extents);
        if(!requested_path.empty()){
            Supported(sealed||source_bound,"Ordinary APFS content requires source-bound extraction; sealed data hashes are unavailable.");
            SelectFile(tree,extents,paths,sealed);
        }
        out.Set("paths",std::move(paths));out.Set("file_contents_verified",JsonValue::Boolean(false));return out;
    }
    JsonValue Run(bool inspect_trees){
        Require(bytes >= 4096 && bytes <= 128ULL * 1024 * 1024 * 1024, "APFS input size invalid.");
        const auto prefix = At(0, 40);
        Require(prefix.substr(32, 4) == "NXSB", "Original decoded input is not raw APFS.");
        bs = static_cast<std::uint32_t>(U(prefix, 36, 4));
        Require(bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0, "APFS block size invalid.");
        const auto zero=At(0,bs);blocks=U(zero,40,8);Require(blocks>0&&blocks==bytes/bs&&bytes%bs==0,"APFS declared geometry differs from exact input.");NX(zero);
        std::vector<std::pair<U64,std::string>> candidates;
        const auto base=U(zero,112,8),count=U(zero,104,4);
        for (U64 i = 0; i < count; ++i) {
            auto b = Block(base + i);
            if (b.substr(32, 4) == "NXSB") {
                try {
                    NX(b);
                    Require(b.substr(72, 16) == zero.substr(72, 16), "APFS checkpoint container UUID mismatch.");
                    Supported(candidates.size() < 1024, "APFS checkpoint candidate memory budget exceeded.");
                    candidates.emplace_back(base + i, std::move(b));
                } catch (const std::runtime_error&) {}
            }
        }
        std::sort(candidates.begin(),candidates.end(),[](const auto& a,const auto& b){return U(a.second,16,8)>U(b.second,16,8);});
        std::string selected;U64 address=0,objects=0,rejected=0;
        for(const auto& c:candidates){try{objects=Checkpoint(c.second,c.first);selected=c.second;address=c.first;break;}catch(const std::runtime_error&){++rejected;}}
        Require(!selected.empty(),"No APFS checkpoint with valid mapped object headers/checksums.");const auto xid=U(selected,16,8);auto records=Omap(U(selected,160,8),xid);auto volumes=JsonValue::ArrayValue();std::set<U64> seen;
        for (U64 i = 0; i < U(selected, 180, 4); ++i) {
            const auto oid = U(selected, 184 + i * 8, 8);
            if (!oid) continue;
            Require(seen.insert(oid).second, "Duplicate APFS volume identifier.");
            const auto r = Lookup(records, oid, xid);
            const auto b = Block(r.paddr);
            Object(b, oid, r.xid, 13);
            Require(U(b, 16, 8) == r.xid && b.substr(32, 4) == "APSB" && U(b, 36, 4) == i,
                    "APFS volume magic/slot/transaction mismatch.");
            const auto name = b.substr(704, 256);
            const auto nul = name.find('\0');
            Require(nul != std::string::npos, "APFS volume name is not terminated.");
            auto v = JsonValue::ObjectValue();
            v.Set("oid", Num(oid));
            v.Set("xid", Num(r.xid));
            v.Set("physical_block", Num(r.paddr));
            v.Set("slot", Num(i));
            v.Set("name", JsonValue::String(name.substr(0, nul)));
            v.Set("uuid_hex", JsonValue::String(Hex(std::string_view(b).substr(240, 16))));
            v.Set("features", Num(U(b, 40, 8)));
            v.Set("readonly_features", Num(U(b, 48, 8)));
            v.Set("incompatible_features", Num(U(b, 56, 8)));
            v.Set("flags", Num(U(b, 264, 8)));
            v.Set("role", Num(U(b, 964, 2)));
            v.Set("omap_physical_block", Num(U(b, 128, 8)));
            v.Set("root_tree_oid", Num(U(b, 136, 8)));
            v.Set("root_tree_type", Num(U(b, 116, 4)));
            v.Set("fext_tree_oid", Num(U(b, 1032, 8)));
            v.Set("fext_tree_type", Num(U(b, 1040, 4)));
            if (inspect_trees) v.Set("trees", VolumeTrees(b, r.xid));
            volumes.ArrayItems().push_back(std::move(v));
        }
        auto out = Empty();
        out.Set("complete", JsonValue::Boolean(true));
        out.Set("metadata_verified", JsonValue::Boolean(true));
        out.Set("scope", JsonValue::String("container-checkpoint-object-headers-omap-volume-superblocks"));
        out.Set("input_bytes", Num(bytes));
        out.Set("block_size", Num(bs));
        out.Set("block_count", Num(blocks));
        out.Set("container_uuid_hex", JsonValue::String(Hex(std::string_view(selected).substr(72, 16))));
        out.Set("checkpoint_xid", Num(xid));
        out.Set("checkpoint_physical_block", Num(address));
        out.Set("checkpoint_candidates", Num(candidates.size()));
        out.Set("rejected_checkpoints", Num(rejected));
        out.Set("checkpoint_object_headers_verified", Num(objects));
        out.Set("omap_records", Num(records.size()));
        out.Set("blocks_read", Num(reads));
        out.Set("volumes", std::move(volumes));
        return out;
    }
};
struct Lease {HANDLE h=INVALID_HANDLE_VALUE;~Lease(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
struct OutputLease {
    HANDLE h = INVALID_HANDLE_VALUE;
    bool retained = false;
    std::filesystem::path directory;
    ~OutputLease() {
        if (h != INVALID_HANDLE_VALUE) {
            if (!retained) {
                FILE_DISPOSITION_INFO disposition{TRUE};
                SetFileInformationByHandle(h, FileDispositionInfo, &disposition, sizeof(disposition));
            }
            CloseHandle(h);
        }
        if (!retained && !directory.empty()) RemoveDirectoryW(directory.c_str());
    }
};
void Active(CancellationToken c, std::chrono::steady_clock::time_point deadline) {
    const auto context = CurrentOperationContext();
    Require(!c.Requested() && !(context && context->CancellationRequested()), "APFS inspection cancelled.");
    Require(std::chrono::steady_clock::now() < deadline && !(context && context->DeadlineExceeded()),
            "APFS inspection deadline exceeded.");
}
}
JsonValue InspectApfsMetadata(const ApfsRead& read, U64 bytes, bool trees) {
    try {
        auto out = Parser{read, bytes}.Run(trees);
        if (trees) {
            out.Set("volume_trees_verified", JsonValue::Boolean(true));
            out.Set("scope", JsonValue::String("container-volume-metadata-directory-paths-file-extent-metadata"));
        }
        return out;
    } catch (const std::exception& e) {
        auto out = Empty();
        out.Set("error", JsonValue::String(e.what()));
        return out;
    }
}
ApfsFileResult ReadApfsFile(const ApfsRead& read,U64 bytes,const std::string& path,const std::function<void()>& control,bool source_bound){
    ApfsFileResult result{Empty(), {}};
    try {
        Require(!path.empty() && path.front() == '/' && path.size() <= 32768 && path.find('\0') == std::string::npos,
                "Absolute original APFS virtual path required.");
        Parser parser{read, bytes};
        parser.requested_path = path;
        parser.control = control;
        parser.source_bound = source_bound;
        const auto metadata = parser.Run(true);
        Require(parser.selected_count == 1, "Requested original APFS file not found.");
        result.report = std::move(parser.selected_file);
        result.report.Set("complete", JsonValue::Boolean(true));
        result.report.Set("metadata_verified", JsonValue::Boolean(true));
        result.report.Set("volume_trees_verified", JsonValue::Boolean(true));
        result.report.Set("scope", JsonValue::String(result.report.Get("file_contents_verified")->Bool()
                                                         ? "selected-original-apfs-file-decoded-data-hashes"
                                                         : "selected-original-apfs-file-source-bound-decoded"));
        for (const char* k : {"filesystem_verified", "publisher_verified", "provider_registered", "published"})
            result.report.Set(k, JsonValue::Boolean(false));
        for (const char* k : {"checkpoint_xid", "container_uuid_hex", "block_size"})
            result.report.Set(k, *metadata.Get(k));
        result.bytes = std::move(parser.file_data);
    } catch (const std::exception& e) {
        result = {Empty(), {}};
        result.report.Set("error", JsonValue::String(e.what()));
    }
    return result;
}
JsonValue StreamApfsFile(const ApfsRead& read,U64 bytes,const std::string& path,const ApfsWrite& sink,const std::function<void()>& control,bool source_bound){
    try {
        Require(bool(sink) && !path.empty() && path.front() == '/' && path.size() <= 32768 &&
                    path.find('\0') == std::string::npos,
                "APFS streaming sink and absolute virtual path required.");
        Parser parser{read, bytes};
        parser.requested_path = path;
        parser.control = control;
        parser.sink = sink;
        parser.memory_mode = false;
        parser.source_bound = source_bound;
        const auto metadata = parser.Run(true);
        Require(parser.selected_count == 1, "Requested original APFS file not found.");
        auto out = std::move(parser.selected_file);
        out.Set("complete", JsonValue::Boolean(true));
        out.Set("metadata_verified", JsonValue::Boolean(true));
        out.Set("volume_trees_verified", JsonValue::Boolean(true));
        out.Set("scope", JsonValue::String(out.Get("file_contents_verified")->Bool()
                                               ? "selected-original-apfs-file-decoded-data-hashes"
                                               : "selected-original-apfs-file-source-bound-decoded"));
        for (const char* k : {"filesystem_verified", "publisher_verified", "provider_registered", "published"})
            out.Set(k, JsonValue::Boolean(false));
        for (const char* k : {"checkpoint_xid", "container_uuid_hex", "block_size"}) out.Set(k, *metadata.Get(k));
        return out;
    } catch (const std::exception& e) {
        auto out = Empty();
        out.Set("error", JsonValue::String(e.what()));
        return out;
    }
}
namespace {
JsonValue InspectStage(const std::filesystem::path& report_path,CancellationToken cancel,std::chrono::steady_clock::time_point deadline,bool trees,const std::string& requested={},const std::filesystem::path& directory={}){
    auto out=Empty();try{
        Active(cancel, deadline);
        std::ifstream f(report_path, std::ios::binary);
        Require(bool(f), "Decoded APFS input report unavailable.");
        std::string text(1024 * 1024 + 1, '\0');
        f.read(text.data(), static_cast<std::streamsize>(text.size()));
        text.resize(static_cast<std::size_t>(f.gcount()));
        Require(text.size() <= 1024 * 1024, "Decoded APFS report budget exceeded.");
        if (text.starts_with("\xef\xbb\xbf")) text.erase(0, 3);
        const auto report = JsonValue::Parse(text);
        Require(report && report->IsObject(), "Invalid decoded APFS report.");
        for (const char* k :
             {"complete", "authentication_verified", "all_clusters_authenticated", "decryption_complete",
              "component_digest_verified", "component_digest_scope_verified", "quarantined"})
            Require(report->Get(k) && report->Get(k)->IsBoolean() && report->Get(k)->Bool(),
                    "Authenticated digest-verified decoded quarantine required.");
        Require(report->GetString("digest_scope") == "decoded-aea-payload",
                "Unsupported decoded APFS input digest scope.");
        const auto sha = report->GetString("sha256");
        Require(sha.size() == 64 &&
                    std::all_of(sha.begin(), sha.end(),
                                [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }),
                "Decoded APFS SHA256 binding required.");
        const std::filesystem::path path(Win32Process::ToWide(report->GetString("path")));
        Require(path.is_absolute(), "Absolute original decoded APFS path required.");
        Lease lease;
        lease.h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(lease.h != INVALID_HANDLE_VALUE, "Stable decoded APFS input unavailable.");
        LARGE_INTEGER size{};
        Require(GetFileSizeEx(lease.h, &size) && size.QuadPart >= 4096 && size.QuadPart <= 128LL * 1024 * 1024 * 1024,
                "Decoded APFS file size invalid.");
        Require(report->Get("decoded_bytes") && report->Get("decoded_bytes")->IsNumber() &&
                    report->Get("decoded_bytes")->Serialize() == std::to_string(size.QuadPart),
                "Decoded APFS size binding mismatch.");
        const auto hash=Sha256FileHandle(lease.h,cancel,deadline);Active(cancel,deadline);Require(hash&&*hash==sha,"Decoded APFS snapshot SHA256 mismatch.");
        const ApfsRead reader = [&](U64 offset, U64 count) {
            Active(cancel, deadline);
            LARGE_INTEGER pos{};
            pos.QuadPart = offset;
            Require(SetFilePointerEx(lease.h, pos, nullptr, FILE_BEGIN), "APFS native seek failed.");
            std::string b(static_cast<std::size_t>(count), '\0');
            DWORD got = 0;
            Require(::ReadFile(lease.h, b.data(), static_cast<DWORD>(count), &got, nullptr) && got == count,
                    "APFS native read failed.");
            return b;
        };
        if(requested.empty())out=InspectApfsMetadata(reader,static_cast<U64>(size.QuadPart),trees);
        else {
            Require(directory.is_absolute()&&directory.filename()!=L"."&&directory.filename()!=L"..","Absolute fresh APFS output directory required.");
            OutputLease output;const auto target=directory/L"file.decoded-quarantined";
            auto open_output = [&] {
                if (output.h != INVALID_HANDLE_VALUE) return;
                Active(cancel, deadline);
                Require(CreateDirectoryW(directory.c_str(), nullptr),
                        "Fresh APFS output directory unavailable or already exists.");
                output.directory = directory;
                output.h = CreateFileW(target.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
                Require(output.h != INVALID_HANDLE_VALUE, "Fresh APFS quarantine file unavailable.");
            };
            out = StreamApfsFile(
                reader, static_cast<U64>(size.QuadPart), requested,
                [&](std::string_view piece) {
                    open_output();
                    Active(cancel, deadline);
                    DWORD written = 0;
                    Require(
                        piece.size() <= 1024 * 1024 &&
                            WriteFile(output.h, piece.data(), static_cast<DWORD>(piece.size()), &written, nullptr) &&
                            written == piece.size(),
                        "APFS quarantine output write failed.");
                },
                [&] { Active(cancel, deadline); }, true);
            Require(out.Get("complete")->Bool(), out.GetString("error").c_str());
            open_output();
            Require(FlushFileBuffers(output.h), "APFS quarantine flush failed.");
            const auto output_hash = Sha256FileHandle(output.h, cancel, deadline);
            Require(output_hash && *output_hash == out.GetString("sha256"), "APFS quarantine output hash mismatch.");
            Active(cancel, deadline);
            out.Set("source_path", JsonValue::String(path.generic_string()));
            out.Set("path", JsonValue::String(target.generic_string()));
            out.Set("source_sha256", JsonValue::String(sha));
            out.Set("quarantined", JsonValue::Boolean(true));
            output.retained = true;
        }
        if(requested.empty()){Active(cancel,deadline);if(out.Get("complete")->Bool()){out.Set("path",JsonValue::String(path.generic_string()));out.Set("source_sha256",JsonValue::String(sha));out.Set("quarantined",JsonValue::Boolean(true));}}
    }catch(const std::exception& e){out=Empty();out.Set("error",JsonValue::String(e.what()));}return out;
}
}
JsonValue InspectApfsStage(const std::filesystem::path& report_path,CancellationToken cancel,std::chrono::steady_clock::time_point deadline,bool trees){return InspectStage(report_path,cancel,deadline,trees);}
JsonValue ExtractApfsStage(const std::filesystem::path& report, const std::string& path,
                           const std::filesystem::path& directory, CancellationToken cancel,
                           std::chrono::steady_clock::time_point deadline) {
    if (path.empty()) {
        auto out = Empty();
        out.Set("error", JsonValue::String("Original APFS virtual path required."));
        return out;
    }
    return InspectStage(report, cancel, deadline, true, path, directory);
}
}
