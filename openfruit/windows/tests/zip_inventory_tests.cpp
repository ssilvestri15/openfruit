#include "zip_inventory.hpp"
#include "native_zip.hpp"
#include "operation_events.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void Put(std::string& b, std::uint64_t value, unsigned n) { for (unsigned i=0;i<n;++i) b.push_back(static_cast<char>(value>>(i*8))); }
void Set(std::string& b, std::size_t pos, std::uint64_t value, unsigned n) { for(unsigned i=0;i<n;++i)b.at(pos+i)=static_cast<char>(value>>(i*8)); }
std::string Central(const std::string& name) {
    std::string b(46,'\0'); Set(b,0,0x02014b50,4); Set(b,6,45,2);
    Set(b,20,0xffffffff,4); Set(b,24,0xffffffff,4); Set(b,28,name.size(),2); Set(b,30,28,2); Set(b,42,0xffffffff,4);
    b+=name; Put(b,1,2); Put(b,24,2); Put(b,4,8); Put(b,4,8); Put(b,5000000000ULL,8);
    return b;
}
struct SparseArchive {
    std::uint64_t directory_offset=6000000000ULL, size=0;
    std::string suffix;
    explicit SparseArchive(std::string directory, std::uint64_t entries=1) : suffix(std::move(directory)) {
        const auto bytes=suffix.size(), zoff=directory_offset+bytes;
        Put(suffix,0x06064b50,4);Put(suffix,44,8);Put(suffix,45,2);Put(suffix,45,2);Put(suffix,0,4);Put(suffix,0,4);
        Put(suffix,entries,8);Put(suffix,entries,8);Put(suffix,bytes,8);Put(suffix,directory_offset,8);
        Put(suffix,0x07064b50,4);Put(suffix,0,4);Put(suffix,zoff,8);Put(suffix,1,4);
        Put(suffix,0x06054b50,4);Put(suffix,0,2);Put(suffix,0,2);Put(suffix,0xffff,2);Put(suffix,0xffff,2);
        Put(suffix,0xffffffff,4);Put(suffix,0xffffffff,4);Put(suffix,0,2);
        size=directory_offset+suffix.size();
    }
    ZipInventoryResult Inspect() const {
        return InspectZipInventory(size,[&](std::uint64_t offset,std::uint64_t bytes)->std::optional<std::string>{
            if(offset>size || bytes>size-offset)return {};
            std::string out(static_cast<std::size_t>(bytes),'\0');
            const auto start=std::max(offset,directory_offset), end=offset+bytes;
            if(end>start)out.replace(static_cast<std::size_t>(start-offset),static_cast<std::size_t>(end-start),
                suffix.substr(static_cast<std::size_t>(start-directory_offset),static_cast<std::size_t>(end-start)));
            return out;
        });
    }
};
void Rejected(const SparseArchive& archive) {
    auto r=archive.Inspect();Require(!r.directory_validated && r.members.empty() && r.archive_bytes==0 && !r.error.empty(),"Malformed ZIP64 accepted or partial result exposed");
}
}
int main() {
    try {
        const auto directory=Central("Original/Library.dylib");
        SparseArchive original(directory);
        auto r=original.Inspect();
        Require(r.directory_validated && r.zip64 && r.members.size()==1 && r.members[0].local_offset==5000000000ULL &&
            r.members[0].name=="Original/Library.dylib" && r.members[0].uncompressed==4 && r.directory_offset==6000000000ULL,
            "Original ZIP64 field order or 64-bit offsets lost");
        auto json=r.ToJson();Require(!json.Get("publisher_verified")->Bool(true) && !json.Get("members_verified")->Bool(true),"Inventory reports content trust");
        for(const auto& path: {"../escape","/absolute","a//b","a/./b","a/../b","a\\b","a:b"})Rejected(SparseArchive(Central(path)));
        auto bad=directory;Set(bad,30,27,2);Rejected(SparseArchive(bad));
        bad=directory;Set(bad,8,1,2);Rejected(SparseArchive(bad));
        bad=directory;Set(bad,34,1,2);Rejected(SparseArchive(bad));
        bad=directory;Set(bad,10,99,2);Rejected(SparseArchive(bad));
        bad=directory;Set(bad,46+std::string("Original/Library.dylib").size()+4+16,UINT64_MAX,8);Rejected(SparseArchive(bad));
        Rejected(SparseArchive(directory+directory,2));Rejected(SparseArchive(directory,2));
        auto malformed=original;Set(malformed.suffix,directory.size()+4,UINT64_MAX,8);Rejected(malformed);
        malformed=original;Set(malformed.suffix,directory.size()+16,1,4);Rejected(malformed);
        malformed=original;Set(malformed.suffix,malformed.suffix.size()-6,1,4);Rejected(malformed);
        malformed=original;Set(malformed.suffix,directory.size()+56+8,UINT64_MAX,8);Rejected(malformed);
        const auto failed=InspectZipInventory(original.size,[](auto,auto)->std::optional<std::string>{return {};});
        Require(!failed.directory_validated && failed.members.empty(),"Reader failure ignored");
        CancellationSource cancel;cancel.Cancel();
        bool reader_called=false;
        auto inactive_reader=[&](auto,auto)->std::optional<std::string>{reader_called=true;return {};};
        auto interrupted=InspectZipInventory(22,inactive_reader,cancel.Token());
        Require(!reader_called && interrupted.error=="ZIP inventory cancelled.","Cancellation did not precede byte acquisition");
        interrupted=InspectZipInventory(22,inactive_reader,{},std::chrono::steady_clock::now());
        Require(!reader_called && interrupted.error=="ZIP inventory deadline exceeded.","Deadline did not precede byte acquisition");
        const auto root=fs::temp_directory_path()/("OPENFRUIT-zip-inventory-"+NewOperationId());
        fs::create_directories(root/"input"/"Original");std::ofstream(root/"input"/"Original"/"Library.dylib")<<"owned original bytes";
        Require(NativeZipWriter::CreateFromDirectory(root/"input",root/"original.zip"),"Owned original ZIP writer failed");
        std::ifstream file(root/"original.zip",std::ios::binary);std::string bytes(std::istreambuf_iterator<char>(file),{});file.close();
        r=InspectZipInventory(bytes.size(),[&](auto offset,auto count)->std::optional<std::string>{return bytes.substr(static_cast<std::size_t>(offset),static_cast<std::size_t>(count));});
        Require(r.directory_validated && !r.zip64 && !r.members.empty(),"Real ZIP32 writer directory rejected");
        bool found=false;for(const auto&m:r.members)if(m.name=="input/Original/Library.dylib")found=true;
        Require(found,"Real writer original file omitted");
        // The unique fixture root is owned entirely by this test.
        fs::remove_all(root);return 0;
    } catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
