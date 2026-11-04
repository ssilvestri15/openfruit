#include "dyld_cache.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string_view>
#include <vector>
namespace OpenFruit {
namespace {
using U64=std::uint64_t;
void Require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
U64 U(std::string_view s,std::size_t p,unsigned n){Require(p<=s.size()&&n<=s.size()-p,"Truncated dyld cache field.");U64 v=0;for(unsigned i=0;i<n;++i)v|=U64(static_cast<unsigned char>(s[p+i]))<<(8*i);return v;}
std::string Hex(std::string_view s){constexpr char digits[]="0123456789abcdef";std::string out;for(unsigned char c:s){out+=digits[c>>4];out+=digits[c&15];}return out;}
JsonValue N(U64 n){return JsonValue::Number(std::to_string(n));}
JsonValue Empty(){auto r=JsonValue::ObjectValue();for(const char* k:{"complete","cache_metadata_verified","cache_closure_verified","code_signature_verified","publisher_verified","provider_registered","published"})r.Set(k,JsonValue::Boolean(false));return r;}
bool Hash(const std::string& s){return s.size()==64&&std::all_of(s.begin(),s.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f');});}
struct Mapping {U64 address,size,file,max,initial;};
U64 Number(const JsonValue& j,const char* key){const auto p=j.Get(key);Require(p&&p->IsNumber(),"Missing native dyld parent numeric metadata.");return std::stoull(p->Serialize());}
struct ParentContext {U64 start,region,offset,platform,os;std::string uuid,architecture,parent_uuid;};
ParentContext Context(const JsonValue& parent,const std::string& path){
    Require(parent.Get("complete")&&parent.Get("complete")->Bool()&&parent.Get("cache_metadata_verified")->Bool(),"Verified native dyld parent required.");const JsonValue* selected=nullptr;
    for(const auto& entry:parent.Get("subcaches")->ArrayItems())if(entry.GetString("virtual_path")==path){Require(!selected,"Ambiguous parent dyld subcache path.");selected=&entry;}
    Require(selected, "Original child path not declared by verified parent.");
    return {Number(parent, "shared_region_start"), Number(parent, "shared_region_size"),
            Number(*selected, "vm_offset"),        Number(parent, "platform"),
            Number(parent, "os_version"),          selected->GetString("uuid_hex"),
            parent.GetString("architecture"),      parent.GetString("uuid_hex")};
}
struct Parser {
    const DyldCacheRead& read;U64 bytes,budget=0,start=0,region=0,header_size=0;
    std::vector<std::pair<U64,U64>> table_ranges;
    const ParentContext* parent=nullptr;
    std::string At(U64 p,U64 n){Require(p<=bytes&&n<=bytes-p&&n<=32ULL*1024*1024&&n<=128ULL*1024*1024-budget,"Dyld cache read range/budget invalid.");budget+=n;auto s=read(p,n);Require(s.size()==n,"Short original dyld cache read.");return s;}
    bool InRegion(U64 p,U64 n=1){return p>=start&&p-start<region&&n<=region-(p-start);}
    std::string Name(U64 p) {
        Require(p >= header_size && p < bytes, "Dyld image path offset invalid.");
        std::string name;
        while (name.size() < 32768 && name.size() < bytes - p) {
            const auto chunk =
                At(p + name.size(), std::min<U64>(256, std::min<U64>(32768 - name.size(), bytes - p - name.size())));
            const auto end = chunk.find('\0');
            name += chunk.substr(0, end);
            if (end != std::string::npos) {
                Require(name.size() > 1 && name.front() == '/' &&
                            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(),
                                                static_cast<int>(name.size()), nullptr, 0) > 0,
                        "Dyld image path encoding/absolute form invalid.");
                for (const auto& [begin, finish] : table_ranges)
                    Require(p + name.size() + 1 <= begin || p >= finish, "Dyld image path overlaps metadata table.");
                return name;
            }
        }
        throw std::runtime_error("Dyld image path not bounded/terminated.");
    }
    std::string Table(U64 p, U64 count, U64 stride, U64 maximum) {
        Require(count <= maximum && (!count || (p >= header_size && count <= UINT64_MAX / stride)),
                "Dyld cache table geometry/count invalid.");
        if (!count) return {};
        const auto length = count * stride;
        Require(p <= bytes && length <= bytes - p, "Dyld table file bounds invalid.");
        for (const auto& [begin, end] : table_ranges)
            Require(p + length <= begin || p >= end, "Overlapping dyld metadata tables.");
        table_ranges.emplace_back(p, p + length);
        return At(p, length);
    }
    JsonValue Run(const std::string& path){
        Require(bytes >= 512 && bytes <= 16ULL * 1024 * 1024 * 1024, "Dyld cache file size unsupported.");
        Require(!path.empty() && path.front() == '/' && path.find('\0') == std::string::npos && path.size() <= 32768,
                "Original dyld cache virtual path required.");
        const auto h = At(0, 512);
        Require(h.substr(0, 7) == "dyld_v1", "Unsupported dyld cache magic/version.");
        const auto zero = h.substr(7, 9).find('\0');
        Require(zero != std::string::npos, "Dyld cache architecture not terminated.");
        auto arch = h.substr(7, zero);
        const auto first = arch.find_first_not_of(' ');
        Require(first != std::string::npos, "Missing dyld cache architecture.");
        arch.erase(0, first);
        Require(arch == "arm64e" || arch == "arm64" || arch == "x86_64" || arch == "x86_64h",
                "Unsupported dyld cache CPU architecture.");
        header_size = U(h, 16, 4);
        Require(header_size >= 512 && header_size <= 1024 && header_size <= bytes,
                "Unsupported dyld cache header layout.");
        const auto declared_start = U(h, 224, 8), declared_region = U(h, 232, 8);
        start = declared_start;
        region = declared_region;
        if (parent) {
            Require(parent->start <= UINT64_MAX - parent->offset &&
                        (declared_start == parent->start + parent->offset || declared_start == parent->start),
                    "Dyld child declared VM base conflicts with parent.");
            Require(!declared_region ||
                        (declared_start >= parent->start && declared_start - parent->start < parent->region &&
                         declared_region <= parent->region - (declared_start - parent->start)),
                    "Dyld child declared region conflicts with parent.");
            start = parent->start;
            region = parent->region;
            Require(arch == parent->architecture && U(h, 216, 4) == parent->platform && U(h, 364, 4) == parent->os,
                    "Dyld child CPU/platform/OS conflicts with parent.");
        }
        Require(start > 0 && region > 0 && region <= 128ULL * 1024 * 1024 * 1024 && start <= UINT64_MAX - region,
                "Dyld shared region bounds invalid.");
        const auto flags = U(h, 220, 4);
        Require(!(flags & ~0x1fffULL), "Unsupported dyld cache format flags.");
        const auto type = U(h, 104, 8);
        Require(type <= 2, "Unsupported dyld cache type.");
        const auto uuid = Hex(std::string_view(h).substr(88, 16));
        Require(uuid != std::string(32, '0'), "Missing dyld cache UUID.");
        if (parent) Require(uuid == parent->uuid, "Dyld child UUID conflicts with parent declaration.");
        const auto count=U(h,20,4);Require(count>0,"Dyld cache has no file mappings.");const auto table=Table(header_size,count,32,20);std::vector<Mapping> mappings;std::vector<std::pair<U64,U64>> files;auto map_json=JsonValue::ArrayValue();
        for (U64 i = 0; i < count; ++i) {
            const auto p = i * 32;
            Mapping m{U(table, p, 8), U(table, p + 8, 8), U(table, p + 16, 8), U(table, p + 24, 4),
                      U(table, p + 28, 4)};
            Require(m.size > 0 && InRegion(m.address, m.size) && m.file <= bytes && m.size <= bytes - m.file &&
                        m.address % 4096 == 0 && m.file % 4096 == 0 && m.size % 4096 == 0 && !(m.max & ~7ULL) &&
                        !(m.initial & ~m.max),
                    "Dyld mapping address/file/protection bounds invalid.");
            Require(mappings.empty() || mappings.back().address + mappings.back().size <= m.address,
                    "Overlapping/unordered dyld VM mappings.");
            mappings.push_back(m);
            files.emplace_back(m.file, m.file + m.size);
            auto j = JsonValue::ObjectValue();
            j.Set("address", N(m.address));
            j.Set("size", N(m.size));
            j.Set("file_offset", N(m.file));
            j.Set("maximum_protection", N(m.max));
            j.Set("initial_protection", N(m.initial));
            map_json.ArrayItems().push_back(std::move(j));
        }
        std::sort(files.begin(), files.end());
        for (std::size_t i = 1; i < files.size(); ++i)
            Require(files[i - 1].second <= files[i].first, "Overlapping dyld file mappings.");
        Require(mappings.front().file == 0 && mappings.front().size >= header_size,
                "Dyld header file mapping missing.");
        if (parent)
            Require(mappings.front().address == parent->start + parent->offset,
                    "Dyld child first mapping conflicts with declared VM offset.");
        const auto slide_count=U(h,316,4);Require(slide_count==count,"Dyld mapping/slide table count mismatch.");const auto slides=Table(U(h,312,4),slide_count,56,20);auto slide_json=JsonValue::ArrayValue();
        for (U64 i = 0; i < count; ++i) {
            const auto p = i * 56;
            const auto& m = mappings[i];
            Require(U(slides, p, 8) == m.address && U(slides, p + 8, 8) == m.size && U(slides, p + 16, 8) == m.file &&
                        U(slides, p + 48, 4) == m.max && U(slides, p + 52, 4) == m.initial,
                    "Dyld mapping/slide table fields disagree.");
            const auto off = U(slides, p + 24, 8), length = U(slides, p + 32, 8), sf = U(slides, p + 40, 8);
            Require(!(sf & ~127ULL) && off <= bytes && length <= bytes - off && (length || !off),
                    "Dyld slide metadata flags/range invalid.");
            auto j = JsonValue::ObjectValue();
            j.Set("file_offset", N(off));
            j.Set("size", N(length));
            j.Set("flags", N(sf));
            if (length) {
                Require(length >= 4, "Truncated dyld slide header.");
                j.Set("version", N(U(At(off, 4), 0, 4)));
            }
            slide_json.ArrayItems().push_back(std::move(j));
        }
        const auto signature = U(h, 40, 8), signature_size = U(h, 48, 8);
        Require(signature >= header_size && signature <= bytes && signature_size > 0 &&
                    signature_size <= bytes - signature,
                "Dyld code-signature range invalid.");
        for (const auto& m : mappings)
            Require(m.file + m.size <= signature, "Dyld mapping overlaps its code signature.");
        auto subcaches=JsonValue::ArrayValue();const auto scount=U(h,396,4);const auto subt=Table(U(h,392,4),scount,56,256);std::set<std::string> suffixes,uuids;std::set<U64> vm_offsets;std::string base=path;if(type==2&&base.ends_with(".development"))base.resize(base.size()-12);
        for (U64 i = 0; i < scount; ++i) {
            const auto p = i * 56;
            const auto id = Hex(std::string_view(subt).substr(p, 16));
            const auto raw = std::string_view(subt).substr(p + 24, 32);
            const auto end = raw.find('\0');
            Require(end != std::string_view::npos && end > 1, "Dyld subcache suffix not bounded/terminated.");
            const auto suffix = std::string(raw.substr(0, end));
            Require(suffix.front() == '.' && suffix.find("..") == std::string::npos &&
                        std::all_of(suffix.begin(), suffix.end(),
                                    [](unsigned char c) {
                                        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                               (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                                    }),
                    "Unsafe dyld subcache suffix.");
            const auto vm = U(subt, p + 16, 8);
            Require(vm > 0 && vm < region && vm % 4096 == 0 && id != std::string(32, '0') && id != uuid &&
                        suffixes.insert(suffix).second && uuids.insert(id).second && vm_offsets.insert(vm).second,
                    "Duplicate/invalid dyld subcache identity/VM offset.");
            auto j = JsonValue::ObjectValue();
            j.Set("uuid_hex", JsonValue::String(id));
            j.Set("vm_offset", N(vm));
            j.Set("suffix", JsonValue::String(suffix));
            j.Set("virtual_path", JsonValue::String(base + suffix));
            j.Set("file_verified", JsonValue::Boolean(false));
            subcaches.ArrayItems().push_back(std::move(j));
        }
        const auto icount=U(h,452,4);const auto images=Table(U(h,448,4),icount,32,100000);const auto text_count=U(h,144,8);const auto texts=Table(U(h,136,8),text_count,32,100000);auto image_json=JsonValue::ArrayValue();std::set<std::string> paths;U64 name_bytes=0;
        for (U64 i = 0; i < icount; ++i) {
            const auto p = i * 32, address = U(images, p, 8);
            Require(InRegion(address), "Dyld image address outside shared region.");
            const auto name = Name(U(images, p + 24, 4));
            name_bytes += name.size();
            Require(name_bytes <= 32ULL * 1024 * 1024 && paths.insert(name).second,
                    "Duplicate dyld image path/name budget exceeded.");
            auto j = JsonValue::ObjectValue();
            j.Set("path", JsonValue::String(name));
            j.Set("address", N(address));
            j.Set("modification_time", N(U(images, p + 8, 8)));
            j.Set("inode", N(U(images, p + 16, 8)));
            j.Set("record_flags", N(U(images, p + 28, 4)));
            j.Set("image_bytes_verified", JsonValue::Boolean(false));
            image_json.ArrayItems().push_back(std::move(j));
        }
        auto text_json=JsonValue::ArrayValue();std::set<std::string> text_paths;
        for (U64 i = 0; i < text_count; ++i) {
            const auto p = i * 32, address = U(texts, p + 16, 8), size = U(texts, p + 24, 4);
            Require(size > 0 && InRegion(address, size), "Dyld image text range invalid.");
            const auto name = Name(U(texts, p + 28, 4));
            const auto image_uuid = Hex(std::string_view(texts).substr(p, 16));
            Require(image_uuid != std::string(32, '0') && text_paths.insert(name).second,
                    "Duplicate/invalid dyld image text identity.");
            auto j = JsonValue::ObjectValue();
            j.Set("path", JsonValue::String(name));
            j.Set("address", N(address));
            j.Set("size", N(size));
            j.Set("uuid_hex", JsonValue::String(image_uuid));
            text_json.ArrayItems().push_back(std::move(j));
        }
        const auto dynamic_offset=U(h,496,8),dynamic_max=U(h,504,8);
        Require((dynamic_offset==0)==(dynamic_max==0),"Incomplete dynamic cache reservation.");
        if(dynamic_offset)Require(dynamic_offset<region&&dynamic_max<=region-dynamic_offset
            &&dynamic_offset%16384==0&&dynamic_max>=16384&&dynamic_max%16384==0,"Invalid dynamic cache reservation.");
        auto out = Empty();
        out.Set("complete", JsonValue::Boolean(true));
        out.Set("cache_metadata_verified", JsonValue::Boolean(true));
        out.Set("scope", JsonValue::String("original-dyld-cache-header-mappings-subcache-identities-image-paths"));
        out.Set("virtual_path", JsonValue::String(path));
        out.Set("architecture", JsonValue::String(arch));
        out.Set("uuid_hex", JsonValue::String(uuid));
        out.Set("cache_type", N(type));
        out.Set("cache_subtype", N(U(h, 456, 4)));
        out.Set("platform", N(U(h, 216, 4)));
        out.Set("os_version", N(U(h, 364, 4)));
        out.Set("alternate_platform", N(U(h, 368, 4)));
        out.Set("alternate_os_version", N(U(h, 372, 4)));
        out.Set("format_flags", N(flags));
        out.Set("shared_region_start", N(start));
        out.Set("shared_region_size", N(region));
        out.Set("dynamic_data_offset", N(dynamic_offset));
        out.Set("dynamic_data_max_size", N(dynamic_max));
        out.Set("dyld_header_address", N(U(h, 120, 8)));
        out.Set("dyld_entry_address", N(U(h, 128, 8)));
        out.Set("signature_offset", N(signature));
        out.Set("signature_size", N(signature_size));
        out.Set("symbol_file_uuid_hex", JsonValue::String(Hex(std::string_view(h).substr(400, 16))));
        out.Set("mappings", std::move(map_json));
        out.Set("slide_metadata", std::move(slide_json));
        out.Set("subcaches", std::move(subcaches));
        out.Set("images", std::move(image_json));
        out.Set("image_texts", std::move(text_json));
        out.Set("declared_region_start", N(declared_start));
        out.Set("declared_region_size", N(declared_region));
        out.Set("parent_context_verified", JsonValue::Boolean(parent != nullptr));
        if (parent) {
            out.Set("parent_uuid_hex", JsonValue::String(parent->parent_uuid));
            out.Set("declared_vm_offset", N(parent->offset));
        }
        return out;
    }
};
struct Lease {HANDLE h=INVALID_HANDLE_VALUE;~Lease(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
using HeldFiles=std::map<std::string,std::unique_ptr<Lease>>;
void Active(CancellationToken cancel, std::chrono::steady_clock::time_point deadline) {
    const auto c = CurrentOperationContext();
    Require(!cancel.Requested() && !(c && c->CancellationRequested()), "Dyld cache inspection cancelled.");
    Require(std::chrono::steady_clock::now() < deadline && !(c && c->DeadlineExceeded()),
            "Dyld cache inspection deadline exceeded.");
}
}
JsonValue InspectDyldCache(const DyldCacheRead& read,U64 bytes,const std::string& path){try{return Parser{read,bytes}.Run(path);}catch(const std::exception& e){auto out=Empty();out.Set("error",JsonValue::String(e.what()));return out;}}
namespace {
JsonValue InspectStage(const std::filesystem::path& report_path,CancellationToken cancel,std::chrono::steady_clock::time_point deadline,const JsonValue* parent=nullptr,HeldFiles* held=nullptr){auto out=Empty();try{
        Active(cancel, deadline);
        std::ifstream f(report_path, std::ios::binary);
        Require(bool(f), "Original APFS file report unavailable.");
        std::string text(1024 * 1024 + 1, '\0');
        f.read(text.data(), text.size());
        text.resize(static_cast<std::size_t>(f.gcount()));
        Require(text.size() <= 1024 * 1024, "Dyld input report budget exceeded.");
        if (text.starts_with("\xef\xbb\xbf")) text.erase(0, 3);
        const auto r = JsonValue::Parse(text);
        Require(r && r->IsObject(), "Invalid dyld input report.");
        for (const char* k :
             {"complete", "file_contents_verified", "metadata_verified", "volume_trees_verified", "quarantined"})
            Require(r->Get(k) && r->Get(k)->IsBoolean() && r->Get(k)->Bool(),
                    "Verified original quarantined APFS file required.");
        Require(r->GetString("scope") == "selected-original-apfs-file-decoded-data-hashes" &&
                    Hash(r->GetString("sha256")) && Hash(r->GetString("source_sha256")),
                "Original APFS file digest/scope binding required.");
        const std::filesystem::path file(Win32Process::ToWide(r->GetString("path")));
        Require(file.is_absolute(), "Absolute original dyld file path required.");
        Lease lease;
        lease.h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(lease.h != INVALID_HANDLE_VALUE, "Stable original dyld input unavailable.");
        LARGE_INTEGER size{};
        Require(GetFileSizeEx(lease.h, &size) && size.QuadPart >= 512 && size.QuadPart <= 16LL * 1024 * 1024 * 1024 &&
                    r->Get("decoded_bytes") && r->Get("decoded_bytes")->IsNumber() &&
                    r->Get("decoded_bytes")->Serialize() == std::to_string(size.QuadPart),
                "Original dyld size binding invalid.");
        const auto sha = Sha256FileHandle(lease.h, cancel, deadline);
        Require(sha && *sha == r->GetString("sha256"), "Original dyld snapshot SHA256 mismatch.");
        if (parent)
            Require(parent->GetString("source_image_sha256") == r->GetString("source_sha256"),
                    "Dyld parent/child original image digest mismatch.");
        const auto context = parent ? Context(*parent, r->GetString("virtual_path")) : ParentContext{};
        const DyldCacheRead read = [&](U64 p, U64 n) {
            Active(cancel, deadline);
            LARGE_INTEGER offset{};
            offset.QuadPart = p;
            Require(SetFilePointerEx(lease.h, offset, nullptr, FILE_BEGIN), "Dyld native seek failed.");
            std::string s(static_cast<std::size_t>(n), '\0');
            DWORD got = 0;
            Require(ReadFile(lease.h, s.data(), static_cast<DWORD>(n), &got, nullptr) && got == n,
                    "Dyld native read failed.");
            return s;
        };
        Parser parser{read, static_cast<U64>(size.QuadPart)};
        parser.parent = parent ? &context : nullptr;
        out = parser.Run(r->GetString("virtual_path"));
        Active(cancel, deadline);
        if (out.Get("complete")->Bool()) {
            out.Set("source_file_sha256", JsonValue::String(*sha));
            out.Set("source_image_sha256", JsonValue::String(r->GetString("source_sha256")));
            out.Set("source_path", JsonValue::String(file.generic_string()));
            out.Set("quarantined", JsonValue::Boolean(true));
            if (parent) out.Set("parent_file_sha256", JsonValue::String(parent->GetString("source_file_sha256")));
            if (held) {
                Require(!held->contains(file.generic_string()), "Duplicate original cache backing file.");
                auto guard = std::make_unique<Lease>();
                guard->h = lease.h;
                lease.h = INVALID_HANDLE_VALUE;
                held->emplace(file.generic_string(), std::move(guard));
            }
        }
}catch(const std::exception& e){out=Empty();out.Set("error",JsonValue::String(e.what()));}return out;}
}

}
namespace OpenFruit {
JsonValue InspectDyldCacheStage(const std::filesystem::path& report,CancellationToken cancel,std::chrono::steady_clock::time_point deadline){return InspectStage(report,cancel,deadline);}
JsonValue InspectDyldSubcache(const DyldCacheRead& parent,U64 parent_bytes,const std::string& parent_path,const DyldCacheRead& child,U64 child_bytes,const std::string& child_path){try{
    const auto verified=Parser{parent,parent_bytes}.Run(parent_path);const auto context=Context(verified,child_path);Parser parser{child,child_bytes};parser.parent=&context;return parser.Run(child_path);
}catch(const std::exception& e){auto out=Empty();out.Set("error",JsonValue::String(e.what()));return out;}}
JsonValue InspectDyldSubcacheStage(const std::filesystem::path& parent_report,const std::filesystem::path& child_report,CancellationToken cancel,std::chrono::steady_clock::time_point deadline){
    const auto parent=InspectStage(parent_report,cancel,deadline);if(!parent.Get("complete")->Bool())return parent;return InspectStage(child_report,cancel,deadline,&parent);
}
namespace {
JsonValue InspectSet(const std::filesystem::path& parent_report,const std::vector<std::filesystem::path>& child_reports,CancellationToken cancel,std::chrono::steady_clock::time_point deadline,HeldFiles* held=nullptr){try{
    const auto main=InspectStage(parent_report,cancel,deadline,nullptr,held);Require(main.Get("complete")->Bool(),"Original main cache verification failed.");
    Require(child_reports.size()==main.Get("subcaches")->ArrayItems().size(),"Complete original declared child set required.");
    auto children=JsonValue::ArrayValue();std::set<std::string> paths;std::vector<JsonValue> combined;
    auto append = [&](const JsonValue& cache) {
        const auto& mappings = cache.Get("mappings")->ArrayItems();
        const auto& slides = cache.Get("slide_metadata")->ArrayItems();
        Require(mappings.size() == slides.size(), "Cache mapping/slide count differs.");
        for (std::size_t i = 0; i < mappings.size(); ++i) {
            auto mapping = mappings[i];
            mapping.Set("mapping_flags", *slides[i].Get("flags"));
            mapping.Set("slide_info_size", *slides[i].Get("size"));
            mapping.Set("virtual_path", JsonValue::String(cache.GetString("virtual_path")));
            mapping.Set("source_path", JsonValue::String(cache.GetString("source_path")));
            mapping.Set("source_file_sha256", JsonValue::String(cache.GetString("source_file_sha256")));
            combined.push_back(std::move(mapping));
        }
    };
    append(main);
    for (const auto& report : child_reports) {
        Active(cancel, deadline);
        auto child = InspectStage(report, cancel, deadline, &main, held);
        Require(child.Get("complete")->Bool(), "Original declared child verification failed.");
        Require(paths.insert(child.GetString("virtual_path")).second, "Duplicate original child input.");
        append(child);
        children.ArrayItems().push_back(std::move(child));
    }
    std::sort(combined.begin(),combined.end(),[](const auto& a,const auto& b){return Number(a,"address")<Number(b,"address");});
    for(std::size_t i=1;i<combined.size();++i)Require(Number(combined[i-1],"address")+Number(combined[i-1],"size")<=Number(combined[i],"address"),"Overlapping original combined cache mappings.");
    auto covered=[&](U64 address,U64 size){for(const auto& m:combined){const auto base=Number(m,"address"),length=Number(m,"size");if(address>=base&&address-base<length&&size<=length-(address-base))return true;}return false;};
    for(const auto& image:main.Get("images")->ArrayItems())Require(covered(Number(image,"address"),1),"Original image header address missing from cache mappings.");
    for(const auto& image:main.Get("image_texts")->ArrayItems())Require(covered(Number(image,"address"),Number(image,"size")),"Original image text range missing from cache mappings.");
    for(const char* key:{"dyld_header_address","dyld_entry_address"})if(Number(main,key))Require(covered(Number(main,key),4),"Original dyld address missing from cache mappings.");
    const auto dynamic_offset=Number(main,"dynamic_data_offset"),dynamic_max=Number(main,"dynamic_data_max_size");
    if(dynamic_offset){const auto dynamic_address=Number(main,"shared_region_start")+dynamic_offset;
        for(const auto& m:combined)Require(dynamic_address+dynamic_max<=Number(m,"address")
            ||dynamic_address>=Number(m,"address")+Number(m,"size"),"Dynamic cache reservation overlaps original file mapping.");}
    Active(cancel, deadline);
    auto out = Empty();
    out.Set("complete", JsonValue::Boolean(true));
    out.Set("mapping_layout_verified", JsonValue::Boolean(true));
    out.Set("scope", JsonValue::String("original-complete-dyld-cache-file-set-mapping-layout"));
    out.Set("source_image_sha256", JsonValue::String(main.GetString("source_image_sha256")));
    out.Set("main", main);
    out.Set("children", std::move(children));
    auto maps = JsonValue::ArrayValue();
    maps.ArrayItems() = std::move(combined);
    out.Set("mappings", std::move(maps));
    out.Set("image_bytes_verified", JsonValue::Boolean(false));
    return out;
}catch(const std::exception& e){auto out=Empty();out.Set("mapping_layout_verified",JsonValue::Boolean(false));out.Set("error",JsonValue::String(e.what()));return out;}}

}
JsonValue InspectDyldCacheSetStage(const std::filesystem::path& parent,const std::vector<std::filesystem::path>& children,CancellationToken cancel,std::chrono::steady_clock::time_point deadline){return InspectSet(parent,children,cancel,deadline);}
struct DyldCacheView::Impl {HeldFiles files;JsonValue layout;CancellationToken cancel;std::chrono::steady_clock::time_point deadline;std::mutex mutex;U64 read_bytes=0;};
DyldCacheView::DyldCacheView():impl_(std::make_unique<Impl>()){}
DyldCacheView::~DyldCacheView()=default;
const JsonValue& DyldCacheView::Layout() const {return impl_->layout;}
std::unique_ptr<DyldCacheView> DyldCacheView::Open(const std::filesystem::path& parent,const std::vector<std::filesystem::path>& children,std::string& error,CancellationToken cancel,std::chrono::steady_clock::time_point deadline){
    auto view=std::unique_ptr<DyldCacheView>(new DyldCacheView);view->impl_->cancel=cancel;view->impl_->deadline=deadline;view->impl_->layout=InspectSet(parent,children,cancel,deadline,&view->impl_->files);
    if(!view->impl_->layout.Get("complete")->Bool()){error=view->impl_->layout.GetString("error");return nullptr;}error.clear();return view;
}
bool DyldCacheView::Read(U64 address,U64 size,std::string& bytes,std::string& error){bytes.clear();try{
    std::lock_guard lock(impl_->mutex);Active(impl_->cancel,impl_->deadline);Require(size>0&&size<=16ULL*1024*1024&&address<=UINT64_MAX-size&&size<=128ULL*1024*1024-impl_->read_bytes,"Original cache VM read range/budget invalid.");
    std::string result;result.reserve(static_cast<std::size_t>(size));U64 cursor=address,remaining=size;
    for(const auto& m:impl_->layout.Get("mappings")->ArrayItems()){
        const auto base=Number(m,"address"),length=Number(m,"size");if(cursor<base)break;if(cursor-base>=length)continue;
        Require(Number(m,"initial_protection")&1,"Original cache VM range is not readable.");const auto count=std::min(remaining,length-(cursor-base));auto& lease=impl_->files.at(m.GetString("source_path"));LARGE_INTEGER off{};off.QuadPart=Number(m,"file_offset")+cursor-base;
        Active(impl_->cancel, impl_->deadline);
        Require(SetFilePointerEx(lease->h, off, nullptr, FILE_BEGIN), "Original cache VM seek failed.");
        std::string chunk(static_cast<std::size_t>(count), '\0');
        DWORD got = 0;
        Require(ReadFile(lease->h, chunk.data(), static_cast<DWORD>(count), &got, nullptr) && got == count,
                "Original cache VM read failed.");
        impl_->read_bytes += count;
        result += chunk;
        cursor += count;
        remaining -= count;
        if (!remaining) break;
    }
    Require(!remaining,"Original cache VM range crosses an unmapped gap.");Active(impl_->cancel,impl_->deadline);bytes=std::move(result);error.clear();return true;
}catch(const std::exception& e){error=e.what();bytes.clear();return false;}}

struct DyldCacheMemory::Impl {
    HeldFiles files;
    HANDLE identity_handle = INVALID_HANDLE_VALUE;
    std::uint32_t identity_volume = 0;
    U64 identity_object = 0;
    std::string identity_path;
    std::vector<HANDLE> sections;
    std::vector<void*> views;
    std::vector<DyldCacheMemoryRange> ranges;
    DyldCacheMemoryRange dynamic;
    JsonValue dynamic_data = JsonValue::ObjectValue();
    ~Impl(){if(dynamic.bytes)VirtualFree(dynamic.bytes,0,MEM_RELEASE);for(auto view:views)UnmapViewOfFile(view);for(auto section:sections)CloseHandle(section);}
};
DyldCacheMemory::DyldCacheMemory():impl_(std::make_unique<Impl>()){}
DyldCacheMemory::~DyldCacheMemory()=default;
const std::vector<DyldCacheMemoryRange>& DyldCacheMemory::Ranges() const {return impl_->ranges;}
const DyldCacheMemoryRange& DyldCacheMemory::DynamicRange() const {return impl_->dynamic;}
JsonValue DyldCacheMemory::DynamicData() const {return impl_->dynamic_data;}
int DyldCacheMemory::FilePathByIdentity(std::uint32_t filesystem,std::uint64_t object,std::string& path) const {
    path.clear();
    if(!impl_->identity_volume||filesystem!=impl_->identity_volume||object!=impl_->identity_object)return 2;
    BY_HANDLE_FILE_INFORMATION actual{};
    if(!GetFileInformationByHandle(impl_->identity_handle,&actual)
        ||actual.dwVolumeSerialNumber!=impl_->identity_volume
        ||((U64(actual.nFileIndexHigh)<<32)|actual.nFileIndexLow)!=impl_->identity_object)return 5;
    path=impl_->identity_path;return 0;
}
std::unique_ptr<DyldCacheMemory> DyldCacheView::MapMemory(std::string& error){error.clear();try{
        std::lock_guard lock(impl_->mutex);
        Active(impl_->cancel, impl_->deadline);
        auto memory = std::unique_ptr<DyldCacheMemory>(new DyldCacheMemory);
        std::map<std::string, HANDLE> sections, shared_sections;
        memory->impl_->sections.reserve(impl_->files.size());
        const auto range_count = impl_->layout.Get("mappings")->ArrayItems().size();
        memory->impl_->views.reserve(range_count);
        memory->impl_->ranges.reserve(range_count);
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        Require(system.dwAllocationGranularity > 0, "Windows mapping granularity unavailable.");
        // Mappings that neither allow writes at their maximum protection nor carry
        // slide fixups (written by the loader) use shared read-only
        // views: guest mprotect cannot exceed the maximum, and unlike copy-on-write
        // views they charge no commit, so concurrent runtimes share the cache pages.
        for (const auto& [path, source] : impl_->files) {
            Active(impl_->cancel, impl_->deadline);
            auto lease = std::make_unique<Lease>();
            Require(DuplicateHandle(GetCurrentProcess(), source->h, GetCurrentProcess(), &lease->h, 0, FALSE,
                                    DUPLICATE_SAME_ACCESS),
                    "Original cache lease duplication failed.");
            const auto section = CreateFileMappingW(lease->h, nullptr, PAGE_WRITECOPY, 0, 0, nullptr);
            Require(section, "Original cache private file mapping failed.");
            memory->impl_->sections.push_back(section);
            const auto shared = CreateFileMappingW(lease->h, nullptr, PAGE_READONLY, 0, 0, nullptr);
            Require(shared, "Original cache shared file mapping failed.");
            memory->impl_->sections.push_back(shared);
            memory->impl_->files.emplace(path, std::move(lease));
            sections.emplace(path, section);
            shared_sections.emplace(path, shared);
        }
    for(const auto& m:impl_->layout.Get("mappings")->ArrayItems()){
        Active(impl_->cancel, impl_->deadline);
        const auto offset = Number(m, "file_offset"), size = Number(m, "size"),
                   aligned = offset - offset % system.dwAllocationGranularity, delta = offset - aligned;
        Require(size <= SIZE_MAX - delta, "Original cache private mapping size overflow.");
        const bool writable =
            (static_cast<std::uint32_t>(Number(m, "maximum_protection")) & 2) != 0 || Number(m, "slide_info_size") != 0;
        const auto section = (writable ? sections : shared_sections).at(m.GetString("source_path"));
        void* view = MapViewOfFile(section, writable ? FILE_MAP_COPY : FILE_MAP_READ, static_cast<DWORD>(aligned >> 32),
                                   static_cast<DWORD>(aligned), static_cast<SIZE_T>(size + delta));
        Require(view, "Original cache private view mapping failed.");
        memory->impl_->views.push_back(view);
        const auto initial=static_cast<std::uint32_t>(Number(m,"initial_protection"));
        const auto maximum=static_cast<std::uint32_t>(Number(m,"maximum_protection"));
        const auto flags=Number(m,"mapping_flags");auto protection=initial;
        // Apple SharedCacheRuntime preflight maps CONST_TPRO_DATA as RW;
        // dyld subsequently selects per-process protection. Other CONST_DATA
        // mappings retain their declared initial permissions. No HW TPRO is advertised.
        if(flags&(1ULL<<6)){
            Require((maximum&3)==3&&!(maximum&4)&&!(initial&4),"TPRO cache mapping requires non-executable read/write maximum.");
            protection=3;
        }
        memory->impl_->ranges.push_back({Number(m,"address"),size,protection,static_cast<char*>(view)+delta,initial,maximum,flags});
    }
    const auto& main=*impl_->layout.Get("main");const auto dynamic_offset=Number(main,"dynamic_data_offset");
    if(dynamic_offset){
        constexpr U64 page_size=16384,header_size=80;
        const auto address=Number(main,"shared_region_start")+dynamic_offset;
        auto* bytes=static_cast<char*>(VirtualAlloc(nullptr,page_size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        Require(bytes,"Dynamic cache anonymous allocation failed.");memory->impl_->dynamic={address,page_size,1,bytes,1,1,0};
        // DynamicRegion v3, independently encoded. Baseline function variant
        // bit0 is always true; optional CPU/system variants are not advertised.
        const auto put=[&](std::size_t offset,U64 value,unsigned count){for(unsigned i=0;i<count;++i)bytes[offset+i]=char(value>>(8*i));};
        BY_HANDLE_FILE_INFORMATION info{};
        Require(GetFileInformationByHandle(memory->impl_->files.at(main.GetString("source_path"))->h,&info),"Dynamic cache backing identity unavailable.");
        const U64 inode=(U64(info.nFileIndexHigh)<<32)|info.nFileIndexLow;
        Require(info.dwVolumeSerialNumber&&inode,"Dynamic cache backing identity is empty.");
        std::memcpy(bytes,"dyld_data    v3",15);put(16,info.dwVolumeSerialNumber,8);put(24,inode,8);
        const auto path=main.GetString("virtual_path");Require(path.size()+1<=page_size-header_size,"Dynamic cache virtual path exceeds region.");
        memory->impl_->identity_handle=memory->impl_->files.at(main.GetString("source_path"))->h;
        memory->impl_->identity_volume=info.dwVolumeSerialNumber;memory->impl_->identity_object=inode;memory->impl_->identity_path=path;
        put(36,header_size,4);put(48,1,8);put(64,1,8);std::memcpy(bytes+header_size,path.c_str(),path.size()+1);
        DWORD previous=0;Require(VirtualProtect(bytes,page_size,PAGE_READONLY,&previous),"Dynamic cache readonly publication failed.");
        auto& data=memory->impl_->dynamic_data;data.Set("initialized",JsonValue::Boolean(true));data.Set("runtime_generated",JsonValue::Boolean(true));
        data.Set("address",N(address));data.Set("size",N(page_size));data.Set("reserved_max_size",*main.Get("dynamic_data_max_size"));
        data.Set("version",N(3));data.Set("protection",N(1));data.Set("header_size",N(header_size));
        data.Set("file_identity_source",JsonValue::String("owned-Windows-backing-file-volume-and-index"));
        data.Set("filesystem_id",N(info.dwVolumeSerialNumber));data.Set("file_id",N(inode));
        data.Set("cache_path",JsonValue::String(path));data.Set("cryptex_path_present",JsonValue::Boolean(false));
        data.Set("system_variant_flags",N(1));data.Set("processor_variant_flags",N(1));
        data.Set("variant_policy",JsonValue::String("baseline-default-only"));data.Set("original_file_bytes",JsonValue::Boolean(false));
    }
    Active(impl_->cancel,impl_->deadline);return memory;
}catch(const std::exception& e){error=e.what();return nullptr;}}
JsonValue MapDyldCacheMemoryStage(const std::filesystem::path& parent,const std::vector<std::filesystem::path>& children,CancellationToken cancel,std::chrono::steady_clock::time_point deadline){try{
    std::string error;auto source=DyldCacheView::Open(parent,children,error,cancel,deadline);if(!source)throw std::runtime_error(error);auto memory=source->MapMemory(error);if(!memory)throw std::runtime_error(error);auto ranges=JsonValue::ArrayValue();U64 total=0;
    for (const auto& range : memory->Ranges()) {
        Active(cancel, deadline);
        std::string first, last;
        Require(source->Read(range.address, 16, first, error) &&
                    source->Read(range.address + range.size - 16, 16, last, error),
                "Original mapped range sample acquisition failed.");
        Require(std::string(static_cast<const char*>(range.bytes), 16) == first &&
                    std::string(static_cast<const char*>(range.bytes) + range.size - 16, 16) == last,
                "Original mapped range bytes differ from native source.");
        total += range.size;
        auto m = JsonValue::ObjectValue();
        m.Set("address", N(range.address));
        m.Set("size", N(range.size));
        m.Set("protection", N(range.protection));
        m.Set("initial_protection", N(range.initial_protection));
        m.Set("maximum_protection", N(range.maximum_protection));
        m.Set("mapping_flags", N(range.mapping_flags));
        m.Set("first_16_hex", JsonValue::String(Hex(first)));
        m.Set("last_16_hex", JsonValue::String(Hex(last)));
        ranges.ArrayItems().push_back(std::move(m));
    }
    auto out = Empty();
    out.Set("complete", JsonValue::Boolean(true));
    out.Set("private_memory_mapped", JsonValue::Boolean(true));
    out.Set("source_image_sha256", JsonValue::String(source->Layout().GetString("source_image_sha256")));
    out.Set("scope", JsonValue::String("original-cache-private-file-backed-memory-mapping-range-samples"));
    out.Set("mapped_bytes", N(total));
    out.Set("ranges", std::move(ranges));
    out.Set("dynamic_data", memory->DynamicData());
    out.Set("slide_fixups_verified", JsonValue::Boolean(false));
    out.Set("execution_verified", JsonValue::Boolean(false));
    return out;
}catch(const std::exception& e){auto out=Empty();out.Set("private_memory_mapped",JsonValue::Boolean(false));out.Set("error",JsonValue::String(e.what()));return out;}}

JsonValue DyldCacheView::WalkSlideFixups(const DyldCacheSlideVisitor& visit){try{
    std::lock_guard lock(impl_->mutex);Active(impl_->cancel,impl_->deadline);
    U64 records=0,authenticated=0,tagged=0,pages=0,slide_ranges=0;Sha256Stream digest;
    const auto& main=*impl_->layout.Get("main");const auto base=Number(main,"shared_region_start"),region=Number(main,"shared_region_size");
    const auto read = [&](HANDLE file, U64 offset, U64 size) {
        Active(impl_->cancel, impl_->deadline);
        Require(size && size <= 16ULL * 1024 * 1024, "Slide read exceeds bounded metadata/page size.");
        LARGE_INTEGER position{};
        position.QuadPart = offset;
        Require(SetFilePointerEx(file, position, nullptr, FILE_BEGIN), "Original slide seek failed.");
        std::string bytes(static_cast<std::size_t>(size), '\0');
        DWORD count = 0;
        Require(ReadFile(file, bytes.data(), static_cast<DWORD>(size), &count, nullptr) && count == size,
                "Short original slide read.");
        return bytes;
    };
    const auto walk=[&](const JsonValue& cache){const auto handle=impl_->files.at(cache.GetString("source_path"))->h;const auto& mappings=cache.Get("mappings")->ArrayItems();const auto& slides=cache.Get("slide_metadata")->ArrayItems();
            for (std::size_t i = 0; i < slides.size(); ++i) {
                Active(impl_->cancel, impl_->deadline);
                const auto size = Number(slides[i], "size");
                if (!size) continue;
                ++slide_ranges;
                Require(size >= 24, "Truncated version5 slide header.");
                const auto header = read(handle, Number(slides[i], "file_offset"), size);
                Require(U(header, 0, 4) == 5, "Original slide pointer version is unsupported.");
                const auto page_size = U(header, 4, 4), count = U(header, 8, 4), value_add = U(header, 16, 8);
                const auto& mapping = mappings[i];
                const auto length = Number(mapping, "size"), address = Number(mapping, "address"),
                           file_offset = Number(mapping, "file_offset");
                Require((page_size == 4096 || page_size == 16384) && length % page_size == 0 &&
                            count == length / page_size && count <= (size - 24) / 2 && value_add == base,
                        "Original slide page geometry/base invalid.");
                for (U64 page = 0; page < count; ++page) {
                    Active(impl_->cancel, impl_->deadline);
                    U64 offset = U(header, 24 + page * 2, 2);
                    if (offset == 65535) continue;
                    Require(offset % 8 == 0 && offset <= page_size - 8, "Original slide chain start invalid.");
                    ++pages;
                    const auto bytes = read(handle, file_offset + page * page_size, page_size);
                    for (;;) {
                        Require(offset <= page_size - 8 && records < 32ULL * 1024 * 1024,
                                "Original slide chain escapes page/budget.");
                        DyldCacheSlideFixup fixup;
                        fixup.address = address + page * page_size + offset;
                        fixup.raw = U(bytes, static_cast<std::size_t>(offset), 8);
                        const auto target_offset = fixup.raw & 0x3ffffffffULL;
                        Require(target_offset < region, "Original slide target escapes shared region.");
                        fixup.target = base + target_offset;
                        fixup.authenticated = (fixup.raw >> 63) != 0;
                        if (fixup.authenticated) {
                            fixup.diversity = static_cast<std::uint16_t>(fixup.raw >> 34);
                            fixup.address_diversity = ((fixup.raw >> 50) & 1) != 0;
                            fixup.key_is_data = ((fixup.raw >> 51) & 1) != 0;
                            ++authenticated;
                        } else {
                            Require(((fixup.raw >> 42) & 1023) == 0,
                                    "Reserved original slide pointer bits are nonzero.");
                            fixup.high8 = static_cast<std::uint8_t>(fixup.raw >> 34);
                            if (fixup.high8) ++tagged;
                        }
                        std::string canonical(32, '\0');
                        const U64 fields[] = {fixup.address, fixup.raw, fixup.target,
                                              U64(fixup.diversity) | (U64(fixup.authenticated) << 16) |
                                                  (U64(fixup.address_diversity) << 17) |
                                                  (U64(fixup.key_is_data) << 18) | (U64(fixup.high8) << 24)};
                        for (unsigned field = 0; field < 4; ++field)
                            for (unsigned byte = 0; byte < 8; ++byte)
                                canonical[field * 8 + byte] = char(fields[field] >> (byte * 8));
                        Require(digest.Update(canonical), "Slide record hash failed.");
                        ++records;
                        if (visit) visit(fixup);
                        const auto next = (fixup.raw >> 52) & 2047;
                        if (!next) break;
                        offset += next * 8;
                    }
                }
            }
    };
    walk(main);
    for (const auto& cache : impl_->layout.Get("children")->ArrayItems()) walk(cache);
    Active(impl_->cancel, impl_->deadline);
    const auto hash = digest.Finish();
    Require(bool(hash), "Slide digest finalization failed.");
    auto out = Empty();
    out.Set("complete", JsonValue::Boolean(true));
    out.Set("scope", JsonValue::String("original-cache-version5-slide-chain-decoding"));
    out.Set("source_image_sha256", JsonValue::String(impl_->layout.GetString("source_image_sha256")));
    out.Set("slide_ranges", N(slide_ranges));
    out.Set("pages_with_fixups", N(pages));
    out.Set("decoded_fixups", N(records));
    out.Set("authenticated_fixups", N(authenticated));
    out.Set("tagged_fixups", N(tagged));
    out.Set("canonical_records_sha256", JsonValue::String(*hash));
    out.Set("slide_fixups_applied", JsonValue::Boolean(false));
    out.Set("pointer_authentication_verified", JsonValue::Boolean(false));
    out.Set("execution_verified", JsonValue::Boolean(false));
    return out;
}catch(const std::exception& e){auto out=Empty();out.Set("error",JsonValue::String(e.what()));return out;}}
JsonValue InspectDyldCacheSlideFixupsStage(const std::filesystem::path& parent,
                                           const std::vector<std::filesystem::path>& children, CancellationToken cancel,
                                           std::chrono::steady_clock::time_point deadline) {
    std::string error;
    auto view = DyldCacheView::Open(parent, children, error, cancel, deadline);
    if (view) return view->WalkSlideFixups({});
    auto out = Empty();
    out.Set("error", JsonValue::String(error));
    return out;
}
}
