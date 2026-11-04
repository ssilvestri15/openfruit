#include "dyld_cache.hpp"
#include "content_hash.hpp"
#include "darwin_image.hpp"
#include <optional>
#include <windows.h>
#include <algorithm>
#include <map>
#include <stdexcept>
#include <string_view>
namespace OpenFruit {
namespace {
using U64=std::uint64_t;
void Check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
U64 U(std::string_view s,U64 p,unsigned n){Check(p<=s.size()&&n<=s.size()-p,"Truncated original cache Mach-O field.");U64 v=0;for(unsigned i=0;i<n;++i)v|=U64(static_cast<unsigned char>(s[p+i]))<<(8*i);return v;}
JsonValue N(U64 n){return JsonValue::Number(std::to_string(n));}
U64 Number(const JsonValue& j,const char* k){const auto p=j.Get(k);Check(p&&p->IsNumber(),"Missing native cache VM metadata.");return std::stoull(p->Serialize());}
std::string Hex(std::string_view s){constexpr char digits[]="0123456789abcdef";std::string out;for(unsigned char c:s){out+=digits[c>>4];out+=digits[c&15];}return out;}
std::string Path(std::string_view command, U64 position, U64 minimum) {
    Check(position >= minimum && position < command.size(), "Original cache Mach-O path offset invalid.");
    const auto rest = command.substr(position);
    const auto end = rest.find('\0');
    Check(end != std::string_view::npos && end > 0 && end <= 32768,
          "Original cache Mach-O path not bounded/terminated.");
    const auto path = rest.substr(0, end);
    Check(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), nullptr, 0) >
              0,
          "Original cache Mach-O path UTF8 invalid.");
    return std::string(path);
}
bool Covered(const JsonValue& layout, U64 address, U64 size) {
    if (!size) return true;
    if (address > UINT64_MAX - size) return false;
    U64 cursor = address, remaining = size;
    for (const auto& m : layout.Get("mappings")->ArrayItems()) {
        const auto base = Number(m, "address"), length = Number(m, "size");
        if (cursor < base) break;
        if (cursor - base >= length) continue;
        const auto count = std::min(remaining, length - (cursor - base));
        cursor += count;
        remaining -= count;
        if (!remaining) return true;
    }
    return false;
}
std::string ReadVmBytes(DyldCacheView& view,U64 address,U64 length){std::string bytes,error;if(!view.Read(address,length,bytes,error))throw std::runtime_error(error);return bytes;}
JsonValue Image(DyldCacheView& view,U64 address,const std::string& path,const std::string& expected_uuid){
    const auto h=ReadVmBytes(view,address,32);Check(U(h,0,4)==0xfeedfacf&&U(h,28,4)==0,"Unsupported original cache Mach-O64 header.");
    const auto cpu=U(h,4,4),subtype=U(h,8,4),type=U(h,12,4),count=U(h,16,4),length=U(h,20,4);const auto architecture=view.Layout().Get("main")->GetString("architecture");
    Check(cpu == (architecture.starts_with("arm64") ? 0x100000cULL : 0x1000007ULL),
          "Original image CPU conflicts with shared cache.");
    Check(type == 6 || type == 7, "Unsupported original cache image file type.");
    Check(count > 0 && count <= 65536 && length <= 1024 * 1024 && count <= length / 8 &&
              address <= UINT64_MAX - 32 - length,
          "Original cache Mach-O command budget invalid.");
    const auto table=ReadVmBytes(view,address+32,length);auto commands=JsonValue::ArrayValue(),segments=JsonValue::ArrayValue(),deps=JsonValue::ArrayValue(),rpaths=JsonValue::ArrayValue(),sections=JsonValue::ArrayValue();U64 cursor=0;std::string uuid,install_name;
    for (U64 i = 0; i < count; ++i) {
        const auto kind = U(table, cursor, 4), size = U(table, cursor + 4, 4);
        Check(size >= 8 && size % 8 == 0 && cursor <= table.size() && size <= table.size() - cursor,
              "Original cache Mach-O command bounds invalid.");
        const auto command = std::string_view(table).substr(cursor, size);
        auto record = JsonValue::ObjectValue();
        record.Set("kind", N(kind));
        record.Set("size", N(size));
        record.Set("offset", N(32 + cursor));
        commands.ArrayItems().push_back(std::move(record));
        if(kind==0x1b){Check(size==24&&uuid.empty(),"Original image UUID command invalid/duplicate.");uuid=Hex(command.substr(8,16));Check(uuid!=std::string(32,'0'),"Missing original image UUID.");
        } else if (kind == 0x19) {
            Check(size >= 72 && U(command, 64, 4) <= (size - 72) / 80 && size == 72 + U(command, 64, 4) * 80,
                  "Original image segment section table invalid.");
            const auto vm = U(command, 24, 8), vm_size = U(command, 32, 8), file = U(command, 40, 8),
                       file_size = U(command, 48, 8), maximum = U(command, 56, 4), initial = U(command, 60, 4);
            Check(vm <= UINT64_MAX - vm_size && file <= UINT64_MAX - file_size && file_size <= vm_size &&
                      !(maximum & ~7ULL) && !(initial & ~maximum) && Covered(view.Layout(), vm, vm_size),
                  "Original image segment VM/protection range invalid.");
            auto name = command.substr(8, 16);
            name = name.substr(0, name.find('\0'));
            auto segment = JsonValue::ObjectValue();
            segment.Set("name", JsonValue::String(std::string(name)));
            segment.Set("address", N(vm));
            segment.Set("size", N(vm_size));
            segment.Set("file_offset", N(file));
            segment.Set("file_size", N(file_size));
            segment.Set("maximum_protection", N(maximum));
            segment.Set("initial_protection", N(initial));
            segment.Set("section_count", N(U(command, 64, 4)));
            std::vector<DarwinSection> original_sections;
            std::string section_error;
            const DarwinSegment owner{std::string(name),vm,vm_size,file,file_size,static_cast<std::uint32_t>(maximum),static_cast<std::uint32_t>(initial)};
            if(!InspectDarwinSegmentSections(command,owner,false,original_sections,section_error))throw std::runtime_error(section_error);
            Check(original_sections.size()<=65536-sections.ArrayItems().size(),"Original image section count budget exceeded.");
            for(const auto& section:original_sections){Check(Covered(view.Layout(),section.address,section.size),"Original section VM bytes not covered by cache.");sections.ArrayItems().push_back(section.ToJson());}
            segments.ArrayItems().push_back(std::move(segment));
        } else if (kind == 0xc || kind == 0xd || kind == 0x80000018 || kind == 0x8000001f || kind == 0x20 ||
                   kind == 0x80000023) {
            Check(size >= 24, "Truncated original image dylib command.");
            const auto name = Path(command, U(command, 8, 4), 24);
            if (kind == 0xd) {
                Check(install_name.empty(), "Duplicate original image install name.");
                install_name = name;
            } else {
                auto dep = JsonValue::ObjectValue();
                dep.Set("install_name", JsonValue::String(name));
                dep.Set("weak", JsonValue::Boolean(kind == 0x80000018));
                dep.Set("reexport", JsonValue::Boolean(kind == 0x8000001f));
                dep.Set("lazy", JsonValue::Boolean(kind == 0x20));
                dep.Set("upward", JsonValue::Boolean(kind == 0x80000023));
                deps.ArrayItems().push_back(std::move(dep));
            }
        } else if (kind == 0xf) {
            Check(size >= 16 && install_name.empty(), "Original dynamic linker identity invalid.");
            install_name = Path(command, U(command, 8, 4), 12);
        } else if (kind == 0x8000001c) {
            Check(size >= 16, "Truncated original image rpath.");
            rpaths.ArrayItems().push_back(JsonValue::String(Path(command, U(command, 8, 4), 12)));
        }
        cursor+=size;
    }
    Check(cursor==length&&!segments.ArrayItems().empty()&&!uuid.empty(),"Original image command geometry/identity incomplete.");Check(expected_uuid.empty()||uuid==expected_uuid,"Original image UUID conflicts with cache text record.");
    auto out = JsonValue::ObjectValue();
    out.Set("path", JsonValue::String(path));
    out.Set("address", N(address));
    out.Set("cpu", N(cpu));
    out.Set("subtype", N(subtype));
    out.Set("file_type", N(type));
    out.Set("flags", N(U(h, 24, 4)));
    out.Set("uuid_hex", JsonValue::String(uuid));
    out.Set("install_name", JsonValue::String(install_name));
    out.Set("header_commands_sha256", JsonValue::String(*Sha256(h + table)));
    out.Set("commands", std::move(commands));
    out.Set("segments", std::move(segments));
    out.Set("sections", std::move(sections));
    out.Set("dependencies", std::move(deps));
    out.Set("rpaths", std::move(rpaths));
    out.Set("image_execution_verified", JsonValue::Boolean(false));
    return out;
}
JsonValue Empty() {
    auto out = JsonValue::ObjectValue();
    for (const char* key : {"complete", "image_metadata_verified", "cache_closure_verified", "slide_fixups_verified",
                            "code_signature_verified", "publisher_verified", "provider_registered", "published",
                            "original_process_execution_verified"})
        out.Set(key, JsonValue::Boolean(false));
    return out;
}
}
JsonValue InspectDyldCacheImagesStage(const std::filesystem::path& parent,const std::vector<std::filesystem::path>& children,CancellationToken cancel,std::chrono::steady_clock::time_point deadline){try{
        std::string error;
        auto view = DyldCacheView::Open(parent, children, error, cancel, deadline);
        if (!view) throw std::runtime_error(error);
        const auto& main = *view->Layout().Get("main");
        std::map<std::string, std::string> uuids;
        for (const auto& text : main.Get("image_texts")->ArrayItems())
            uuids.emplace(text.GetString("path"), text.GetString("uuid_hex"));
        auto images = JsonValue::ArrayValue();
        for (const auto& image : main.Get("images")->ArrayItems()) {
            const auto path = image.GetString("path");
            try {
                const auto text = uuids.find(path);
                Check(text != uuids.end(), "Original image text UUID declaration unavailable.");
                images.ArrayItems().push_back(Image(*view, Number(image, "address"), path, text->second));
            } catch (const std::exception& e) {
                throw std::runtime_error(path + ": " + e.what());
            }
        }
    auto dyld=JsonValue::ObjectValue();if(Number(main,"dyld_header_address"))dyld=Image(*view,Number(main,"dyld_header_address"),"","");
    auto out = Empty();
    out.Set("complete", JsonValue::Boolean(true));
    out.Set("image_metadata_verified", JsonValue::Boolean(true));
    out.Set("scope", JsonValue::String("original-cache-vm-macho-headers-load-commands-identities-dependencies"));
    out.Set("source_image_sha256", JsonValue::String(main.GetString("source_image_sha256")));
    out.Set("main_uuid_hex", JsonValue::String(main.GetString("uuid_hex")));
    out.Set("images", std::move(images));
    out.Set("dyld", std::move(dyld));
    return out;
}catch(const std::exception& e){auto out=Empty();out.Set("error",JsonValue::String(e.what()));return out;}}
namespace {
JsonValue Exports(DyldCacheView& source,const std::string& virtual_image){try{
    Check(!virtual_image.empty()&&virtual_image.front()=='/'&&virtual_image.size()<=32768&&virtual_image.find('\0')==std::string::npos,"Original virtual image path required.");
    std::string error;auto* view=&source;const auto& main=*view->Layout().Get("main");std::optional<JsonValue> owner;
    for (const auto& image : main.Get("images")->ArrayItems())
        if (image.GetString("path") == virtual_image) {
            std::string uuid;
            for (const auto& text : main.Get("image_texts")->ArrayItems())
                if (text.GetString("path") == virtual_image) uuid = text.GetString("uuid_hex");
            Check(!uuid.empty(), "Original image text identity unavailable.");
            owner = Image(*view, Number(image, "address"), virtual_image, uuid);
            break;
        }
    if(!owner&&Number(main,"dyld_header_address")){auto linker=Image(*view,Number(main,"dyld_header_address"),"","");if(linker.GetString("install_name")==virtual_image){linker.Set("path",JsonValue::String(virtual_image));owner=std::move(linker);}}
    Check(owner.has_value(),"Original requested image not declared by cache.");std::optional<std::pair<U64,U64>> data;
    for (const auto& record : owner->Get("commands")->ArrayItems()) {
        const auto kind = Number(record, "kind");
        if (kind != 0x80000033 && kind != 0x22 && kind != 0x80000022) continue;
        const auto command =
            ReadVmBytes(*view, Number(*owner, "address") + Number(record, "offset"), Number(record, "size"));
        const auto position = kind == 0x80000033 ? 8 : 40;
        Check(command.size() == (kind == 0x80000033 ? 16 : 48), "Original export command size invalid.");
        const auto off = U(command, position, 4), size = U(command, position + 4, 4);
        if (size) {
            Check(!data, "Ambiguous original image export commands.");
            data = std::pair{off, size};
        }
    }
    const JsonValue* linkedit=nullptr;for(const auto& segment:owner->Get("segments")->ArrayItems())if(segment.GetString("name")=="__LINKEDIT"){Check(!linkedit,"Ambiguous original image LINKEDIT segment.");linkedit=&segment;}
    U64 trie_address = 0;
    std::string bytes;
    if (data) {
        Check(linkedit, "Original image LINKEDIT segment unavailable.");
        const auto file = Number(*linkedit, "file_offset"), size = Number(*linkedit, "file_size"),
                   address = Number(*linkedit, "address");
        Check(data->first >= file && data->first - file <= size && data->second <= size - (data->first - file) &&
                  address <= UINT64_MAX - (data->first - file),
              "Original export data outside LINKEDIT range.");
        trie_address = address + data->first - file;
        bytes = ReadVmBytes(*view, trie_address, data->second);
    }
    std::vector<DarwinDependency> deps;
    for (const auto& dep : owner->Get("dependencies")->ArrayItems())
        deps.push_back({dep.GetString("install_name"), dep.Get("weak")->Bool(), dep.Get("reexport")->Bool(),
                        dep.Get("upward")->Bool(), dep.Get("lazy")->Bool()});
    std::vector<DarwinExport> exports;
    if (!InspectDarwinExportTrie(bytes, deps, exports, error)) throw std::runtime_error(error);
    auto symbols = JsonValue::ArrayValue();
    for (const auto& symbol : exports) {
        auto value = JsonValue::ObjectValue();
        value.Set("symbol", JsonValue::String(symbol.symbol));
        value.Set("flags", N(symbol.flags));
        value.Set("value", N(symbol.value));
        value.Set("auxiliary", N(symbol.auxiliary));
        value.Set("library_ordinal", N(symbol.library_ordinal));
        value.Set("imported_name", JsonValue::String(symbol.imported_name));
        if (symbol.flags & 8)
            value.Set("reexport_install_name", JsonValue::String(deps.at(symbol.library_ordinal - 1).install_name));
        else if ((symbol.flags & 3) == 2)
            value.Set("original_address", N(symbol.value));
        else {
            const auto base = Number(*owner, "address");
            Check(base <= UINT64_MAX - symbol.value && Covered(view->Layout(), base + symbol.value, 1),
                  "Original export value outside cache VM mappings.");
            value.Set("original_address", N(base + symbol.value));
        }
        value.Set("execution_verified", JsonValue::Boolean(false));
        symbols.ArrayItems().push_back(std::move(value));
    }
    auto out = Empty();
    out.Set("complete", JsonValue::Boolean(true));
    out.Set("image_metadata_verified", JsonValue::Boolean(true));
    out.Set("export_metadata_verified", JsonValue::Boolean(true));
    out.Set("scope", JsonValue::String("original-cache-vm-image-linkedit-export-trie"));
    out.Set("source_image_sha256", JsonValue::String(main.GetString("source_image_sha256")));
    out.Set("main_uuid_hex", JsonValue::String(main.GetString("uuid_hex")));
    out.Set("image", std::move(*owner));
    out.Set("export_trie_present", JsonValue::Boolean(data.has_value()));
    out.Set("export_file_offset", N(data ? data->first : 0));
    out.Set("export_vm_address", N(trie_address));
    out.Set("export_data_size", N(data ? data->second : 0));
    out.Set("export_data_sha256", JsonValue::String(*Sha256(bytes)));
    out.Set("exports", std::move(symbols));
    return out;
}catch(const std::exception& e){auto out=Empty();out.Set("export_metadata_verified",JsonValue::Boolean(false));out.Set("error",JsonValue::String(e.what()));return out;}}

}
JsonValue InspectDyldCacheImageExportsStage(const std::string& path, const std::filesystem::path& parent,
                                            const std::vector<std::filesystem::path>& children,
                                            CancellationToken cancel, std::chrono::steady_clock::time_point deadline) {
    std::string error;
    auto view = DyldCacheView::Open(parent, children, error, cancel, deadline);
    if (view) return Exports(*view, path);
    auto out = Empty();
    out.Set("export_metadata_verified", JsonValue::Boolean(false));
    out.Set("error", JsonValue::String(error));
    return out;
}
bool DyldCacheView::ContainsImage(const std::string& path, std::string& error) {
    error.clear();
    try {
        const auto& main = *Layout().Get("main");
        for (const auto& image : main.Get("images")->ArrayItems())
            if (image.GetString("path") == path) return true;
        if (Number(main, "dyld_header_address"))
            return Image(*this, Number(main, "dyld_header_address"), "", "").GetString("install_name") == path;
        return false;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}
bool DyldCacheView::InspectImage(const std::string& path,DarwinImage& metadata,std::string& error){metadata={};error.clear();try{
        const auto r = Exports(*this, path);
        if (!r.Get("complete")->Bool()) throw std::runtime_error(r.GetString("error"));
        const auto& image = *r.Get("image");
        DarwinImage result;
        result.cache_header_address = Number(image, "address");
        result.header_flags = static_cast<std::uint32_t>(Number(image, "flags"));
        result.cpu = static_cast<std::uint32_t>(Number(image, "cpu"));
        result.subtype = static_cast<std::uint32_t>(Number(image, "subtype"));
        result.file_type = static_cast<std::uint32_t>(Number(image, "file_type"));
        result.sha256 = image.GetString("header_commands_sha256");
        result.install_name = image.GetString("install_name");
        for (const auto& item : image.Get("sections")->ArrayItems()) {
            DarwinSection section;
            section.name = item.GetString("name");
            section.segment_name = item.GetString("segment_name");
            section.address = Number(item, "address");
            section.size = Number(item, "size");
            section.file_offset = Number(item, "file_offset");
            section.alignment = static_cast<std::uint32_t>(Number(item, "alignment"));
            section.flags = static_cast<std::uint32_t>(Number(item, "flags"));
            section.relocation_offset = static_cast<std::uint32_t>(Number(item, "relocation_offset"));
            section.relocation_count = static_cast<std::uint32_t>(Number(item, "relocation_count"));
            section.reserved1 = static_cast<std::uint32_t>(Number(item, "reserved1"));
            section.reserved2 = static_cast<std::uint32_t>(Number(item, "reserved2"));
            section.reserved3 = static_cast<std::uint32_t>(Number(item, "reserved3"));
            result.sections.push_back(std::move(section));
        }
    for(const auto& dep:image.Get("dependencies")->ArrayItems())result.dependencies.push_back({dep.GetString("install_name"),dep.Get("weak")->Bool(),dep.Get("reexport")->Bool(),dep.Get("upward")->Bool(),dep.Get("lazy")->Bool()});
    for(const auto& p:image.Get("rpaths")->ArrayItems())result.rpaths.push_back(p.StringValue());
    for (const auto& segment : image.Get("segments")->ArrayItems())
        result.segments.push_back({segment.GetString("name"), Number(segment, "address"), Number(segment, "size"),
                                   Number(segment, "file_offset"), Number(segment, "file_size"),
                                   static_cast<std::uint32_t>(Number(segment, "maximum_protection")),
                                   static_cast<std::uint32_t>(Number(segment, "initial_protection"))});
    for(const auto& command:image.Get("commands")->ArrayItems())if(Number(command,"kind")==5){
        Check(!result.unix_thread.present,"Duplicate original cached Unix thread command.");
        const auto bytes=ReadVmBytes(*this,result.cache_header_address+Number(command,"offset"),Number(command,"size"));
        std::string thread_error;if(!InspectDarwinUnixThread(bytes,result,result.unix_thread,thread_error))throw std::runtime_error(thread_error);
    }
    const auto host=Number(*Layout().Get("main"),"platform");
    for (const auto& command : image.Get("commands")->ArrayItems()) {
        const auto kind = Number(command, "kind");
        if (kind & 0x80000000) result.required_commands.push_back(static_cast<std::uint32_t>(kind));
        if (kind == 0x32) {
            const auto bytes =
                ReadVmBytes(*this, Number(image, "address") + Number(command, "offset"), Number(command, "size"));
            Check(bytes.size() >= 24 && U(bytes, 20, 4) <= (bytes.size() - 24) / 8 &&
                      bytes.size() == 24 + U(bytes, 20, 4) * 8,
                  "Original cached build-version geometry invalid.");
            const auto platform = static_cast<std::uint32_t>(U(bytes, 8, 4));
            if (!result.platform || platform == host) result.platform = platform;
        } else if (kind == 0x24 || kind == 0x25 || kind == 0x2f || kind == 0x30) {
            Check(Number(command, "size") == 16, "Original cached minimum-version command invalid.");
            const std::uint32_t platform = kind == 0x24 ? 1 : kind == 0x25 ? 2 : kind == 0x2f ? 3 : 4;
            if (!result.platform || platform == host) result.platform = platform;
        }
    }
    result.exports_present = r.Get("export_trie_present")->Bool();
    result.exports_file_offset = Number(r, "export_file_offset");
    result.exports_data_size = Number(r, "export_data_size");
    for (const auto& symbol : r.Get("exports")->ArrayItems())
        result.exports.push_back({symbol.GetString("symbol"), symbol.GetString("imported_name"),
                                  Number(symbol, "flags"), Number(symbol, "value"), Number(symbol, "auxiliary"),
                                  static_cast<std::uint32_t>(Number(symbol, "library_ordinal"))});
    metadata = std::move(result);
    return true;
}catch(const std::exception& e){error=e.what();return false;}}

}
