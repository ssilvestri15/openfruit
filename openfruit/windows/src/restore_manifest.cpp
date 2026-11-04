#include "restore_manifest.hpp"
#include "content_hash.hpp"
#include "zip_stage.hpp"
#include "operation_events.hpp"
#include <plist/plist.h>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <unordered_map>
namespace OpenFruit {
namespace {
struct Plist {
    plist_t root = nullptr;
    ~Plist(){if(root)plist_free(root);}
};
struct Iter {
    plist_dict_iter value = nullptr;
    ~Iter(){if(value)plist_dict_free_iter(value);}
};
std::string Text(plist_t node) {
    if(!node||plist_get_node_type(node)!=PLIST_STRING)throw std::runtime_error("Restore metadata string required.");
    std::uint64_t count=0;const auto* bytes=plist_get_string_ptr(node,&count);
    if(!bytes||count>4096)throw std::runtime_error("Restore metadata text budget exceeded.");
    std::string value(bytes,static_cast<std::size_t>(count));
    if(value.find('\0')!=std::string::npos)throw std::runtime_error("Restore metadata contains embedded null.");return value;
}
template<class F> void Dict(plist_t node,F&& consume){
    if(!node||plist_get_node_type(node)!=PLIST_DICT||plist_dict_get_size(node)>4096)throw std::runtime_error("Restore metadata dictionary invalid.");
    Iter iter;plist_dict_new_iter(node,&iter.value);if(!iter.value)throw std::runtime_error("Restore metadata iterator unavailable.");
    for(;;){char* raw=nullptr;plist_t value=nullptr;plist_dict_next_item(node,iter.value,&raw,&value);
        if(!raw)break;std::unique_ptr<char,decltype(&plist_mem_free)> key(raw,plist_mem_free);
        std::string name(raw);if(name.empty()||name.size()>4096)throw std::runtime_error("Restore metadata key invalid.");consume(name,value);
    }
}
JsonValue Scalars(plist_t node){
    auto out=JsonValue::ObjectValue();Dict(node,[&](const std::string& key,plist_t value){
        switch(plist_get_node_type(value)){
        case PLIST_STRING:out.Set(key,JsonValue::String(Text(value)));break;
        case PLIST_BOOLEAN:{uint8_t v=0;plist_get_bool_val(value,&v);out.Set(key,JsonValue::Boolean(v!=0));break;}
        case PLIST_INT:{
            if(plist_int_val_is_negative(value)){int64_t v=0;plist_get_int_val(value,&v);out.Set(key,JsonValue::Number(std::to_string(v)));}
            else{uint64_t v=0;plist_get_uint_val(value,&v);out.Set(key,JsonValue::Number(std::to_string(v)));}break;
        }
        default:break; // Non-scalar fields are outside this metadata projection.
        }
    });return out;
}
void Parse(const ZipMemberResult& bytes,Plist& plist){
    if(!bytes.stream_verified||bytes.body.empty()||bytes.body.size()>64ULL*1024*1024||Sha256(bytes.body)!=bytes.sha256)
        throw std::runtime_error("Verified original restore member bytes required.");
    plist_format_t format{};
    if(plist_from_memory(bytes.body.data(),static_cast<uint32_t>(bytes.body.size()),&plist.root,&format)!=PLIST_ERR_SUCCESS||
        !plist.root||plist_get_node_type(plist.root)!=PLIST_DICT)throw std::runtime_error("Original restore plist parse failed.");
}
std::string Hex(plist_t data){
    if(!data)return {};
    if(plist_get_node_type(data)!=PLIST_DATA)throw std::runtime_error("Restore component digest is not original data.");
    uint64_t count=0;const auto* bytes=plist_get_data_ptr(data,&count);
    if(!bytes||count==0||count>64)throw std::runtime_error("Restore component digest length invalid.");
    constexpr char digits[]="0123456789abcdef";std::string result;result.reserve(static_cast<std::size_t>(count)*2);
    for(uint64_t n=0;n<count;++n){const auto v=static_cast<unsigned char>(bytes[n]);result.push_back(digits[v>>4]);result.push_back(digits[v&15]);}return result;
}
}
RestoreManifestResult ParseRestoreManifests(const ZipInventoryResult& inventory,const ZipMemberResult& restore,const ZipMemberResult& manifest){
    RestoreManifestResult result;
    try{
        if(!inventory.directory_validated)throw std::runtime_error("Validated original restore archive directory required.");
        Plist a,b;Parse(restore,a);Parse(manifest,b);
        const auto version=Text(plist_dict_get_item(a.root,"ProductVersion")), build=Text(plist_dict_get_item(a.root,"ProductBuildVersion"));
        if(version.empty()||build.empty()||version!=Text(plist_dict_get_item(b.root,"ProductVersion"))||build!=Text(plist_dict_get_item(b.root,"ProductBuildVersion")))
            throw std::runtime_error("Original restore versions or builds disagree.");
        std::unordered_map<std::string,const ZipInventoryMember*> members;
        for(const auto& m:inventory.members)if(!members.emplace(m.name,&m).second)throw std::runtime_error("Ambiguous restore archive member.");
        auto require_member=[&](const std::string& path){if(!members.contains(path))throw std::runtime_error("Original restore component missing from archive.");};
        auto filesystems=JsonValue::ObjectValue();
        Dict(plist_dict_get_item(a.root,"SystemRestoreImageFileSystems"),[&](const std::string& path,plist_t value){require_member(path);filesystems.Set(path,JsonValue::String(Text(value)));});
        auto identities=plist_dict_get_item(b.root,"BuildIdentities");
        if(!identities||plist_get_node_type(identities)!=PLIST_ARRAY)throw std::runtime_error("Original restore build identities required.");
        const auto count=plist_array_get_size(identities);if(!count||count>4096)throw std::runtime_error("Restore identity budget exceeded.");
        auto list=JsonValue::ArrayValue();std::uint64_t component_count=0;
        for(uint32_t n=0;n<count;++n){
            const auto identity=plist_array_get_item(identities,n);auto item=JsonValue::ObjectValue();
            item.Set("index",JsonValue::Number(std::to_string(n)));item.Set("identity_metadata",Scalars(identity));
            item.Set("info",Scalars(plist_dict_get_item(identity,"Info")));auto components=JsonValue::ArrayValue();
            Dict(plist_dict_get_item(identity,"Manifest"),[&](const std::string& key,plist_t value){
                if(++component_count>65536)throw std::runtime_error("Restore component budget exceeded.");
                if(!value||plist_get_node_type(value)!=PLIST_DICT)throw std::runtime_error("Restore component dictionary required.");
                const auto info=plist_dict_get_item(value,"Info");auto component=JsonValue::ObjectValue();component.Set("name",JsonValue::String(key));
                component.Set("info",Scalars(info));const auto path_node=plist_dict_get_item(info,"Path");
                const auto path=path_node?Text(path_node):std::string{};
                if(path_node){if(path.empty())throw std::runtime_error("Empty original restore component path.");require_member(path);}
                component.Set("path",JsonValue::String(path));component.Set("directory_member",JsonValue::Boolean(path_node!=nullptr));
                component.Set("digest_hex",JsonValue::String(Hex(plist_dict_get_item(value,"Digest"))));
                component.Set("metadata",Scalars(value));components.ArrayItems().push_back(std::move(component));
            });item.Set("components",std::move(components));list.ArrayItems().push_back(std::move(item));
        }
        result.metadata.Set("product_version",JsonValue::String(version));result.metadata.Set("product_build",JsonValue::String(build));
        result.metadata.Set("restore_sha256",JsonValue::String(restore.sha256));result.metadata.Set("manifest_sha256",JsonValue::String(manifest.sha256));
        result.metadata.Set("filesystems",std::move(filesystems));result.metadata.Set("identities",std::move(list));
        result.metadata.Set("component_count",JsonValue::Number(std::to_string(component_count)));result.metadata_validated=true;
    }catch(const std::exception& e){result={};result.error=e.what();}catch(...){result={};result.error="Original restore metadata inspection failed.";}return result;
}
RestoreManifestResult InspectRestoreArchive(const RangeTransferRequest& options){
    const auto inventory=InspectRemoteZip(options);
    const auto restore=ReadRemoteZipMember(inventory,"Restore.plist",options);
    if(!restore.stream_verified){RestoreManifestResult r;r.error=restore.error;return r;}
    const auto manifest=ReadRemoteZipMember(inventory,"BuildManifest.plist",options);
    if(!manifest.stream_verified){RestoreManifestResult r;r.error=manifest.error;return r;}
    return ParseRestoreManifests(inventory,restore,manifest);
}
JsonValue RestoreManifestResult::ToJson() const{
    auto out=metadata;out.Set("metadata_validated",JsonValue::Boolean(metadata_validated));out.Set("error",JsonValue::String(error));
    out.Set("publisher_verified",JsonValue::Boolean(false));out.Set("compatibility_validated",JsonValue::Boolean(false));
    out.Set("provider_registered",JsonValue::Boolean(false));return out;
}
JsonValue StageRestoreComponents(const RangeTransferRequest& options,const std::string& name,const std::filesystem::path& directory,std::optional<std::size_t> variant){
    auto report=JsonValue::ObjectValue();auto outputs=JsonValue::ArrayValue();bool complete=false;std::string error;
    try{
        const auto inventory=InspectRemoteZip(options);
        const auto restore=ReadRemoteZipMember(inventory,"Restore.plist",options),manifest=ReadRemoteZipMember(inventory,"BuildManifest.plist",options);
        const auto metadata=ParseRestoreManifests(inventory,restore,manifest);if(!metadata.metadata_validated)throw std::runtime_error(metadata.error);
        report.Set("product_version",JsonValue::String(metadata.metadata.GetString("product_version")));
        report.Set("product_build",JsonValue::String(metadata.metadata.GetString("product_build")));
        report.Set("manifest_sha256",JsonValue::String(manifest.sha256));report.Set("directory_sha256",JsonValue::String(inventory.directory_sha256));
        std::unordered_map<std::string,std::pair<std::string,std::string>> seen;std::vector<std::string> paths;std::unordered_map<std::string,std::size_t> uses;
        for(const auto& identity:metadata.metadata.Get("identities")->ArrayItems())for(const auto& component:identity.Get("components")->ArrayItems())if(component.GetString("name")==name){
            const auto path=component.GetString("path"),digest=component.GetString("digest_hex"),method=component.Get("info")->GetString("HashMethod");
            if(path.empty()||digest.empty()||method.empty())throw std::runtime_error("Declared component path/digest/hash method required.");
            const auto value=std::pair{method,digest};auto [item,inserted]=seen.emplace(path,value);
            if(!inserted&&item->second!=value)throw std::runtime_error("Conflicting original component bindings.");if(inserted)paths.push_back(path);++uses[path];
        }
        if(paths.empty())throw std::runtime_error("Original component absent from build identities.");
        report.Set("selected_variant_count",JsonValue::Number(std::to_string(paths.size())));
        std::stable_sort(paths.begin(),paths.end(),[&](const std::string& a,const std::string& b){return uses[a]>uses[b];});
        if(variant){
            if(*variant>=paths.size())throw std::runtime_error("Requested component variant does not exist.");
            paths={paths[*variant]};report.Set("variant_index",JsonValue::Number(std::to_string(*variant)));
        }
        std::error_code ec;if(!directory.is_absolute()||directory!=directory.lexically_normal()||!std::filesystem::create_directory(directory,ec)||ec)throw std::runtime_error("Fresh absolute component quarantine root required.");
        auto request=options;request.url=inventory.source_url;request.expected_total=inventory.archive_bytes;request.expected_etag=inventory.source_etag;
        for(const auto& path:paths){
            const auto& binding=seen.at(path);const auto staged=StageZipMember(inventory,path,[&](std::uint64_t offset,std::uint64_t count)->std::optional<std::string>{
                request.offset=offset;request.bytes=count;auto bytes=HttpTransfer::ReadRange(request);if(!bytes.Succeeded())return {};return std::move(bytes.body);
            },directory/NewOperationId(),binding.first,binding.second,options.cancellation,options.deadline);
            auto item=staged.ToJson();item.Set("member",JsonValue::String(path));item.Set("declared_hash_method",JsonValue::String(binding.first));item.Set("declared_digest",JsonValue::String(binding.second));
            // An AEA member's manifest digest covers its decoded payload: the
            // retained encrypted input is verified against it by the AEA decode stage.
            item.Set("digest_verification",JsonValue::String(staged.digest_matched?"member":staged.encrypted_input_retained?"deferred-to-aea-decode":"failed"));
            outputs.ArrayItems().push_back(std::move(item));
            if(!staged.digest_matched&&!staged.encrypted_input_retained)throw std::runtime_error(staged.error);
        }
        complete=true;
    }catch(const std::exception& e){error=e.what();}catch(...){error="Original component staging failed.";}
    report.Set("complete",JsonValue::Boolean(complete));report.Set("outputs",std::move(outputs));report.Set("error",JsonValue::String(error));
    report.Set("publisher_verified",JsonValue::Boolean(false));report.Set("compatibility_validated",JsonValue::Boolean(false));report.Set("provider_registered",JsonValue::Boolean(false));return report;
}
}
