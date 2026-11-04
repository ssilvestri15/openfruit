#include "zip_stage.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <algorithm>
#include <stdexcept>
namespace OpenFruit {
namespace {
struct Output {
    HANDLE value=INVALID_HANDLE_VALUE;bool keep=false;
    ~Output(){if(value!=INVALID_HANDLE_VALUE){if(!keep){FILE_DISPOSITION_INFO dispose{TRUE};SetFileInformationByHandle(value,FileDispositionInfo,&dispose,sizeof(dispose));}CloseHandle(value);}}
};
}
ZipStageResult StageZipMember(const ZipInventoryResult& inventory,const std::string& name,const ZipInventoryRead& reader,
    const std::filesystem::path& directory,const std::string& method,const std::string& digest,CancellationToken cancellation,
    std::chrono::steady_clock::time_point deadline){
    OperationSpan span("runtime.component_quarantine");ZipStageResult result;
    try{
        const auto length=method=="sha2-384"?96:method=="sha2-256"?64:0;
        if(!length||digest.size()!=length||!std::all_of(digest.begin(),digest.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f');}))
            throw std::runtime_error("Supported original component hash method and digest required.");
        if(!directory.is_absolute()||directory!=directory.lexically_normal())throw std::runtime_error("Absolute normalized new quarantine directory required.");
        if(cancellation.Requested()||std::chrono::steady_clock::now()>=deadline)throw std::runtime_error("Component staging interrupted.");
        std::error_code ec;if(!std::filesystem::create_directory(directory,ec)||ec)throw std::runtime_error("Fresh quarantine directory required.");
        const auto path=directory/(NewOperationId()+".quarantined");
        Output output;output.value=CreateFileW(path.c_str(),GENERIC_WRITE|DELETE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
        if(output.value==INVALID_HANDLE_VALUE)throw std::runtime_error("Native quarantine file creation failed.");
        std::uint64_t written=0,last_progress=0,total=0;std::string prefix;for(const auto& m:inventory.members)if(m.name==name)total=m.uncompressed;
        const auto context=span.Context();
        result.stream=StreamZipMember(inventory,name,reader,[&](std::string_view bytes){
            if(prefix.size()<12)prefix.append(bytes.substr(0,12-prefix.size()));
            DWORD count=0;if(!WriteFile(output.value,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr)||count!=bytes.size())return false;
            written+=count;if(context&&(written-last_progress>=16ULL*1024*1024||written==total)){last_progress=written;auto progress=JsonValue::ObjectValue();progress.Set("bytes",JsonValue::Number(std::to_string(written)));progress.Set("total_bytes",JsonValue::Number(std::to_string(total)));progress.Set("basis",JsonValue::String("bytes"));context->Emit("task.progress",std::move(progress));}return true;
        },cancellation,deadline);
        if(!result.stream.stream_verified)throw std::runtime_error(result.stream.error);
        const auto actual=method=="sha2-384"?result.stream.sha384:result.stream.sha256;
        if(actual!=digest){
            // Keep only ZIP-verified original encrypted input for the missing
            // decoder. This is not a component-digest/publisher approval.
            auto word=[&](std::size_t offset){std::uint32_t v=0;for(unsigned n=0;n<4;++n)v|=std::uint32_t(static_cast<unsigned char>(prefix[offset+n]))<<(8*n);return v;};
            const bool aea=prefix.size()==12&&prefix.substr(0,4)=="AEA1"&&(word(4)&0xffffff)==1&&word(8)<=65536&&result.stream.decoded_bytes>=12&&word(8)<=result.stream.decoded_bytes-12;
            if(!aea)throw std::runtime_error("Original component manifest digest mismatch.");
            if(!FlushFileBuffers(output.value))throw std::runtime_error("Native quarantine flush failed.");
            output.keep=true;result.path=path;result.encrypted_input_retained=true;
            result.error="Original AEA member digest differs; decoded component digest scope is unverified.";
        }else{
        if(cancellation.Requested()||std::chrono::steady_clock::now()>=deadline)throw std::runtime_error("Component staging interrupted.");
        if(!FlushFileBuffers(output.value))throw std::runtime_error("Native quarantine flush failed.");
        output.keep=true;result.path=path;result.digest_matched=true;
        }
    }catch(const std::exception& e){result={};result.error=e.what();}catch(...){result={};result.error="Native component quarantine failed.";}
    auto completion=JsonValue::ObjectValue();completion.Set("digest_matched",JsonValue::Boolean(result.digest_matched));completion.Set("publisher_verified",JsonValue::Boolean(false));
    span.Complete(std::move(completion),result.digest_matched);return result;
}
JsonValue ZipStageResult::ToJson() const{
    auto out=stream.ToJson();out.Set("path",JsonValue::String(path.generic_string()));out.Set("digest_matched",JsonValue::Boolean(digest_matched));out.Set("error",JsonValue::String(error));
    out.Set("quarantined",JsonValue::Boolean(digest_matched||encrypted_input_retained));
    out.Set("encrypted_input_retained",JsonValue::Boolean(encrypted_input_retained));
    out.Set("component_digest_scope_verified",JsonValue::Boolean(false));return out;
}
}
