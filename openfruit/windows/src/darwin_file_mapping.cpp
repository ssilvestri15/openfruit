#include "darwin_file_mapping.hpp"
#include <windows.h>
#include <algorithm>
#include <cstring>
namespace OpenFruit {
namespace {
struct Handle {HANDLE value=nullptr;~Handle(){if(value)CloseHandle(value);}};
struct View {void* value=nullptr;~View(){if(value)UnmapViewOfFile(value);}};
int FileError(DWORD error){return error==ERROR_ACCESS_DENIED?13:error==ERROR_NOT_ENOUGH_MEMORY||error==ERROR_OUTOFMEMORY?12:5;}
}
struct DarwinPrivateFileMapping::State {
    Handle file;void* bytes=nullptr;std::uint64_t size=0,delta=0,source_offset=0,source_bytes=0,file_size=0;
    std::string path,sha256;
    ~State(){if(bytes)VirtualFree(bytes,0,MEM_RELEASE);}
};
DarwinPrivateFileMapping::DarwinPrivateFileMapping():state_(std::make_unique<State>()){}
DarwinPrivateFileMapping::~DarwinPrivateFileMapping()=default;
std::shared_ptr<DarwinPrivateFileMapping> DarwinPrivateFileMapping::Capture(void* handle,std::uint64_t file_size,
    const std::string& path,const std::string& sha256,std::uint64_t offset,std::uint64_t length,std::uint64_t page_size,int& error){
    error=22;
    if((page_size!=4096&&page_size!=16384)||!length||offset>INT64_MAX||length>UINT64_MAX-offset)return {};
    // A future pager must raise the actual beyond-EOF fault. Do not expose
    // entire nonexistent file pages as successful zero-backed mappings.
    const auto mask=page_size-1,delta=offset&mask,source_offset=offset&~mask;
    if(length>UINT64_MAX-delta-mask)return {};
    const auto size=(length+delta+mask)&~mask;
    if(offset>=file_size){error=45;return {};}
    const auto source_bytes=std::min(size,file_size-source_offset);
    // Darwin maps complete pages and zeroes the tail of the last partial
    // source page. The requested length may include that same tail, whether
    // MAP_FIXED is used or not. A complete page beyond EOF still needs a
    // faulting pager and must not become successful anonymous storage.
    if(size-source_bytes>=page_size){error=45;return {};}
    // Explicit snapshot resource limit, not truncation or fabricated success.
    if(size>256ULL*1024*1024){error=12;return {};}
    try{
        auto result=std::shared_ptr<DarwinPrivateFileMapping>(new DarwinPrivateFileMapping);auto& state=*result->state_;
        if(!DuplicateHandle(GetCurrentProcess(),handle,GetCurrentProcess(),&state.file.value,0,FALSE,DUPLICATE_SAME_ACCESS)){error=FileError(GetLastError());return {};}
        LARGE_INTEGER actual{};if(!GetFileSizeEx(state.file.value,&actual)||actual.QuadPart<0||std::uint64_t(actual.QuadPart)!=file_size){error=5;return {};}
        Handle section;section.value=CreateFileMappingW(state.file.value,nullptr,PAGE_READONLY,0,0,nullptr);
        if(!section.value){error=FileError(GetLastError());return {};}
        SYSTEM_INFO system{};GetSystemInfo(&system);const auto granularity=std::uint64_t(system.dwAllocationGranularity);
        if(!granularity||(granularity&(granularity-1))){error=5;return {};}
        const auto view_offset=source_offset&~(granularity-1),view_delta=source_offset-view_offset;
        View view;view.value=MapViewOfFile(section.value,FILE_MAP_READ,DWORD(view_offset>>32),DWORD(view_offset),SIZE_T(view_delta+source_bytes));
        if(!view.value){error=FileError(GetLastError());return {};}
        state.bytes=VirtualAlloc(nullptr,SIZE_T(size),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if(!state.bytes){error=12;return {};}
        std::memcpy(state.bytes,static_cast<const unsigned char*>(view.value)+view_delta,SIZE_T(source_bytes));
        // VirtualAlloc zeroes only the final partial EOF page. Bytes after the
        // requested length but still inside the file/page are actual source.
        state.size=size;state.delta=delta;state.source_offset=source_offset;state.source_bytes=source_bytes;
        state.file_size=file_size;state.path=path;state.sha256=sha256;error=0;return result;
    }catch(const std::bad_alloc&){error=12;return {};}
}
void* DarwinPrivateFileMapping::Bytes()const noexcept{return state_->bytes;}
std::uint64_t DarwinPrivateFileMapping::Size()const noexcept{return state_->size;}
std::uint64_t DarwinPrivateFileMapping::Delta()const noexcept{return state_->delta;}
JsonValue DarwinPrivateFileMapping::ToJson()const{
    auto out=JsonValue::ObjectValue();out.Set("path",JsonValue::String(state_->path));out.Set("sha256",JsonValue::String(state_->sha256));
    out.Set("source",JsonValue::String("held-original-file-private-snapshot"));out.Set("source_lease_retained",JsonValue::Boolean(true));
    for(auto [key,value]: {std::pair{"size",state_->size},{"delta",state_->delta},{"source_offset",state_->source_offset},{"source_bytes",state_->source_bytes},{"file_size",state_->file_size}})out.Set(key,JsonValue::Number(std::to_string(value)));
    return out;
}
}
