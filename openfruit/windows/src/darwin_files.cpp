#include "darwin_files.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <array>
#include <limits>
#include <algorithm>
#include <stdexcept>

namespace OpenFruit {
namespace {
int FileError(DWORD error){switch(error){
case ERROR_FILE_NOT_FOUND:case ERROR_PATH_NOT_FOUND:return 2;
case ERROR_ACCESS_DENIED:case ERROR_SHARING_VIOLATION:return 13;
case ERROR_TOO_MANY_OPEN_FILES:return 24;
case ERROR_NOT_ENOUGH_MEMORY:case ERROR_OUTOFMEMORY:return 12;
case ERROR_INVALID_PARAMETER:return 22;
default:return 5;
}}
struct Handle {HANDLE value=INVALID_HANDLE_VALUE;~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
}
struct DarwinFiles::State {
    struct Output {std::int32_t fd=0;DWORD native_type=0;std::uint64_t calls=0,bytes=0;bool closed=false;std::vector<unsigned char> prefix;};
    std::vector<std::shared_ptr<Output>> output_history;
    std::uint64_t output_calls=0,output_bytes=0;
    struct File {Handle handle;std::shared_ptr<Output> output;std::uint64_t size=0,offset=0;std::uint32_t flags=0;
        bool directory=false,input=false;
        std::string virtual_path,resolved_path,sha256;std::filesystem::path source;};
    std::map<std::string,std::filesystem::path> files;
    std::set<std::string> directories;
    std::string working_directory;
    std::map<std::string,std::string> real_paths;
    std::map<std::string,std::string> expected_hashes;
    struct Descriptor {
        std::shared_ptr<File> file;std::uint32_t flags=0;
        File* operator->() const{return file.get();}
        File& operator*() const{return *file;}
    };
    std::map<std::int32_t,Descriptor> descriptors;
    std::shared_ptr<void> lease_owner=std::make_shared<char>();
    struct Opened {std::int32_t fd;std::string path,sha256;std::uint64_t size;};
    std::vector<Opened> open_prefix;
    DarwinClosureOptions options;
    std::uint64_t max_descriptors=4096;
    std::uint64_t opens=0,closes=0,reads=0,bytes=0,seeks=0;
    struct Signature {std::string path,sha256;DarwinFileSignature evidence;std::shared_ptr<DarwinPrivateFileMapping> lease;};
    std::map<std::string,Signature> signatures;
    DarwinFileResult Acquire(const std::string&,std::uint32_t,std::unique_ptr<File>&);
};
DarwinFiles::DarwinFiles(const DarwinClosure& closure,const DarwinClosureOptions& options,const std::string& initial_directory):state_(std::make_unique<State>()){
    state_->files=closure.original_files;state_->real_paths=closure.original_real_paths;state_->options=options;
    state_->directories=closure.original_directories;
    state_->working_directory=NormalizeDarwinVirtualPath(initial_directory);
    if(!state_->directories.contains(state_->working_directory))throw std::invalid_argument("Guest initial working directory is not mounted.");
    for(const auto& image:closure.images)if(!image.shared_cache)state_->expected_hashes.emplace(image.virtual_path,image.metadata.sha256);
}
DarwinFiles::~DarwinFiles()=default;
bool DarwinFiles::Contains(std::int32_t fd) const noexcept{return state_->descriptors.contains(fd);}
void DarwinFiles::SetMaxDescriptors(std::uint64_t max_descriptors) noexcept{state_->max_descriptors=std::min<std::uint64_t>(max_descriptors,4096);}
std::uint64_t DarwinFiles::MaxDescriptors() const noexcept{return state_->max_descriptors;}
std::uint64_t DarwinFiles::TotalReads() const noexcept{return state_->reads;}
std::uint64_t DarwinFiles::TotalOutputCalls() const noexcept{return state_->output_calls;}
DarwinFileResult DarwinFiles::State::Acquire(const std::string& requested,std::uint32_t flags,std::unique_ptr<File>& output){
    // This mount is immutable. Creation, writable descriptors and locking have
    // no implementation here; do not acknowledge them as successful opens.
    if((flags&3)!=0||(flags&(0x200|0x400))!=0)return {0,30};
    // The admitted namespace has no TTY objects; NOCTTY cannot acquire one.
    // Directory flags affect lookup/type, not access to immutable file bytes.
    constexpr std::uint32_t supported=0x01000000U|0x00100000U|0x20000000U|0x00020000U|0x00000100U;
    if((flags&~supported)!=0)return {0,45};
    if(requested.empty())return {0,2};
    const auto lookup=requested.front()=='/'?requested:working_directory+'/'+requested;
    std::string path;try{path=NormalizeDarwinVirtualPath(lookup);}catch(...){return {0,22};}
    // Check traversed components before normalization can discard a symlink or
    // non-directory via "..". Mount indexing rejects directory symlinks.
    std::string traversed="/";
    for(std::size_t begin=1;begin<=lookup.size();){
        const auto end=lookup.find('/',begin);const auto component=lookup.substr(begin,end==std::string::npos?end:end-begin);
        if(!component.empty()&&component!="."){
            if(component==".."){const auto slash=traversed.rfind('/');traversed=slash?traversed.substr(0,slash):"/";}
            else traversed=(traversed=="/"?"/":traversed+'/')+component;
            const auto alias=real_paths.find(traversed);
            if((flags&0x20000000U)&&alias!=real_paths.end()&&alias->second!=traversed)return {0,62};
        }
        if(end==std::string::npos)break;
        if(!directories.contains(traversed))return {0,files.contains(traversed)?20:2};
        begin=end+1;
    }
    const bool directory=directories.contains(path);
    const auto found=files.find(path);if(!directory&&found==files.end())return {0,2};
    if(!directory&&(flags&0x00100000U))return {0,20};
    const auto resolved=real_paths.find(path);
    if(!directory&&(resolved==real_paths.end()))return {0,5};
    if(!directory&&(flags&0x100U)&&resolved->second!=path)return {0,62};
    auto file=std::make_unique<State::File>();file->virtual_path=path;file->directory=directory;
    file->resolved_path=directory?path:resolved->second;
    if(!directory){file->source=found->second;
        file->handle.value=CreateFileW(file->source.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file->handle.value==INVALID_HANDLE_VALUE)return {0,FileError(GetLastError())};
        // Bind the handle to the canonical catalog entry, even if a path was
        // redirected after indexing. A held handle excludes writes and deletion.
        std::array<wchar_t,32768> actual{};
        const auto length=GetFinalPathNameByHandleW(file->handle.value,actual.data(),static_cast<DWORD>(actual.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        auto expected=file->source.wstring();if(!expected.starts_with(L"\\\\?\\"))
            expected=expected.starts_with(L"\\\\")?L"\\\\?\\UNC\\"+expected.substr(2):L"\\\\?\\"+expected;
        if(!length||length>=actual.size()||CompareStringOrdinal(actual.data(),static_cast<int>(length),expected.data(),static_cast<int>(expected.size()),TRUE)!=CSTR_EQUAL)return {0,13};
        BY_HANDLE_FILE_INFORMATION info{};
        if(!GetFileInformationByHandle(file->handle.value,&info))return {0,FileError(GetLastError())};
        if(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)return {0,21};
        file->size=(std::uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
        if(file->size>static_cast<std::uint64_t>(INT64_MAX))return {0,27};
        const auto hash=Sha256FileHandle(file->handle.value,options.cancellation,options.deadline);
        if(!hash)return {0,5};file->sha256=*hash;
        const auto identity=expected_hashes.find(path);
        if(identity!=expected_hashes.end()&&identity->second!=*hash)return {0,5};
    }
    // O_DIRECTORY/NOFOLLOW/NOCTTY control lookup/open, and CLOEXEC belongs
    // to the descriptor. Darwin FMASK retains none of those in F_GETFL.
    // Only read-only access status is implemented by this immutable mount.
    file->flags=flags&3U;
    output=std::move(file);return {};
}
DarwinFileResult DarwinFiles::Open(const std::string& requested,std::uint32_t flags){
    // XNU open1 checks the access mode before falloc, then resolves the vnode.
    if((flags&3U)==3U)return {0,22};
    std::int32_t fd=0;while(state_->descriptors.contains(fd))++fd;
    if(static_cast<std::uint64_t>(fd)>=state_->max_descriptors)return {0,24};
    std::unique_ptr<State::File> file;const auto acquired=state_->Acquire(requested,flags,file);
    if(acquired.error)return acquired;
    if(state_->open_prefix.size()<16)state_->open_prefix.push_back({fd,file->virtual_path,file->sha256,file->size});
    const auto descriptor_flags=(flags&0x01000000U)?1U:0U;
    state_->descriptors.emplace(fd,State::Descriptor{std::move(file),descriptor_flags});++state_->opens;
    return {static_cast<std::uint64_t>(fd),0};
}
DarwinFileResult DarwinFiles::Stat(const std::string& path,DarwinFileMetadata& metadata){
    metadata={};std::unique_ptr<State::File> file;const auto acquired=state_->Acquire(path,0,file);
    if(acquired.error)return acquired;
    if(file->directory)return {0,45};
    return {0,QueryDarwinReadonlyFileMetadata(file->handle.value,metadata)};
}
DarwinFileResult DarwinFiles::Access(const std::string& path,std::uint32_t mode){
    if((mode&~7U)!=0)return {0,22};
    std::unique_ptr<State::File> file;const auto acquired=state_->Acquire(path,0,file);
    if(acquired.error)return acquired;
    if(mode&2)return {0,30};
    // A read-open establishes no execute/search authority. The metadata mode
    // is a SID-only projection, not an access check for this task's real IDs.
    if(mode&1)return {0,45};
    return {0,0};
}
DarwinFileResult DarwinFiles::Fstat(std::int32_t fd,DarwinFileMetadata& metadata) const{
    metadata={};const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    if(found->second->output||found->second->input||found->second->directory)return {0,45};
    return {0,QueryDarwinReadonlyFileMetadata(found->second->handle.value,metadata)};
}
std::shared_ptr<DarwinPrivateFileMapping> DarwinFiles::PrivateMapping(std::int32_t fd,std::uint64_t offset,std::uint64_t length,std::uint64_t page_size,int& error) const{
    error=9;const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {};
    const auto& file=*found->second;if(file.output||file.input){error=9;return {};}if(file.directory){error=19;return {};}
    return DarwinPrivateFileMapping::Capture(file.handle.value,file.size,file.resolved_path,file.sha256,offset,length,page_size,error);
}
DarwinFileResult DarwinFiles::OpenAt(std::int32_t directory,const std::string& path,std::uint32_t flags){
    if(path.empty())return {0,2};
    // Absolute paths ignore dirfd, including an invalid descriptor. AT_FDCWD
    // uses this task's validated virtual launch directory, never Windows CWD.
    if(path.front()=='/'||directory==-2)return Open(path,flags);
    const auto found=state_->descriptors.find(directory);
    if(found==state_->descriptors.end())return {0,9};
    const auto& base=*found->second;if(!base.directory)return {0,20};
    return Open(base.resolved_path+'/'+path,flags);
}
DarwinFileResult DarwinFiles::BindOutput(std::int32_t fd,void* native_handle){
    if(fd<0||static_cast<std::uint64_t>(fd)>=state_->max_descriptors||state_->descriptors.contains(fd))return {0,22};
    if(!native_handle||native_handle==INVALID_HANDLE_VALUE)return {0,9};
    const auto type=GetFileType(native_handle)&~FILE_TYPE_REMOTE;
    if(type!=FILE_TYPE_PIPE&&type!=FILE_TYPE_DISK&&type!=FILE_TYPE_CHAR)return {0,45};
    auto file=std::make_unique<State::File>();file->flags=1;
    if(!DuplicateHandle(GetCurrentProcess(),native_handle,GetCurrentProcess(),&file->handle.value,0,FALSE,DUPLICATE_SAME_ACCESS))return {0,FileError(GetLastError())};
    file->output=std::make_shared<State::Output>();file->output->fd=fd;file->output->native_type=type;file->output->prefix.reserve(4096);
    if(state_->output_history.size()<16)state_->output_history.push_back(file->output);
    state_->descriptors.emplace(fd,State::Descriptor{std::move(file),0});return {};
}
DarwinFileResult DarwinFiles::BindInput(std::int32_t fd,void* native_handle){
    if(fd<0||static_cast<std::uint64_t>(fd)>=state_->max_descriptors||state_->descriptors.contains(fd))return {0,22};
    if(!native_handle||native_handle==INVALID_HANDLE_VALUE)return {0,9};
    if((GetFileType(native_handle)&~FILE_TYPE_REMOTE)!=FILE_TYPE_PIPE)return {0,45};
    DWORD pipe_flags=0;
    if(!GetNamedPipeInfo(native_handle,&pipe_flags,nullptr,nullptr,nullptr))return {0,FileError(GetLastError())};
    if(pipe_flags&PIPE_TYPE_MESSAGE)return {0,45};
    // Peek validates this is a readable byte-stream pipe endpoint. Do not
    // change its blocking mode or consume data during admission.
    DWORD available=0;
    if(!PeekNamedPipe(native_handle,nullptr,0,nullptr,&available,nullptr)){
        const auto error=GetLastError();if(error!=ERROR_BROKEN_PIPE)return {0,error==ERROR_OPERATION_ABORTED?4:error==ERROR_ACCESS_DENIED?9:FileError(error)};
    }
    auto file=std::make_unique<State::File>();file->input=true;
    if(!DuplicateHandle(GetCurrentProcess(),native_handle,GetCurrentProcess(),&file->handle.value,0,FALSE,DUPLICATE_SAME_ACCESS))return {0,FileError(GetLastError())};
    state_->descriptors.emplace(fd,State::Descriptor{std::move(file),0});return {};
}
DarwinFileResult DarwinFiles::Dup(std::int32_t fd){
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    std::int32_t target=0;while(state_->descriptors.contains(target))++target;
    if(static_cast<std::uint64_t>(target)>=state_->max_descriptors)return {0,24};
    state_->descriptors.emplace(target,State::Descriptor{found->second.file,0});return {static_cast<std::uint64_t>(target),0};
}
DarwinFileResult DarwinFiles::Dup2(std::int32_t fd,std::int32_t target){
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end()||target<0||static_cast<std::uint64_t>(target)>=state_->max_descriptors)return {0,9};
    if(fd==target)return {static_cast<std::uint64_t>(target),0};
    State::Descriptor alias{found->second.file,0};
    const auto replaced=state_->descriptors.find(target);
    if(replaced!=state_->descriptors.end()){
        if(replaced->second->output&&replaced->second.file.use_count()==1)replaced->second->output->closed=true;
        replaced->second=std::move(alias);++state_->closes;
    }else state_->descriptors.emplace(target,std::move(alias));
    return {static_cast<std::uint64_t>(target),0};
}
DarwinFileResult DarwinFiles::WriteCapacity(std::int32_t fd,std::uint64_t requested) const{
    // XNU rejects nbyte > INT_MAX before preparing/looking up the fd.
    if(requested>INT32_MAX)return {0,22};
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end()||!found->second->output)return {0,9};
    return {std::min<std::uint64_t>(requested,16ULL*1024*1024),0};
}
DarwinFileResult DarwinFiles::Write(std::int32_t fd,std::span<const char> bytes){
    const auto capacity=WriteCapacity(fd,bytes.size());if(capacity.error)return capacity;
    auto& file=*state_->descriptors.at(fd);auto& output=*file.output;DWORD written=0;
    if(capacity.value&&!WriteFile(file.handle.value,bytes.data(),static_cast<DWORD>(capacity.value),&written,nullptr)){
        const auto error=GetLastError();return {0,error==ERROR_BROKEN_PIPE||error==ERROR_NO_DATA?32:error==ERROR_DISK_FULL?28:error==ERROR_ACCESS_DENIED?9:FileError(error)};
    }
    ++output.calls;output.bytes+=written;++state_->output_calls;state_->output_bytes+=written;
    const auto saved=std::min<std::size_t>(written,4096-output.prefix.size());
    if(saved)output.prefix.insert(output.prefix.end(),bytes.data(),bytes.data()+saved);
    return {written,0};
}
DarwinFileResult DarwinFiles::Close(std::int32_t fd){const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    if(found->second->output&&found->second.file.use_count()==1)found->second->output->closed=true;state_->descriptors.erase(found);++state_->closes;return {};}
DarwinFileResult DarwinFiles::ReadCapacity(std::int32_t fd,std::uint64_t requested,std::optional<std::uint64_t> position) const{
    // XNU read_internal rejects nbyte > INT_MAX before preparing the fd.
    if(requested>INT32_MAX)return {0,22};
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    return ReadCapacityDescription(found->second.file,requested,position);
}
DarwinFileResult DarwinFiles::ReadCapacityDescription(const std::shared_ptr<void>& description,std::uint64_t requested,std::optional<std::uint64_t> position) const{
    const auto& file=*std::static_pointer_cast<State::File>(description);const auto offset=position.value_or(file.offset);
    if(file.output)return {0,9};
    if(file.input){
        if(position)return {0,29};
        if(!requested)return {};
        DWORD available=0;
        if(!PeekNamedPipe(file.handle.value,nullptr,0,nullptr,&available,nullptr)){
            const auto error=GetLastError();if(error==ERROR_BROKEN_PIPE)return {};
            return {0,error==ERROR_OPERATION_ABORTED?4:error==ERROR_ACCESS_DENIED?9:FileError(error)};
        }
        if(!available)return {0,0,true};
        return {std::min<std::uint64_t>({requested,available,16ULL*1024*1024}),0};
    }
    if(file.directory)return {0,21};
    if(offset>INT64_MAX)return {0,22};
    return {offset>=file.size?0:std::min<std::uint64_t>({requested,file.size-offset,16ULL*1024*1024}),0};
}
DarwinFileResult DarwinFiles::Read(std::int32_t fd,std::span<char> bytes,std::optional<std::uint64_t> position){
    ReadLease lease;const auto capacity=AcquireRead(fd,bytes.size(),position,lease);
    if(capacity.error||capacity.pending)return capacity;
    return Read(lease,bytes,position);
}
DarwinFileResult DarwinFiles::AcquireRead(std::int32_t fd,std::uint64_t requested,std::optional<std::uint64_t> position,ReadLease& lease) const{
    lease={};const auto capacity=ReadCapacity(fd,requested,position);
    if(!capacity.error){lease.description_=state_->descriptors.at(fd).file;lease.owner_=state_->lease_owner;}
    return capacity;
}
DarwinFileResult DarwinFiles::ReadCapacity(const ReadLease& lease,std::uint64_t requested,std::optional<std::uint64_t> position) const{
    if(requested>INT32_MAX)return {0,22};
    if(!lease.description_||lease.owner_.lock()!=state_->lease_owner)return {0,9};
    return ReadCapacityDescription(lease.description_,requested,position);
}
DarwinFileResult DarwinFiles::Read(const ReadLease& lease,std::span<char> bytes,std::optional<std::uint64_t> position){
    const auto capacity=ReadCapacity(lease,bytes.size(),position);if(capacity.error||capacity.pending)return capacity;
    auto& file=*std::static_pointer_cast<State::File>(lease.description_);const auto offset=position.value_or(file.offset);
    ++state_->reads;if(!capacity.value)return {};
    const auto count=static_cast<DWORD>(capacity.value);
    LARGE_INTEGER at{};at.QuadPart=static_cast<LONGLONG>(offset);
    if(!file.input&&!SetFilePointerEx(file.handle.value,at,nullptr,FILE_BEGIN))return {0,FileError(GetLastError())};
    DWORD read=0;if(!ReadFile(file.handle.value,bytes.data(),count,&read,nullptr)){
        const auto error=GetLastError();if(file.input&&error==ERROR_BROKEN_PIPE)return {};
        return {0,error==ERROR_OPERATION_ABORTED?4:FileError(error)};
    }
    if(!position&&!file.input)file.offset+=read;state_->bytes+=read;return {read,0};
}
DarwinFileResult DarwinFiles::Seek(std::int32_t fd,std::int64_t offset,std::uint32_t whence){
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    auto& file=*found->second;if(file.output||file.input)return {0,29};if(file.directory)return {0,45};if(whence>2)return {0,22};
    const auto base=whence==0?0:whence==1?file.offset:file.size;
    const auto negative=offset<0;const auto magnitude=negative?std::uint64_t(-(offset+1))+1:std::uint64_t(offset);
    if(negative?magnitude>base:magnitude>std::uint64_t(INT64_MAX)-base)return {0,22};
    file.offset=negative?base-magnitude:base+magnitude;++state_->seeks;return {file.offset,0};
}
DarwinFileResult DarwinFiles::Fcntl(std::int32_t fd,std::uint32_t command,std::uint64_t argument){
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    auto& file=*found->second;
    if(command==1)return {found->second.flags,0};
    if(command==2){found->second.flags=static_cast<std::uint32_t>(argument)&1;return {};}
    if(command==3)return {file.flags,0};
    return {0,45};
}
DarwinFileResult DarwinFiles::SignatureDescriptor(std::int32_t fd) const{
    const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end()||found->second->output||found->second->input)return {0,9};
    if(found->second->directory)return {0,45};return {};
}
DarwinFileResult DarwinFiles::RegisterSignature(std::int32_t fd,std::uint64_t slice,std::uint64_t offset,std::uint64_t size,DarwinFileSignature& output){
    output={};auto result=SignatureDescriptor(fd);if(result.error)return result;
    if(size>40ULL*1024*1024)return {0,7};
    const auto& file=*state_->descriptors.at(fd);
    if(slice>=file.size||size>file.size-slice)return {0,45};
    int error=0;auto lease=DarwinPrivateFileMapping::Capture(file.handle.value,file.size,file.resolved_path,file.sha256,0,file.size,4096,error);
    if(!lease)return {0,error};
    if(slice!=0){
        if(slice%4!=0||slice+4>file.size)return {0,45};
        const auto* raw=static_cast<const unsigned char*>(lease->Bytes())+slice;
        const std::uint32_t magic=(std::uint32_t(raw[0])<<24)|(std::uint32_t(raw[1])<<16)|(std::uint32_t(raw[2])<<8)|std::uint32_t(raw[3]);
        if(magic!=0xfeedface&&magic!=0xfeedfacf&&magic!=0xcffaedfe&&magic!=0xcefaedfe)return {0,45};
    }
    std::string diagnostic;DarwinFileSignature verified;
    error=VerifyDarwinFileSignature(std::string_view(static_cast<const char*>(lease->Bytes())+slice,static_cast<std::size_t>(file.size-slice)),offset,size,verified,diagnostic);
    if(error)return {0,error};
    const auto key=slice==0?file.sha256:(file.sha256+":"+std::to_string(slice));
    if(!state_->signatures.contains(key)&&state_->signatures.size()>=16)return {0,24};
    state_->signatures.insert_or_assign(key,State::Signature{file.resolved_path,file.sha256,verified,lease});
    output=verified;return {verified.end_offset,0};
}
DarwinFileResult DarwinFiles::Path(std::int32_t fd,std::string& path) const{
    path.clear();const auto found=state_->descriptors.find(fd);if(found==state_->descriptors.end())return {0,9};
    if(found->second->output||found->second->input)return {0,45};
    path=found->second->resolved_path;return {};
}
DarwinFileResult DarwinFiles::CheckLibrary(std::int32_t fd,std::uint64_t slice,std::uint32_t status,JsonValue& evidence,std::string& reason) const{
    evidence=JsonValue::ObjectValue();reason.clear();
    evidence.Set("source",JsonValue::String("native-task-and-immutable-source-library-policy"));
    evidence.Set("task_status",JsonValue::Number(std::to_string(status)));
    const bool required=(status&0x3010U)!=0; // enforcement/required/forced validation
    evidence.Set("validation_required",JsonValue::Boolean(required));
    evidence.Set("source_registered",JsonValue::Boolean(false));
    evidence.Set("platform_authority",JsonValue::Boolean(false));
    auto descriptor=SignatureDescriptor(fd);if(descriptor.error)return descriptor;
    const auto& file=*state_->descriptors.at(fd);
    const auto key=slice==0?file.sha256:(file.sha256+":"+std::to_string(slice));
    auto registration=state_->signatures.find(key);
    evidence.Set("path",JsonValue::String(file.resolved_path));evidence.Set("sha256",JsonValue::String(file.sha256));
    if(registration==state_->signatures.end()||!registration->second.lease){
        if(slice){reason="Native library policy does not implement FAT-slice validation.";return {0,45};}
        reason="Original file has no verified native signature registration.";return {0,80};}
    evidence.Set("source_registered",JsonValue::Boolean(true));
    if(required){reason="Required task library validation has no native trust provider.";return {0,45};}
    // This ordinary task has no signed/enforced Apple library-validation domain.
    // Admission still requires its actual immutable verified source registration.
    // Never grant platform status, entitlements or certificate-chain trust here.
    return {};
}
JsonValue DarwinFiles::ToJson() const{
    auto result=JsonValue::ObjectValue(),files=JsonValue::ArrayValue();
    for(const auto& [fd,file]:state_->descriptors){if(file->output||file->input)continue;if(files.ArrayItems().size()>=16)break;
        auto item=JsonValue::ObjectValue();item.Set("fd",JsonValue::Number(std::to_string(fd)));
        item.Set("virtual_path",JsonValue::String(file->virtual_path));item.Set("sha256",JsonValue::String(file->sha256));
        item.Set("kind",JsonValue::String(file->directory?"directory":"original-file"));
        item.Set("descriptor_flags",JsonValue::Number(std::to_string(file.flags)));
        item.Set("offset",JsonValue::Number(std::to_string(file->offset)));item.Set("size",JsonValue::Number(std::to_string(file->size)));
        files.ArrayItems().push_back(std::move(item));}
    result.Set("descriptors",std::move(files));result.Set("readonly_original_files",JsonValue::Boolean(true));
    auto inputs=JsonValue::ArrayValue();for(const auto& [fd,file]:state_->descriptors){if(!file->input)continue;
        auto item=JsonValue::ObjectValue();item.Set("fd",JsonValue::Number(std::to_string(fd)));
        item.Set("source",JsonValue::String("duplicated-native-byte-pipe-exclusive-reader"));
        item.Set("descriptor_flags",JsonValue::Number(std::to_string(file.flags)));inputs.ArrayItems().push_back(std::move(item));}
    result.Set("input_descriptors",std::move(inputs));
    auto registrations=JsonValue::ArrayValue();for(const auto& [key,signature]:state_->signatures){auto item=signature.evidence.ToJson();
        item.Set("path",JsonValue::String(signature.path));item.Set("sha256",JsonValue::String(signature.sha256));
        item.Set("source_lease_retained",JsonValue::Boolean(bool(signature.lease)));registrations.ArrayItems().push_back(std::move(item));}
    result.Set("signature_registrations",std::move(registrations));
    auto outputs=JsonValue::ArrayValue();for(const auto& output:state_->output_history){auto item=JsonValue::ObjectValue();
        item.Set("fd",JsonValue::Number(std::to_string(output->fd)));item.Set("source",JsonValue::String("duplicated-native-output-handle"));
        item.Set("native_type",JsonValue::Number(std::to_string(output->native_type)));item.Set("closed",JsonValue::Boolean(output->closed));
        item.Set("calls",JsonValue::Number(std::to_string(output->calls)));item.Set("bytes",JsonValue::Number(std::to_string(output->bytes)));
        const char digits[]="0123456789abcdef";std::string hex;for(auto byte:output->prefix){hex+=digits[byte>>4];hex+=digits[byte&15];}
        item.Set("prefix_hex",JsonValue::String(hex));outputs.ArrayItems().push_back(std::move(item));}
    result.Set("output_descriptors",std::move(outputs));result.Set("write_calls",JsonValue::Number(std::to_string(state_->output_calls)));
    result.Set("bytes_written",JsonValue::Number(std::to_string(state_->output_bytes)));
    result.Set("directory_catalog_size",JsonValue::Number(std::to_string(state_->directories.size())));
    result.Set("working_directory",JsonValue::String(state_->working_directory));
    auto opened=JsonValue::ArrayValue();for(const auto& file:state_->open_prefix){auto item=JsonValue::ObjectValue();
        item.Set("fd",JsonValue::Number(std::to_string(file.fd)));item.Set("virtual_path",JsonValue::String(file.path));
        item.Set("sha256",JsonValue::String(file.sha256));item.Set("size",JsonValue::Number(std::to_string(file.size)));opened.ArrayItems().push_back(std::move(item));}
    result.Set("open_prefix",std::move(opened));
    for(const auto& [key,value]:std::array<std::pair<const char*,std::uint64_t>,5>{{{"opens",state_->opens},{"closes",state_->closes},{"reads",state_->reads},{"bytes_read",state_->bytes},{"seeks",state_->seeks}}})result.Set(key,JsonValue::Number(std::to_string(value)));
    return result;
}
}
