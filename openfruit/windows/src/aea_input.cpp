#include "aea_input.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <algorithm>
#include <fstream>
#include <map>
#include <mutex>
#include <stdexcept>
namespace OpenFruit {
namespace {
std::uint32_t U(const std::string& bytes,std::size_t offset){
    if(offset>bytes.size()||bytes.size()-offset<4)throw std::runtime_error("Truncated original AEA metadata.");
    std::uint32_t out=0;for(unsigned n=0;n<4;++n)out|=std::uint32_t(static_cast<unsigned char>(bytes[offset+n]))<<(8*n);return out;
}
std::string Base64(const std::string& text){
    if(text.empty()||text.size()>4096||text.size()%4)throw std::runtime_error("Original AEA FCS base64 invalid.");
    bool padding=false;unsigned pads=0;
    for(char c:text){if(c=='='){padding=true;if(++pads>2)throw std::runtime_error("Original AEA FCS padding invalid.");}
        else if(padding||!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='+'||c=='/'))throw std::runtime_error("Original AEA FCS alphabet invalid.");}
    DWORD count=0;if(!CryptStringToBinaryA(text.data(),static_cast<DWORD>(text.size()),CRYPT_STRING_BASE64|CRYPT_STRING_STRICT,nullptr,&count,nullptr,nullptr))throw std::runtime_error("Original AEA FCS base64 decode failed.");
    std::string out(count,'\0');if(!CryptStringToBinaryA(text.data(),static_cast<DWORD>(text.size()),CRYPT_STRING_BASE64|CRYPT_STRING_STRICT,reinterpret_cast<BYTE*>(out.data()),&count,nullptr,nullptr))throw std::runtime_error("Original AEA FCS base64 decode failed.");
    out.resize(count);return out;
}
bool PublicKeyUrl(const std::string& text,bool allow_cdn=false){
    if(text.empty()||text.size()>4096||text.find_first_of("\r\n\0",0,3)!=std::string::npos)return false;
    auto url=Win32Process::ToWide(text);URL_COMPONENTS parts{};parts.dwStructSize=sizeof(parts);
    parts.dwHostNameLength=parts.dwUrlPathLength=parts.dwExtraInfoLength=parts.dwUserNameLength=parts.dwPasswordLength=static_cast<DWORD>(-1);
    if(!WinHttpCrackUrl(url.c_str(),static_cast<DWORD>(url.size()),0,&parts)||parts.nScheme!=INTERNET_SCHEME_HTTPS||parts.nPort!=443||parts.dwUserNameLength||parts.dwPasswordLength||parts.dwExtraInfoLength)return false;
    const std::wstring host(parts.lpszHostName,parts.dwHostNameLength),path(parts.lpszUrlPath,parts.dwUrlPathLength);
    if((host!=L"wkms-public.apple.com"&&(!allow_cdn||host!=L"fcs-keys-pub-prod.cdn-apple.com"))||!path.starts_with(L"/fcs-keys/"))return false;
    const auto leaf=path.substr(10);return !leaf.empty()&&leaf.size()<=256&&std::all_of(leaf.begin(),leaf.end(),[](wchar_t c){
        return(c>=L'a'&&c<=L'z')||(c>=L'A'&&c<=L'Z')||(c>=L'0'&&c<=L'9')||c==L'_'||c==L'-'||c==L'+'||c==L'=';
    });
}
JsonValue StageInput(const std::filesystem::path& path){
    std::ifstream file(path,std::ios::binary);if(!file)throw std::runtime_error("Original stage report unavailable.");
    std::string text(1024*1024+1,'\0');file.read(text.data(),static_cast<std::streamsize>(text.size()));text.resize(static_cast<std::size_t>(file.gcount()));if(text.size()>1024*1024)throw std::runtime_error("Stage report byte budget exceeded.");
    if(text.starts_with("\xef\xbb\xbf"))text.erase(0,3);const auto report=JsonValue::Parse(text);
    if(!report||!report->IsObject()||!report->Get("outputs")||!report->Get("outputs")->IsArray()||report->Get("outputs")->ArrayItems().size()!=1)throw std::runtime_error("Exactly one original retained AEA output required.");
    const auto input=report->Get("outputs")->ArrayItems().front();
    if(!input.Get("stream_verified")||!input.Get("stream_verified")->Bool()||!input.Get("encrypted_input_retained")||!input.Get("encrypted_input_retained")->Bool())throw std::runtime_error("ZIP-verified retained encrypted input required.");return input;
}
struct QuarantineOutput {HANDLE value=INVALID_HANDLE_VALUE;bool keep=false;~QuarantineOutput(){if(value!=INVALID_HANDLE_VALUE){if(!keep){FILE_DISPOSITION_INFO dispose{TRUE};SetFileInformationByHandle(value,FileDispositionInfo,&dispose,sizeof(dispose));}CloseHandle(value);}}};

}
std::optional<std::wstring> ResolveAeaFcsRedirect(const std::wstring& source,const std::wstring& location){
    if(!PublicKeyUrl(Win32Process::ToNarrow(source))||!PublicKeyUrl(Win32Process::ToNarrow(location),true))return {};
    URL_COMPONENTS from{},to{};from.dwStructSize=sizeof(from);to.dwStructSize=sizeof(to);
    from.dwUrlPathLength=to.dwUrlPathLength=to.dwHostNameLength=static_cast<DWORD>(-1);
    if(!WinHttpCrackUrl(source.c_str(),static_cast<DWORD>(source.size()),0,&from)||!WinHttpCrackUrl(location.c_str(),static_cast<DWORD>(location.size()),0,&to))return {};
    if(std::wstring(to.lpszHostName,to.dwHostNameLength)!=L"fcs-keys-pub-prod.cdn-apple.com"||
        std::wstring(from.lpszUrlPath,from.dwUrlPathLength)!=std::wstring(to.lpszUrlPath,to.dwUrlPathLength))return {};
    return location;
}
struct AeaInput::Impl {
    HANDLE handle=INVALID_HANDLE_VALUE;
    std::uint64_t size=0;
    std::uint32_t profile=0,auth_bytes=0;
    std::string sha256,header_sha256;
    std::map<std::string,std::string> metadata;
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline;
    bool fcs_shape=false,key_url_allowed=false;
    mutable std::mutex read_mutex;
    ~Impl(){for(auto& [key,value]:metadata)if(!value.empty())SecureZeroMemory(value.data(),value.size());if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
    std::string Read(std::uint64_t offset,std::uint64_t count) const {
        const auto context=CurrentOperationContext();
        if(cancellation.Requested()||(context&&context->CancellationRequested()))throw std::runtime_error("AEA input cancelled.");
        if(std::chrono::steady_clock::now()>=deadline||(context&&context->DeadlineExceeded()))throw std::runtime_error("AEA input deadline exceeded.");
        if(offset>size||count>size-offset||count>16ULL*1024*1024)throw std::runtime_error("AEA input read bounds exceeded.");
        std::lock_guard lock(read_mutex);
        LARGE_INTEGER position{};position.QuadPart=offset;if(!SetFilePointerEx(handle,position,nullptr,FILE_BEGIN))throw std::runtime_error("AEA original input seek failed.");
        std::string bytes(static_cast<std::size_t>(count),'\0');DWORD got=0;
        if(count&&(!ReadFile(handle,bytes.data(),static_cast<DWORD>(count),&got,nullptr)||got!=count))throw std::runtime_error("AEA original input read failed.");return bytes;
    }
};
AeaInput::AeaInput(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
AeaInput::~AeaInput()=default;
std::unique_ptr<AeaInput> AeaInput::Open(const std::filesystem::path& path,const std::string& expected,std::string& error,CancellationToken cancellation,std::chrono::steady_clock::time_point deadline){
    error.clear();try{
        if(expected.size()!=64||!std::all_of(expected.begin(),expected.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f');}))throw std::runtime_error("Original AEA SHA256 binding required.");
        auto state=std::make_unique<Impl>();state->cancellation=cancellation;state->deadline=deadline;
        state->handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(state->handle==INVALID_HANDLE_VALUE)throw std::runtime_error("Stable original AEA input unavailable.");
        LARGE_INTEGER size{};if(!GetFileSizeEx(state->handle,&size)||size.QuadPart<12||size.QuadPart>128LL*1024*1024*1024)throw std::runtime_error("Original AEA size invalid.");state->size=size.QuadPart;
        state->Read(0,0);const auto hash=Sha256FileHandle(state->handle,cancellation,deadline);state->Read(0,0);
        if(!hash||*hash!=expected)throw std::runtime_error("Original AEA snapshot SHA256 mismatch.");state->sha256=*hash;
        const auto header=state->Read(0,12);if(header.substr(0,4)!="AEA1"||U(header,4)!=1)throw std::runtime_error("Unsupported original AEA profile or strength.");
        state->profile=1;state->auth_bytes=U(header,8);if(state->auth_bytes>65536||state->auth_bytes>state->size-12)throw std::runtime_error("Original AEA auth-data bounds invalid.");
        const auto auth=state->Read(12,state->auth_bytes);const auto header_hash=Sha256(header+auth);if(!header_hash)throw std::runtime_error("AEA header hashing failed.");state->header_sha256=*header_hash;
        std::size_t offset=0;while(offset<auth.size()){
            const auto count=U(auth,offset);if(count<6||count>auth.size()-offset)throw std::runtime_error("Original AEA metadata record bounds invalid.");
            const auto record=auth.substr(offset+4,count-4);const auto separator=record.find('\0');
            if(separator==std::string::npos||!separator||separator>256)throw std::runtime_error("Original AEA metadata key invalid.");
            const auto key=record.substr(0,separator);if(!std::all_of(key.begin(),key.end(),[](unsigned char c){return c>=33&&c<=126;}))throw std::runtime_error("Original AEA metadata key encoding invalid.");
            if(state->metadata.size()>=256||!state->metadata.emplace(key,record.substr(separator+1)).second)throw std::runtime_error("Duplicate or excessive AEA metadata.");offset+=count;
        }
        const auto fcs=state->metadata.find("com.apple.wkms.fcs-response");if(fcs!=state->metadata.end()){
            auto json = JsonValue::Parse(fcs->second);
            if (!json || !json->IsObject() || json->ObjectItems().size() != 2 || !json->Get("enc-request") ||
                !json->Get("enc-request")->IsString() || !json->Get("wrapped-key") ||
                !json->Get("wrapped-key")->IsString())
                throw std::runtime_error("Original AEA FCS envelope shape invalid.");
            auto enc=Base64(json->GetString("enc-request")),wrapped=Base64(json->GetString("wrapped-key"));
            if(enc.size()!=65||static_cast<unsigned char>(enc[0])!=4||wrapped.size()!=48)throw std::runtime_error("Unsupported original AEA FCS envelope sizes.");state->fcs_shape=true;
            SecureZeroMemory(enc.data(),enc.size());SecureZeroMemory(wrapped.data(),wrapped.size());
        }
        const auto key=state->metadata.find("com.apple.wkms.fcs-key-url");state->key_url_allowed=key!=state->metadata.end()&&PublicKeyUrl(key->second);
        return std::unique_ptr<AeaInput>(new AeaInput(std::move(state)));
    }catch(const std::exception& e){error=e.what();}catch(...){error="Original AEA inspection failed.";}return {};
}
std::optional<std::string> AeaInput::Read(std::uint64_t offset,std::uint64_t count,std::string& error) const{error.clear();try{return impl_->Read(offset,count);}catch(const std::exception& e){error=e.what();return {};}}
const std::string* AeaInput::Metadata(const std::string& key) const{auto item=impl_->metadata.find(key);return item==impl_->metadata.end()?nullptr:&item->second;}
std::unique_ptr<AeaFcsKey> AeaInput::AcquireFcsKey(std::string& error) const {
    error.clear();try{
        impl_->Read(0,0);if(!impl_->key_url_allowed||!impl_->fcs_shape)throw std::runtime_error("Original allowed FCS key URL and envelope required.");
        JsonPostRequest request;request.url=Win32Process::ToWide(*Metadata("com.apple.wkms.fcs-key-url"));request.max_bytes=16*1024;
        request.cancellation=impl_->cancellation;request.deadline=impl_->deadline;
        auto fetched=HttpTransfer::GetBytes(request);impl_->Read(0,0);
        if(!fetched.Succeeded()&&!fetched.redirect_url.empty()){
            const auto destination=ResolveAeaFcsRedirect(request.url,fetched.redirect_url);
            if(!destination)throw std::runtime_error("Original FCS redirect violates Apple origin or key-path policy.");
            request.url=*destination;auto redirected=HttpTransfer::GetBytes(request);impl_->Read(0,0);
            if(!redirected.Succeeded())throw std::runtime_error("Native FCS redirected key retrieval failed (HTTP "+std::to_string(redirected.http_status)+", status "+std::to_string(static_cast<int>(redirected.status))+").");
            return AeaFcsKey::ImportPem(redirected.body,error);
        }
        if(!fetched.Succeeded())throw std::runtime_error("Native FCS key retrieval failed (HTTP "+std::to_string(fetched.http_status)+", status "+std::to_string(static_cast<int>(fetched.status))+").");
        return AeaFcsKey::ImportPem(fetched.body,error);
    }catch(const std::exception& e){error=e.what();}return {};
}
std::unique_ptr<SecretBytes> AeaInput::UnwrapFcsKey(std::string& error) const {
    error.clear();try{
        auto key=AcquireFcsKey(error);if(!key)return {};
        const auto envelope=JsonValue::Parse(*Metadata("com.apple.wkms.fcs-response"));
        auto enc=Base64(envelope->GetString("enc-request")),wrapped=Base64(envelope->GetString("wrapped-key"));
        auto unwrapped=key->OpenHpke(enc,wrapped,{},{},error);
        SecureZeroMemory(enc.data(),enc.size());SecureZeroMemory(wrapped.data(),wrapped.size());impl_->Read(0,0);
        if(unwrapped&&unwrapped->View().size()!=32)throw std::runtime_error("Original FCS unwrapped key size invalid.");return unwrapped;
    }catch(const std::exception& e){error=e.what();}return {};
}
std::unique_ptr<AeaRoot> AeaInput::InspectRoot(std::string& error) const {
    error.clear();try{
        auto master=UnwrapFcsKey(error);if(!master)return {};
        const auto auth=impl_->Read(12,impl_->auth_bytes),salt=impl_->Read(12+impl_->auth_bytes,32),encrypted=impl_->Read(44+impl_->auth_bytes,112);
        return AeaRoot::Open(impl_->profile,auth,master->View(),salt,encrypted,impl_->size,error);
    }catch(const std::exception& e){error=e.what();}return {};
}
AeaDecodeResult AeaInput::Decode(const AeaSink& sink,std::string& error) const {
    auto root=InspectRoot(error);if(!root){AeaDecodeResult fail;fail.error=error;return fail;}
    auto result=root->Decode([&](std::uint64_t offset,std::uint64_t bytes){return Read(offset,bytes,error);},sink,impl_->cancellation,impl_->deadline);error=result.error;return result;
}
JsonValue AeaInput::ToJson() const{
    auto out=JsonValue::ObjectValue();out.Set("metadata_read",JsonValue::Boolean(true));out.Set("snapshot_bound",JsonValue::Boolean(true));
    out.Set("bytes",JsonValue::Number(std::to_string(impl_->size)));out.Set("profile",JsonValue::Number(std::to_string(impl_->profile)));out.Set("auth_data_bytes",JsonValue::Number(std::to_string(impl_->auth_bytes)));
    out.Set("sha256",JsonValue::String(impl_->sha256));out.Set("header_sha256",JsonValue::String(impl_->header_sha256));
    out.Set("fcs_envelope_shape_validated",JsonValue::Boolean(impl_->fcs_shape));out.Set("fcs_key_url_allowed",JsonValue::Boolean(impl_->key_url_allowed));
    out.Set("authentication_verified",JsonValue::Boolean(false));out.Set("decryption_complete",JsonValue::Boolean(false));out.Set("component_digest_verified",JsonValue::Boolean(false));out.Set("publisher_verified",JsonValue::Boolean(false));
    auto entries = JsonValue::ArrayValue();
    for (const auto& [key, value] : impl_->metadata) {
        auto item = JsonValue::ObjectValue();
        item.Set("key", JsonValue::String(key));
        item.Set("bytes", JsonValue::Number(std::to_string(value.size())));
        entries.ArrayItems().push_back(std::move(item));
    }
    out.Set("metadata", std::move(entries));
    return out;
}
JsonValue InspectAeaStage(const std::filesystem::path& path,bool acquire_key,bool unwrap_key,bool inspect_root){
    auto out=JsonValue::ObjectValue();try{
        const auto input=StageInput(path);
        std::string error;auto session=AeaInput::Open(std::filesystem::path(Win32Process::ToWide(input.GetString("path"))),input.GetString("sha256"),error,{},std::chrono::steady_clock::now()+std::chrono::minutes(2));
        if(!session)throw std::runtime_error(error);out=session->ToJson();
        if(inspect_root){auto root=session->InspectRoot(error);if(!root)throw std::runtime_error(error);
            const auto result=root->ToJson();for(const auto& [key,value]:result.ObjectItems())out.Set(key,value);
            out.Set("fcs_key_validated",JsonValue::Boolean(true));out.Set("fcs_key_ephemeral",JsonValue::Boolean(true));out.Set("fcs_key_unwrapped",JsonValue::Boolean(true));out.Set("fcs_envelope_authenticated",JsonValue::Boolean(true));
        }else if(unwrap_key){auto secret=session->UnwrapFcsKey(error);if(!secret)throw std::runtime_error(error);
            out.Set("fcs_key_validated", JsonValue::Boolean(true));
            out.Set("fcs_key_ephemeral", JsonValue::Boolean(true));
            out.Set("fcs_key_unwrapped", JsonValue::Boolean(true));
            out.Set("fcs_envelope_authenticated", JsonValue::Boolean(true));
            out.Set("fcs_unwrapped_key_bytes", JsonValue::Number(std::to_string(secret->View().size())));
        }else if(acquire_key){auto key=session->AcquireFcsKey(error);if(!key)throw std::runtime_error(error);
            out.Set("fcs_key_validated",JsonValue::Boolean(true));out.Set("fcs_key_ephemeral",JsonValue::Boolean(true));}
    } catch (const std::exception& e) {
        out = JsonValue::ObjectValue();
        out.Set("metadata_read", JsonValue::Boolean(false));
        out.Set("error", JsonValue::String(e.what()));
        out.Set("fcs_key_validated", JsonValue::Boolean(false));
        out.Set("fcs_key_unwrapped", JsonValue::Boolean(false));
        out.Set("aea_root_authenticated", JsonValue::Boolean(false));
    }
    return out;
}
JsonValue DecodeAeaStage(const std::filesystem::path& report,const std::filesystem::path& directory){
    auto out=JsonValue::ObjectValue();out.Set("complete",JsonValue::Boolean(false));out.Set("publisher_verified",JsonValue::Boolean(false));out.Set("provider_registered",JsonValue::Boolean(false));
    try{
        const auto input=StageInput(report);const auto method=input.GetString("declared_hash_method"),digest=input.GetString("declared_digest");const auto length=method=="sha2-384"?96:method=="sha2-256"?64:0;
        if(!length||digest.size()!=length||!std::all_of(digest.begin(),digest.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f');}))throw std::runtime_error("Original component digest and supported method required.");
        std::string error;auto session=AeaInput::Open(std::filesystem::path(Win32Process::ToWide(input.GetString("path"))),input.GetString("sha256"),error,{},std::chrono::steady_clock::now()+std::chrono::hours(2));if(!session)throw std::runtime_error(error);
        if(!directory.is_absolute()||directory!=directory.lexically_normal())throw std::runtime_error("Absolute normalized fresh AEA quarantine directory required.");
        std::error_code ec;if(!std::filesystem::create_directory(directory,ec)||ec)throw std::runtime_error("Fresh AEA quarantine directory required.");
        const auto path = directory / (NewOperationId() + ".decoded-quarantined");
        QuarantineOutput file;
        file.value = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file.value == INVALID_HANDLE_VALUE) throw std::runtime_error("Native AEA quarantine output unavailable.");
        const auto decoded=session->Decode([&](std::string_view bytes){DWORD written=0;return WriteFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)&&written==bytes.size();},error);
        if(!decoded.authenticated)throw std::runtime_error(decoded.error);if(!FlushFileBuffers(file.value))throw std::runtime_error("Native AEA quarantine output flush failed.");
        const bool matched = (method == "sha2-384" ? decoded.sha384 : decoded.sha256) == digest;
        out = decoded.ToJson();
        out.Set("complete", JsonValue::Boolean(matched));
        out.Set("component_digest_verified", JsonValue::Boolean(matched));
        out.Set("component_digest_scope_verified", JsonValue::Boolean(matched));
        out.Set("digest_scope", JsonValue::String(matched ? "decoded-aea-payload" : "unresolved"));
        out.Set("declared_hash_method", JsonValue::String(method));
        out.Set("declared_digest", JsonValue::String(digest));
        out.Set("source_sha256", JsonValue::String(input.GetString("sha256")));
        out.Set("member", JsonValue::String(input.GetString("member")));
        out.Set("path", JsonValue::String(path.generic_string()));
        out.Set("quarantined", JsonValue::Boolean(true));
        out.Set("provider_registered", JsonValue::Boolean(false));
        out.Set("published", JsonValue::Boolean(false));
        if(!matched)out.Set("error",JsonValue::String("Original decoded AEA component digest mismatch; authenticated output retained in quarantine."));file.keep=true;
    }catch(const std::exception& e){out.Set("error",JsonValue::String(e.what()));}return out;
}

}
