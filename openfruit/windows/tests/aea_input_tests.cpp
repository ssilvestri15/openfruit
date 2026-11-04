#include "aea_input.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace fs=std::filesystem;
namespace {
void Require(bool value,const char* error){if(!value)throw std::runtime_error(error);}
void Put(std::string& b,std::uint32_t value){for(unsigned n=0;n<4;++n)b.push_back(static_cast<char>(value>>(8*n)));}
std::string Record(const std::string& key,const std::string& value){std::string b;Put(b,static_cast<std::uint32_t>(5+key.size()+value.size()));b+=key;b+='\0';b+=value;return b;}
std::string Image(const std::string& md){std::string b="AEA1";Put(b,1);Put(b,static_cast<std::uint32_t>(md.size()));return b+md+"owned original encrypted payload";}
void Save(const fs::path& path,const std::string& bytes){std::ofstream(path,std::ios::binary).write(bytes.data(),static_cast<std::streamsize>(bytes.size()));}
std::string OwnedPem(const wchar_t* algorithm){
    NCRYPT_PROV_HANDLE provider=0;NCRYPT_KEY_HANDLE key=0;
    Require(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)==ERROR_SUCCESS,"Owned CNG provider failed");
    Require(NCryptCreatePersistedKey(provider,&key,algorithm,nullptr,0,0)==ERROR_SUCCESS,"Owned ephemeral key failed");
    DWORD policy=NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    Require(NCryptSetProperty(key,NCRYPT_EXPORT_POLICY_PROPERTY,reinterpret_cast<BYTE*>(&policy),sizeof(policy),0)==ERROR_SUCCESS&&NCryptFinalizeKey(key,0)==ERROR_SUCCESS,"Owned key policy failed");
    DWORD count=0;Require(NCryptExportKey(key,0,NCRYPT_PKCS8_PRIVATE_KEY_BLOB,nullptr,nullptr,0,&count,0)==ERROR_SUCCESS,"Owned key export size failed");
    std::string der(count,'\0');Require(NCryptExportKey(key,0,NCRYPT_PKCS8_PRIVATE_KEY_BLOB,nullptr,reinterpret_cast<BYTE*>(der.data()),count,&count,0)==ERROR_SUCCESS,"Owned key export failed");
    DWORD encoded=0;Require(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(der.data()),count,CRYPT_STRING_BASE64,nullptr,&encoded),"Owned PEM size failed");
    std::string pem(encoded,'\0');Require(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(der.data()),count,CRYPT_STRING_BASE64,pem.data(),&encoded),"Owned PEM failed");
    while(!pem.empty()&&pem.back()=='\0')pem.pop_back();SecureZeroMemory(der.data(),der.size());NCryptFreeObject(key);NCryptFreeObject(provider);
    return "-----BEGIN PRIVATE KEY-----\n"+pem+"-----END PRIVATE KEY-----\n";
}

std::string Hex(const std::string& text){std::string bytes;for(std::size_t i=0;i<text.size();i+=2)bytes.push_back(static_cast<char>(std::stoul(text.substr(i,2),nullptr,16)));return bytes;}

}
int main(){try{
    const std::wstring source_url=L"https://wkms-public.apple.com/fcs-keys/owned-key=";
    const std::wstring cdn_url=L"https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/owned-key=";
    Require(ResolveAeaFcsRedirect(source_url,cdn_url)==cdn_url,"Original Apple CDN redirect rejected");
    for(const std::wstring wrong:{L"http://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/owned-key=",L"https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/other=",L"https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/owned-key=?query",L"https://fcs-keys-pub-prod.cdn-apple.com.evil.invalid/fcs-keys/owned-key=",L"https://user@fcs-keys-pub-prod.cdn-apple.com/fcs-keys/owned-key=",L"https://fcs-keys-pub-prod.cdn-apple.com:444/fcs-keys/owned-key=",L"https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/owned-key=#fragment"})Require(!ResolveAeaFcsRedirect(source_url,wrong),"FCS redirect key/origin changed");
    Require(!ResolveAeaFcsRedirect(cdn_url,cdn_url),"Repeated FCS redirects permitted");
    std::string key_error;auto pem=OwnedPem(NCRYPT_ECDSA_P256_ALGORITHM);auto imported=AeaFcsKey::ImportPem(pem,key_error);
    Require(imported&&key_error.empty()&&imported->ToJson().Get("fcs_key_validated")->Bool()&&!imported->ToJson().Get("authentication_verified")->Bool(true),"Native original P256 PKCS8 import failed or approved AEA authentication");imported.reset();
    Require(!AeaFcsKey::ImportPem(OwnedPem(NCRYPT_ECDSA_P384_ALGORITHM),key_error),"Non-P256 FCS key accepted");
    Require(!AeaFcsKey::ImportPem(pem+"unconsumed",key_error)&&!AeaFcsKey::ImportPem("-----BEGIN PRIVATE KEY-----\nbad!\n-----END PRIVATE KEY-----",key_error),"Malformed/trailing FCS PEM accepted");SecureZeroMemory(pem.data(),pem.size());
    // Public CFRG RFC9180 reference key and ciphertext; not an application credential.
    // Source: cfrg/draft-irtf-cfrg-hpke/test-vectors.json; mode0/KEM16/KDF1/AEAD2.
    const std::string reference_pem=R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMX+RXbe8YpxI/nZVh4l+AeKC0+hEX3nyf2XQMaiAgrKhRANCAASrx+SaTGs1Ztd9AwSt3G7Q6YUS/8z1Beao4+slxoUTb4UxSFRIdt52wPLvmc3DoFzPXe14YMfAISOPniBz0jVs
-----END PRIVATE KEY-----
)PEM";
    auto reference=AeaFcsKey::ImportPem(reference_pem,key_error);Require(reference!=nullptr,"Reference HPKE P256 import failed");
    const auto enc=Hex("04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0"),ct=Hex("58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f"),info=Hex("4f6465206f6e2061204772656369616e2055726e"),aad=Hex("436f756e742d30"),expected=Hex("4265617574792069732074727574682c20747275746820626561757479");
    auto plain=reference->OpenHpke(enc,ct,info,aad,key_error);Require(plain&&plain->View()==expected&&key_error.empty(),"RFC9180 P256/SHA256/AES256-GCM reference plaintext mismatch");plain.reset();
    for(const std::size_t offset:{std::size_t(0),ct.size()-1}){auto tampered=ct;tampered[offset]^=1;Require(!reference->OpenHpke(enc,tampered,info,aad,key_error),"HPKE tampered ciphertext/tag accepted");}
    Require(!reference->OpenHpke(enc,ct,info+"changed",aad,key_error)&&!reference->OpenHpke(enc,ct,info,aad+"changed",key_error),"HPKE did not bind info and AAD");
    auto invalid_point=std::string(65,'\0');invalid_point[0]=4;Require(!reference->OpenHpke(invalid_point,ct,info,aad,key_error),"HPKE off-curve encapsulation accepted");
    Require(!reference->OpenHpke(enc.substr(0,64),ct,info,aad,key_error)&&!reference->OpenHpke(enc,ct.substr(0,15),info,aad,key_error)&&!reference->OpenHpke(enc,std::string(65537,'x'),info,aad,key_error),"HPKE encoding/tag/budget bounds ignored");
    auto other=AeaFcsKey::ImportPem(OwnedPem(NCRYPT_ECDSA_P256_ALGORITHM),key_error);Require(other&&!other->OpenHpke(enc,ct,info,aad,key_error),"HPKE wrong recipient key accepted");
    Require(!reference->OpenHpke(enc,Hex("b4e7c90d1dd62cb563694956eb517ab55d5e7d1f6366a0066c04ababaa444dbaf60a30d7bb7d3e91b969762dee"),info,Hex("436f756e742d31"),key_error),"Single-shot HPKE accepted sequence-one ciphertext at sequence zero");
    // Owned independent SHA256-HKDF/HMAC/AES-CTR root vector, generated using
    // Python hashlib/hmac and cryptography AES; not production input injection.
    const auto master=Hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),salt=Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),encrypted_root=Hex("d0d5141c4d855cd57a1570da3ddb3bc7eb716fe3d3c00407a83fd0c755b0d94e48962c7499dfcd73484f50dc493877d6a05e81abd94fdb591fbf859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717");
    auto authenticated_root=AeaRoot::Open(1,"owned auth",master,salt,encrypted_root,1024,key_error);
    Require(authenticated_root&&authenticated_root->ToJson().Get("decoded_file_bytes")->Serialize()=="128"&&authenticated_root->ToJson().Get("aea_root_authenticated")->Bool()&&!authenticated_root->ToJson().Get("authentication_verified")->Bool(true),"Independent native AEA root authentication/decode failed or approved whole-container integrity");
    for(const std::size_t position:{std::size_t(0),std::size_t(32),std::size_t(80)}){auto changed=encrypted_root;changed[position]^=1;Require(!AeaRoot::Open(1,"owned auth",master,salt,changed,1024,key_error),"AEA root/HMAC/cluster-link tamper accepted");}
    Require(!AeaRoot::Open(1,"changed auth",master,salt,encrypted_root,1024,key_error)&&!AeaRoot::Open(1,"owned auth",std::string(32,'x'),salt,encrypted_root,1024,key_error)&&!AeaRoot::Open(1,"owned auth",master,std::string(32,'x'),encrypted_root,1024,key_error),"AEA root auth-data/master/salt binding ignored");
    Require(!AeaRoot::Open(1,"owned auth",master,salt,encrypted_root,1025,key_error)&&!AeaRoot::Open(2,"owned auth",master,salt,encrypted_root,1024,key_error),"AEA source byte-count/profile binding ignored");
    for(const auto& invalid:{Hex("cb40f51318bcc2391e222cd7d40a2186a4f2fc4863d4cca7cf363f71838a9452c8962c7499dfcd73484f50dc493877d6a05e81abd94fdb591fbf859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717"),Hex("c3e25576c3db07686bfd0d6c36fe3fb99c681b6a8a2c4441595cead91d78908848962c7499dfcd73484f50dc493877d6e05e81abd94fdb591fbf859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717"),Hex("c1af6d82c5c862a6342435cf561df795431ae90261504c8d525ea646effe94c348962c7499dfcd73484f50dc493877d6a05e81abdd4fdb591fbf859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717"),Hex("751a33699a76191718ee0b5044ef9497322d05cd83e304af3232dfa984fee8c448962c7499dfcd73484f50dc493877d6a05e81abd94fdb590dbf859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717"),Hex("8d7369ae2d97317be8644832c496b1cff3a47079a2a2e095ad7fe87cc5513c2248962c7499dfcd73484f50dc493877d6a05e81abd94fdb591fbe859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717"),Hex("9b0439fa7d3d1aa361236e8d0b6df5171e0622bcaa91c93933ccbd39a475b10bc8962c34b9dfcd73484f50dc493877d6a05e81abd94fdb591fbf859fef6e4c00274727739717c0fd754c57e38b64edc81717171717171717171717171717171717171717171717171717171717171717")})Require(!AeaRoot::Open(1,"owned auth",master,salt,invalid,1024,key_error),"Authenticated invalid AEA root metadata accepted");
    const auto root=fs::temp_directory_path()/("OPENFRUIT-aea-input-"+NewOperationId());fs::create_directory(root);const auto path=root/"original.aea";
    const auto md=Record("com.apple.wkms.fcs-key-url","https://wkms-public.apple.com/fcs-keys/owned-key-identifier")+Record("original-key","owned metadata value");auto bytes=Image(md);Save(path,bytes);
    auto borrowed=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    Require(borrowed!=INVALID_HANDLE_VALUE,"Borrowed hash fixture open failed");
    LARGE_INTEGER position{};position.QuadPart=7;Require(SetFilePointerEx(borrowed,position,nullptr,FILE_BEGIN),"Borrowed hash fixture seek failed");
    Require(Sha256FileHandle(borrowed)==Sha256(bytes),"Borrowed handle hash did not start from original file beginning");
    position.QuadPart=0;Require(SetFilePointerEx(borrowed,position,&position,FILE_CURRENT)&&position.QuadPart==bytes.size(),"Borrowed hash did not preserve handle ownership or EOF position");
    Require(CloseHandle(borrowed),"Borrowed hashing closed caller handle");
    std::string error;auto session=AeaInput::Open(path,Sha256(bytes).value_or(""),error);Require(session!=nullptr&&error.empty(),"Original AEA metadata inspection failed");
    const auto report=session->ToJson();Require(report.Get("metadata_read")->Bool()&&report.Get("snapshot_bound")->Bool()&&report.Get("fcs_key_url_allowed")->Bool(),"AEA source snapshot or key origin not preserved");
    Require(!report.Get("authentication_verified")->Bool(true)&&!report.Get("decryption_complete")->Bool(true)&&report.Serialize().find("owned metadata value")==std::string::npos&&report.Serialize().find("owned-key-identifier")==std::string::npos,"AEA metadata leaked values or approved authentication");
    Require(session->Metadata("original-key")&&*session->Metadata("original-key")=="owned metadata value","Original metadata bytes changed");
    auto write=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);Require(write==INVALID_HANDLE_VALUE,"AEA session permits source mutation");
    Require(!DeleteFileW(path.c_str()),"AEA session permits source replacement");
    Require(!session->Read(bytes.size(),1,error).has_value()&&!error.empty(),"AEA source read escaped bounds");session.reset();
    Require(!AeaInput::Open(path,std::string(64,'0'),error),"Wrong AEA input snapshot accepted");
    for(const auto& malformed:{Image(Record("duplicate","one")+Record("duplicate","two")),Image(std::string(4,'\0')),Image("short"),Image(Record("com.apple.wkms.fcs-response","{\"enc-request\":\"bad\",\"wrapped-key\":\"bad\"}"))}){
        Save(path,malformed);Require(!AeaInput::Open(path,Sha256(malformed).value_or(""),error)&&!error.empty(),"Malformed AEA metadata accepted");
    }
    const auto untrusted=Image(Record("com.apple.wkms.fcs-key-url","https://example.com/fcs-keys/owned"));Save(path,untrusted);session=AeaInput::Open(path,Sha256(untrusted).value_or(""),error);
    Require(session&&!session->ToJson().Get("fcs_key_url_allowed")->Bool(true),"Untrusted AEA key origin approved");session.reset();
    // Structural acceptance must never imply P256 point validity or cryptographic authentication.
    const std::string structural_enc="BA"+std::string(85,'A')+"=";const std::string wrapped(64,'A');
    const auto shaped=Image(Record("com.apple.wkms.fcs-response","{\"enc-request\":\""+structural_enc+"\",\"wrapped-key\":\""+wrapped+"\"}"));
    Save(path,shaped);session=AeaInput::Open(path,Sha256(shaped).value_or(""),error);
    Require(session&&session->ToJson().Get("fcs_envelope_shape_validated")->Bool()&&!session->ToJson().Get("authentication_verified")->Bool(true),"Structural FCS acceptance was confused with authentication");session.reset();
    Save(path,bytes);CancellationSource source;source.Cancel();Require(!AeaInput::Open(path,Sha256(bytes).value_or(""),error,source.Token()),"AEA source cancellation ignored");
    fs::remove_all(root);return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
