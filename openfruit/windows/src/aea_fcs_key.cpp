#include "aea_fcs_key.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
namespace OpenFruit {
namespace {
void Check(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Secret { std::string bytes; ~Secret(){if(!bytes.empty())SecureZeroMemory(bytes.data(),bytes.size());} };
struct Decoded { void* value=nullptr; DWORD bytes=0; ~Decoded(){if(value){SecureZeroMemory(value,bytes);LocalFree(value);}} };
bool White(char c){return c==' '||c=='\r'||c=='\n'||c=='\t';}
void DerEnvelope(const std::string& bytes){
    Check(bytes.size()>=2&&static_cast<unsigned char>(bytes[0])==0x30,"FCS PKCS8 DER envelope invalid.");
    const auto first=static_cast<unsigned char>(bytes[1]);std::size_t count=2,length=first;
    if(first&0x80){const auto n=first&0x7f;Check(n&&n<=4&&bytes.size()>=2+n&&bytes[2]!=0,"FCS PKCS8 DER length invalid.");
        length=0;for(unsigned i=0;i<n;++i)length=(length<<8)|static_cast<unsigned char>(bytes[2+i]);count+=n;
        Check(length>=128,"FCS PKCS8 DER length is noncanonical.");}
    Check(length==bytes.size()-count,"FCS PKCS8 DER trailing or truncated bytes.");
}
}
struct AeaFcsKey::Impl {
    NCRYPT_PROV_HANDLE provider=0;NCRYPT_KEY_HANDLE key=0;
    BCRYPT_ALG_HANDLE ecdh=nullptr;BCRYPT_KEY_HANDLE agreement_key=nullptr;std::string public_encoding;
    ~Impl(){if(agreement_key)BCryptDestroyKey(agreement_key);if(ecdh)BCryptCloseAlgorithmProvider(ecdh,0);if(key)NCryptFreeObject(key);if(provider)NCryptFreeObject(provider);}
};
AeaFcsKey::AeaFcsKey(std::unique_ptr<Impl> value):impl_(std::move(value)){}
AeaFcsKey::~AeaFcsKey()=default;
std::unique_ptr<AeaFcsKey> AeaFcsKey::ImportPem(std::string_view pem,std::string& error){
    error.clear();try{
        Check(!pem.empty()&&pem.size()<=16*1024,"FCS PEM byte budget exceeded.");
        while(!pem.empty()&&White(pem.front()))pem.remove_prefix(1);while(!pem.empty()&&White(pem.back()))pem.remove_suffix(1);
        constexpr std::string_view begin="-----BEGIN PRIVATE KEY-----",end="-----END PRIVATE KEY-----";
        Check(pem.starts_with(begin)&&pem.ends_with(end),"FCS unencrypted PKCS8 PEM required.");
        pem.remove_prefix(begin.size());pem.remove_suffix(end.size());Secret base64;
        for(char c:pem)if(!White(c))base64.bytes+=c;
        Check(!base64.bytes.empty()&&base64.bytes.size()%4==0,"FCS PKCS8 base64 length invalid.");
        bool padding=false;unsigned pads=0;for(char c:base64.bytes){if(c=='='){padding=true;Check(++pads<=2,"FCS PKCS8 base64 padding invalid.");}
            else Check(!padding&&((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'),"FCS PKCS8 base64 alphabet invalid.");}
        DWORD count=0;Check(CryptStringToBinaryA(base64.bytes.data(),static_cast<DWORD>(base64.bytes.size()),CRYPT_STRING_BASE64|CRYPT_STRING_STRICT,nullptr,&count,nullptr,nullptr),"FCS PKCS8 base64 decode failed.");
        Secret der;der.bytes.resize(count);Check(CryptStringToBinaryA(base64.bytes.data(),static_cast<DWORD>(base64.bytes.size()),CRYPT_STRING_BASE64|CRYPT_STRING_STRICT,reinterpret_cast<BYTE*>(der.bytes.data()),&count,nullptr,nullptr),"FCS PKCS8 base64 decode failed.");der.bytes.resize(count);DerEnvelope(der.bytes);
        Decoded info;Check(CryptDecodeObjectEx(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,PKCS_PRIVATE_KEY_INFO,reinterpret_cast<const BYTE*>(der.bytes.data()),static_cast<DWORD>(der.bytes.size()),CRYPT_DECODE_ALLOC_FLAG,nullptr,&info.value,&info.bytes),"FCS PKCS8 structure invalid.");
        const auto* private_info=static_cast<const CRYPT_PRIVATE_KEY_INFO*>(info.value);
        constexpr unsigned char p256[]={0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
        Check(private_info->Version==0&&private_info->Algorithm.pszObjId&&std::strcmp(private_info->Algorithm.pszObjId,szOID_ECC_PUBLIC_KEY)==0&&
            private_info->Algorithm.Parameters.cbData==sizeof(p256)&&std::memcmp(private_info->Algorithm.Parameters.pbData,p256,sizeof(p256))==0,"FCS key must be original named-curve P256 PKCS8.");
        auto state=std::make_unique<Impl>();Check(NCryptOpenStorageProvider(&state->provider,MS_KEY_STORAGE_PROVIDER,0)==ERROR_SUCCESS,"Native FCS CNG provider unavailable.");
        // No key name/parameter list: Microsoft Software KSP imports an ephemeral key.
        Check(NCryptImportKey(state->provider,0,NCRYPT_PKCS8_PRIVATE_KEY_BLOB,nullptr,&state->key,reinterpret_cast<BYTE*>(der.bytes.data()),static_cast<DWORD>(der.bytes.size()),NCRYPT_SILENT_FLAG|NCRYPT_DO_NOT_FINALIZE_FLAG)==ERROR_SUCCESS,"Original FCS private key failed CNG validation.");
        DWORD export_policy=NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        Check(NCryptSetProperty(state->key,NCRYPT_EXPORT_POLICY_PROPERTY,reinterpret_cast<BYTE*>(&export_policy),sizeof(export_policy),0)==ERROR_SUCCESS&&NCryptFinalizeKey(state->key,NCRYPT_SILENT_FLAG)==ERROR_SUCCESS,"Original ephemeral FCS key finalization failed.");
        DWORD bits=0,returned=0;Check(NCryptGetProperty(state->key,NCRYPT_LENGTH_PROPERTY,reinterpret_cast<BYTE*>(&bits),sizeof(bits),&returned,0)==ERROR_SUCCESS&&returned==sizeof(bits)&&bits==256,"Native FCS key width invalid.");
        DWORD blob_size=0;Check(NCryptExportKey(state->key,0,BCRYPT_ECCPRIVATE_BLOB,nullptr,nullptr,0,&blob_size,0)==ERROR_SUCCESS&&blob_size==sizeof(BCRYPT_ECCKEY_BLOB)+96,"Native FCS private representation unsupported.");
        Secret blob;blob.bytes.resize(blob_size);Check(NCryptExportKey(state->key,0,BCRYPT_ECCPRIVATE_BLOB,nullptr,reinterpret_cast<BYTE*>(blob.bytes.data()),blob_size,&blob_size,0)==ERROR_SUCCESS,"Native FCS key representation export failed.");
        BCRYPT_ECCKEY_BLOB header{};std::memcpy(&header,blob.bytes.data(),sizeof(header));Check(header.cbKey==32&&(header.dwMagic==BCRYPT_ECDSA_PRIVATE_P256_MAGIC||header.dwMagic==BCRYPT_ECDH_PRIVATE_P256_MAGIC),"Native FCS private curve representation invalid.");
        state->public_encoding=std::string(1,'\x04')+blob.bytes.substr(sizeof(header),64);
        header.dwMagic=BCRYPT_ECDH_PRIVATE_P256_MAGIC;std::memcpy(blob.bytes.data(),&header,sizeof(header));
        Check(BCryptOpenAlgorithmProvider(&state->ecdh,BCRYPT_ECDH_P256_ALGORITHM,nullptr,0)>=0&&BCryptImportKeyPair(state->ecdh,nullptr,BCRYPT_ECCPRIVATE_BLOB,&state->agreement_key,reinterpret_cast<BYTE*>(blob.bytes.data()),blob_size,0)>=0,"Native FCS ECDH key import failed.");
        return std::unique_ptr<AeaFcsKey>(new AeaFcsKey(std::move(state)));
    }catch(const std::exception& e){error=e.what();}catch(...){error="Native FCS key import failed.";}return {};
}
std::unique_ptr<SecretBytes> AeaFcsKey::OpenHpke(std::string_view enc,std::string_view ciphertext,std::string_view info,std::string_view aad,std::string& error) const {
    return HpkeP256Aes256Open(impl_->agreement_key,impl_->public_encoding,enc,ciphertext,info,aad,error);
}
JsonValue AeaFcsKey::ToJson() const {auto out=JsonValue::ObjectValue();out.Set("fcs_key_validated",JsonValue::Boolean(true));out.Set("fcs_key_ephemeral",JsonValue::Boolean(true));out.Set("authentication_verified",JsonValue::Boolean(false));out.Set("decryption_complete",JsonValue::Boolean(false));return out;}
}
