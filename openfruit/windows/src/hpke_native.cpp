#include "hpke_native.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>
namespace OpenFruit {
SecretBytes::SecretBytes(std::size_t count):bytes_(count,'\0'){}
SecretBytes::~SecretBytes(){if(!bytes_.empty())SecureZeroMemory(bytes_.data(),bytes_.size());}
unsigned char* SecretBytes::Data() noexcept {return reinterpret_cast<unsigned char*>(bytes_.data());}
namespace {
void Check(bool value,const char* error){if(!value)throw std::runtime_error(error);}
void Cng(NTSTATUS status,const char* error){Check(status>=0,error);}
struct Algorithm {BCRYPT_ALG_HANDLE value=nullptr;~Algorithm(){if(value)BCryptCloseAlgorithmProvider(value,0);}};
struct Key {BCRYPT_KEY_HANDLE value=nullptr;~Key(){if(value)BCryptDestroyKey(value);}};
struct Agreement {BCRYPT_SECRET_HANDLE value=nullptr;~Agreement(){if(value)BCryptDestroySecret(value);}};
struct Hash {BCRYPT_HASH_HANDLE value=nullptr;~Hash(){if(value)BCryptDestroyHash(value);}};
std::unique_ptr<SecretBytes> Hmac(std::string_view key,std::string_view data){
    Algorithm alg;Cng(BCryptOpenAlgorithmProvider(&alg.value,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG),"Native HPKE HMAC provider failed.");
    Hash hash;Cng(BCryptCreateHash(alg.value,&hash.value,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),static_cast<ULONG>(key.size()),0),"Native HPKE HMAC setup failed.");
    Cng(BCryptHashData(hash.value,reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),static_cast<ULONG>(data.size()),0),"Native HPKE HMAC input failed.");
    auto out=std::make_unique<SecretBytes>(32);Cng(BCryptFinishHash(hash.value,out->Data(),32,0),"Native HPKE HMAC finish failed.");return out;
}
std::unique_ptr<SecretBytes> Extract(std::string_view salt,std::string_view suite,std::string_view label,std::string_view ikm){
    auto input=std::make_unique<SecretBytes>(7+suite.size()+label.size()+ikm.size());auto target=input->Data();
    std::memcpy(target,"HPKE-v1",7);std::size_t at=7;
    for(const auto part:{suite,label,ikm}){if(!part.empty())std::memcpy(target+at,part.data(),part.size());at+=part.size();}
    const std::string zero(32,'\0');return Hmac(salt.empty()?std::string_view(zero):salt,input->View());
}
std::unique_ptr<SecretBytes> Expand(std::string_view prk,std::string_view suite,std::string_view label,std::string_view info,std::size_t length){
    Check(length<=32,"Native HPKE expansion size unsupported.");
    auto input=std::make_unique<SecretBytes>(2+7+suite.size()+label.size()+info.size()+1);auto target=input->Data();
    target[0]=static_cast<unsigned char>(length>>8);target[1]=static_cast<unsigned char>(length);std::memcpy(target+2,"HPKE-v1",7);std::size_t at=9;
    for(const auto part:{suite,label,info}){if(!part.empty())std::memcpy(target+at,part.data(),part.size());at+=part.size();}target[at]=1;
    auto block=Hmac(prk,input->View());auto out=std::make_unique<SecretBytes>(length);std::memcpy(out->Data(),block->Data(),length);return out;
}
}
std::unique_ptr<SecretBytes> HpkeP256Aes256Open(void* key,std::string_view recipient_public,std::string_view enc,std::string_view ct,std::string_view info,std::string_view aad,std::string& error){
    error.clear();try{
        Check(key&&recipient_public.size()==65&&static_cast<unsigned char>(recipient_public[0])==4&&enc.size()==65&&static_cast<unsigned char>(enc[0])==4,"Native HPKE P256 key encoding invalid.");
        Check(ct.size()>=16&&ct.size()<=65536&&info.size()<=65536&&aad.size()<=65536,"Native HPKE input byte budget invalid.");
        Algorithm ecdh;Cng(BCryptOpenAlgorithmProvider(&ecdh.value,BCRYPT_ECDH_P256_ALGORITHM,nullptr,0),"Native HPKE ECDH provider failed.");
        std::vector<unsigned char> public_blob(sizeof(BCRYPT_ECCKEY_BLOB)+64);BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDH_PUBLIC_P256_MAGIC,32};std::memcpy(public_blob.data(),&header,sizeof(header));std::memcpy(public_blob.data()+sizeof(header),enc.data()+1,64);
        Key peer;Cng(BCryptImportKeyPair(ecdh.value,nullptr,BCRYPT_ECCPUBLIC_BLOB,&peer.value,public_blob.data(),static_cast<ULONG>(public_blob.size()),0),"Native HPKE P256 encapsulation point rejected.");
        Agreement agreement;Cng(BCryptSecretAgreement(static_cast<BCRYPT_KEY_HANDLE>(key),peer.value,&agreement.value,0),"Native HPKE ECDH agreement failed.");
        auto dh=std::make_unique<SecretBytes>(32);ULONG written=0;Cng(BCryptDeriveKey(agreement.value,BCRYPT_KDF_RAW_SECRET,nullptr,dh->Data(),32,&written,0),"Native HPKE ECDH secret derivation failed.");Check(written==32,"Native HPKE ECDH secret width invalid.");
        // CNG RAW_SECRET is little-endian; RFC 9180 P256 DH is a big-endian x-coordinate.
        std::reverse(dh->Data(),dh->Data()+32);
        const std::string kem("KEM\x00\x10",5),suite("HPKE\x00\x10\x00\x01\x00\x02",10);
        auto eae=Extract({},kem,"eae_prk",dh->View());const std::string kem_context=std::string(enc)+std::string(recipient_public);
        auto shared=Expand(eae->View(),kem,"shared_secret",kem_context,32);
        auto psk_id_hash=Extract({},suite,"psk_id_hash",{});auto info_hash=Extract({},suite,"info_hash",info);
        auto context=std::make_unique<SecretBytes>(65);context->Data()[0]=0;std::memcpy(context->Data()+1,psk_id_hash->Data(),32);std::memcpy(context->Data()+33,info_hash->Data(),32);
        auto secret=Extract(shared->View(),suite,"secret",{});auto aes_key=Expand(secret->View(),suite,"key",context->View(),32);auto nonce=Expand(secret->View(),suite,"base_nonce",context->View(),12);
        Algorithm aes;Cng(BCryptOpenAlgorithmProvider(&aes.value,BCRYPT_AES_ALGORITHM,nullptr,0),"Native HPKE AES provider failed.");
        Cng(BCryptSetProperty(aes.value,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),sizeof(BCRYPT_CHAIN_MODE_GCM),0),"Native HPKE AES-GCM mode failed.");
        Key symmetric;Cng(BCryptGenerateSymmetricKey(aes.value,&symmetric.value,nullptr,0,aes_key->Data(),32,0),"Native HPKE AES key setup failed.");
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;BCRYPT_INIT_AUTH_MODE_INFO(auth);auth.pbNonce=nonce->Data();auth.cbNonce=12;
        auth.pbAuthData=reinterpret_cast<PUCHAR>(const_cast<char*>(aad.data()));auth.cbAuthData=static_cast<ULONG>(aad.size());auth.pbTag=reinterpret_cast<PUCHAR>(const_cast<char*>(ct.data()+ct.size()-16));auth.cbTag=16;
        auto plain=std::make_unique<SecretBytes>(ct.size()-16);
        Cng(BCryptDecrypt(symmetric.value,reinterpret_cast<PUCHAR>(const_cast<char*>(ct.data())),static_cast<ULONG>(ct.size()-16),&auth,nullptr,0,plain->Data(),static_cast<ULONG>(plain->View().size()),&written,0),"Native HPKE AES-GCM authentication failed.");
        Check(written==plain->View().size(),"Native HPKE plaintext size invalid.");return plain;
    }catch(const std::exception& e){error=e.what();}catch(...){error="Native HPKE unwrap failed.";}return {};
}
}
