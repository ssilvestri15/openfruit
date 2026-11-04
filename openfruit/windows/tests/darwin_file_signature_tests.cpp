#include "darwin_file_signature.hpp"
#include "macho_code_directory.hpp"
#include "darwin_files.hpp"
#include <windows.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <algorithm>
using namespace OpenFruit;
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
void Put(std::string& s,std::size_t p,std::uint64_t v,unsigned n=4,bool le=false){for(unsigned i=0;i<n;++i){s[p+(le?i:n-i-1)]=static_cast<char>(v&255);v>>=8;}}
struct Fixture {std::filesystem::path path;~Fixture(){if(!path.empty())DeleteFileW(path.c_str());}};
int main(int argc,char** argv){try{
    std::string image(12288,'\0');Put(image,0,0xfeedfacf,4,true);Put(image,4,0x100000c,4,true);
    Put(image,12,6,4,true);Put(image,16,3,4,true);Put(image,20,160,4,true);
    for(unsigned p:{32U,104U}){Put(image,p,0x19,4,true);Put(image,p+4,72,4,true);Put(image,p+32,16384,8,true);Put(image,p+56,p==32?5:1,4,true);Put(image,p+60,p==32?5:1,4,true);}
    image.replace(40,6,"__TEXT");Put(image,56,0x100000000,8,true);Put(image,80,8192,8,true);
    image.replace(112,10,"__LINKEDIT");Put(image,128,0x100004000,8,true);Put(image,144,8192,8,true);Put(image,152,4096,8,true);
    Put(image,176,0x1d,4,true);Put(image,180,16,4,true);Put(image,184,8192,4,true);Put(image,188,4096,4,true);
    std::string directory,error;Require(BuildMachOCodeDirectory(image,"owned.library","OWNEDTEAM1",{},directory,error),error.c_str());
    Put(directory,12,2); // ad-hoc signature; no certificate authority claimed
    std::string blob(20,'\0');Put(blob,0,0xfade0cc0);Put(blob,4,20+directory.size());Put(blob,8,1);Put(blob,16,20);blob+=directory;
    image.replace(8192,blob.size(),blob);DarwinFileSignature result;
    Require(!VerifyDarwinFileSignature(image,8192,4096,result,error)&&result.ad_hoc&&!result.cms_present&&result.end_offset==8192&&result.code_pages==2,"valid owned ad-hoc pages not admitted");
    Require(!result.ToJson().Get("platform_authority")->Bool()&&!result.ToJson().Get("certificate_chain_trusted")->Bool(),"signature integrity fabricated trust");
    Require(result.identifier=="owned.library"&&std::any_of(result.cdhash.begin(),result.cdhash.end(),[](auto b){return b!=0;}),"Verified CodeDirectory identity/hash discarded");
    const auto first_cdhash=result.cdhash;
    Put(directory,20,0); // Invalid identifier offset cannot publish metadata/hash.
    auto bad_identifier=image;bad_identifier.replace(8192+20,directory.size(),directory);
    Require(VerifyDarwinFileSignature(bad_identifier,8192,4096,result,error)==80&&result.identifier.empty()&&result.cdhash==std::array<std::uint8_t,20>{},"Malformed CodeDirectory published text identity or digest");
    Require(!VerifyDarwinFileSignature(image,8192,4096,result,error)&&result.cdhash==first_cdhash,"Stable original CodeDirectory hash changed between registrations");
    auto bad=image;bad[1000]^=1;Require(VerifyDarwinFileSignature(bad,8192,4096,result,error)==80&&result.end_offset==0,"altered original code acknowledged");
    bad=image;bad[8192+20+16]^=1;Require(VerifyDarwinFileSignature(bad,8192,4096,result,error)==80,"invalid hash table accepted");
    bad=image;Put(bad,8192+16,0xffffffff);Require(VerifyDarwinFileSignature(bad,8192,4096,result,error)==80,"slot escaped original blob");
    bad=image;Put(bad,8192+20+12,0);Require(VerifyDarwinFileSignature(bad,8192,4096,result,error)==80,"non-ad-hoc signature without CMS accepted");
    Require(VerifyDarwinFileSignature(image,8193,4096,result,error)==80&&VerifyDarwinFileSignature(image,8192,4095,result,error)==80,"request ignored Mach-O signature command");
    Fixture fixture;wchar_t temp[MAX_PATH]{},name[MAX_PATH]{};
    Require(GetTempPathW(MAX_PATH,temp)&&GetTempFileNameW(temp,L"ofs",0,name),"signature fixture creation failed");fixture.path=name;
    {std::ofstream f(fixture.path,std::ios::binary);f.write(image.data(),image.size());Require(bool(f),"signature fixture write failed");}
    DarwinClosure closure;closure.original_directories.insert("/");closure.original_files["/owned-code"]=std::filesystem::canonical(fixture.path);closure.original_real_paths["/owned-code"]="/owned-code";
    auto files=std::make_unique<DarwinFiles>(closure);const auto opened=files->Open("/owned-code",0);Require(!opened.error,"original source descriptor admission failed");
    auto fd=static_cast<std::int32_t>(opened.value);
    JsonValue library;std::string library_reason;
    Require(files->CheckLibrary(fd,0,0,library,library_reason).error==80&&!library.Get("source_registered")->Bool(),"unregistered library admitted");
    Require(files->RegisterSignature(-1,0,8192,4096,result).error==9,"invalid descriptor signature admitted");
    auto directory_fd=files->Open("/",0x100000);Require(!directory_fd.error&&files->RegisterSignature(directory_fd.value,0,8192,4096,result).error==45,"virtual directory signature fabricated");
    Require(files->RegisterSignature(fd,1,8192,4096,result).error==45,"unimplemented FAT slice admitted");
    Require(files->RegisterSignature(fd,0,8192,40ULL*1024*1024+1,result).error==7,"signature allocation limit ignored");
    Require(files->RegisterSignature(fd,0,8192,4095,result).error==80&&files->ToJson().Get("signature_registrations")->ArrayItems().empty(),"invalid request published a registration");
    Require(!files->Seek(fd,37,0).error,"source cursor set failed");
    const auto registration=files->RegisterSignature(fd,0,8192,4096,result);
    Require(!registration.error&&registration.value==8192&&result.ad_hoc,"held source registration failed");
    Require(!files->CheckLibrary(fd,0,0,library,library_reason).error&&library.Get("source_registered")->Bool()
        &&!library.Get("validation_required")->Bool()&&!library.Get("platform_authority")->Bool()&&library_reason.empty(),"ordinary task/source admission fabricated trust");
    for(auto required:{0x10U,0x1000U,0x2000U})Require(files->CheckLibrary(fd,0,required,library,library_reason).error==45
        &&library.Get("validation_required")->Bool()&&!library_reason.empty(),"required trust domain silently admitted");
    Require(files->CheckLibrary(fd,1,0,library,library_reason).error==45&&files->CheckLibrary(-1,0,0,library,library_reason).error==9,"unsupported slice/descriptor admitted as library");
    Require(files->Seek(fd,0,1).value==37&&files->ToJson().Get("reads")->Int()==0,"registration consumed source descriptor cursor");
    Require(!files->Close(fd).error&&files->RegisterSignature(fd,0,8192,4096,result).error==9,"closed fd used stale registration");
    const auto registrations=files->ToJson().Get("signature_registrations")->ArrayItems();
    Require(registrations.size()==1&&registrations[0].Get("source_lease_retained")->Bool()&&registrations[0].GetString("path")=="/owned-code","descriptor close discarded registration identity/lease");
    auto writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    Require(writer==INVALID_HANDLE_VALUE,"registration failed to retain immutable source lease");
    files.reset();writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    Require(writer!=INVALID_HANDLE_VALUE,"task destruction retained stale source lease");CloseHandle(writer);
    if(argc==2){auto path=std::filesystem::absolute(argv[1]).wstring();if(!path.starts_with(L"\\\\?\\"))path=L"\\\\?\\"+path;
        std::ifstream f(std::filesystem::path(path),std::ios::binary);Require(bool(f),"original signature fixture file could not be opened");
        std::string original((std::istreambuf_iterator<char>(f)),{});MachOSigningLayout layout;
        const auto inspected=InspectMachOSigningLayout(original,layout,error);Require(inspected,error.c_str());
        const auto verified=VerifyDarwinFileSignature(original,layout.signature_offset,layout.signature_size,result,error);Require(!verified,error.c_str());
        std::cout<<"Original pages="<<result.code_pages<<" code_limit="<<result.code_limit<<" end_offset="<<result.end_offset<<" CMS="<<result.cms_verified<<'\n';
        // Original bytes are input only. Corrupt code and CMS independently.
        auto original_bad=original;original_bad[1000]^=1;Require(VerifyDarwinFileSignature(original_bad,layout.signature_offset,layout.signature_size,result,error)==80,"original code mutation not detected");
        // Alter CD flags while preserving page hashes and embedded slots: the
        // original CMS must reject this independently of page verification.
        auto Be32=[&](std::size_t at){std::uint32_t n=0;for(unsigned i=0;i<4;++i)n=n*256+static_cast<unsigned char>(original[at+i]);return n;};
        const auto cd_offset=Be32(layout.signature_offset+16);original_bad=original;
        original_bad[layout.signature_offset+cd_offset+15]^=1;
        Require(VerifyDarwinFileSignature(original_bad,layout.signature_offset,layout.signature_size,result,error)==80&&error.find("CMS")!=std::string::npos,"original CMS did not authenticate CodeDirectory metadata");
    }
    std::cout<<"CodeDirectory coverage, original page mutation, malformed slots, absent authenticator and explicit no-trust state PASS\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
