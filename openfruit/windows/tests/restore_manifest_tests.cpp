#include "restore_manifest.hpp"
#include "content_hash.hpp"
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
namespace {
ZipMemberResult Verified(const std::string& xml){ZipMemberResult r;r.body=xml;r.sha256=Sha256(xml).value_or("");r.stream_verified=true;return r;}
const std::string prefix="<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>ProductVersion</key><string>1.2</string><key>ProductBuildVersion</key><string>A123</string>";
const std::string restore=prefix+"<key>SystemRestoreImageFileSystems</key><dict><key>Original.dmg.aea</key><string>APFS</string></dict></dict></plist>";
const std::string manifest=prefix+"<key>BuildIdentities</key><array><dict><key>ApChipID</key><integer>42</integer><key>Info</key><dict><key>DeviceClass</key><string>original</string></dict><key>Manifest</key><dict><key>OriginalComponent</key><dict><key>Digest</key><data>AQID</data><key>Trusted</key><true/><key>Info</key><dict><key>Path</key><string>Original.dmg.aea</string><key>HashMethod</key><string>original-algorithm</string></dict></dict></dict></dict></array></dict></plist>";
void Require(bool value,const char* error){if(!value)throw std::runtime_error(error);}
void Fail(const ZipInventoryResult& inventory,const ZipMemberResult& a,const ZipMemberResult& b){auto r=ParseRestoreManifests(inventory,a,b);Require(!r.metadata_validated&&r.metadata.ObjectItems().empty()&&!r.error.empty(),"Malformed restore accepted or partial metadata exposed");}
}
int main(){try{
    ZipInventoryResult inventory;inventory.directory_validated=true;ZipInventoryMember member;member.name="Original.dmg.aea";inventory.members.push_back(member);
    const auto a=Verified(restore),b=Verified(manifest);auto r=ParseRestoreManifests(inventory,a,b);
    Require(r.metadata_validated&&r.metadata.GetString("product_version")=="1.2"&&r.metadata.GetString("product_build")=="A123","Original identity parse failed");
    const auto& identity=r.metadata.Get("identities")->ArrayItems().at(0);const auto& component=identity.Get("components")->ArrayItems().at(0);
    Require(component.GetString("name")=="OriginalComponent"&&component.GetString("path")=="Original.dmg.aea"&&component.GetString("digest_hex")=="010203","Original component metadata changed");
    Require(component.Get("info")->GetString("HashMethod")=="original-algorithm"&&component.Get("metadata")->Get("Trusted")->Bool(),"Declared digest semantics or trust field lost");
    const auto json=r.ToJson();Require(!json.Get("publisher_verified")->Bool(true)&&!json.Get("compatibility_validated")->Bool(true)&&!json.Get("provider_registered")->Bool(true),"Declared Trusted field elevated to runtime verification");
    auto bad=b;bad.body+="changed";Fail(inventory,a,bad);
    bad=b;bad.stream_verified=false;Fail(inventory,a,bad);
    auto text=manifest;const auto version=text.find("<string>1.2</string>");text.replace(version,20,"<string>9.9</string>");Fail(inventory,a,Verified(text));
    auto missing=inventory;missing.members.clear();Fail(missing,a,b);
    missing=inventory;missing.members.push_back(member);Fail(missing,a,b);
    Fail(inventory,a,Verified("<plist><array/></plist>"));Fail(inventory,Verified("malformed"),b);
    text=manifest;const auto digest=text.find("<data>AQID</data>");text.replace(digest,17,"<string>AQID</string>");Fail(inventory,a,Verified(text));
    RangeTransferRequest options;options.url=L"https://example.com/original";
    inventory.source_url=L"https://example.com/different";inventory.source_etag=L"\"v1\"";
    Require(ReadRemoteZipMember(inventory,"Original.dmg.aea",options).error=="Original ZIP source identity mismatch.","Different source URL accepted");
    options.url=inventory.source_url;options.expected_etag=L"\"different\"";
    Require(ReadRemoteZipMember(inventory,"Original.dmg.aea",options).error=="Original ZIP source identity mismatch.","Different source ETag accepted");
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
