#include "sdk_selection.hpp"
#include "sdk_usage.hpp"
#include "artifact_store.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void Write(const fs::path& path, const std::string& bytes) { std::ofstream file(path, std::ios::binary); file << bytes; file.close(); Require(static_cast<bool>(file), "owned write failed"); }
std::string Read(const fs::path& path) { std::ifstream file(path, std::ios::binary); return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()}; }
void MakeSdk(const fs::path& sdk) {
    fs::create_directories(sdk / "usr/lib"); fs::create_directories(sdk / "System/Library/Frameworks");
    Write(sdk / "SDKSettings.json", "{}"); Write(sdk / "usr/lib/owned", "original immutable owned payload");
    Write(sdk / "busy-a", "owned a"); Write(sdk / "busy-b", "owned b");
}
std::uint64_t Identity(const fs::path& path) {
    HANDLE held = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    Require(held != INVALID_HANDLE_VALUE, "owned identity open failed");
    BY_HANDLE_FILE_INFORMATION info{}; const bool good = GetFileInformationByHandle(held, &info) != FALSE; CloseHandle(held);
    Require(good, "owned identity read failed"); return (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
}
struct CrashSink : EventSink {
    std::string boundary;
    explicit CrashSink(std::string value) : boundary(std::move(value)) {}
    void Emit(OperationEvent event) noexcept override { if (event.kind == boundary) TerminateProcess(GetCurrentProcess(), 71); }
};
struct Fixture {
    fs::path root, sdk, configuration, receipt, quarantine;
    Config config;
    std::string before, after;
    std::uint64_t identity;
    Fixture(const fs::path& base, const std::string& name) : root(base/name), sdk(root/"sdk"), configuration(root/"state/config.toml") {
        MakeSdk(sdk); fs::create_directories(configuration.parent_path());
        config.OPENFRUIT_home=(root/"home").wstring(); config.user_state_root=configuration.parent_path().wstring();
        config.ios_sdk_paths[L"27"]=sdk.wstring(); config.ios_sdk_version=L"27"; config.sdk_path=sdk.wstring();
        Require(config.Save(configuration.wstring()), "owned configuration save failed");
        before=Read(configuration); identity=Identity(sdk);
        Require(config.PublicationSha256() == Sha256(before), "pure publication digest differs from actual Save bytes");
    }
    void Crash(const std::wstring& self, const std::wstring& boundary=L"sdk.removal.configuration_committed") {
        ProcessRunOptions control; control.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
        const auto process=Win32Process::Run(self,{self,L"--remove-crash",configuration.wstring(),boundary},L"",{},nullptr,nullptr,control);
        Require(process.launched && !process.timed_out && process.exit_code==71, "actual removal crash boundary was not reached");
        for (const auto& item:fs::directory_iterator(root)) if (item.path().extension()==".json" && item.path().filename().wstring().starts_with(L"sdk.sdk-removal-")) {
            Require(receipt.empty(), "ambiguous original fixture receipt"); receipt=item.path();
        }
        Require(!receipt.empty(), "real crash did not retain receipt");
        const auto record=JsonValue::Parse(Read(receipt));
        Require(record && record->GetString("schema")=="openfruit.sdk-removal.v3", "real transaction did not publish v3 receipt");
        quarantine=fs::path(Win32Process::ToWide(record->GetString("quarantine"))); after=Read(configuration);
        if (boundary==L"sdk.removal.configuration_committed")
            Require(!fs::exists(sdk) && Identity(quarantine)==identity && record->GetString("configuration_after_sha256")==Sha256(after).value_or(""),
                "v3 after-image or retained identity differs from actual commit");
    }
    void Refused() {
        const auto receipt_bytes=Read(receipt), config_bytes=Read(configuration);
        const auto result=SDKRemoval::Cleanup(receipt,configuration);
        Require(!result.Succeeded() && result.cleanup_pending && fs::exists(receipt) && Read(receipt)==receipt_bytes &&
            Read(configuration)==config_bytes && Read(quarantine/"usr/lib/owned")=="original immutable owned payload",
            "unproven cleanup changed retained payload, receipt or configuration");
    }
};
struct ProgressSink : EventSink {
    fs::path quarantine;
    std::weak_ptr<OperationContext> context;
    bool cancel=false, observed=false;
    HANDLE busy=INVALID_HANDLE_VALUE;
    ~ProgressSink() { Release(); }
    void Release() { if(busy!=INVALID_HANDLE_VALUE){CloseHandle(busy);busy=INVALID_HANDLE_VALUE;} }
    void Emit(OperationEvent event) noexcept override {
        if(observed || event.kind!="sdk.removal.cleanup.entry")return;
        observed=true;
        if(cancel){ if(const auto active=context.lock())active->RequestCancellation(); return; }
        for(const auto* name:{"busy-a","busy-b"}) {
            busy=CreateFileW((quarantine/name).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(busy!=INVALID_HANDLE_VALUE)break;
        }
    }
};
void Tests(const fs::path& base,const std::wstring& self,const std::wstring& cli) {
    {
        Fixture fixture(base,"ordinary"); fixture.Crash(self);
        const auto result=SDKRemoval::Cleanup(fixture.receipt,fixture.configuration);
        Require(result.Succeeded() && !result.cleanup_pending && result.retained_directory.empty() && result.retained_receipt.empty() &&
            !fs::exists(fixture.quarantine) && !fs::exists(fixture.receipt) && Read(fixture.configuration)==fixture.after,
            "explicit cleanup did not consume committed prepared-phase receipt");
    }
    {
        Fixture fixture(base,"separator-aliases"); fixture.Crash(self);
        for(const auto& middle:{fs::path("."),fs::path("unresolved/..")}) {
            const auto non_normal_receipt = fixture.receipt.parent_path()/middle/fixture.receipt.filename();
            const auto rejected = SDKRemoval::Cleanup(non_normal_receipt, fixture.configuration);
            Require(rejected.status==SDKRemovalStatus::InvalidPath && fs::exists(fixture.receipt) &&
                Identity(fixture.quarantine)==fixture.identity && Read(fixture.configuration)==fixture.after,
                "Separator normalization admitted dot components in a cleanup receipt path");
        }
        auto receipt_spelling = fixture.receipt.wstring();
        auto config_spelling = fixture.configuration.wstring();
        std::replace(receipt_spelling.begin(), receipt_spelling.end(), L'\\', L'/');
        std::replace(config_spelling.begin(), config_spelling.end(), L'\\', L'/');
        const auto result = SDKRemoval::Cleanup(fs::path(receipt_spelling), fs::path(config_spelling));
        Require(result.Succeeded() && !result.cleanup_pending && !fs::exists(fixture.quarantine) &&
            !fs::exists(fixture.receipt) && Read(fixture.configuration)==fixture.after,
            "Windows separator aliases did not preserve receipt/configuration identity");
    }
    {
        Fixture fixture(base,"in-use"); fixture.Crash(self);
        { SDKUsage reader(fixture.quarantine); Require(reader.Held(),"owned SDK reader failed");
          const auto result=SDKRemoval::Cleanup(fixture.receipt,fixture.configuration);
          Require(result.status==SDKRemovalStatus::InUse && Identity(fixture.quarantine)==fixture.identity,"active SDK reader bypassed"); }
        { const auto publisher=ArtifactLease::Acquire(fixture.sdk);
          Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).status==SDKRemovalStatus::InUse,"active SDK publisher bypassed"); }
        { const auto publisher=ArtifactLease::Acquire(fixture.configuration);
          Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).status==SDKRemovalStatus::InUse,"active config writer bypassed"); }
        Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).Succeeded(),"released cleanup could not retry");
    }
    {
        Fixture fixture(base,"partial-file-busy"); fixture.Crash(self);
        auto sink=std::make_shared<ProgressSink>();sink->quarantine=fixture.quarantine;
        auto context=std::make_shared<OperationContext>();context->sink=sink;sink->context=context;
        SDKRemovalResult result;
        { OperationBinding binding(context);result=SDKRemoval::Cleanup(fixture.receipt,fixture.configuration); }
        Require(sink->observed && sink->busy!=INVALID_HANDLE_VALUE && !result.Succeeded() && result.cleanup_pending &&
            Identity(fixture.quarantine)==fixture.identity && fs::exists(fixture.receipt) && Read(fixture.configuration)==fixture.after,
            "file-busy partial cleanup was hidden or changed committed configuration");
        sink->Release();
        Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).Succeeded(),"partial cleanup retry incorrectly required intact SDK layout");
    }
    {
        Fixture fixture(base,"cancel-partial");fixture.Crash(self);
        auto sink=std::make_shared<ProgressSink>();sink->quarantine=fixture.quarantine;sink->cancel=true;
        auto context=std::make_shared<OperationContext>();context->sink=sink;sink->context=context;
        SDKRemovalResult result;
        { OperationBinding binding(context);result=SDKRemoval::Cleanup(fixture.receipt,fixture.configuration); }
        Require(sink->observed && result.status==SDKRemovalStatus::Cancelled && result.cleanup_pending &&
            Identity(fixture.quarantine)==fixture.identity && Read(fixture.configuration)==fixture.after && fs::exists(fixture.receipt),
            "cancellation lost receipt or remaining payload");
        Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).Succeeded(),"cancelled cleanup could not retry");
    }
    for(const auto& boundary:{"sdk.removal.prepared","sdk.removal.detached","sdk.removal.configuration_committed"}) {
        Fixture fixture(base,std::string("cancel-")+boundary);
        struct CancelSink:EventSink {
            std::weak_ptr<OperationContext> context;std::string boundary;
            void Emit(OperationEvent event) noexcept override { if(event.kind==boundary)if(const auto active=context.lock())active->RequestCancellation(); }
        };
        auto context=std::make_shared<OperationContext>();auto sink=std::make_shared<CancelSink>();
        sink->context=context;sink->boundary=boundary;context->sink=sink;
        SDKRemovalResult result;
        { OperationBinding binding(context);result=SDKRemoval::Remove(fixture.config,L"27",fixture.configuration); }
        if(std::string(boundary)=="sdk.removal.configuration_committed") {
            Require(result.Succeeded() && result.cleanup_pending && !result.retained_receipt.empty() && !fs::exists(fixture.sdk),
                "postcommit cancellation misreported completed unregistration or pending cleanup");
            Require(SDKRemoval::Cleanup(result.retained_receipt,fixture.configuration).Succeeded(),"postcommit cancellation retry failed");
        } else Require(result.status==SDKRemovalStatus::Cancelled && Read(fixture.configuration)==fixture.before &&
            Identity(fixture.sdk)==fixture.identity && Read(fixture.sdk/"usr/lib/owned")=="original immutable owned payload",
            "precommit cancellation changed SDK identity or registration");
    }
    {
        Fixture fixture(base,"cancel-existing");auto context=std::make_shared<OperationContext>();context->RequestCancellation();
        OperationBinding binding(context);
        Require(SDKRemoval::Remove(fixture.config,L"27",fixture.configuration).status==SDKRemovalStatus::Cancelled &&
            Read(fixture.configuration)==fixture.before && Identity(fixture.sdk)==fixture.identity,"pre-existing cancellation committed removal");
    }
    {
        Fixture fixture(base,"deadline-existing");auto context=std::make_shared<OperationContext>();
        context->control=std::make_shared<OperationControl>(std::chrono::steady_clock::now()-std::chrono::seconds(1));
        OperationBinding binding(context);
        Require(SDKRemoval::Remove(fixture.config,L"27",fixture.configuration).status==SDKRemovalStatus::Cancelled &&
            Read(fixture.configuration)==fixture.before && Identity(fixture.sdk)==fixture.identity,"expired deadline committed removal");
    }
    {
        Fixture fixture(base,"prepared-uncommitted");fixture.Crash(self,L"sdk.removal.detached");fixture.Refused();
        Require(Read(fixture.configuration)==fixture.before && Identity(fixture.quarantine)==fixture.identity,"uncommitted receipt was treated as committed");
    }
    for(const auto& reason:{"v1","v2","modified-config","new-original","ambiguous","wrong-identity","receipt-hardlink","root-reparse","replaced-root","registered-quarantine","protected-root","config-hardlink","lease-hardlink"}) {
        Fixture fixture(base,reason);fixture.Crash(self);auto record=*JsonValue::Parse(Read(fixture.receipt));
        if(std::string(reason)=="v1")record.Set("schema",JsonValue::String("openfruit.sdk-removal.v1"));
        else if(std::string(reason)=="v2")record.Set("schema",JsonValue::String("openfruit.sdk-removal.v2"));
        else if(std::string(reason)=="modified-config")Write(fixture.configuration,fixture.after+"\n# user changed this config\n");
        else if(std::string(reason)=="new-original")MakeSdk(fixture.sdk);
        else if(std::string(reason)=="ambiguous")Write(fs::path(fixture.sdk.wstring()+L".sdk-removal-"+Win32Process::ToWide(NewOperationId())+L".json"),Read(fixture.receipt));
        else if(std::string(reason)=="wrong-identity")record.Set("file_index_low",JsonValue::String("4294967296"));
        else if(std::string(reason)=="receipt-hardlink")fs::create_hard_link(fixture.receipt,fixture.root/"receipt-alias.json");
        else if(std::string(reason)=="config-hardlink")fs::create_hard_link(fixture.configuration,fixture.root/"config-alias.toml");
        else if(std::string(reason)=="lease-hardlink")fs::create_hard_link(fs::path(fixture.sdk.wstring()+L".import-lock"),fixture.root/"lease-alias");
        else if(std::string(reason)=="registered-quarantine" || std::string(reason)=="protected-root") {
            auto current=Config::Load(fixture.configuration.wstring(),false);
            if(std::string(reason)=="registered-quarantine")current.ios_sdk_paths[L"28"]=fixture.quarantine.wstring();
            else current.OPENFRUIT_home=(fixture.quarantine/"managed").wstring();
            Require(current.Save(fixture.configuration.wstring()),"owned unsafe current-state setup failed");
            record.Set("configuration_after_sha256",JsonValue::String(Sha256File(fixture.configuration).value_or("")));
        }
        else if(std::string(reason)=="root-reparse" || std::string(reason)=="replaced-root") {
            const auto saved=fixture.root/"saved-original";fs::rename(fixture.quarantine,saved);
            if(std::string(reason)=="root-reparse")Require(NativeArtifactStore::CreateDirectoryJunction(fixture.quarantine,saved),"owned root junction failed");
            else MakeSdk(fixture.quarantine);
        }
        if(std::string(reason)!="receipt-hardlink")Write(fixture.receipt,record.Serialize());
        fixture.Refused();
    }
    {
        Fixture fixture(base,"descendant-links");const auto outside=fixture.root/"outside";fs::create_directory(outside);
        Write(outside/"keep","external owned bytes");const auto outside_id=Identity(outside);
        Require(NativeArtifactStore::CreateDirectoryJunction(fixture.sdk/"outside-link",outside),"owned descendant junction failed");
        fs::create_hard_link(outside/"keep",fixture.sdk/"hardlink");fixture.Crash(self);
        Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).Succeeded() &&
            Read(outside/"keep")=="external owned bytes" && Identity(outside)==outside_id,"cleanup followed a descendant link or wrote hardlinked source");
    }
    {
        Fixture fixture(base,"death-after-payload");fixture.Crash(self);
        ProcessRunOptions control;control.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
        const auto result=Win32Process::Run(self,{self,L"--cleanup-crash",fixture.configuration.wstring(),fixture.receipt.wstring()},L"",{},nullptr,nullptr,control);
        Require(result.launched && !result.timed_out && result.exit_code==71 && !fs::exists(fixture.quarantine) && fs::exists(fixture.receipt),
            "real cleanup crash did not preserve metadata after payload deletion");
        Require(SDKRemoval::Cleanup(fixture.receipt,fixture.configuration).Succeeded() && !fs::exists(fixture.receipt) &&
            Read(fixture.configuration)==fixture.after,"metadata-only cleanup retry failed");
    }
    {
        Fixture fixture(base,"cli-cleanup");fixture.Crash(self);
        const auto result=Win32Process::Run(cli,{cli,L"sdk",L"cleanup",fixture.receipt.wstring()},L"",
            {{L"OPENFRUIT_USER_STATE",fixture.configuration.parent_path().wstring()},{L"OPENFRUIT_HOME",fixture.config.OPENFRUIT_home}});
        Require(result.launched && result.exit_code==0 && !fs::exists(fixture.quarantine) && !fs::exists(fixture.receipt) &&
            Read(fixture.configuration)==fixture.after,"native CLI did not complete committed cleanup");
    }
}
}
int main(int argc,char** argv) {
    if(argc==4 && std::string(argv[1])=="--remove-crash") {
        const fs::path configuration(Win32Process::ToWide(argv[2])); auto config=Config::Load(configuration.wstring(),false);
        auto context=std::make_shared<OperationContext>(); context->sink=std::make_shared<CrashSink>(argv[3]);
        OperationBinding binding(context); SDKRemoval::Remove(config,L"27",configuration); return 72;
    }
    if(argc==4 && std::string(argv[1])=="--cleanup-crash") {
        auto context=std::make_shared<OperationContext>(); context->sink=std::make_shared<CrashSink>("sdk.removal.cleanup.payload_removed");
        OperationBinding binding(context); SDKRemoval::Cleanup(fs::path(Win32Process::ToWide(argv[3])),fs::path(Win32Process::ToWide(argv[2]))); return 72;
    }
    if(argc!=2)return 2;
    const auto root=fs::temp_directory_path()/("OPENFRUIT-sdk-cleanup-"+NewOperationId());
    try {
        Tests(root,fs::absolute(Win32Process::ToWide(argv[0])).wstring(),fs::absolute(Win32Process::ToWide(argv[1])).wstring());
        fs::remove_all(root); std::cout<<"SDK committed receipt cleanup, crash retry and native CLI passed\n";return 0;
    } catch(const std::exception& error){std::cerr<<error.what()<<"; retained owned fixture: "<<root<<'\n';return 1;}
}
