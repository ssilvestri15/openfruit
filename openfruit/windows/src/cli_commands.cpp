#include "utf8_path.hpp"
#include "cli_commands.hpp"
#include "config.hpp"
#include "application_service.hpp"
#include "device_usbmux.hpp"
#include "device_session.hpp"
#include "ipa_verification.hpp"
#include "compiler_proxy.hpp"
#include "apple_auth.hpp"
#include "apple_cookies.hpp"
#include "apple_download_catalog.hpp"
#include "browser_apple_auth.hpp"
#include "win32_process.hpp"
#include "wsl_bridge.hpp"
#include "sdk_manager.hpp"
#include "sdk_catalog.hpp"
#include "sdk_selection.hpp"
#include "sdk_read_operations.hpp"
#include "cache_read_operations.hpp"
#include "sdk_auto_selection.hpp"
#include "sdk_usage.hpp"
#include "sdk_acquisition.hpp"
#include "xip_archive.hpp"
#include "sdk_archive_extraction.hpp"
#include "archive_tree_extraction.hpp"
#include "macro_engine.hpp"
#include "darwin_macro_provider_import.hpp"
#include "darwin_provider_acquisition.hpp"
#include "darwin_image.hpp"
#include "darwin_closure.hpp"
#include "darwin_mapping.hpp"
#include "darwin_arm64.hpp"
#include "darwin_progress.hpp"
#include "zip_inventory.hpp"
#include "zip_member.hpp"
#include "restore_manifest.hpp"
#include "aea_input.hpp"
#include "apfs_metadata.hpp"
#include "dyld_cache.hpp"
#include "package_engine.hpp"
#include "app_builder.hpp"
#include "packager_signer.hpp"
#include "device_deployer.hpp"
#include "preview_agent.hpp"
#include "environment_manager.hpp"
#include "tool_paths.hpp"
#include "system_info.hpp"
#include "universal_project.hpp"
#include "capabilities.hpp"
#include "project_inspection.hpp"
#include "git_symlinks.hpp"
#include "build_workspace.hpp"
#include "project_selection_metadata.hpp"
#include "event_journal.hpp"
#include "operation_events.hpp"
#include "console_cancellation.hpp"
#include "artifact_store.hpp"
#include "cache_compression_manager.hpp"
#include "dependency_updater.hpp"
#include "openfruit_version.hpp"

#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <windows.h>
#include <iostream>
#include <memory>
#include <filesystem>
#include "xcode_project.hpp"
#include <algorithm>
#include <unordered_map>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
constexpr const char* kOpenFruitVersion = OPENFRUIT_VERSION;

int ReportSDKRemoval(const SDKRemovalResult& result) {
    auto& output = result.Succeeded() ? std::cout : std::cerr;
    output << (result.Succeeded() ? "" : "OpenFruit: ") << result.message << '\n';
    if (!result.retained_receipt.empty())
        output << "Retained receipt: " << Win32Process::ToNarrow(result.retained_receipt.wstring()) << '\n';
    else if (!result.retained_directory.empty())
        output << "Retained directory: " << Win32Process::ToNarrow(result.retained_directory.wstring()) << '\n';
    const auto context = CurrentOperationContext();
    if (result.status == SDKRemovalStatus::Cancelled ||
        (result.cleanup_pending && context && (context->CancellationRequested() || context->DeadlineExceeded())))
        return 130;
    return result.Succeeded() ? 0 : 1;
}
}

void PrintUsage() {
    std::cout << "========================================================================\n"
              << "  OpenFruit v" OPENFRUIT_VERSION " - Native Graph Build System\n"
              << "========================================================================\n\n"
              << "Usage: openfruit <command> [arguments] [options]\n\n"
              << "Commands:\n"
              << "  build <project-or-path>    Compile, link, package, and optionally sign/deploy\n"
              << "  package <project-or-path>  Assemble App Bundle (.app) and create unsigned .ipa\n"
              << "  deploy <ipa-path>          Install application on physical iOS device via USB\n"
              << "  sdk [list|select|remove|catalog|download|path] Manage Apple iOS SDKs and platform headers\n"
              << "  sdk cleanup <receipt>     Finish a proven committed SDK removal\n"
              << "  sdk inspect-archive <xip>  Read iOS SDK metadata without installing the archive\n"
              << "  sdk archive-members <xip> <path-filter> Inventory original members and linked partners\n"
              << "  sdk extract-members <xip> <new-directory> <member-path>... Extract original archive trees\n"
              << "  sdk extract-archive <xip> <new-directory> Extract an unverified SDK staging tree\n"
              << "  runtime import-macro-provider <local-specification> <selected-sdk> Validate and publish original local provider inputs\n"
              << "  runtime acquire-macro-provider <selected-sdk> Acquire and publish the original macro provider of a managed SDK\n"
              << "  runtime report-progress <inventory> <probe> <command-report> <ledger> [previous-report] Summarize scoped Darwin contracts and evidence\n"
              << "  runtime probe-cache-arm64 <server> <plugin-or-dash> <parent-report> <child-report...> [--protocol-stdio <new-report-file>] --trees <tree...> Probe bounded original Darwin bootstrap\n"
              << "  runtime prepare-cache-arm64 <server> <plugin-or-dash> <parent-report> <child-report...> --trees <tree...> Prepare original mapped argument state\n"
              << "  runtime map-cache-arm64 <server> <plugin-or-dash> <parent-report> <child-report...> --trees <tree...> Map original ARM64 tree/cache graph\n"
              << "  runtime inspect-cache-closure <server> <plugin-or-dash> <parent-report> <child-report...> --trees <tree...> Inspect original tree/cache graph\n"
              << "  runtime inspect-closure <server> <plugin-or-dash> <tree>... Inspect original dependency paths\n"
              << "  runtime inspect-image <image> Inspect original Mach-O slices without execution\n"
              << "  runtime archive-members <https-url> Inspect original remote ZIP/ZIP64 directory\n"
              << "  runtime inspect-archive-member <https-url> <member> Verify a bounded original ZIP member stream\n"
              << "  runtime inspect-restore <https-url> Inspect original restore identities and component metadata\n"
              << "  runtime inspect-apfs <decoded-stage-report> Verify original APFS container and volume metadata\n"
              << "  runtime inspect-apfs-trees <decoded-stage-report> Verify APFS volume trees and derive paths/extents\n"
              << "  runtime extract-apfs-file <decoded-stage-report> <virtual-path> <fresh-directory> Verify and quarantine original file bytes\n"
              << "  runtime inspect-dyld-cache-slide-fixups <parent-report> [child-report...] Decode original slide chains\n"
              << "  runtime map-dyld-cache-memory <parent-report> [child-report...] Map original ranges as private file-backed memory\n"
              << "  runtime inspect-dyld-cache-exports <virtual-image> <parent-report> [child-report...] Read original export trie\n"
              << "  runtime inspect-dyld-cache-images <parent-report> [child-report...] Inspect original Mach-O images through cache VM\n"
              << "  runtime inspect-dyld-cache-set <parent-report> [child-report...] Verify combined original cache layout\n"
              << "  runtime inspect-dyld-subcache <parent-report> <child-report> Verify original child against main cache\n"
              << "  runtime inspect-dyld-cache <verified-apfs-file-report> Derive original cache mappings, subcaches and image paths\n"
              << "  runtime decode-aea-component <stage-report> <new-directory> Authenticate and quarantine original AEA output\n"
              << "  runtime inspect-aea-root <stage-report> Authenticate/decode original AEA root metadata\n"
              << "  runtime unwrap-aea-key <stage-report> Authenticate the original FCS envelope natively\n"
              << "  runtime inspect-aea-key <stage-report> Retrieve and validate the original FCS key natively\n"
              << "  runtime inspect-aea <stage-report> Inspect retained original AEA metadata under a read lease\n"
              << "  runtime stage-restore-component <https-url> <component> <new-directory> Quarantine every original component variant\n"
              << "  runtime map-image <server> <tree>... Map native-CPU original images and apply supported fixups\n"
              << "  runtime run-arm64 <server> <symbol> <tree>... Execute an ARM64 function through the native CPU backend\n"
              << "  cache [status|compress|pack|unpack|prune|clean] Manage, compress, archive, and prune build cache\n"
              << "  config [get|set|list]      Inspect or modify user configuration and credentials\n"
              << "  auth login                 Sign in to Apple Developer in a browser\n"
              << "  auth cookies import <file> Import Apple cookies from a Netscape cookie file\n"
              << "  auth cookies clear         Disable stored Apple cookies for future operations\n"
              << "  doctor                     Verify environment and build dependencies\n"
              << "  bootstrap                  Check, import and install missing OpenFruit dependencies\n"
              << "  update-dependency          Download, install and register in PATH all external tools\n"
              << "  devices [--json]           List connected physical iOS devices (USB / Network)\n"
              << "  device <info|log|screenshot|record|debug|install|launch> Native device operations over USB or Wi-Fi\n"
              << "  verify <path.ipa> [--json] Verify IPA signature, CodeDirectory hashes, CMS seal and integrity\n"
              << "  events replay <directory> Read structured build events as JSON Lines\n"
              << "  info                       Display system topology, hardware threads, and paths\n\n"
              << "Options:\n"
              << "  -j, --jobs <N>             Number of parallel worker threads (default: auto-detected CPU cores)\n"
              << "  -c, --configuration <cfg>  Build configuration: 'debug' or 'release' (default: debug)\n"
              << "  --scheme <name|path>        Select a shared Xcode scheme\n"
              << "  --target-id <UUID>          Select an exact Xcode target UUID\n"
              << "  --target-project <path>     Qualify a target UUID with its project\n"
              << "  --build-for <purpose>       Scheme membership: running/testing/profiling/analyzing/archiving\n"
              << "                             Builds only; does not run, test, analyze or archive\n"
              << "  --sdk-path <path>          Override Apple SDK path\n"
              << "  --sdk-version <version>    Select a configured iOS SDK version (for example 18 or 26)\n"
              << "  --cache-path <path>        Use an invocation-scoped build cache root\n"
              << "  --bundle-id <id>           Override application Bundle Identifier\n"
              << "  --match-profile            Rebind application Bundle ID to match provisioning profile\n"
              << "  --rebind-bundle-id         Alias for --match-profile\n"
              << "  --display-name <name>      Override application display name\n"
              << "  --p12 <path>               Path to Apple Developer .p12 certificate\n"
              << "  --p12-password <pass>      Password for .p12 certificate\n"
              << "  --provision <path>         Path to .mobileprovision provisioning profile\n"
              << "  --deploy                   Automatically deploy to connected iOS device after build\n"
              << "  --preview                  Link the OPENFRUIT preview agent (IDE live preview; never for release)\n"
              << "  --udid <ID>                Specify target iOS device UDID for deployment\n"
              << "  --diagnostics=json         Emit real-time build telemetry and events as JSON Lines (for OpenFruit IDE)\n"
              << "  NAME=value                 Override a build setting for every target, as xcodebuild does\n"
              << "  -v, --verbose              Enable verbose build diagnostics\n"
              << "  -h, --help                 Display this help message\n\n"
              << "Examples:\n"
              << "  openfruit build C:\\Projects\\MyApp\n"
              << "  openfruit build ./MyApp.xcodeproj --configuration release --deploy\n"
              << "  openfruit build . -j 16 --deploy\n"
              << "  openfruit config set signing_p12_path C:\\certs\\developer.p12\n"
              << "  openfruit deploy build\\MyApp-signed.ipa\n";
}

int RunCommand(int argc, char* argv[], std::shared_ptr<EventJournal> journal) {
    std::unique_ptr<OperationBinding> journal_binding;
    try {
        if (argc >= 3 && std::string(argv[1]) == "runtime" && std::string(argv[2]) == "import-macro-provider") {
            if (argc != 5) { std::cerr << "Usage: OPENFRUIT runtime import-macro-provider <local-specification> <selected-sdk>\n"; return 2; }
            std::string error;
            if (!ImportDarwinMacroProvider(fs::path(Win32Process::ToWide(argv[3])), ToolPaths::LocalHome(),
                    fs::path(Win32Process::ToWide(argv[4])), error)) {
                std::cerr << "Original macro provider import failed: " << error << '\n'; return 1;
            }
            std::cout << "Original local macro provider validated and published; publisher assurance unchanged.\n";
            return 0;
        }
        if (argc >= 3 && std::string(argv[1]) == "runtime" && std::string(argv[2]) == "acquire-macro-provider") {
            if (argc != 4) { std::cerr << "Usage: OPENFRUIT runtime acquire-macro-provider <selected-sdk>\n"; return 2; }
            const auto acquired = EnsureDarwinMacroProvider(fs::path(Win32Process::ToWide(argv[3])), ToolPaths::LocalHome(), std::cout);
            if (!acquired.succeeded) { std::cerr << "Original macro provider acquisition failed: " << acquired.message << '\n'; return 1; }
            std::cout << (acquired.already_present ? "Original macro provider already published.\n" : "Original macro provider published.\n");
            return 0;
        }
        if(argc>=3&&std::string(argv[1])=="runtime"&&std::string(argv[2])=="report-progress"){
            if(argc!=7&&argc!=8){std::cerr<<"Usage: openfruit runtime report-progress <inventory> <probe> <command-report> <ledger> [previous-report]\n";return 2;}
            const auto path=[](const char* value){return fs::path(Win32Process::ToWide(value));};
            std::cout<<ReportDarwinProgress(path(argv[3]),path(argv[4]),path(argv[5]),path(argv[6]),argc==8?path(argv[7]):fs::path{}).Serialize(true)<<'\n';return 0;
        }
        if (!journal) {
            journal = EventJournal::AttachFromEnvironment();
            if (journal) journal_binding = std::make_unique<OperationBinding>(journal->Context());
        }
        if (CompilerProxy::IsActive() && !(argc >= 2 && std::string(argv[1]) == "runtime")) {
            return CompilerProxy::Run(
                argc,
                argv
            );
        }

        if (argc < 2) {
            PrintUsage();
            return 1;
        }

        std::string command = argv[1];
        if (command == "-h" || command == "--help" || command == "help") {
            PrintUsage();
            return 0;
        }
        if (command == "--version" || command == "version") {
            std::cout << kOpenFruitVersion << "\n";
            return 0;
        }

        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="inspect-dyld-cache-slide-fixups"){
            if (argc < 4) {
                std::cerr
                    << "Usage: openfruit runtime inspect-dyld-cache-slide-fixups <parent-report> [child-report...]\n";
                return 2;
            }
            std::vector<fs::path> children;
            for (int i = 4; i < argc; ++i) children.emplace_back(Win32Process::ToWide(argv[i]));
            const auto result =
                InspectDyldCacheSlideFixupsStage(fs::path(Win32Process::ToWide(argv[3])), children, {},
                                                 std::chrono::steady_clock::now() + std::chrono::minutes(10));
            std::cout << result.Serialize(true) << '\n';
            return result.Get("complete")->Bool() ? 0 : 1;
        }
        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="map-dyld-cache-memory"){
            if (argc < 4) {
                std::cerr << "Usage: openfruit runtime map-dyld-cache-memory <parent-report> [child-report...]\n";
                return 2;
            }
            std::vector<fs::path> children;
            for (int i = 4; i < argc; ++i) children.emplace_back(Win32Process::ToWide(argv[i]));
            const auto result = MapDyldCacheMemoryStage(fs::path(Win32Process::ToWide(argv[3])), children, {},
                                                        std::chrono::steady_clock::now() + std::chrono::minutes(10));
            std::cout << result.Serialize(true) << '\n';
            return result.Get("complete")->Bool() ? 0 : 1;
        }
        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="inspect-dyld-cache-exports"){
            if(argc<5){std::cerr<<"Usage: openfruit runtime inspect-dyld-cache-exports <virtual-image> <parent-report> [child-report...]\n";return 2;}
            std::vector<fs::path> reports;
            for (int i = 5; i < argc; ++i) reports.emplace_back(Win32Process::ToWide(argv[i]));
            const auto result =
                InspectDyldCacheImageExportsStage(argv[3], fs::path(Win32Process::ToWide(argv[4])), reports, {},
                                                  std::chrono::steady_clock::now() + std::chrono::minutes(10));
            std::cout << result.Serialize(true) << '\n';
            return result.Get("complete")->Bool() ? 0 : 1;
        }
        if(command=="runtime"&&argc>=3&&(std::string(argv[2])=="inspect-dyld-cache-set"||std::string(argv[2])=="inspect-dyld-cache-images")){
            if(argc<4){std::cerr<<"Usage: openfruit runtime inspect-dyld-cache-set <parent-report> [child-report...]\n";return 2;}
            std::vector<fs::path> reports;for(int i=4;i<argc;++i)reports.emplace_back(Win32Process::ToWide(argv[i]));
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
            const auto result =
                std::string(argv[2]) == "inspect-dyld-cache-images"
                    ? InspectDyldCacheImagesStage(fs::path(Win32Process::ToWide(argv[3])), reports, {}, deadline)
                    : InspectDyldCacheSetStage(fs::path(Win32Process::ToWide(argv[3])), reports, {}, deadline);
            std::cout << result.Serialize(true) << '\n';
            return result.Get("complete")->Bool() ? 0 : 1;
        }
        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="inspect-dyld-subcache"){
            if(argc!=5){std::cerr<<"Usage: openfruit runtime inspect-dyld-subcache <verified-parent-apfs-file-report> <verified-child-apfs-file-report>\n";return 2;}
            const auto result=InspectDyldSubcacheStage(fs::path(Win32Process::ToWide(argv[3])),fs::path(Win32Process::ToWide(argv[4])),{},std::chrono::steady_clock::now()+std::chrono::minutes(10));std::cout<<result.Serialize(true)<<'\n';return result.Get("complete")->Bool()?0:1;
        }
        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="inspect-dyld-cache"){
            if(argc!=4){std::cerr<<"Usage: openfruit runtime inspect-dyld-cache <verified-apfs-file-report>\n";return 2;}
            const auto result=InspectDyldCacheStage(fs::path(Win32Process::ToWide(argv[3])),{},std::chrono::steady_clock::now()+std::chrono::minutes(10));std::cout<<result.Serialize(true)<<'\n';return result.Get("complete")->Bool()?0:1;
        }
        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="extract-apfs-file"){
            if(argc!=6){std::cerr<<"Usage: openfruit runtime extract-apfs-file <decoded-stage-report> <virtual-path> <fresh-directory>\n";return 2;}
            const auto result=ExtractApfsStage(fs::path(Win32Process::ToWide(argv[3])),argv[4],fs::path(Win32Process::ToWide(argv[5])),{},std::chrono::steady_clock::now()+std::chrono::minutes(10));std::cout<<result.Serialize(true)<<'\n';return result.Get("complete")->Bool()?0:1;
        }
        if(command=="runtime"&&argc>=3&&(std::string(argv[2])=="inspect-apfs"||std::string(argv[2])=="inspect-apfs-trees")){
            if(argc!=4){std::cerr<<"Usage: openfruit runtime inspect-apfs <decoded-stage-report>\n";return 2;}
            const auto result=InspectApfsStage(fs::path(Win32Process::ToWide(argv[3])),{},std::chrono::steady_clock::now()+std::chrono::minutes(10),std::string(argv[2])=="inspect-apfs-trees");std::cout<<result.Serialize(true)<<'\n';return result.Get("complete")->Bool()?0:1;
        }
        if(command=="runtime"&&argc>=3&&std::string(argv[2])=="decode-aea-component"){
            if(argc!=5){std::cerr<<"Usage: openfruit runtime decode-aea-component <stage-report> <new-directory>\n";return 2;}
            const auto result=DecodeAeaStage(fs::path(Win32Process::ToWide(argv[3])),fs::absolute(fs::path(Win32Process::ToWide(argv[4]))).lexically_normal());std::cout<<result.Serialize(true)<<'\n';return result.Get("complete")->Bool()?0:1;
        }
        if(command=="runtime"&&argc>=3&&(std::string(argv[2])=="inspect-aea"||std::string(argv[2])=="inspect-aea-key"||std::string(argv[2])=="unwrap-aea-key"||std::string(argv[2])=="inspect-aea-root")){
            if(argc!=4){std::cerr<<"Usage: openfruit runtime inspect-aea <stage-report>\n";return 2;}
            const bool acquire=std::string(argv[2])=="inspect-aea-key",unwrap=std::string(argv[2])=="unwrap-aea-key",inspect_root=std::string(argv[2])=="inspect-aea-root";
            const auto result=InspectAeaStage(fs::path(Win32Process::ToWide(argv[3])),acquire,unwrap,inspect_root);std::cout<<result.Serialize(true)<<'\n';return result.Get(inspect_root?"aea_root_authenticated":unwrap?"fcs_key_unwrapped":acquire?"fcs_key_validated":"metadata_read")->Bool()?0:1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "stage-restore-component") {
            if(argc!=6){std::cerr<<"Usage: openfruit runtime stage-restore-component <https-url> <component> <new-directory>\n";return 2;}
            RangeTransferRequest request;request.url=Win32Process::ToWide(argv[3]);request.deadline=std::chrono::steady_clock::now()+std::chrono::hours(2);
            const auto result=StageRestoreComponents(request,argv[4],fs::absolute(fs::path(Win32Process::ToWide(argv[5]))).lexically_normal());
            std::cout<<result.Serialize(true)<<'\n';return result.Get("complete")->Bool()?0:1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "inspect-restore") {
            if(argc!=4){std::cerr<<"Usage: openfruit runtime inspect-restore <https-url>\n";return 2;}
            RangeTransferRequest request;request.url=Win32Process::ToWide(argv[3]);request.deadline=std::chrono::steady_clock::now()+std::chrono::minutes(2);
            const auto result=InspectRestoreArchive(request);std::cout<<result.ToJson().Serialize(true)<<'\n';return result.metadata_validated?0:1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "inspect-archive-member") {
            if (argc != 5) { std::cerr << "Usage: openfruit runtime inspect-archive-member <https-url> <member>\n"; return 2; }
            RangeTransferRequest request;request.url=Win32Process::ToWide(argv[3]);
            request.deadline=std::chrono::steady_clock::now()+std::chrono::minutes(2);
            const auto result=ReadRemoteZipMember(request,argv[4]);
            std::cout<<result.ToJson().Serialize(true)<<'\n';return result.stream_verified?0:1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "archive-members") {
            if (argc != 4) { std::cerr << "Usage: openfruit runtime archive-members <https-url>\n"; return 2; }
            RangeTransferRequest request; request.url = Win32Process::ToWide(argv[3]);
            request.deadline = std::chrono::steady_clock::now() + std::chrono::minutes(2);
            const auto result = InspectRemoteZip(request);
            std::cout << result.ToJson().Serialize(true) << '\n';
            return result.directory_validated ? 0 : 1;
        }
        if(command=="runtime"&&argc>=3&&(std::string(argv[2])=="inspect-cache-closure"||std::string(argv[2])=="map-cache-arm64"||std::string(argv[2])=="prepare-cache-arm64"||std::string(argv[2])=="probe-cache-arm64")){
            if(argc<8){std::cerr<<"Usage: openfruit runtime probe-cache-arm64 <server> <plugin-or-dash> <parent-report> <child-report...> [--protocol-stdio <new-report-file>] --trees <original-tree...>\n";return 2;}
            const std::string mode=argv[2];
            std::vector<fs::path> children,trees;fs::path report_path;
            std::size_t user_instruction_limit = 0;
            int index=6;
            for(;index<argc&&std::string(argv[index])!="--trees";++index){
                if(std::string(argv[index])=="--protocol-stdio"){
                    if(mode!="probe-cache-arm64"||!report_path.empty()||index+1==argc||std::string(argv[index+1])=="--trees"){
                        std::cerr<<"--protocol-stdio requires one new report file and probe-cache-arm64\n";return 2;
                    }
                    report_path=Win32Process::ToWide(argv[++index]);
                    if(report_path.empty()){std::cerr<<"Protocol report path is empty\n";return 2;}
                }else if(std::string(argv[index])=="--instruction-limit"){
                    if(index+1==argc||std::string(argv[index+1])=="--trees"){
                        std::cerr<<"--instruction-limit requires instruction count\n";return 2;
                    }
                    user_instruction_limit=std::stoull(argv[++index]);
                }else children.emplace_back(Win32Process::ToWide(argv[index]));
            }
            if(index==argc||index+1==argc){std::cerr<<"Original tree delimiter and mounts required\n";return 2;}
            for(++index;index<argc;++index)trees.emplace_back(Win32Process::ToWide(argv[index]));
            const auto close_report=[](void* handle){if(handle&&handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);};
            std::unique_ptr<void,decltype(close_report)> report_file(nullptr,close_report);
            DarwinProcessStreams streams;
            if(!report_path.empty()){
                // Diagnostic JSON must never share the guest's binary protocol
                // stream. CREATE_NEW also protects existing source/report files.
                const auto handle=CreateFileW(report_path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
                if(handle==INVALID_HANDLE_VALUE){std::cerr<<"Cannot create new protocol diagnostic report: "<<GetLastError()<<'\n';return 2;}
                report_file.reset(handle);
                streams.input=GetStdHandle(STD_INPUT_HANDLE);
                streams.output=GetStdHandle(STD_OUTPUT_HANDLE);
                streams.error=GetStdHandle(STD_ERROR_HANDLE);
            }
            const auto emit_report=[&](const JsonValue& report){
                const auto text=report.Serialize(true)+'\n';
                if(!report_file){std::cout<<text;return bool(std::cout);}
                for(std::size_t offset=0;offset<text.size();){
                    const auto count=static_cast<DWORD>(std::min<std::size_t>(text.size()-offset,MAXDWORD));DWORD written=0;
                    if(!WriteFile(report_file.get(),text.data()+offset,count,&written,nullptr)||!written){
                        std::cerr<<"Cannot write protocol diagnostic report\n";return false;
                    }
                    offset+=written;
                }
                return true;
            };
            if(report_file&&(!streams.input||streams.input==INVALID_HANDLE_VALUE||!streams.output||streams.output==INVALID_HANDLE_VALUE||!streams.error||streams.error==INVALID_HANDLE_VALUE)){
                auto report=JsonValue::ObjectValue();report.Set("mapped",JsonValue::Boolean(false));
                report.Set("diagnostic",JsonValue::String("Inherited protocol stdin/stdout/stderr unavailable"));emit_report(report);return 1;
            }
            std::vector<std::string> plugins;
            if(std::string(argv[4])!="-"){
                std::stringstream plugin_stream(argv[4]);
                std::string plugin_item;
                while(std::getline(plugin_stream,plugin_item,',')){
                    if(!plugin_item.empty())plugins.push_back(plugin_item);
                }
            }
            DarwinClosureOptions options;options.deadline=std::chrono::steady_clock::now()+std::chrono::minutes(10);
            if(mode=="probe-cache-arm64")options.instruction_limit=user_instruction_limit?user_instruction_limit:(report_path.empty()?150000000:600000000);
            std::string error;options.shared_cache=DyldCacheView::Open(fs::path(Win32Process::ToWide(argv[5])),children,error,{},options.deadline);
            if(!options.shared_cache){auto report=JsonValue::ObjectValue();report.Set("analysis_complete",JsonValue::Boolean(false));report.Set("diagnostic",JsonValue::String(error));emit_report(report);return 1;}
            if(mode=="map-cache-arm64"||mode=="prepare-cache-arm64"||mode=="probe-cache-arm64"){
                const auto mapped=MapDarwinArm64Images(argv[3],trees,options,plugins,mode=="prepare-cache-arm64",mode=="probe-cache-arm64",streams);
                auto report = JsonValue::ObjectValue();
                report.Set("mapped", JsonValue::Boolean(mapped.mapped));
                report.Set("process_arguments", mapped.process_arguments);
                report.Set("process_stack", mapped.process_stack);
                report.Set("process_thread", mapped.process_thread);
                report.Set("bootstrap", mapped.bootstrap);
                report.Set("image_count", JsonValue::Number(std::to_string(mapped.images)));
                report.Set("range_count", JsonValue::Number(std::to_string(mapped.ranges)));
                report.Set("applied_fixups", JsonValue::Number(std::to_string(mapped.applied_fixups)));
                auto weak = JsonValue::ArrayValue();
                for (const auto& binding : mapped.weak_bindings) {
                    auto item = JsonValue::ObjectValue();
                    item.Set("owner", JsonValue::String(binding.owner));
                    item.Set("symbol", JsonValue::String(binding.symbol));
                    item.Set("target", JsonValue::Number(std::to_string(binding.target)));
                    weak.ArrayItems().push_back(std::move(item));
                }
                report.Set("weak_bindings", std::move(weak));
                auto initializers=JsonValue::ArrayValue();for(const auto& initializer:mapped.initializers)initializers.ArrayItems().push_back(initializer.ToJson());report.Set("initializers",std::move(initializers));
                auto order = JsonValue::ArrayValue();
                for (const auto& image : mapped.initialization_order)
                    order.ArrayItems().push_back(JsonValue::String(image));
                report.Set("eager_initialization_order", std::move(order));
                report.Set("runtime_initialized", JsonValue::Boolean(false));
                report.Set("execution_validated", JsonValue::Boolean(false));
                report.Set("diagnostic", JsonValue::String(mapped.diagnostic));
                if(!emit_report(report))return 1;
                const auto* exit_status=mapped.bootstrap.Get("exit_status");
                const bool clean_protocol_exit=!report_path.empty()
                    &&mapped.bootstrap.GetString("stop_reason")=="exited"
                    &&exit_status&&exit_status->IsNumber()&&exit_status->Int(-1)==0;
                return (mapped.mapped&&(mode!="probe-cache-arm64"||clean_protocol_exit))?0:1;
            }
            const auto closure=DarwinClosure::Inspect(argv[3],plugins,trees,options);if(!emit_report(closure.ToJson()))return 1;return closure.analyzed?0:1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "inspect-closure") {
            if (argc < 6) { std::cerr << "Usage: openfruit runtime inspect-closure <virtual-server> <virtual-plugin-or-dash> <original-tree>...\n"; return 2; }
            std::vector<std::string> plugins; if (std::string(argv[4]) != "-") plugins.emplace_back(argv[4]);
            std::vector<fs::path> trees; for (int index = 5; index < argc; ++index) trees.emplace_back(Win32Process::ToWide(argv[index]));
            DarwinClosureOptions options;
            const auto result = DarwinClosure::Inspect(argv[3], plugins, trees, options);
            std::cout << result.ToJson().Serialize(true) << '\n';
            return result.analyzed ? 0 : 1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "run-arm64") {
            if (argc < 6) { std::cerr << "Usage: openfruit runtime run-arm64 <virtual-server> <symbol> <original-tree>...\n"; return 2; }
            std::vector<fs::path> trees; for (int index = 5; index < argc; ++index) trees.emplace_back(Win32Process::ToWide(argv[index]));
            const auto result = RunDarwinArm64Function(argv[3], trees, argv[4]);
            auto report = JsonValue::ObjectValue();
            report.Set("schema_version", JsonValue::Number("1"));
            report.Set("function_returned", JsonValue::Boolean(result.returned));
            report.Set("result_value", JsonValue::Number(std::to_string(result.value)));
            report.Set("runtime_initialized", JsonValue::Boolean(false));
            report.Set("plugin_execution_validated", JsonValue::Boolean(false));
            report.Set("diagnostic", JsonValue::String(result.diagnostic));
            std::cout << report.Serialize(true) << '\n'; return result.returned ? 0 : 1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "map-image") {
            if (argc < 5) { std::cerr << "Usage: openfruit runtime map-image <virtual-server> <original-tree>...\n"; return 2; }
            std::vector<fs::path> trees; for (int index = 4; index < argc; ++index) trees.emplace_back(Win32Process::ToWide(argv[index]));
            std::string error; const auto mapped = DarwinMappedImages::Load(argv[3], trees, error);
            auto report = JsonValue::ObjectValue();
            report.Set("schema_version", JsonValue::Number("1"));
            report.Set("mapped", JsonValue::Boolean(bool(mapped)));
            report.Set("mapped_image_count", JsonValue::Number(std::to_string(mapped ? mapped->ImageCount() : 0)));
            report.Set("applied_fixup_count", JsonValue::Number(std::to_string(mapped ? mapped->AppliedFixups() : 0)));
            auto initializers=JsonValue::ArrayValue();if(mapped)for(const auto& initializer:mapped->Initializers())initializers.ArrayItems().push_back(initializer.ToJson());
            report.Set("initializers",std::move(initializers));
            auto order=JsonValue::ArrayValue();if(mapped)for(const auto& image:mapped->EagerInitializationOrder())order.ArrayItems().push_back(JsonValue::String(image));
            report.Set("eager_initialization_order",std::move(order));
            report.Set("runtime_initialized", JsonValue::Boolean(false));
            report.Set("execution_validated", JsonValue::Boolean(false));
            report.Set("diagnostic", JsonValue::String(error));
            std::cout << report.Serialize(true) << '\n'; return mapped ? 0 : 1;
        }
        if (command == "runtime" && argc >= 3 && std::string(argv[2]) == "inspect-image") {
            if (argc != 4) { std::cerr << "Usage: openfruit runtime inspect-image <original-image>\n"; return 2; }
            const auto result = DarwinImageInventory::Inspect(fs::path(Win32Process::ToWide(argv[3])));
            std::cout << result.ToJson().Serialize(true) << '\n';
            return result.inspected ? 0 : 1;
        }
        if (command == "events") {
            if (argc < 4 || std::string(argv[2]) != "replay") {
                std::cerr << "Usage: openfruit events replay <journal-directory> [--after N] [--limit N]\n";
                return 2;
            }
            std::uint64_t after = 0;
            std::size_t limit = 1000;
            for (int i = 4; i < argc; ++i) {
                const std::string option = argv[i];
                if (option == "--after" && i + 1 < argc) after = std::stoull(argv[++i]);
                else if (option == "--limit" && i + 1 < argc) limit = std::stoull(argv[++i]);
                else { std::cerr << "Invalid event replay option\n"; return 2; }
            }
            std::string error;
            if (!EventJournal::Replay(fs::path(Win32Process::ToWide(argv[3])), after,
                                      std::min<std::size_t>(limit, 10000), std::cout, error)) {
                std::cerr << error << '\n';
                return 1;
            }
            return 0;
        }

        if (command == "auth" && argc >= 3 && std::string(argv[2]) == "cookies") {
            const bool importing = argc == 5 && std::string(argv[3]) == "import";
            const bool clearing = argc == 4 && std::string(argv[3]) == "clear";
            if (!importing && !clearing) {
                std::cerr << "Usage: openfruit auth cookies import <Netscape-cookie-file> | clear\n";
                return 2;
            }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "credential-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const Config settings = Config::Load();
            const fs::path metadata = settings.secrets_path.empty()
                ? ToolPaths::UserStateRoot() / "credentials" / "secrets.json" : fs::path(settings.secrets_path);
            Secrets credentials = Secrets::Load(metadata.wstring());
            if (clearing) {
                const bool cleared = AppleCookieStore::Clear(credentials, metadata);
                if (cleared) std::cout << "Stored Apple cookies disabled for future operations.\n";
                else std::cerr << "OpenFruit: cookie removal failed; previous credentials retained.\n";
                return cleared ? 0 : 1;
            }
            const auto result = AppleCookieStore::Import(credentials, fs::path(Win32Process::ToWide(argv[4])), metadata);
            if (!result.Succeeded()) std::cerr << "OpenFruit: cookie import failed; previous credentials retained.\n";
            else std::cout << "Apple cookies protected and stored (" << result.count
                           << " records). Authentication has not been verified.\n";
            return result.Succeeded() ? 0 : 1;
        }

        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "archive-members") {
            if (argc != 5) { std::cerr << "Usage: openfruit sdk archive-members <Xcode-xip-file> <literal-path-filter>\n"; return 2; }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const auto result = XipInventory::Inspect(fs::path(Win32Process::ToWide(argv[3])), argv[4]);
            std::cout << result.ToJson().Serialize(true) << '\n';
            return result.Complete() ? 0 : 1;
        }
        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "extract-members") {
            if (argc < 6) { std::cerr << "Usage: openfruit sdk extract-members <Xcode-xip-file> <new-directory> <member-path>...\n"; return 2; }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            std::vector<std::string> paths;
            for (int index = 5; index < argc; ++index) paths.emplace_back(argv[index]);
            const auto result = ArchiveTreeExtraction::ExtractMembers(fs::absolute(fs::path(Win32Process::ToWide(argv[3]))),
                fs::absolute(fs::path(Win32Process::ToWide(argv[4]))), paths);
            std::cout << result.ToJson().Serialize(true) << '\n';
            return result.Succeeded() ? 0 : 1;
        }
        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "extract-archive") {
            if (argc != 5) { std::cerr << "Usage: openfruit sdk extract-archive <Xcode-xip-file> <new-directory>\n"; return 2; }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const auto result = SDKArchiveExtraction::ExtractIos(fs::absolute(fs::path(Win32Process::ToWide(argv[3]))),
                fs::absolute(fs::path(Win32Process::ToWide(argv[4]))));
            std::cout << result.ToJson().Serialize(true) << '\n';
            return result.Succeeded() ? 0 : 1;
        }
        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "inspect-archive") {
            if (argc != 4) {
                std::cerr << "Usage: openfruit sdk inspect-archive <Xcode-xip-file>\n";
                return 2;
            }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const auto metadata = SDKArchiveMetadata::DiscoverIos(fs::path(Win32Process::ToWide(argv[3])));
            std::cout << metadata.ToJson().Serialize(true) << '\n';
            return metadata.Found() ? 0 : 1;
        }

        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "catalog") {
            if (argc > 4) { std::cerr << "Usage: openfruit sdk catalog [Xcode-version]\n"; return 2; }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const Config settings = Config::Load();
            const fs::path metadata = settings.secrets_path.empty()
                ? ToolPaths::UserStateRoot() / "credentials" / "secrets.json" : fs::path(settings.secrets_path);
            const Secrets credentials = Secrets::Load(metadata.wstring());
            AppleCookieJar cookies;
            AppleCatalogResult catalog;
            if (AppleCookieStore::Load(credentials, cookies))
                catalog = AppleDownloadCatalog::Fetch(cookies, {},
                    std::chrono::steady_clock::now() + std::chrono::seconds(45));
            else catalog.status = AppleCatalogStatus::CredentialsUnavailable;
            auto output = JsonValue::ObjectValue();
            output.Set("status", JsonValue::String(catalog.status == AppleCatalogStatus::Succeeded ? "succeeded" :
                catalog.status == AppleCatalogStatus::CredentialsUnavailable ? "credentials_unavailable" :
                catalog.status == AppleCatalogStatus::Unauthorized ? "unauthorized" :
                catalog.status == AppleCatalogStatus::InvalidResponse ? "invalid_response" :
                catalog.status == AppleCatalogStatus::Cancelled ? "cancelled" :
                catalog.status == AppleCatalogStatus::TimedOut ? "timed_out" : "transport_failure"));
            output.Set("origin_verified", JsonValue::Boolean(catalog.origin_verified));
            output.Set("http_status", JsonValue::Number(std::to_string(catalog.http_status)));
            output.Set("diagnostic_code", JsonValue::String(catalog.diagnostic_code));
            auto files = JsonValue::ArrayValue();
            const std::string selected = argc == 4 ? "Xcode " + std::string(argv[3]) : "";
            for (const auto& file : catalog.xip_files) {
                if (!selected.empty() && file.product_name != selected) continue;
                auto item = JsonValue::ObjectValue();
                item.Set("download_id", JsonValue::String(file.download_id));
                item.Set("product", JsonValue::String(file.product_name));
                item.Set("filename", JsonValue::String(file.filename));
                item.Set("bytes", JsonValue::Number(std::to_string(file.bytes)));
                files.ArrayItems().push_back(std::move(item));
            }
            output.Set("files", std::move(files));
            std::cout << output.Serialize(true) << '\n';
            return catalog.Succeeded() ? 0 : 1;
        }

        // SDK selection consumes persisted registrations, without bootstrapping
        // tools or loading signing credentials as a side effect.
        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "select") {
            if (argc != 4) {
                std::cerr << "Usage: openfruit sdk select <registered-version>\n";
                return 2;
            }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const fs::path configuration_path(Config::GetDefaultConfigPath());
            Config selection = Config::Load(configuration_path.wstring());
            const auto result = SDKSelection::Select(selection, Win32Process::ToWide(argv[3]), configuration_path);
            if (!result.Succeeded()) std::cerr << "OpenFruit: " << result.message << "\n";
            else std::cout << result.message << "\n";
            return result.Succeeded() ? 0 : 1;
        }

        // SDK removal unregisters SDKs, safely removes managed directories when not in active use,
        // and updates persisted configuration without side-effect bootstrapping.
        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "remove") {
            if (argc != 4) {
                std::cerr << "Usage: openfruit sdk remove <registered-version>\n";
                return 2;
            }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const fs::path configuration_path(Config::GetDefaultConfigPath());
            Config config_snapshot = Config::Load(configuration_path.wstring());
            const auto result = SDKRemoval::Remove(config_snapshot, Win32Process::ToWide(argv[3]), configuration_path);
            return ReportSDKRemoval(result);
        }

        if (command == "sdk" && argc >= 3 && std::string(argv[2]) == "cleanup") {
            if (argc != 4) {
                std::cerr << "Usage: openfruit sdk cleanup <retained-receipt-path>\n";
                return 2;
            }
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const auto result = SDKRemoval::Cleanup(fs::path(Win32Process::ToWide(argv[3])),
                fs::path(Config::GetDefaultConfigPath()));
            return ReportSDKRemoval(result);
        }

        // Discovery must not initialize credentials, mutate configuration or
        // bootstrap providers. It only inspects known native prerequisites.
        if (command == "sdk") {
            const std::string subcommand = argc >= 3 ? argv[2] : "path";
            if (subcommand == "list" || subcommand == "path") {
                if (argc > 3) {
                    std::cerr << "Usage: openfruit sdk [list|path]\n";
                    return 2;
                }
                SDKReadRequest request;
                request.configuration = Config::Load(Config::GetDefaultConfigPath(), false);
                request.managed_home = fs::path(request.configuration.OPENFRUIT_home);
                const DWORD capacity = GetEnvironmentVariableW(L"OPENFRUIT_IOS_SDK", nullptr, 0);
                if (capacity) {
                    std::wstring value(capacity, L'\0');
                    const DWORD length = GetEnvironmentVariableW(L"OPENFRUIT_IOS_SDK", value.data(), capacity);
                    // A present-but-empty variable is a valid absent override.
                    if (length >= capacity) {
                        std::cerr << "OpenFruit: SDK override changed while reading the request.\n";
                        return 1;
                    }
                    value.resize(length);
                    request.sdk_override = fs::path(value);
                }
                if (subcommand == "list") {
                    const auto result = SDKReadOperations::List(request);
                    if (const auto context = CurrentOperationContext()) context->Emit("sdk.list.snapshot", result.ToJson());
                    std::cout << "Configured iOS SDKs:\n";
                    for (const auto& item : result.entries) {
                        const auto& entry = item.catalog;
                        std::cout << "  " << Win32Process::ToNarrow(entry.registration.version)
                                  << (entry.selected ? " * " : "   ")
                                  << Win32Process::ToNarrow(entry.registration.path.wstring())
                                  << (entry.layout.Usable() ? "" : " [layout incomplete]") << '\n';
                    }
                    return 0;
                }
                const auto result = SDKReadOperations::Path(request);
                if (const auto context = CurrentOperationContext()) context->Emit("sdk.path.snapshot", result.ToJson());
                if (result.status == SDKReadStatus::Available) {
                    std::cout << Win32Process::ToNarrow(result.path.wstring()) << '\n';
                    return 0;
                }
                std::cerr << (result.status == SDKReadStatus::InvalidRequest
                    ? "OpenFruit: SDK query requires absolute input paths.\n"
                    : "No Apple SDK currently detected.\n");
                return result.status == SDKReadStatus::InvalidRequest ? 2 : 1;
            }
        }
        // Observation and bounded pruning use explicit snapshots and never
        // initialize tools, rewrite configuration or load credentials.
        if (command == "cache") {
            const std::string sub = argc >= 3 ? argv[2] : "status";
            if (sub == "status") {
                if (argc > 3) {
                    std::cerr << "Usage: openfruit cache [status]\n";
                    return 2;
                }
                const Config settings = Config::Load(Config::GetDefaultConfigPath(), false);
                CacheReadRequest request;
                request.user_state_root = fs::path(settings.user_state_root);
                request.managed_cache_root = fs::path(settings.cache_root);
                if (const auto context = CurrentOperationContext()) {
                    request.control.cancellation = std::shared_ptr<std::atomic<bool>>(
                        context->control, &context->control->cancellation_requested);
                    request.control.deadline = context->control->deadline;
                }
                const auto result = CacheReadOperations::Inspect(request);
                if (const auto context = CurrentOperationContext()) context->Emit("cache.status.snapshot", result.ToJson());
                std::cout << "OPENFRUIT cache/workspace observation (logical file lengths):\n";
                for (const auto& item : result.namespaces) {
                    std::cout << "  " << item.name << ": " << Win32Process::ToNarrow(item.path.wstring()) << '\n';
                    if (item.observed_logical_file_bytes)
                        std::cout << "    " << *item.observed_logical_file_bytes << " observed logical bytes";
                    else std::cout << "    size not measured";
                    std::cout << (item.measurement_complete ? " [complete within namespace]" : " [partial/unknown]") << '\n';
                }
                std::cout << "Bounded, non-atomic observation; physical/reclaimable space and consumer activity unknown.\n"
                             "All entries protected by this inventory; use the separate prune policy for eligible contexts.\n";
                if (result.status == CacheReadStatus::Cancelled) return 130;
                if (result.status == CacheReadStatus::TimedOut) return 124;
                if (result.status == CacheReadStatus::InvalidRequest) return 2;
                return result.error_count ? 1 : 0;
            }
            if (sub == "prune") {
                if (argc != 4) {
                    std::cerr << "Usage: openfruit cache prune <max-bytes-quota>\n";
                    return 2;
                }
                std::uint64_t max_bytes = 0;
                try {
                    const std::string quota = argv[3];
                    if (quota.empty() || quota.find_first_not_of("0123456789") != std::string::npos)
                        throw std::invalid_argument("Quota must contain decimal digits only");
                    max_bytes = std::stoull(argv[3]);
                } catch (...) {
                    std::cerr << "Invalid quota bytes specified.\n";
                    return 2;
                }
                const Config settings = Config::Load(Config::GetDefaultConfigPath(), false);
                const fs::path execution_dir =
                    (settings.user_state_root.empty() ? ToolPaths::UserStateRoot() : fs::path(settings.user_state_root)) / "c" / "v";
                // The managed cache contains installed SDK/provider inputs and
                // acquisition archives, not exclusively disposable artifacts.
                // Never prune its category directories as individual cache entries.
                // Legacy transactional import locks did not cover product consumers.
                // Resolver paths also remain accessible to older named-mutex users.
                // Only r2 contexts are exclusively consumed under lifetime leases.
                CachePruneOptions prune_options;
                prune_options.max_bytes_quota = max_bytes;
                prune_options.require_existing_consumer_lease = true;
                prune_options.eligible_entry = [](const fs::path& path) {
                    const auto name = path.filename().string();
                    return name.size() == 19 && name.starts_with("r2-") &&
                        name.find_first_not_of("0123456789abcdef", 3) == std::string::npos;
                };
                if (const auto context = CurrentOperationContext()) {
                    prune_options.control.cancellation = std::shared_ptr<std::atomic<bool>>(
                        context->control, &context->control->cancellation_requested);
                    prune_options.control.deadline = context->control->deadline;
                }
                const auto report = NativeArtifactStore::PruneCache(execution_dir, prune_options);
                std::cout << "Cache pruned: " << report.entries_removed << " entries removed, "
                          << (report.bytes_reclaimed / (1024 * 1024)) << " logical MB deleted (physical recovery may differ).\n";
                std::cout << "Managed SDK/provider/download caches, resolvers and legacy workspaces protected; quota applies to r2 execution contexts.\n"
                          << "Skipped: " << report.entries_skipped_in_use
                          << " in use, " << report.entries_skipped_unmanaged
                          << " outside the eligible format or without a participating consumer lease";
                if (report.entries_deferred_budget > 0) {
                    std::cout << ", " << report.entries_deferred_budget << " deferred by retention budget";
                }
                std::cout << ".\n";
                if (!report.success) std::cerr << report.error_message << "\n";
                if (report.cancelled) return 130;
                if (report.timed_out) return 124;
                return report.success ? 0 : 1;
            }
            if (sub == "compress") {
                const Config settings = Config::Load(Config::GetDefaultConfigPath(), false);
                fs::path target_dir;
                if (argc >= 4 && std::string(argv[3]) != "--all") {
                    target_dir = fs::absolute(Win32Process::ToWide(argv[3]));
                } else {
                    target_dir = settings.user_state_root.empty() ? ToolPaths::UserStateRoot() : fs::path(settings.user_state_root);
                }
                std::cout << "OPENFRUIT: Enabling transparent NTFS compression on cache directory: "
                          << Win32Process::ToNarrow(target_dir.wstring()) << "\n";
                const auto report = CacheCompressionManager::CompressDirectoryTree(target_dir, true, [](const std::string& msg) {
                    std::cout << "  " << msg << "\n";
                });
                if (!report.success) {
                    std::cerr << "OPENFRUIT Error: " << report.error_message << "\n";
                    return 1;
                }
                std::cout << "OPENFRUIT: Compression complete.\n"
                          << "  Directories configured for transparent compression: " << report.directories_configured << "\n"
                          << "  Files compressed: " << report.files_compressed << "\n"
                          << "  Original logical size: " << (report.uncompressed_bytes / (1024 * 1024)) << " MB\n";
                return 0;
            }
            if (sub == "pack") {
                if (argc < 4) {
                    std::cerr << "Usage: openfruit cache pack <project-or-target>\n";
                    return 2;
                }
                const std::string project_hint = argv[3];
                const Config settings = Config::Load(Config::GetDefaultConfigPath(), false);
                const fs::path user_state = settings.user_state_root.empty() ? ToolPaths::UserStateRoot() : fs::path(settings.user_state_root);
                std::cout << "OPENFRUIT: Packing cold cache for '" << project_hint << "'...\n";
                const auto report = CacheCompressionManager::PackProjectCache(user_state, project_hint);
                if (!report.success) {
                    std::cerr << "OPENFRUIT Error: " << report.error_message << "\n";
                    return 1;
                }
                std::cout << "OPENFRUIT: Cache successfully archived!\n"
                          << "  Archive path:   " << Win32Process::ToNarrow(report.archive_path.wstring()) << "\n"
                          << "  Original size:  " << (report.original_bytes / (1024 * 1024)) << " MB\n"
                          << "  Archived size:  " << (report.archive_bytes / (1024 * 1024)) << " MB\n"
                          << "  Disk space reclaimed: " << ((report.original_bytes > report.archive_bytes ? report.original_bytes - report.archive_bytes : 0) / (1024 * 1024)) << " MB\n";
                return 0;
            }
            if (sub == "unpack") {
                if (argc < 4) {
                    std::cerr << "Usage: openfruit cache unpack <project-or-target>\n";
                    return 2;
                }
                const std::string project_hint = argv[3];
                const Config settings = Config::Load(Config::GetDefaultConfigPath(), false);
                const fs::path user_state = settings.user_state_root.empty() ? ToolPaths::UserStateRoot() : fs::path(settings.user_state_root);
                std::cout << "OPENFRUIT: Unpacking cold cache for '" << project_hint << "'...\n";
                const auto report = CacheCompressionManager::UnpackProjectCache(user_state, project_hint);
                if (!report.success) {
                    std::cerr << "OPENFRUIT Error: " << report.error_message << "\n";
                    return 1;
                }
                std::cout << "OPENFRUIT: Cache restored successfully to active workspace.\n";
                return 0;
            }
            if (sub == "clean" || sub == "gc" || (sub == "prune" && argc == 3) || (sub == "prune" && argc == 4 && std::string(argv[3]) == "--all")) {
                const Config settings = Config::Load(Config::GetDefaultConfigPath(), false);
                const fs::path user_state = settings.user_state_root.empty() ? ToolPaths::UserStateRoot() : fs::path(settings.user_state_root);
                const fs::path managed_cache = settings.cache_root.empty() ? ToolPaths::CacheRoot() : fs::path(settings.cache_root);
                std::cout << "OPENFRUIT: Collecting garbage and pruning orphaned/stale caches (SwiftPM checkouts, Darwin staging, old diagnostics)...\n";
                const auto report = CacheCompressionManager::CollectGarbage(user_state, managed_cache, 3);
                std::cout << "OPENFRUIT: Garbage collection complete.\n"
                          << "  Entries removed: " << report.entries_removed << "\n"
                          << "  Reclaimed space: " << (report.bytes_reclaimed / (1024 * 1024)) << " MB ("
                          << (static_cast<double>(report.bytes_reclaimed) / (1024.0 * 1024.0 * 1024.0)) << " GB)\n";
                for (const auto& detail : report.details) {
                    std::cout << "    - " << detail << "\n";
                }
                return 0;
            }
            std::cerr << "Usage: openfruit cache [status|compress|pack|unpack|prune|clean]\n";
            return 1;
        }
        if ((command == "devices" || command == "device") &&
            std::any_of(argv + 2, argv + argc, [](const char* value) { return std::string(value) == "--native"; })) {
            bool json_output = false;
            for (int i = 2; i < argc; ++i) {
                const std::string option = argv[i];
                if (option == "--json") json_output = true;
                else if (option != "--native") {
                    std::cerr << "Usage: openfruit devices --native [--json]\n";
                    return 2;
                }
            }
            DeviceUsbmuxRequest request;
            if (const auto operation = CurrentOperationContext()) {
                request.control.cancellation = std::shared_ptr<std::atomic<bool>>(
                    operation->control, &operation->control->cancellation_requested);
                request.control.deadline = operation->control->deadline;
            }
            const auto result = DeviceUsbmux::ListDevices(request);
            const char* status = "transport_error";
            switch (result.status) {
            case DeviceUsbmuxStatus::Complete: status = "complete"; break;
            case DeviceUsbmuxStatus::Unavailable: status = "unavailable"; break;
            case DeviceUsbmuxStatus::Cancelled: status = "cancelled"; break;
            case DeviceUsbmuxStatus::TimedOut: status = "timed_out"; break;
            case DeviceUsbmuxStatus::InvalidRequest: status = "invalid_request"; break;
            case DeviceUsbmuxStatus::Unsupported: status = "unsupported"; break;
            case DeviceUsbmuxStatus::ProtocolError: status = "protocol_error"; break;
            case DeviceUsbmuxStatus::TransportError: break;
            }
            auto report = JsonValue::ObjectValue();
            report.Set("schema", JsonValue::String("openfruit.devices.v1"));
            report.Set("backend", JsonValue::String("native_usbmux"));
            report.Set("status", JsonValue::String(status));
            report.Set("native_error", JsonValue::Number(std::to_string(result.native_error)));
            report.Set("daemon_result", JsonValue::Number(std::to_string(result.daemon_result)));
            report.Set("error", JsonValue::String(result.error));
            auto devices = JsonValue::ArrayValue();
            for (const auto& device : result.devices) {
                auto item = JsonValue::ObjectValue();
                item.Set("udid", JsonValue::String(device.udid));
                item.Set("device_id", JsonValue::Number(std::to_string(device.device_id)));
                item.Set("product_id", JsonValue::Number(std::to_string(device.product_id)));
                item.Set("connection", JsonValue::String(device.connection_type));
                devices.ArrayItems().push_back(std::move(item));
            }
            report.Set("devices", std::move(devices));
            if (const auto operation = CurrentOperationContext()) operation->Emit("device.discovery.result", report);
            if (json_output) std::cout << report.Serialize(true) << '\n';
            else if (result.status == DeviceUsbmuxStatus::Complete) {
                std::cout << "Native usbmux devices: " << result.devices.size() << '\n';
                for (const auto& device : result.devices)
                    std::cout << "  " << device.udid << " (" << device.connection_type << ")\n";
            } else std::cerr << "OPENFRUIT native discovery: " << status << ": " << result.error << '\n';
            if (result.status == DeviceUsbmuxStatus::Cancelled) return 130;
            if (result.status == DeviceUsbmuxStatus::TimedOut) return 124;
            if (result.status == DeviceUsbmuxStatus::InvalidRequest) return 2;
            if (result.status == DeviceUsbmuxStatus::Unavailable || result.status == DeviceUsbmuxStatus::Unsupported) return 3;
            return result.status == DeviceUsbmuxStatus::Complete ? 0 : 1;
        }
        if (command == "capabilities") {
            const auto capabilities = Capabilities::Query();
            if (const auto context = CurrentOperationContext()) context->Emit("capabilities.snapshot", capabilities);
            std::cout << capabilities.Serialize(true) << "\n";
            return 0;
        }
        if (command == "info") {
            const unsigned int cores = SystemInfo::GetOptimalThreadCount();
            const std::wstring info_repo_root = SystemInfo::DiscoverRepoRoot();
            std::cout << "OPENFRUIT System & Hardware Topology:\n"
                      << "  Detected CPU Cores:      " << cores << "\n"
                      << "  Repository / Root Path:  " << Win32Process::ToNarrow(info_repo_root) << "\n"
                      << "  System Directory:        " << Win32Process::ToNarrow(SystemInfo::GetSystem32Directory()) << "\n"
                      << "  WSL Executable:          " << Win32Process::ToNarrow(SystemInfo::GetWslExecutable()) << "\n"
                      << "  WSL Available:           " << (WSLBridge::IsWslAvailable() ? "YES" : "NO") << "\n"
                      << "  OPENFRUIT Home:            " << ToolPaths::LocalHome().string() << "\n"
                      << "  User State:              " << ToolPaths::UserStateRoot().string() << "\n"
                      << "  Cache Root:              " << ToolPaths::CacheRoot().string() << "\n"
                      << "  Config File:             " << Win32Process::ToNarrow(Config::GetDefaultConfigPath()) << "\n";
            return 0;
        }
        if (command == "inspect") {
            if (argc < 3) {
                std::cerr << "Usage: openfruit inspect <project-path> [--configuration <Debug|Release>] [--json]\n";
                return 2;
            }
            std::wstring project_path = Win32Process::ToWide(argv[2]);
            std::string config_name = "Debug";
            ProjectInspectionRequest inspection_request;
            inspection_request.path = fs::absolute(project_path);
            fs::path inspection_target_project;
            bool json_output = false;
            for (int i = 3; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--json") json_output = true;
                else if (arg == "--configuration" && i + 1 < argc) {
                    config_name = argv[++i];
                    inspection_request.configuration = config_name;
                } else if ((arg == "--scheme" || arg == "--target-id" || arg == "--target-project") && i + 1 < argc) {
                    const std::string value = argv[++i];
                    if (arg == "--scheme") {
                        if (inspection_request.scheme) return 2;
                        const fs::path path(Win32Process::ToWide(value));
                        inspection_request.scheme = path.has_parent_path()
                            ? Win32Process::ToNarrow(fs::absolute(path).lexically_normal().wstring()) : value;
                    } else if (arg == "--target-id") {
                        if (inspection_request.target) return 2;
                        inspection_request.target = ProjectTargetSelection{{}, value};
                    } else inspection_target_project = fs::absolute(Win32Process::ToWide(value)).lexically_normal();
                } else { std::cerr << "OPENFRUIT: invalid or incomplete inspect option: " << arg << '\n'; return 2; }
            }
            if (!inspection_target_project.empty()) {
                if (!inspection_request.target) { std::cerr << "OPENFRUIT: --target-project requires --target-id.\n"; return 2; }
                inspection_request.target->project = inspection_target_project;
            }
            const auto result = inspection_request.scheme || inspection_request.target
                ? ProjectInspection::Inspect(inspection_request) : ProjectInspection::Inspect(project_path, config_name);
            if (json_output) {
                std::cout << result.ToJson().Serialize(true) << "\n";
                return result.success ? 0 : 1;
            }
            if (!result.success) {
                std::cerr << "OpenFruit: " << result.error_message << "\n";
                return 1;
            }
            const auto& proj = result.project;
            std::cout << "Project:           " << Win32Process::ToNarrow(proj.project_name) << "\n"
                      << "Product:           " << Win32Process::ToNarrow(proj.product_name) << "\n"
                      << "Module:            " << Win32Process::ToNarrow(proj.module_name) << "\n"
                      << "Bundle ID:         " << Win32Process::ToNarrow(proj.bundle_id) << "\n"
                      << "Minimum OS:        iOS " << Win32Process::ToNarrow(proj.minimum_os_version) << "\n"
                      << "Configuration:     " << Win32Process::ToNarrow(proj.configuration) << "\n"
                      << "Swift Sources:     " << proj.swift_sources.size() << "\n"
                      << "C/ObjC Sources:    " << proj.c_sources.size() << "\n"
                      << "System Frameworks: " << proj.system_frameworks.size() << "\n";
            return 0;
        }
        if (command == "config") {
            if (argc < 3) {
                std::cout << "Usage: openfruit config <get|set|list> [key] [value]\n";
                return 1;
            }
            Config config = Config::Load(Config::GetDefaultConfigPath(), false);
            std::string sub = argv[2];
            if (sub == "list") {
                std::cout << "OPENFRUIT Configuration:\n"
                          << "  paths.home:              " << config.GetValue("paths.home") << "\n"
                          << "  paths.user_state:        " << config.GetValue("paths.user_state") << "\n"
                          << "  paths.cache:             " << config.GetValue("paths.cache") << "\n"
                          << "  sdk.ios.path:            " << config.GetValue("sdk.ios.path") << "\n"
                          << "  sdk.ios.version:         " << config.GetValue("sdk.ios.version") << "\n"
                          << "  sdk.xcode.path:          " << config.GetValue("sdk.xcode.path") << "\n"
                          << "  toolchains.swift:        " << config.GetValue("toolchains.swift") << "\n"
                          << "  toolchains.llvm:         " << config.GetValue("toolchains.llvm") << "\n"
                          << "  tools.git:               " << config.GetValue("tools.git") << "\n"
                          << "  tools.zsign:             " << config.GetValue("tools.zsign") << "\n"
                          << "  tools.pymobiledevice3:   " << config.GetValue("tools.pymobiledevice3") << "\n"
                          << "  secrets.file:            " << config.GetValue("secrets.file") << "\n"
                          << "  certificates_dir:        " << config.GetValue("secrets.certificates_dir") << "\n"
                          << "  signing.p12:             " << config.GetValue("signing.p12") << "\n"
                          << "  signing.profile:         " << config.GetValue("signing.provisioning_profile") << "\n"
                          << "  signing.password_dpapi:  " << config.GetValue("signing.password_dpapi") << "\n"
                          << "  apple_id:                " << config.GetValue("apple_id") << "\n"
                          << "  default_bundle_id:       " << config.GetValue("build.default_bundle_id") << "\n"
                          << "  default_jobs:            " << config.GetValue("build.default_jobs") << "\n";
                return 0;
            } else if (sub == "get" && argc >= 4) {
                std::cout << argv[3] << " = " << config.GetValue(argv[3]) << "\n";
                return 0;
            } else if (sub == "set" && argc >= 5) {
                config.SetValue(argv[3], argv[4]);
                config.Save();
                std::cout << "Configuration updated: " << argv[3] << " = " << argv[4] << "\n";
                return 0;
            }
            return 1;
        }
        std::wstring repo_root = SystemInfo::DiscoverRepoRoot();
        Config config = Config::Load();
        config.AutoDiscover(repo_root);
        config.ApplyEnvironment();

        const bool requires_credentials =
            command == "auth" || command == "login" ||
            command == "certs" || command == "profiles" ||
            command == "run" ||
            command == "build";
        Secrets secrets;
        if (requires_credentials) {
            secrets = Secrets::Load(config.secrets_path);
            if (!config.signing_p12_path.empty()) secrets.signing_p12_path = config.signing_p12_path;
            if (!config.signing_profile_path.empty()) secrets.signing_profile_path = config.signing_profile_path;
            if (!config.signing_password_dpapi_path.empty()) secrets.signing_password = L"DPAPI:" + config.signing_password_dpapi_path;
            secrets.AutoDiscover(repo_root, config.secrets_path);
            bool signing_config_changed = false;
            if (config.signing_p12_path.empty() && !secrets.signing_p12_path.empty()) { config.signing_p12_path = secrets.signing_p12_path; signing_config_changed = true; }
            if (config.signing_profile_path.empty() && !secrets.signing_profile_path.empty()) { config.signing_profile_path = secrets.signing_profile_path; signing_config_changed = true; }
            if (config.signing_password_dpapi_path.empty() && secrets.signing_password.rfind(L"DPAPI:", 0) == 0) { config.signing_password_dpapi_path = secrets.signing_password.substr(6); signing_config_changed = true; }
            if (signing_config_changed) config.Save();
        }

    // 3. AUTH COMMAND
    if (command == "auth") {
        if (argc == 3 && std::string(argv[2]) == "login") {
            const fs::path metadata = config.secrets_path.empty()
                ? ToolPaths::UserStateRoot() / "credentials" / "secrets.json" : fs::path(config.secrets_path);
            const auto result = BrowserAppleAuth::Login(secrets, fs::absolute(metadata));
            if (!result.Succeeded()) std::cerr << "OpenFruit: Apple browser login failed: " << result.detail << "\n";
            else std::cout << "OpenFruit: Apple Developer session verified and protected.\n";
            return result.Succeeded() ? 0 : 1;
        }
        std::cout << "Usage: openfruit auth login\n";
        return 1;
    }

    // 4. SDK COMMAND
    if (command == "sdk") {
        std::string sub = argc >= 3 ? argv[2] : "path";
        if (sub == "download") {
            if (argc != 4) { std::cerr << "Usage: openfruit sdk download <Xcode-version>\n"; return 2; }
            std::string version = argv[3];
            if (!journal) {
                journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "sdk-events");
                journal_binding = std::make_unique<OperationBinding>(journal->Context());
            }
            const auto result = SDKAcquisition::Download(version, ToolPaths::LocalHome());
            if (!result.Succeeded()) std::cerr << "OpenFruit: " << result.message << "\n";
            else std::cout << "Installed iOS SDK: " << Win32Process::ToNarrow(result.destination.wstring()) << "\n";
            return result.Succeeded() ? 0 : 1;
        }
    }


    // 5. DOCTOR / BOOTSTRAP COMMANDS
    if (command == "doctor" || command == "bootstrap") {
        const bool install = command == "bootstrap";
        if (install) {
            std::cout << "Running OPENFRUIT bootstrap...\n";
        } else {
            std::cout << "Running OPENFRUIT Environment Health Check...\n";
        }
        const BootstrapResult bootstrap = EnvironmentManager::CheckAndBootstrap(
            fs::path(repo_root), config, install, true);
        return bootstrap.build_ready ? 0 : 1;
    }

    // 5b. UPDATE-DEPENDENCY COMMAND (Automated tool installation, progress tracking, and PATH registration)
    if (command == "update-dependency" || command == "update-dependencies") {
        bool json_output = false;
        bool silent = true;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--json") json_output = true;
            else if (arg == "--verbose") silent = false;
        }

        if (!json_output) {
            std::cout << "OpenFruit: Checking and updating system dependencies...\n";
        }
        auto progress_callback = [json_output](const DependencyProgress& p) {
            if (json_output) return;
            std::cout << "  [" << p.tool_name << "] " << p.phase;
            if (p.total_bytes > 0) {
                int pct = static_cast<int>((p.current_bytes * 100) / p.total_bytes);
                std::cout << " (" << pct << "% - "
                          << (p.current_bytes / (1024 * 1024)) << "/"
                          << (p.total_bytes / (1024 * 1024)) << " MB)";
            }
            if (!p.message.empty()) {
                std::cout << ": " << p.message;
            }
            std::cout << "\n";
        };

        const auto update_res = DependencyUpdater::UpdateAll(config, silent, progress_callback);

        if (json_output) {
            std::cout << update_res.ToJson().Serialize(true) << "\n";
            return update_res.success ? 0 : 1;
        }

        std::cout << "\nDependency update finished:\n";
        if (!update_res.path_entries_added.empty()) {
            std::cout << "  New directories registered in Windows PATH:\n";
            for (const auto& pe : update_res.path_entries_added) {
                std::cout << "    + " << pe << "\n";
            }
        }
        if (!update_res.updated_tools.empty()) {
            std::cout << "  Tools installed/updated:\n";
            for (const auto& ut : update_res.updated_tools) {
                std::cout << "    * " << ut << "\n";
            }
        }
        if (!update_res.errors.empty()) {
            std::cerr << "  Errors encountered:\n";
            for (const auto& err : update_res.errors) {
                std::cerr << "    ! " << err << "\n";
            }
            return 1;
        }
        std::cout << "  All dependencies are verified and available in PATH.\n";
        return 0;
    }


    // 6. BUILD COMMAND
    if (command == "build" || command == "package") {
        if (argc < 3) {
            PrintUsage();
            return 1;
        }

        std::string target_path = argv[2];
        fs::path abs_target = fs::absolute(Win32Process::ToWide(target_path));
        unsigned int jobs = config.default_jobs > 0 ? config.default_jobs : SystemInfo::GetOptimalThreadCount();
        bool deploy = false;
        bool preview = false;
        std::wstring udid = L"";
        std::wstring configuration = L"debug";
        ProjectInspectionRequest selection_request;
        selection_request.path = abs_target;
        bool configuration_explicit = false;
        bool action_explicit = false;
        fs::path target_project;
        std::wstring override_sdk = config.sdk_path;
        std::wstring override_sdk_version = config.ios_sdk_version;
        std::wstring override_cache;
        std::wstring override_bundle_id = L"";
        std::wstring override_display_name = L"";
        std::wstring override_p12 = secrets.signing_p12_path;
        std::wstring override_prov = secrets.signing_profile_path;
        bool sdk_override_explicit = false;
        bool cache_override_explicit = false;
        bool p12_override_explicit = false;
        bool provisioning_override_explicit = false;
        bool match_profile_bundle_id = false;
        bool pack_cache = false;
        // Parse command-line overrides before bootstrap so dependency validation
        // sees the exact environment requested by the user. CLI always has
        // precedence over config/managed auto-discovery.
        std::unordered_map<std::string, std::string> command_line_settings;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--scheme" || arg == "--target-id" || arg == "--target-project" || arg == "--build-for") {
                if (i + 1 >= argc || std::string(argv[i + 1]).starts_with("--")) {
                    std::cerr << "OPENFRUIT: missing value for " << arg << "\n";
                    return 2;
                }
                const std::string value = argv[++i];
                if (arg == "--scheme") {
                    if (selection_request.scheme) { std::cerr << "OPENFRUIT: duplicate --scheme.\n"; return 2; }
                    const fs::path path(Win32Process::ToWide(value));
                    selection_request.scheme = path.has_parent_path()
                        ? Win32Process::ToNarrow(fs::absolute(path).lexically_normal().wstring()) : value;
                } else if (arg == "--target-id") {
                    if (selection_request.target) { std::cerr << "OPENFRUIT: duplicate --target-id.\n"; return 2; }
                    selection_request.target = ProjectTargetSelection{{}, value};
                } else if (arg == "--target-project") {
                    if (!target_project.empty()) { std::cerr << "OPENFRUIT: duplicate --target-project.\n"; return 2; }
                    target_project = fs::absolute(Win32Process::ToWide(value)).lexically_normal();
                } else {
                    if (action_explicit) { std::cerr << "OPENFRUIT: duplicate --build-for.\n"; return 2; }
                    action_explicit = true;
                    if (value == "running") selection_request.action = ProjectBuildAction::Running;
                    else if (value == "testing") selection_request.action = ProjectBuildAction::Testing;
                    else if (value == "profiling") selection_request.action = ProjectBuildAction::Profiling;
                    else if (value == "analyzing") selection_request.action = ProjectBuildAction::Analyzing;
                    else if (value == "archiving") selection_request.action = ProjectBuildAction::Archiving;
                    else { std::cerr << "OPENFRUIT: unsupported --build-for purpose.\n"; return 2; }
                }
                continue;
            }
            if ((arg == "--configuration" || arg == "-c") &&
                (i + 1 >= argc || std::string(argv[i + 1]).starts_with("-"))) {
                std::cerr << "OPENFRUIT: missing configuration value.\n";
                return 2;
            }
            if ((arg == "--jobs" || arg == "-j") && i + 1 < argc) {
                jobs = (unsigned int)std::stoi(argv[++i]);
            } else if (arg.rfind("-j", 0) == 0 && arg.size() > 2) {
                jobs = (unsigned int)std::stoi(arg.substr(2));
            } else if (arg.rfind("--jobs=", 0) == 0 && arg.size() > 7) {
                jobs = (unsigned int)std::stoi(arg.substr(7));
            } else if ((arg == "--configuration" || arg == "-c") && i + 1 < argc) {
                if (configuration_explicit) { std::cerr << "OPENFRUIT: duplicate configuration.\n"; return 2; }
                configuration_explicit = true;
                std::string cfg_val = argv[++i];
                if (cfg_val.empty()) { std::cerr << "OPENFRUIT: empty configuration value.\n"; return 2; }
                selection_request.configuration = cfg_val;
                std::string lower_cfg = cfg_val;
                std::transform(lower_cfg.begin(), lower_cfg.end(), lower_cfg.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (lower_cfg == "debug") {
                    configuration = L"debug";
                } else if (lower_cfg == "release") {
                    configuration = L"release";
                } else {
                    configuration = Win32Process::ToWide(cfg_val);
                }
            } else if (arg == "--deploy") {
                deploy = true;
            } else if (arg == "--preview") {
                preview = true;
            } else if ((arg == "--udid" || arg == "--device") && i + 1 < argc) {
                udid = Win32Process::ToWide(argv[++i]);
            } else if (arg == "--sdk-path" && i + 1 < argc) {
                /*
                 * Package and compiler subprocesses run from package-specific
                 * working directories.  Freeze an explicit SDK override as an
                 * absolute path at the CLI boundary so its meaning cannot
                 * change when those subprocesses are launched.
                 */
                override_sdk = fs::absolute(
                    Win32Process::ToWide(argv[++i])
                ).lexically_normal().wstring();
                sdk_override_explicit = true;
            } else if ((arg == "--sdk" || arg == "-sdk") && i + 1 < argc) {
                sdk_override_explicit = true;
                const std::string sdk_raw = argv[++i];
                const std::wstring sdk_wide = Win32Process::ToWide(sdk_raw);
                if (fs::exists(sdk_wide) || sdk_raw.find('/') != std::string::npos || sdk_raw.find('\\') != std::string::npos) {
                    override_sdk = fs::absolute(sdk_wide).lexically_normal().wstring();
                } else {
                    override_sdk_version = sdk_wide;
                    auto configured = config.ios_sdk_paths.find(override_sdk_version);
                    std::wstring version_slot = override_sdk_version;
                    const std::size_t dot = version_slot.find(L'.');
                    if (configured == config.ios_sdk_paths.end() && dot != std::wstring::npos) {
                        version_slot = version_slot.substr(0, dot);
                        configured = config.ios_sdk_paths.find(version_slot);
                    }
                    if (configured != config.ios_sdk_paths.end()) {
                        override_sdk = configured->second;
                    } else {
                        const fs::path managed = ToolPaths::LocalHome() / "sdk" / "ios" / version_slot / "iPhoneOS.sdk";
                        override_sdk = managed.wstring();
                    }
                }
            } else if (arg == "--sdk-version" && i + 1 < argc) {
                sdk_override_explicit = true;
                override_sdk_version = Win32Process::ToWide(argv[++i]);

                auto configured = config.ios_sdk_paths.find(override_sdk_version);
                std::wstring version_slot = override_sdk_version;
                const std::size_t dot = version_slot.find(L'.');
                if (configured == config.ios_sdk_paths.end() && dot != std::wstring::npos) {
                    version_slot = version_slot.substr(0, dot);
                    configured = config.ios_sdk_paths.find(version_slot);
                }

                if (configured != config.ios_sdk_paths.end()) {
                    override_sdk = configured->second;
                } else {
                    const fs::path managed = ToolPaths::LocalHome() / "sdk" / "ios" / version_slot / "iPhoneOS.sdk";
                    override_sdk = managed.wstring();
                }
            } else if (arg == "--cache-path" && i + 1 < argc) {
                override_cache = fs::absolute(
                    Win32Process::ToWide(argv[++i])).lexically_normal().wstring();
                cache_override_explicit = true;
            } else if (arg == "--bundle-id" && i + 1 < argc) {
                override_bundle_id = Win32Process::ToWide(argv[++i]);
            } else if (arg == "--match-profile" || arg == "--rebind-bundle-id") {
                match_profile_bundle_id = true;
            } else if (arg == "--pack-cache") {
                pack_cache = true;
            } else if (arg == "--display-name" && i + 1 < argc) {
                override_display_name = Win32Process::ToWide(argv[++i]);
            } else if (arg == "--p12" && i + 1 < argc) {
                override_p12 = Win32Process::ToWide(argv[++i]);
                p12_override_explicit = true;
            } else if (arg == "--provision" && i + 1 < argc) {
                override_prov = Win32Process::ToWide(argv[++i]);
                provisioning_override_explicit = true;
            } else if (const auto equals = arg.find('='); equals != std::string::npos && equals > 0 &&
                       std::all_of(arg.begin(), arg.begin() + static_cast<std::ptrdiff_t>(equals), [](char c) {
                           return std::isupper(static_cast<unsigned char>(c)) || std::isdigit(static_cast<unsigned char>(c)) || c == '_';
                       }) && !std::isdigit(static_cast<unsigned char>(arg[0]))) {
                // xcodebuild-style build setting override: NAME=value.
                command_line_settings[arg.substr(0, equals)] = arg.substr(equals + 1);
            }
        }
        XcodeProject::SetCommandLineBuildSettings(command_line_settings);

        if (!target_project.empty()) {
            if (!selection_request.target) { std::cerr << "OPENFRUIT: --target-project requires --target-id.\n"; return 2; }
            selection_request.target->project = target_project;
        }
        if (action_explicit && !selection_request.scheme) {
            std::cerr << "OPENFRUIT: --build-for requires --scheme.\n";
            return 2;
        }

        if (command == "package" && (deploy || p12_override_explicit || provisioning_override_explicit)) {
            std::cerr << "OPENFRUIT: package produces an unsigned IPA; signing/deploy options require build or sign.\n";
            return 2;
        }

        BuildRequest request;
        request.project = selection_request;
        request.mode = command == "package" ? BuildProductMode::UnsignedPackage : BuildProductMode::BuildAndSign;
        request.configuration = configuration;
        request.jobs = jobs;
        if (sdk_override_explicit) {
            request.sdk_path = override_sdk;
            request.sdk_version = override_sdk_version;
        }
        if (cache_override_explicit) request.cache_path = override_cache;
        if (!override_bundle_id.empty()) request.bundle_id = override_bundle_id;
        if (!override_display_name.empty()) request.display_name = override_display_name;
        if (p12_override_explicit) request.p12_path = override_p12;
        if (provisioning_override_explicit) request.provisioning_profile_path = override_prov;
        request.match_profile_bundle_id = match_profile_bundle_id;
        request.deploy = deploy;
        request.preview = preview;
        request.pack_cache = pack_cache;
        request.device_udid = udid;
        const BuildContext context{fs::path(repo_root), config, secrets, CurrentOperationContext(), journal};
        const auto result = ApplicationService::Build(request, context);
        if (const auto operation = CurrentOperationContext())
            operation->Emit("application.build.result", result.ToJson());
        return result.exit_code;
    }

    // 7. DEPLOY ONLY COMMAND
    if (command == "deploy") {
        const BootstrapResult bootstrap = EnvironmentManager::CheckAndBootstrap(
            fs::path(repo_root), config, false, false);
        if (!bootstrap.deploy_ready) {
            std::cerr << "OpenFruit: deployment tooling is incomplete. Run 'OPENFRUIT bootstrap'.\n";
            return 1;
        }
        std::wstring ipa;
        std::wstring udid;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--udid" && i + 1 < argc) {
                udid = Win32Process::ToWide(argv[++i]);
            } else if (!arg.empty() && arg[0] != '-') {
                if (ipa.empty()) ipa = Win32Process::ToWide(arg);
            }
        }
        if (ipa.empty()) {
            std::cout << "Usage: openfruit deploy <ipa-path> [--udid <ID>]\n";
            return 1;
        }
        bool ok = DeviceDeployer::Deploy(repo_root, ipa, udid);
        return ok ? 0 : 1;
    }

    // 8. DEVICES LIST COMMAND
    if (command == "devices" || (command == "device" && argc <= 2)) {
        bool json_mode = false;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--json" || arg == "--diagnostics=json") {
                json_mode = true;
            }
        }
        auto devices = DeviceDeployer::ListDevices(repo_root);
        if (json_mode) {
            auto arr = JsonValue::ArrayValue();
            for (const auto& dev : devices) {
                auto obj = JsonValue::ObjectValue();
                obj.Set("udid", JsonValue::String(dev.udid));
                obj.Set("name", JsonValue::String(dev.name));
                obj.Set("connection", JsonValue::String(dev.connection_type));
                arr.ArrayItems().push_back(std::move(obj));
            }
            std::cout << arr.Serialize(true) << "\n";
            return 0;
        }

        std::cout << "Connected iOS Devices (" << devices.size() << " found):\n";
        if (devices.empty()) {
            std::cout << "  No connected iOS devices detected via USB or network.\n";
        } else {
            for (const auto& dev : devices) {
                std::cout << "  - " << dev.name << " (" << dev.connection_type << "): " << dev.udid << "\n";
            }
        }
        return 0;
    }

    // 9. VERIFY IPA COMMAND
    if (command == "verify" || command == "verify-ipa") {
        if (argc < 3) {
            std::cerr << "Usage: openfruit verify <path-to-ipa> [--json]\n";
            return 2;
        }
        fs::path ipa_path = Utf8Path(argv[2]);
        if (!fs::exists(ipa_path)) {
            std::cerr << "OPENFRUIT: IPA archive not found: " << argv[2] << "\n";
            return 1;
        }
        bool json_mode = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--json") json_mode = true;
        }
        IpaVerificationRequest req;
        req.archive = ipa_path;
        auto res = VerifyIpa(req);
        if (json_mode) {
            std::cout << res.ToJson().Serialize(true) << "\n";
        } else {
            std::cout << "IPA Verification: "
                      << IpaVerificationStatusName(res.status) << "\n";
            std::cout << "  Archive size: " << res.archive_bytes << " bytes\n";
            std::cout << "  Decoded size: " << res.decoded_bytes << " bytes\n";
            std::cout << "  Members checked: " << res.members_verified << "\n";
            for (const auto& m : res.images) {
                std::cout << "  Mach-O: " << m.member << "\n";
                std::cout << "    Identifier: " << m.signature.identifier << "\n";
                std::cout << "    CDHash: " << m.signature.primary_cdhash << "\n";
                std::cout << "    Code Pages Verified: " << (m.signature.code_pages_verified ? "Yes" : "No") << "\n";
                std::cout << "    Special Slots Verified: " << (m.signature.special_slots_verified ? "Yes" : "No") << "\n";
                std::cout << "    CMS Present: " << (m.signature.cms_present ? "Yes" : "No") << "\n";
                std::cout << "    CMS Signature Valid: " << (m.signature.cms_signature_verified ? "Yes" : "No") << "\n";
            }
            if (!res.issues.empty()) {
                std::cout << "  Issues:\n";
                for (const auto& issue : res.issues) {
                    std::cout << "    - [" << issue.code << "] " << issue.message;
                    if (!issue.member.empty()) std::cout << " (" << issue.member << ")";
                    std::cout << "\n";
                }
            }
        }
        return res.status == IpaVerificationStatus::IntegrityVerified ? 0 : 1;
    }

    // 10. DEVICE COMMAND SUITE (deploy, log, screenshot, record, debug, info)
    if (command == "device") {
        if (argc < 3) {
            std::cout << "Usage: openfruit device <info|log|screenshot|record|debug|install|launch|preview> [options]\n"
                      << "  info                         Query connected device parameters\n"
                      << "  log                          Stream real-time syslog from device\n"
                      << "  screenshot <out.png>         Capture device screenshot\n"
                      << "  record <out-dir> [--duration <sec>] Capture screen recording frames\n"
                      << "  debug [--port <port>]        Start local LLDB debug proxy (default 10567)\n"
                      << "  install <path.ipa>           Install IPA natively on device\n"
                      << "  launch <bundle-id>           Launch application on device\n"
                      << "\nOptions:\n"
                      << "  --device <udid>              Select specific device UDID\n"
                      << "  --wifi <ip-or-host>          Connect directly to device over Wi-Fi\n";
            return 2;
        }

        std::string subcmd = argv[2];
        if (subcmd == "help" || subcmd == "--help" || subcmd == "-h") {
            std::cout << "Usage: openfruit device <info|log|screenshot|record|debug|install|launch|preview> [options]\n"
                      << "  info                         Query connected device parameters\n"
                      << "  log                          Stream real-time syslog from device\n"
                      << "  screenshot <out.png>         Capture device screenshot\n"
                      << "  record <out-dir> [--duration <sec>] Capture screen recording frames\n"
                      << "  debug [--port <port>]        Start local LLDB debug proxy (default 10567)\n"
                      << "  install <path.ipa>           Install IPA natively on device\n"
                      << "  launch <bundle-id>           Launch application on device\n"
                      << "\nOptions:\n"
                      << "  --device <udid>              Select specific device UDID\n"
                      << "  --wifi <ip-or-host>          Connect directly to device over Wi-Fi\n";
            return 0;
        }
        std::string target_udid;
        std::string wifi_host;
        std::string extra_arg;
        uint16_t debug_port = 10567;
        uint32_t record_duration = 10;

        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--device" || arg == "--udid") && i + 1 < argc) {
                target_udid = argv[++i];
            } else if (arg == "--wifi" && i + 1 < argc) {
                wifi_host = argv[++i];
            } else if (arg == "--port" && i + 1 < argc) {
                debug_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else if (arg == "--duration" && i + 1 < argc) {
                record_duration = static_cast<uint32_t>(std::stoi(argv[++i]));
            } else if (extra_arg.empty() && !arg.starts_with("-")) {
                extra_arg = arg;
            }
        }

        DeviceTarget target;
        if (!wifi_host.empty()) {
            target.mode = DeviceTransportMode::WiFi;
            target.host = wifi_host;
            target.port = 62078;
            target.udid = "wifi-" + wifi_host;
        } else {
            target.mode = DeviceTransportMode::Usb;
            target.udid = target_udid;
        }

        DeviceSession session(target);
        std::string err;
        if (!session.Connect(err)) {
            std::cerr << "OPENFRUIT: Failed to connect to device: " << err << "\n";
            return 1;
        }

        std::string session_id;
        auto record = DeviceUsbmux::LoadPairingRecord(target.udid);
        if (record.is_valid && !session.StartSession(record, session_id, err)) {
            std::cerr << "OPENFRUIT: Lockdown session failed: " << err << "\n";
            return 1;
        }

        if (subcmd == "preview") {
            // Binary stream on stdout (see native/preview-agent); status on stderr.
            _setmode(_fileno(stdout), _O_BINARY);
            std::atomic<bool> cancel = false;
            const bool ok = session.StreamPreview(kPreviewAgentPort, [](const char* data, std::size_t size) {
                return std::fwrite(data, 1, size, stdout) == size && std::fflush(stdout) == 0;
            }, cancel, err);
            if (!ok) std::cerr << "OPENFRUIT: preview failed: " << err << "\n";
            return ok ? 0 : 1;
        }

        if (subcmd == "info") {
            std::string dev_name;
            session.GetValue("DeviceName", dev_name, err);
            std::string dev_os;
            session.GetValue("ProductVersion", dev_os, err);
            std::string dev_model;
            session.GetValue("ProductType", dev_model, err);
            std::cout << "Connected Device Info:\n"
                      << "  Transport: " << (target.mode == DeviceTransportMode::WiFi ? "WiFi (" + target.host + ")" : "USB") << "\n"
                      << "  Name:      " << (dev_name.empty() ? "iOS Device" : dev_name) << "\n"
                      << "  Model:     " << dev_model << "\n"
                      << "  Version:   iOS " << dev_os << "\n"
                      << "  UDID:      " << target.udid << "\n";
            return 0;
        }

        if (subcmd == "log" || subcmd == "syslog") {
            std::cout << "OPENFRUIT: Streaming live syslog from device (Ctrl+C to stop)...\n";
            std::atomic<bool> cancel = false;
            return session.StreamSyslog([](const std::string& line) {
                std::cout << line << "\n";
            }, cancel, err) ? 0 : 1;
        }

        if (subcmd == "screenshot") {
            if (extra_arg.empty()) {
                std::cerr << "Usage: openfruit device screenshot <output.png> [--wifi <ip>]\n";
                return 2;
            }
            if (session.CaptureScreenshot(extra_arg, err)) {
                std::cout << "OPENFRUIT: Screenshot successfully saved to " << extra_arg << "\n";
                return 0;
            }
            std::cerr << "OPENFRUIT: Screenshot failed: " << err << "\n";
            return 1;
        }

        if (subcmd == "record") {
            std::string out_dir = extra_arg.empty() ? "." : extra_arg;
            std::atomic<bool> cancel = false;
            if (session.RecordScreenFrames(out_dir, record_duration, cancel, err)) {
                return 0;
            }
            std::cerr << "OPENFRUIT: Screen recording failed: " << err << "\n";
            return 1;
        }

        if (subcmd == "debug") {
            std::atomic<bool> cancel = false;
            return session.StartDebugProxy(debug_port, cancel, err) ? 0 : 1;
        }

        if (subcmd == "install" || subcmd == "deploy") {
            if (extra_arg.empty()) {
                std::cerr << "Usage: openfruit device install <path.ipa> [--wifi <ip>]\n";
                return 2;
            }
            bool ok = session.DeployIpa(extra_arg, [](int pct, const std::string& st) {
                std::cout << "\rDeploying: [" << pct << "%] " << st << std::flush;
            }, err);
            std::cout << "\n";
            if (ok) {
                std::cout << "OPENFRUIT: Successfully installed " << extra_arg << " on device!\n";
                return 0;
            }
            std::cerr << "OPENFRUIT: Installation failed: " << err << "\n";
            return 1;
        }

        if (subcmd == "launch" || subcmd == "start" || subcmd == "run") {
            if (extra_arg.empty()) {
                std::cerr << "Usage: openfruit device launch <bundle-id> [--wifi <ip>]\n";
                return 2;
            }
            uint32_t pid = 0;
            if (session.LaunchApp(extra_arg, pid, err)) {
                std::cout << "OPENFRUIT: Successfully launched " << extra_arg;
                if (pid > 0) std::cout << " (PID " << pid << ")";
                std::cout << " on device!\n";
                return 0;
            }
            std::cerr << "OPENFRUIT: Launch failed: " << err << "\n";
            return 1;
        }

        std::cerr << "Unknown device subcommand: " << subcmd << "\n";
        return 2;
    }

    PrintUsage();
    return 1;
    } catch (const std::exception& ex) {
        if (const auto context = CurrentOperationContext()) {
            auto error = JsonValue::ObjectValue();
            error.Set("message", JsonValue::String(ex.what()));
            error.Set("stack_capture_site", JsonValue::String("exception_handler"));
            auto frames = JsonValue::ArrayValue();
            void* addresses[32]{};
            const auto count = CaptureStackBackTrace(0, 32, addresses, nullptr);
            for (USHORT i = 0; i < count; ++i) {
                std::ostringstream address;
                address << "0x" << std::hex << reinterpret_cast<std::uintptr_t>(addresses[i]);
                frames.ArrayItems().push_back(JsonValue::String(address.str()));
            }
            error.Set("stack_frames", std::move(frames));
            error.Set("stack_trace_status", JsonValue::String("unsymbolicated"));
            context->Emit("engine.exception", std::move(error), "error");
        }
        std::cerr << "OPENFRUIT Fatal Exception: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "OPENFRUIT Unknown Fatal Exception encountered." << std::endl;
        return 1;
    }
}

