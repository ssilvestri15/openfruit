#include "compiler_proxy.hpp"
#include "config.hpp"
#include "event_journal.hpp"
#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "tool_paths.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
int main(int argc, char** argv) {
    auto journal = OpenFruit::EventJournal::AttachFromEnvironment();
    std::unique_ptr<OpenFruit::OperationBinding> binding;
    if (journal) binding = std::make_unique<OpenFruit::OperationBinding>(journal->Context());
    if (OpenFruit::CompilerProxy::IsActive()) return OpenFruit::CompilerProxy::Run(argc, argv);
    if (argc != 3) {
        std::cerr << "usage: swift_import_recovery_probe <repo-root> <owned-ambiguous-package>\n";
        return 2;
    }
    auto config = OpenFruit::Config::Load();
    config.ApplyEnvironment();
    journal = OpenFruit::EventJournal::Create(OpenFruit::ToolPaths::UserStateRoot() / "diagnostics" / "recovery-probe");
    binding = std::make_unique<OpenFruit::OperationBinding>(journal->Context());
    const auto sdk = OpenFruit::SDKManager::DiscoverSDK(fs::absolute(argv[1]).wstring());
    if (!sdk.is_valid) return 3;
    const auto result = OpenFruit::PackageEngine::BuildSwiftPMPackage(
        fs::absolute(argv[1]).wstring(), fs::absolute(argv[2]).wstring(), sdk, L"debug", 2);
    journal->Flush();
    std::cout << "RECOVERY_JOURNAL=" << journal->Directory().string() << "\n";
    if (result.success || journal->HasErrors()) return 4;
    std::ifstream events(journal->Directory() / "events.jsonl");
    std::string line;
    while (std::getline(events, line)) {
        auto event = OpenFruit::JsonValue::Parse(line);
        if (!event || event->GetString("kind") != "recovery.metrics") continue;
        const auto* data = event->Get("data");
        if (!data) continue;
        const auto* rejected = data->Get("ambiguity_rejections");
        const auto* walks = data->Get("sdk_walks");
        if (rejected && rejected->Int() > 0 && (!walks || walks->Int() == 0)) {
            std::cout << "AMBIGUITY_REJECTED_BEFORE_SDK_SCAN=pass\n";
            return 0;
        }
    }
    std::cerr << "No authoritative recovery ambiguity evidence; inspect original failure.\n";
    return 5;
}
