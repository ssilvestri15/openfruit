#include "sdk_usage.hpp"
#include "artifact_store.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--contender") {
        OpenFruit::SDKUsage concurrent(fs::path(OpenFruit::Win32Process::ToWide(argv[2])));
        const bool renamed = MoveFileExW(OpenFruit::Win32Process::ToWide(argv[2]).c_str(),
            OpenFruit::Win32Process::ToWide(argv[3]).c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
        const DWORD error = renamed ? ERROR_SUCCESS : GetLastError();
        std::cout << "held=" << concurrent.Held() << " renamed=" << renamed << " error=" << error << '\n';
        return concurrent.Held() && !renamed && error == ERROR_SHARING_VIOLATION ? 0 : 1;
    }
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-sdk-usage-" + OpenFruit::NewOperationId());
    const auto sdk = root / "sdk", renamed = root / "retired-sdk", source = root / "new-sdk";
    fs::create_directories(sdk); fs::create_directories(source);
    { std::ofstream file(sdk / "previous"); file << "owned existing SDK"; }
    { std::ofstream file(source / "new"); file << "owned replacement SDK"; }
    bool passed = true;
    {
        OpenFruit::SDKUsage use(sdk);
        passed = use.Held();
        const auto executable = fs::absolute(argv[0]).wstring();
        const auto contender = OpenFruit::Win32Process::Run(executable,
            {executable, L"--contender", sdk.wstring(), renamed.wstring()});
        if (!contender.success) std::cerr << contender.std_out;
        passed = passed && contender.success && fs::exists(sdk / "previous") && !fs::exists(renamed);
        passed = passed && !OpenFruit::NativeArtifactStore::ImportTreeTransactional(source, sdk, {})
            && fs::exists(sdk / "previous") && !fs::exists(sdk / "new");
    }
    passed = passed && MoveFileExW(sdk.c_str(), renamed.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
    {
        OpenFruit::SDKUsage missing(root / "missing");
        OpenFruit::SDKUsage file(renamed / "previous");
        passed = passed && !missing.Held() && !file.Held() && !fs::exists(root / "missing");
    }
    fs::remove_all(root); // Unique owned fixture only.
    if (!passed) std::cerr << "SDK usage must share readers, reject replacement and release directory handles.\n";
    return passed ? 0 : 1;
}
