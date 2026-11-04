#pragma once

#include "win32_process.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

class WSLBridge {
public:
    static std::string WindowsToWslPath(const std::wstring& win_path);
    static std::wstring WslToWindowsPath(const std::string& wsl_path);

    // DrvFs can expose a different view of a Windows-managed directory. If
    // the required file is not visible in WSL, publish a same-volume hard-link
    // tree in user state without duplicating the SDK's file contents.
    static std::filesystem::path EnsureVisibleTree(
        const std::filesystem::path& source,
        const std::filesystem::path& projection,
        const std::filesystem::path& required_relative_file,
        std::string& error);

    static bool IsWslAvailable();

    static ProcessResult Exec(
        const std::string& command,
        const std::string& distro = "Ubuntu",
        const std::wstring& working_directory = L""
    );

    static ProcessResult ExecDarling(
        const std::string& command,
        const std::string& distro = "Ubuntu"
    );

    static bool IsDarlingShellspawnReady(
        const std::string& distro = "Ubuntu"
    );

    static bool EnsureDarlingHealthy(
        const std::string& distro = "Ubuntu"
    );
};

} // namespace OpenFruit
