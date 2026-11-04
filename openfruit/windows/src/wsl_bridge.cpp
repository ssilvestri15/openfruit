#include "wsl_bridge.hpp"
#include "system_info.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <system_error>

namespace OpenFruit {

namespace {


std::wstring ExtendedWindowsPath(const std::filesystem::path& path) {
    const std::wstring absolute = std::filesystem::absolute(path).wstring();
    if (absolute.starts_with(L"\\\\?\\")) return absolute;
    if (absolute.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + absolute.substr(2);
    return L"\\\\?\\" + absolute;
}

std::string EffectiveDistro(const std::string& requested) {
    wchar_t buffer[256] = {};
    const DWORD length = GetEnvironmentVariableW(L"OPENFRUIT_WSL_DISTRO", buffer, 256);
    if (length > 0 && length < 256 && (requested.empty() || requested == "Ubuntu")) {
        return Win32Process::ToNarrow(std::wstring(buffer, length));
    }
    return requested.empty() ? std::string("Ubuntu") : requested;
}

} // namespace


std::string WSLBridge::WindowsToWslPath(const std::wstring& win_path) {
    if (win_path.empty()) return "";
    std::string path = Win32Process::ToNarrow(win_path);
    std::replace(path.begin(), path.end(), '\\', '/');

    // Handle drive letter: "C:/..." -> "/mnt/c/..."
    if (path.size() >= 2 && path[1] == ':') {
        char drive = (char)std::tolower(path[0]);
        path = "/mnt/" + std::string(1, drive) + path.substr(2);
    }
    return path;
}

std::wstring WSLBridge::WslToWindowsPath(const std::string& wsl_path) {
    if (wsl_path.empty()) return L"";
    std::string path = wsl_path;

    // Handle "/mnt/c/..." -> "C:\..."
    if (path.rfind("/mnt/", 0) == 0 && path.size() >= 7 && path[6] == '/') {
        char drive = (char)std::toupper(path[5]);
        path = std::string(1, drive) + ":" + path.substr(6);
    }
    std::replace(path.begin(), path.end(), '/', '\\');
    return Win32Process::ToWide(path);
}

std::filesystem::path WSLBridge::EnsureVisibleTree(
    const std::filesystem::path& source,
    const std::filesystem::path& projection,
    const std::filesystem::path& required_relative_file,
    std::string& error
) {
    namespace fs = std::filesystem;
    error.clear();
    std::error_code ec;
    if (!fs::is_regular_file(source / required_relative_file, ec) || ec) {
        error = "The source tree is missing its required file.";
        return {};
    }
    auto visible = [&](const fs::path& path) {
        const std::string wsl = WindowsToWslPath(path.wstring());
        std::string quoted = "'";
        for (char ch : wsl) quoted += ch == '\'' ? "'\\''" : std::string(1, ch);
        quoted += "'";
        return Exec("test -f " + quoted).success;
    };
    if (visible(source / required_relative_file)) return source;

    const fs::path completion = projection / ".OPENFRUIT-complete";
    if (fs::is_regular_file(completion, ec) && !ec &&
        fs::equivalent(source / required_relative_file,
            projection / required_relative_file, ec) && !ec &&
        visible(projection / required_relative_file)) return projection;

    ec.clear();
    fs::create_directories(projection, ec);
    if (ec) {
        error = "Unable to create the WSL-visible projection: " + ec.message();
        return {};
    }
    const fs::path extended_source_root(ExtendedWindowsPath(source));
    for (fs::recursive_directory_iterator it(extended_source_root, ec), end;
         !ec && it != end; it.increment(ec)) {
        const fs::path relative = it->path().lexically_relative(
            extended_source_root);
        const fs::path destination = projection / relative;
        if (it->is_symlink(ec)) {
            ec.clear();
            std::error_code link_ec;
            const fs::path target = fs::read_symlink(it->path(), link_ec);
            if (!link_ec) {
                fs::create_directories(
                    fs::path(ExtendedWindowsPath(destination.parent_path())), ec);
                if (!ec) {
                    fs::remove(destination, ec);
                    ec.clear();
                    std::error_code stat_ec;
                    const bool is_dir = fs::is_directory(it->path(), stat_ec);
                    stat_ec.clear();
                    const bool is_reg = fs::is_regular_file(it->path(), stat_ec);
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
                    const DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE |
                        (is_dir ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0);
                    if (!CreateSymbolicLinkW(
                            ExtendedWindowsPath(destination).c_str(),
                            target.c_str(), flags)) {
                        ec.clear();
                        if (is_reg) {
                            std::error_code can_ec;
                            const fs::path canonical_src = fs::canonical(it->path(), can_ec);
                            const fs::path src_to_link = (!can_ec && !canonical_src.empty()) ? canonical_src : it->path();
                            if (!CreateHardLinkW(
                                    ExtendedWindowsPath(destination).c_str(),
                                    ExtendedWindowsPath(src_to_link).c_str(), nullptr)) {
                                ec.clear();
                                fs::copy_file(src_to_link, destination,
                                    fs::copy_options::overwrite_existing, ec);
                            }
                        } else if (is_dir) {
                            fs::create_directories(
                                fs::path(ExtendedWindowsPath(destination)), ec);
                        }
                    }
                }
            }
            ec.clear();
            continue;
        }
        if (it->is_directory(ec)) {
            fs::create_directories(
                fs::path(ExtendedWindowsPath(destination)), ec);
        } else if (it->is_regular_file(ec)) {
            fs::create_directories(
                fs::path(ExtendedWindowsPath(destination.parent_path())), ec);
            if (!ec) {
                const fs::path extended_source(ExtendedWindowsPath(it->path()));
                const fs::path extended_destination(ExtendedWindowsPath(destination));
                bool same = false;
                if (fs::exists(extended_destination, ec) && !ec) {
                    same = fs::equivalent(extended_source,
                        extended_destination, ec);
                }
                if (!ec && !same) {
                    fs::remove(extended_destination, ec);
                    if (!ec && !CreateHardLinkW(
                            extended_destination.c_str(),
                            extended_source.c_str(), nullptr)) {
                        ec = std::error_code(static_cast<int>(GetLastError()),
                            std::system_category());
                    }
                }
            }
        } else if (!ec) {
            error = "The source contains an unsupported filesystem entry: " +
                relative.string();
            return {};
        }
        if (ec) {
            error = "Unable to project " + relative.string() + ": " + ec.message();
            return {};
        }
    }
    if (ec) {
        error = "Unable to enumerate the SDK tree: " + ec.message();
        return {};
    }
    std::ofstream marker(completion, std::ios::binary | std::ios::trunc);
    marker << "OPENFRUIT WSL tree projection v1\n";
    marker.close();
    if (!marker || !visible(projection / required_relative_file)) {
        error = "The projected tree is still not visible from WSL.";
        return {};
    }
    return projection;
}

bool WSLBridge::IsWslAvailable() {
    std::wstring wsl_exe = SystemInfo::GetWslExecutable();
    const std::string distro = EffectiveDistro("Ubuntu");
    ProcessResult res = Win32Process::Run(wsl_exe, { L"wsl.exe", L"-d", Win32Process::ToWide(distro), L"--", L"true" });
    return res.success;
}

ProcessResult WSLBridge::Exec(
    const std::string& command,
    const std::string& distro,
    const std::wstring& working_directory
) {
    std::wstring wsl_exe = SystemInfo::GetWslExecutable();
    const std::string effective_distro = EffectiveDistro(distro);
    std::vector<std::wstring> args = {
        L"wsl.exe",
        L"-d", Win32Process::ToWide(effective_distro),
        L"--",
        L"bash", L"-c", Win32Process::ToWide(command)
    };
    return Win32Process::Run(wsl_exe, args, working_directory);
}

ProcessResult WSLBridge::ExecDarling(
    const std::string& command,
    const std::string& distro
) {
    std::string darling_cmd = "darling shell " + command;
    return Exec(darling_cmd, distro);
}


bool WSLBridge::IsDarlingShellspawnReady(
    const std::string& distro
) {
    const ProcessResult result = Exec(
        "test -S \"$HOME/.darling/var/run/shellspawn.sock\"",
        distro
    );
    return result.success;
}

bool WSLBridge::EnsureDarlingHealthy(
    const std::string& distro
) {
    if (IsDarlingShellspawnReady(distro)) {
        const ProcessResult probe = ExecDarling(
            "true",
            distro
        );
        if (probe.success) {
            return true;
        }
    }

    // A shared provider has no exclusive lifecycle ownership here.
    // Report unavailable instead of resetting other sessions.
    return false;
}

} // namespace OpenFruit
