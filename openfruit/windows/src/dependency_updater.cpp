#include "dependency_updater.hpp"
#include "openfruit_version.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "http_transfer.hpp"
#include "native_zip.hpp"
#include "operation_events.hpp"
#include "environment_manager.hpp"

#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace OpenFruit {

namespace {

void ReportProgress(
    const DependencyProgressCallback& cb,
    const std::string& name,
    const std::string& phase,
    std::uint64_t current_bytes,
    std::uint64_t total_bytes,
    const std::string& msg = ""
) {
    if (cb) {
        DependencyProgress p;
        p.tool_name = name;
        p.phase = phase;
        p.current_bytes = current_bytes;
        p.total_bytes = total_bytes;
        p.message = msg;
        cb(p);
    }
}

std::wstring NormalizePath(const std::wstring& path) {
    if (path.empty()) return {};
    std::error_code ec;
    auto abs = fs::absolute(path, ec);
    if (!ec) return abs.lexically_normal().wstring();
    return path;
}

bool RunProcessSilently(const std::wstring& exe, const std::vector<std::wstring>& args, int* out_exit = nullptr) {
    ProcessResult res = Win32Process::Run(exe, args);
    if (out_exit) *out_exit = res.exit_code;
    return res.success;
}

// Queries GitHub API for the latest release of a repository and discovers the download URL of a matching asset.
std::wstring ResolveLatestGitHubAssetUrl(
    const std::string& owner_repo,
    const std::vector<std::string>& filename_patterns,
    const std::wstring& fallback_url = L""
) {
    std::string response_body;
    JsonPostRequest req;
    req.url = Win32Process::ToWide("https://api.github.com/repos/" + owner_repo + "/releases/latest");
    req.max_bytes = 1024 * 1024;
    {
        auto res = HttpTransfer::GetJson(req);
        if (res.Succeeded() && !res.body.empty()) {
            response_body = std::move(res.body);
        }
    }

    // If /releases/latest returns 404 or fails, try the releases list endpoint
    if (response_body.empty()) {
        req.url = Win32Process::ToWide("https://api.github.com/repos/" + owner_repo + "/releases");
        auto res2 = HttpTransfer::GetJson(req);
        if (res2.Succeeded() && !res2.body.empty()) {
            response_body = std::move(res2.body);
        }
    }

    if (response_body.empty()) {
        return fallback_url;
    }

    const auto parsed = JsonValue::Parse(response_body);
    if (!parsed) return fallback_url;

    // Helper lambda to search an array of assets
    auto find_asset_in_array = [&](const JsonValue::Array& assets) -> std::wstring {
        for (const auto& pattern : filename_patterns) {
            for (const auto& asset : assets) {
                if (!asset.IsObject()) continue;
                std::string asset_name = asset.GetString("name");
                std::string lower_asset = asset_name;
                for (char& c : lower_asset) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                std::string lower_pattern = pattern;
                for (char& c : lower_pattern) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (lower_asset.find(lower_pattern) != std::string::npos) {
                    std::string download_url = asset.GetString("browser_download_url");
                    if (!download_url.empty()) {
                        return Win32Process::ToWide(download_url);
                    }
                }
            }
        }
        return L"";
    };

    if (parsed->IsArray() && !parsed->ArrayItems().empty()) {
        for (const auto& rel : parsed->ArrayItems()) {
            if (!rel.IsObject()) continue;
            const auto* assets = rel.Get("assets");
            if (assets && assets->IsArray()) {
                std::wstring found = find_asset_in_array(assets->ArrayItems());
                if (!found.empty()) return found;
            }
        }
    } else if (parsed->IsObject()) {
        const auto* assets = parsed->Get("assets");
        if (assets && assets->IsArray()) {
            std::wstring found = find_asset_in_array(assets->ArrayItems());
            if (!found.empty()) return found;
        }
    }

    return fallback_url;
}

} // namespace

JsonValue DependencyUpdateResult::ToJson() const {
    auto json = JsonValue::ObjectValue();
    json.Set("success", JsonValue::Boolean(success));
    auto updated = JsonValue::ArrayValue();
    for (const auto& u : updated_tools) {
        updated.ArrayItems().push_back(JsonValue::String(u));
    }
    json.Set("updated_tools", std::move(updated));

    auto path_entries = JsonValue::ArrayValue();
    for (const auto& p : path_entries_added) {
        path_entries.ArrayItems().push_back(JsonValue::String(p));
    }
    json.Set("path_entries_added", std::move(path_entries));

    auto errs = JsonValue::ArrayValue();
    for (const auto& e : errors) {
        errs.ArrayItems().push_back(JsonValue::String(e));
    }
    json.Set("errors", std::move(errs));
    return json;
}

bool DependencyUpdater::EnsureInPath(const std::wstring& directory_path, bool* out_already_present) {
    if (directory_path.empty()) return false;
    const std::wstring dir_norm = NormalizePath(directory_path);
    if (out_already_present) *out_already_present = false;

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) {
        return false;
    }

    DWORD bytes = 0;
    DWORD type = REG_EXPAND_SZ;
    std::wstring current_path;
    if (RegQueryValueExW(key, L"Path", nullptr, &type, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
        std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(key, L"Path", nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &bytes) == ERROR_SUCCESS) {
            while (!buffer.empty() && buffer.back() == L'\0') buffer.pop_back();
            current_path = buffer;
        }
    }

    // Check if dir_norm is already in current_path
    std::wstringstream ss(current_path);
    std::wstring item;
    bool found = false;
    while (std::getline(ss, item, L';')) {
        if (!item.empty() && NormalizePath(item) == dir_norm) {
            found = true;
            break;
        }
    }

    if (found) {
        if (out_already_present) *out_already_present = true;
        RegCloseKey(key);
        return true;
    }

    // Append dir_norm to PATH
    std::wstring new_path = current_path;
    if (!new_path.empty() && new_path.back() != L';') {
        new_path += L';';
    }
    new_path += dir_norm;

    LONG set_res = RegSetValueExW(
        key,
        L"Path",
        0,
        type,
        reinterpret_cast<const BYTE*>(new_path.c_str()),
        static_cast<DWORD>((new_path.size() + 1) * sizeof(wchar_t))
    );
    RegCloseKey(key);

    if (set_res == ERROR_SUCCESS) {
        // Broadcast WM_SETTINGCHANGE so new shells pick it up immediately
        DWORD_PTR result_ptr = 0;
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            reinterpret_cast<LPARAM>(L"Environment"),
            SMTO_ABORTIFHUNG,
            3000,
            &result_ptr
        );
        return true;
    }

    return false;
}

bool DependencyUpdater::EnsureOpenFruitInPath() {
    const fs::path openfruit_bin = ToolPaths::LocalHome() / "bin";
    std::error_code ec;
    fs::create_directories(openfruit_bin, ec);
    return EnsureInPath(openfruit_bin.wstring());
}

DependencyUpdateResult DependencyUpdater::UpdateAll(
    Config& config,
    bool silent,
    DependencyProgressCallback on_progress
) {
    DependencyUpdateResult result;
    const fs::path local_home = ToolPaths::LocalHome();
    const fs::path openfruit_bin = local_home / "bin";
    const fs::path signing_bin = openfruit_bin / "signing";
    const fs::path temp_dir = ToolPaths::UserStateRoot() / "temp";
    std::error_code ec;
    fs::create_directories(openfruit_bin, ec);
    fs::create_directories(signing_bin, ec);
    fs::create_directories(temp_dir, ec);

    // 1. Ensure OpenFruit and signing binaries are in PATH
    bool already_openfruit_path = false;
    if (EnsureInPath(openfruit_bin.wstring(), &already_openfruit_path)) {
        if (!already_openfruit_path) {
            result.path_entries_added.push_back(openfruit_bin.string());
        }
    }
    bool already_signing_path = false;
    if (EnsureInPath(signing_bin.wstring(), &already_signing_path)) {
        if (!already_signing_path) {
            result.path_entries_added.push_back(signing_bin.string());
        }
    }

    // 2. OpenIB: Check if present in openfruit_bin; if not, discover and download fallback from latest release
    const fs::path openib_exe = openfruit_bin / "openib.exe";
    if (!fs::exists(openib_exe)) {
        ReportProgress(on_progress, "openib", "downloading", 0, 0, "Resolving and downloading openib.exe from latest release...");
        const std::wstring openib_url = ResolveLatestGitHubAssetUrl(
            OPENFRUIT_REPOSITORY,
            {"openib.exe"},
            L"https://github.com/" OPENFRUIT_REPOSITORY_W L"/releases/latest/download/openib.exe"
        );
        TransferRequest req;
        req.url = openib_url;
        req.destination = openib_exe;
        req.progress_callback = [&](std::uint64_t curr, std::uint64_t total) {
            ReportProgress(on_progress, "openib", "downloading", curr, total);
        };
        const auto tr = HttpTransfer::Download(req);
        if (tr.Succeeded()) {
            result.updated_tools.push_back("openib");
            ReportProgress(on_progress, "openib", "completed", tr.bytes, tr.bytes, "openib installed successfully");
        } else {
            ReportProgress(on_progress, "openib", "skipped", 0, 0, "openib local build is preferred");
        }
    } else {
        ReportProgress(on_progress, "openib", "completed", 0, 0, "openib is ready");
    }

    // 3. zsign: Check if zsign.exe exists in PATH or signing directory
    fs::path zsign_existing = ToolPaths::Zsign({});
    if (zsign_existing.empty() || !fs::exists(zsign_existing)) {
        const fs::path zsign_target = signing_bin / "zsign.exe";
        ReportProgress(on_progress, "zsign", "downloading", 0, 0, "Resolving latest zsign release from GitHub...");
        // Dynamically discover latest Windows asset from GitHub releases (e.g. zsign-windows-x64.zip or zsign.exe)
        const std::wstring zsign_asset_url = ResolveLatestGitHubAssetUrl(
            "zhlynn/zsign",
            {"windows-x64.zip", "zsign.exe"},
            L"https://github.com/zhlynn/zsign/releases/download/v1.1.2/zsign.exe"
        );

        TransferRequest req;
        req.url = zsign_asset_url;
        // If zip archive, download to temp and extract
        const bool is_zip = (zsign_asset_url.find(L".zip") != std::wstring::npos);
        req.destination = is_zip ? (temp_dir / "zsign_latest.zip") : zsign_target;
        req.progress_callback = [&](std::uint64_t curr, std::uint64_t total) {
            ReportProgress(on_progress, "zsign", "downloading", curr, total);
        };
        const auto tr = HttpTransfer::Download(req);
        if (tr.Succeeded()) {
            if (is_zip) {
                ReportProgress(on_progress, "zsign", "extracting", tr.bytes, tr.bytes, "Extracting zsign...");
                const fs::path extract_dir = temp_dir / "zsign_extracted";
                fs::create_directories(extract_dir, ec);
                // Extract using tar.exe or ArchiveShim
                int extract_exit = 0;
                RunProcessSilently(L"tar.exe", {L"tar.exe", L"-xf", req.destination.wstring(), L"-C", extract_dir.wstring()}, &extract_exit);
                
                // Locate zsign.exe in extracted folder
                fs::path extracted_zsign = extract_dir / "zsign.exe";
                if (!fs::exists(extracted_zsign)) {
                    for (const auto& entry : fs::recursive_directory_iterator(extract_dir, ec)) {
                        if (entry.is_regular_file() && entry.path().filename() == "zsign.exe") {
                            extracted_zsign = entry.path();
                            break;
                        }
                    }
                }
                if (fs::exists(extracted_zsign)) {
                    fs::copy_file(extracted_zsign, zsign_target, fs::copy_options::overwrite_existing, ec);
                }
                fs::remove_all(extract_dir, ec);
                fs::remove(req.destination, ec);
            }
            if (fs::exists(zsign_target)) {
                config.zsign_path = zsign_target.wstring();
                config.Save();
                result.updated_tools.push_back("zsign");
                ReportProgress(on_progress, "zsign", "completed", tr.bytes, tr.bytes, "zsign downloaded and configured");
            } else {
                result.errors.push_back("Failed to extract zsign.exe from downloaded asset");
                ReportProgress(on_progress, "zsign", "failed", 0, 0, "zsign extraction failed");
            }
        } else {
            result.errors.push_back("Failed to download zsign: HTTP transfer error");
            ReportProgress(on_progress, "zsign", "failed", 0, 0, "zsign download failed");
        }
    } else {
        ReportProgress(on_progress, "zsign", "completed", 0, 0, "zsign is ready: " + zsign_existing.string());
    }

    // 4. Git for Windows
    const fs::path git_path = ToolPaths::Git();
    if (git_path.empty() || !fs::exists(git_path)) {
        ReportProgress(on_progress, "git", "installing", 0, 0, "Git not detected; installing Git...");
        int exit_code = 0;
        bool installed = false;

        // Try winget first for clean system integration
        const bool winget_ok = RunProcessSilently(
            L"winget.exe",
            {L"winget.exe", L"install", L"--id", L"Git.Git", L"-e", L"--silent", L"--accept-package-agreements", L"--accept-source-agreements"},
            &exit_code
        );
        if (winget_ok && exit_code == 0) {
            installed = true;
        } else {
            // Dynamic fallback: Query GitHub API for git-for-windows latest installer
            ReportProgress(on_progress, "git", "downloading", 0, 0, "Resolving latest Git for Windows release from GitHub...");
            const std::wstring git_installer_url = ResolveLatestGitHubAssetUrl(
                "git-for-windows/git",
                {"64-bit.exe"},
                L""
            );
            if (!git_installer_url.empty()) {
                const fs::path installer_path = temp_dir / "git_installer.exe";
                TransferRequest git_req;
                git_req.url = git_installer_url;
                git_req.destination = installer_path;
                git_req.progress_callback = [&](std::uint64_t curr, std::uint64_t total) {
                    ReportProgress(on_progress, "git", "downloading", curr, total);
                };
                const auto git_tr = HttpTransfer::Download(git_req);
                if (git_tr.Succeeded()) {
                    ReportProgress(on_progress, "git", "installing", 0, 0, "Running Git installer silently...");
                    int inst_exit = 0;
                    // InnoSetup silent parameters for Git for Windows
                    const bool inst_ok = RunProcessSilently(
                        installer_path.wstring(),
                        {installer_path.wstring(), L"/VERYSILENT", L"/NORESTART", L"/NOCANCEL", L"/SP-", L"/CLOSEAPPLICATIONS", L"/RESTARTAPPLICATIONS"},
                        &inst_exit
                    );
                    fs::remove(installer_path, ec);
                    if (inst_ok && inst_exit == 0) {
                        installed = true;
                    }
                }
            }
        }

        if (installed) {
            result.updated_tools.push_back("Git");
            ReportProgress(on_progress, "git", "completed", 0, 0, "Git installed successfully");
        } else {
            result.errors.push_back("Failed to install Git automatically via winget or GitHub releases");
            ReportProgress(on_progress, "git", "failed", 0, 0, "Git installation failed");
        }
    } else {
        ReportProgress(on_progress, "git", "completed", 0, 0, "Git is ready: " + git_path.string());
    }

    // 5. LLVM / ld64.lld
    const fs::path llvm_bin = ToolPaths::LlvmBin({});
    const fs::path lld_exe = llvm_bin / "ld64.lld.exe";
    if (!fs::exists(lld_exe)) {
        ReportProgress(on_progress, "llvm", "checking", 0, 0, "Apple-capable LLVM ld64.lld missing...");
        // Ensure managed directory is in PATH
        EnsureInPath((local_home / "toolchains" / "llvm" / "bin").wstring());
    } else {
        ReportProgress(on_progress, "llvm", "completed", 0, 0, "LLVM ld64.lld is ready: " + lld_exe.string());
        EnsureInPath(llvm_bin.wstring());
    }

    // 6. Swift Toolchain
    const fs::path swift_bin = ToolPaths::SwiftBin({});
    if (swift_bin.empty() || !fs::exists(swift_bin / "swift.exe")) {
        ReportProgress(on_progress, "swift", "installing", 0, 0, "Swift toolchain not detected; installing via winget...");
        int exit_code = 0;
        const bool winget_ok = RunProcessSilently(
            L"winget.exe",
            {L"winget.exe", L"install", L"--id", L"Swift.Toolchain", L"-e", L"--silent", L"--accept-package-agreements", L"--accept-source-agreements"},
            &exit_code
        );
        if (winget_ok && exit_code == 0) {
            result.updated_tools.push_back("Swift.Toolchain");
            ReportProgress(on_progress, "swift", "completed", 0, 0, "Swift installed successfully");
        } else {
            result.errors.push_back("Failed to install Swift Toolchain automatically via winget");
            ReportProgress(on_progress, "swift", "failed", 0, 0, "Swift Toolchain installation failed");
        }
    } else {
        ReportProgress(on_progress, "swift", "completed", 0, 0, "Swift is ready: " + swift_bin.string());
        EnsureInPath(swift_bin.wstring());
    }

    // 7. Re-run EnvironmentManager bootstrap to link everything
    EnvironmentManager::CheckAndBootstrap({}, config, true, false);

    result.success = result.errors.empty();
    return result;
}

} // namespace OpenFruit
