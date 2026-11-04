#include "compiler_proxy.hpp"
#include "win32_process.hpp"
#include "wsl_bridge.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {

bool HasEnvironmentValue(const wchar_t* name) {
    return GetEnvironmentVariableW(name, nullptr, 0) != 0;
}

fs::path CurrentExecutable() {
    std::wstring value(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        value.data(),
        static_cast<DWORD>(value.size())
    );
    if (length == 0 || length >= value.size()) {
        return {};
    }
    value.resize(length);
    return fs::path(value);
}

int RunNativeCrashStub() {
    std::cerr << "Please submit a bug report and include the crash backtrace.\n";
    return 86;
}

} // namespace

int main(int argc, char* argv[]) {
    const fs::path executable = CurrentExecutable();
    const bool named_swiftc =
        executable.filename().wstring() == L"swiftc.exe";

    if (!named_swiftc && HasEnvironmentValue(L"OPENFRUIT_PROBE_NATIVE_STUB")) {
        return RunNativeCrashStub();
    }

    if (CompilerProxy::IsActive()) {
        return CompilerProxy::Run(argc, argv);
    }

    if (argc != 3) {
        std::cerr << "usage: swift_fallback_modulemap_probe "
                     "<clean-diagnostic-root> <fallback-observer-script>\n";
        return 2;
    }

    const fs::path root = fs::absolute(fs::path(argv[1]));
    const fs::path observer = fs::absolute(fs::path(argv[2]));
    if (fs::exists(root)) {
        std::cerr << "diagnostic root already exists: " << root.string() << "\n";
        return 3;
    }
    if (!fs::is_regular_file(observer)) {
        std::cerr << "fallback observer is missing: " << observer.string() << "\n";
        return 4;
    }

    std::error_code ec;
    const fs::path include = root / "generated" / "include";
    fs::create_directories(include, ec);
    if (ec) {
        std::cerr << "cannot create diagnostic root: " << ec.message() << "\n";
        return 5;
    }

    const fs::path header = include / "ProbeHeader.h";
    const fs::path modulemap = root / "generated" / "module.modulemap";
    {
        std::ofstream output(header, std::ios::binary | std::ios::trunc);
        output << "#define OPENFRUIT_MODULEMAP_PROBE 1\n";
    }
    {
        std::string escaped = header.string();
        std::string serialized;
        serialized.reserve(escaped.size() * 2);
        for (const char value : escaped) {
            if (value == '\\') {
                serialized += "\\\\";
            } else {
                serialized += value;
            }
        }
        std::ofstream output(modulemap, std::ios::binary | std::ios::trunc);
        output << "module OPENFRUITFallbackProbe {\n"
               << "    umbrella header \"" << serialized << "\"\n"
               << "    export *\n"
               << "}\n";
    }

    const fs::path proxy = root / "bin" / "swiftc.exe";
    fs::create_directories(proxy.parent_path(), ec);
    fs::copy_file(executable, proxy, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        std::cerr << "cannot materialize compiler proxy: " << ec.message() << "\n";
        return 6;
    }

    const std::wstring module_argument =
        L"-fmodule-map-file=" + modulemap.wstring();
    const std::wstring observer_wsl = Win32Process::ToWide(
        WSLBridge::WindowsToWslPath(observer.wstring())
    );
    const std::vector<std::pair<std::wstring, std::wstring>> environment = {
        {L"OPENFRUIT_SWIFT_TARGET_PROXY_REAL", executable.wstring()},
        {L"OPENFRUIT_PROBE_NATIVE_STUB", L"1"},
        {L"OPENFRUIT_SWIFT_FALLBACK_BIN", observer_wsl},
        {L"OPENFRUIT_SWIFT_FALLBACK_PREBUILT", L"/tmp/OPENFRUIT-probe/prebuilt"},
        {L"OPENFRUIT_SWIFT_FALLBACK_MODULE_CACHE", L"/tmp/OPENFRUIT-probe/module-cache"},
        {L"OPENFRUIT_SWIFT_FALLBACK_SDK", L"/tmp/OPENFRUIT-probe/sdk"},
        {L"OPENFRUIT_SWIFT_FALLBACK_RESOURCE_DIR", L"/tmp/OPENFRUIT-probe/resource-dir"},
        {L"OPENFRUIT_WSL_DISTRO", L"Ubuntu"}
    };
    const std::vector<std::wstring> arguments = {
        proxy.wstring(),
        L"-target", L"arm64-apple-ios18.6",
        module_argument,
        L"-Xcc", module_argument
    };

    const ProcessResult result = Win32Process::Run(
        proxy.wstring(), arguments, root.wstring(), environment
    );
    std::cout << result.std_out;
    std::cerr << result.std_err;
    std::cout << "MODULEMAP=" << modulemap.string() << "\n"
              << "HEADER=" << header.string() << "\n"
              << "FALLBACK_EXIT=" << result.exit_code << "\n";
    return result.exit_code;
}
