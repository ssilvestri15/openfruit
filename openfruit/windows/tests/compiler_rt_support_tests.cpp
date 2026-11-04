#include "compiler_rt_support.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
#include <cstring>
#include <algorithm>
#include <cstdint>
namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary | std::ios::trunc) << text;
}
std::string Read(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
std::string MakePath(const fs::path& path) {
    std::string out;
    for (char c : path.generic_string()) {
        if (c == ' ' || c == '#' || c == ':' || c == '\\') out += '\\';
        if (c == '$') out += '$';
        out += c;
    }
    return out;
}
int FakeCompiler(int argc, wchar_t** argv) {
    fs::path sdk, source, object, deps;
    for (int i = 1; i + 1 < argc; ++i) {
        std::wstring flag = argv[i];
        if (flag == L"-isysroot") sdk = argv[++i];
        else if (flag == L"-c") source = argv[++i];
        else if (flag == L"-o") object = argv[++i];
        else if (flag == L"-MF") deps = argv[++i];
    }
    std::ofstream(sdk / "invocations", std::ios::app) << "compile\n";
    if (fs::exists(sdk / "fail")) return 2;
    std::string bytes(56, '\0');
    auto put = [&](std::size_t n, std::uint32_t x) { std::memcpy(bytes.data() + n, &x, 4); };
    put(0, 0xfeedfacf); put(4, 0x0100000c); put(12, 1); put(16, 1); put(20, 24);
    put(32, 0x32); put(36, 24); put(40, 2); put(44, 0x110000);
    // Owned fake compiler is solely a cache/ABI contract fixture, never an
    // assertion that a real compiler or iOS execution succeeded.
    if (fs::exists(sdk / "bad-abi")) put(4, 0x01000007);
    Write(object, bytes);
    Write(deps, MakePath(object) + ": " + MakePath(source) + " \\\n " + MakePath(sdk / "header with space.h") + "\n");
    return 0;
}
std::size_t Count(const fs::path& sdk) {
    auto text = Read(sdk / "invocations");
    return static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n'));
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && std::wstring(argv[1]) == L"-target") return FakeCompiler(argc, argv);
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-compiler-rt-contract-" + NewOperationId());
    try {
        fs::create_directories(root);
        wchar_t own[MAX_PATH]; Require(GetModuleFileNameW(nullptr, own, MAX_PATH) > 0, "self path");
        const auto compiler = root / "compiler.exe";
        fs::copy_file(own, compiler);
        SetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", (root / "cache").c_str());
        SDKInfo sdk; sdk.sdk_path = (root / "SDK with space").wstring();
        sdk.target_triple = L"arm64-apple-ios17.0";
        const fs::path sdk_root(sdk.sdk_path);
        Write(sdk_root / "SDKSettings.json", "{\"Version\":\"27.0\"}");
        Write(sdk_root / "header with space.h", "first");
        {
            auto cancelled = std::make_shared<OperationContext>();
            cancelled->RequestCancellation();
            OperationBinding binding(cancelled);
            Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk).empty() && Count(sdk_root) == 0,
                "cancelled operation must not compile or publish");
        }
        auto first = EnsureIosAvailabilityRuntimeObject(root, compiler, sdk);
        Require(!first.empty() && Count(sdk_root) == 1, "initial provider publication");
        Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk) == first && Count(sdk_root) == 1,
            "valid dependency-bound cache should be reused");
        Write(sdk_root / "header with space.h", "changed");
        Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk) == first && Count(sdk_root) == 2,
            "system header content must invalidate cache");
        Write(first, "corrupt");
        Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk) == first && Count(sdk_root) == 3,
            "corrupt Mach-O object must be rebuilt");
        auto tampered = Read(first);
        tampered[24] = 4; // structurally valid Mach-O header, different digest
        Write(first, tampered);
        Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk) == first && Count(sdk_root) == 4,
            "valid-looking object tampering must invalidate digest");
        Write(sdk_root / "SDKSettings.json", "{\"Version\":\"28.0\"}");
        auto second = EnsureIosAvailabilityRuntimeObject(root, compiler, sdk);
        Require(!second.empty() && second != first && Count(sdk_root) == 5, "SDK metadata identity");
        sdk.target_triple = L"arm64-apple-ios18.0";
        Write(sdk_root / "bad-abi", "1");
        Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk).empty(), "wrong architecture must fail closed");
        fs::remove(sdk_root / "bad-abi");
        Write(sdk_root / "fail", "1");
        Require(EnsureIosAvailabilityRuntimeObject(root, compiler, sdk).empty(), "compiler failure must not publish cache");
        fs::remove(sdk_root / "fail");
        const auto before = Count(sdk_root);
        fs::path a, b;
        std::thread t1([&] { a = EnsureIosAvailabilityRuntimeObject(root, compiler, sdk); });
        std::thread t2([&] { b = EnsureIosAvailabilityRuntimeObject(root, compiler, sdk); });
        t1.join(); t2.join();
        Require(!a.empty() && a == b && Count(sdk_root) == before + 1, "concurrent providers need one lease/publication");
        // Replacing compiler contents changes its fingerprint even at same path.
        { std::ofstream file(compiler, std::ios::binary | std::ios::app); file << "compiler identity change"; }
        auto third = EnsureIosAvailabilityRuntimeObject(root, compiler, sdk);
        Require(!third.empty() && third != a && Count(sdk_root) == before + 2, "compiler content identity");
        fs::remove_all(root);
        std::cout << "compiler-rt cache/ABI contract fixtures PASS (not real compiler execution proof)\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nFixture retained: " << root.string() << '\n';
        return 1;
    }
}
