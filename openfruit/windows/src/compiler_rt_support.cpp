#include "compiler_rt_support.hpp"
#include "win32_process.hpp"
#include "tool_paths.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include <chrono>
#include <cstdint>
#include <set>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

/*
 * LLVM compiler-rt, compiler-rt/lib/builtins/os_version_check.c
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 * Upstream: https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/builtins/os_version_check.c
 *
 * OPENFRUIT embeds the upstream Apple branch (inactive Android code omitted), so a Windows
 * cross-build can provide the compiler-generated availability builtin when a
 * developer's extracted Xcode tree does not include libclang_rt.ios.a.
 */
constexpr const char* kLlvmOsVersionCheckSource = R"OPENFRUIT_C(//===-- os_version_check.c - OS version checking  -------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the function __isOSVersionAtLeast, used by
// Objective-C's @available
//
//===----------------------------------------------------------------------===//

#ifdef __APPLE__

#include <TargetConditionals.h>
#include <assert.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// These three variables hold the host's OS version.
static int32_t GlobalMajor, GlobalMinor, GlobalSubminor;
static dispatch_once_t DispatchOnceCounter;
static dispatch_once_t CompatibilityDispatchOnceCounter;

// _availability_version_check darwin API support.
typedef uint32_t dyld_platform_t;

typedef struct {
  dyld_platform_t platform;
  uint32_t version;
} dyld_build_version_t;

typedef bool (*AvailabilityVersionCheckFuncTy)(uint32_t count,
                                               dyld_build_version_t versions[]);

static AvailabilityVersionCheckFuncTy AvailabilityVersionCheck;

// We can't include <CoreFoundation/CoreFoundation.h> directly from here, so
// just forward declare everything that we need from it.

typedef const void *CFDataRef, *CFAllocatorRef, *CFPropertyListRef,
    *CFStringRef, *CFDictionaryRef, *CFTypeRef, *CFErrorRef;

#if __LLP64__
typedef unsigned long long CFTypeID;
typedef unsigned long long CFOptionFlags;
typedef signed long long CFIndex;
#else
typedef unsigned long CFTypeID;
typedef unsigned long CFOptionFlags;
typedef signed long CFIndex;
#endif

typedef unsigned char UInt8;
typedef _Bool Boolean;
typedef CFIndex CFPropertyListFormat;
typedef uint32_t CFStringEncoding;

// kCFStringEncodingASCII analog.
#define CF_STRING_ENCODING_ASCII 0x0600
// kCFStringEncodingUTF8 analog.
#define CF_STRING_ENCODING_UTF8 0x08000100
#define CF_PROPERTY_LIST_IMMUTABLE 0

typedef CFDataRef (*CFDataCreateWithBytesNoCopyFuncTy)(CFAllocatorRef,
                                                       const UInt8 *, CFIndex,
                                                       CFAllocatorRef);
typedef CFPropertyListRef (*CFPropertyListCreateWithDataFuncTy)(
    CFAllocatorRef, CFDataRef, CFOptionFlags, CFPropertyListFormat *,
    CFErrorRef *);
typedef CFPropertyListRef (*CFPropertyListCreateFromXMLDataFuncTy)(
    CFAllocatorRef, CFDataRef, CFOptionFlags, CFStringRef *);
typedef CFStringRef (*CFStringCreateWithCStringNoCopyFuncTy)(CFAllocatorRef,
                                                             const char *,
                                                             CFStringEncoding,
                                                             CFAllocatorRef);
typedef const void *(*CFDictionaryGetValueFuncTy)(CFDictionaryRef,
                                                  const void *);
typedef CFTypeID (*CFGetTypeIDFuncTy)(CFTypeRef);
typedef CFTypeID (*CFStringGetTypeIDFuncTy)(void);
typedef Boolean (*CFStringGetCStringFuncTy)(CFStringRef, char *, CFIndex,
                                            CFStringEncoding);
typedef void (*CFReleaseFuncTy)(CFTypeRef);

extern __attribute__((weak_import))
bool _availability_version_check(uint32_t count,
                                 dyld_build_version_t versions[]);

static void _initializeAvailabilityCheck(bool LoadPlist) {
  if (AvailabilityVersionCheck && !LoadPlist) {
    // New API is supported and we're not being asked to load the plist,
    // exit early!
    return;
  }

  // Use the new API if it's is available.
  if (_availability_version_check)
    AvailabilityVersionCheck = &_availability_version_check;

  if (AvailabilityVersionCheck && !LoadPlist) {
    // New API is supported and we're not being asked to load the plist,
    // exit early!
    return;
  }
  // Still load the PLIST to ensure that the existing calls to
  // __isOSVersionAtLeast still work even with new compiler-rt and old OSes.

  // Load CoreFoundation dynamically
  const void *NullAllocator = dlsym(RTLD_DEFAULT, "kCFAllocatorNull");
  if (!NullAllocator)
    return;
  const CFAllocatorRef AllocatorNull = *(const CFAllocatorRef *)NullAllocator;
  CFDataCreateWithBytesNoCopyFuncTy CFDataCreateWithBytesNoCopyFunc =
      (CFDataCreateWithBytesNoCopyFuncTy)dlsym(RTLD_DEFAULT,
                                               "CFDataCreateWithBytesNoCopy");
  if (!CFDataCreateWithBytesNoCopyFunc)
    return;
  CFPropertyListCreateWithDataFuncTy CFPropertyListCreateWithDataFunc =
      (CFPropertyListCreateWithDataFuncTy)dlsym(RTLD_DEFAULT,
                                                "CFPropertyListCreateWithData");
// CFPropertyListCreateWithData was introduced only in macOS 10.6+, so it
// will be NULL on earlier OS versions.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CFPropertyListCreateFromXMLDataFuncTy CFPropertyListCreateFromXMLDataFunc =
      (CFPropertyListCreateFromXMLDataFuncTy)dlsym(
          RTLD_DEFAULT, "CFPropertyListCreateFromXMLData");
#pragma clang diagnostic pop
  // CFPropertyListCreateFromXMLDataFunc is deprecated in macOS 10.10, so it
  // might be NULL in future OS versions.
  if (!CFPropertyListCreateWithDataFunc && !CFPropertyListCreateFromXMLDataFunc)
    return;
  CFStringCreateWithCStringNoCopyFuncTy CFStringCreateWithCStringNoCopyFunc =
      (CFStringCreateWithCStringNoCopyFuncTy)dlsym(
          RTLD_DEFAULT, "CFStringCreateWithCStringNoCopy");
  if (!CFStringCreateWithCStringNoCopyFunc)
    return;
  CFDictionaryGetValueFuncTy CFDictionaryGetValueFunc =
      (CFDictionaryGetValueFuncTy)dlsym(RTLD_DEFAULT, "CFDictionaryGetValue");
  if (!CFDictionaryGetValueFunc)
    return;
  CFGetTypeIDFuncTy CFGetTypeIDFunc =
      (CFGetTypeIDFuncTy)dlsym(RTLD_DEFAULT, "CFGetTypeID");
  if (!CFGetTypeIDFunc)
    return;
  CFStringGetTypeIDFuncTy CFStringGetTypeIDFunc =
      (CFStringGetTypeIDFuncTy)dlsym(RTLD_DEFAULT, "CFStringGetTypeID");
  if (!CFStringGetTypeIDFunc)
    return;
  CFStringGetCStringFuncTy CFStringGetCStringFunc =
      (CFStringGetCStringFuncTy)dlsym(RTLD_DEFAULT, "CFStringGetCString");
  if (!CFStringGetCStringFunc)
    return;
  CFReleaseFuncTy CFReleaseFunc =
      (CFReleaseFuncTy)dlsym(RTLD_DEFAULT, "CFRelease");
  if (!CFReleaseFunc)
    return;

  char *PListPath = "/System/Library/CoreServices/SystemVersion.plist";

#if TARGET_OS_SIMULATOR
  char *PListPathPrefix = getenv("IPHONE_SIMULATOR_ROOT");
  if (!PListPathPrefix)
    return;
  char FullPath[strlen(PListPathPrefix) + strlen(PListPath) + 1];
  strcpy(FullPath, PListPathPrefix);
  strcat(FullPath, PListPath);
  PListPath = FullPath;
#endif
  FILE *PropertyList = fopen(PListPath, "r");
  if (!PropertyList)
    return;

  // Dynamically allocated stuff.
  CFDictionaryRef PListRef = NULL;
  CFDataRef FileContentsRef = NULL;
  UInt8 *PListBuf = NULL;

  fseek(PropertyList, 0, SEEK_END);
  long PListFileSize = ftell(PropertyList);
  if (PListFileSize < 0)
    goto Fail;
  rewind(PropertyList);

  PListBuf = malloc((size_t)PListFileSize);
  if (!PListBuf)
    goto Fail;

  size_t NumRead = fread(PListBuf, 1, (size_t)PListFileSize, PropertyList);
  if (NumRead != (size_t)PListFileSize)
    goto Fail;

  // Get the file buffer into CF's format. We pass in a null allocator here *
  // because we free PListBuf ourselves
  FileContentsRef = (*CFDataCreateWithBytesNoCopyFunc)(
      NULL, PListBuf, (CFIndex)NumRead, AllocatorNull);
  if (!FileContentsRef)
    goto Fail;

  if (CFPropertyListCreateWithDataFunc)
    PListRef = (*CFPropertyListCreateWithDataFunc)(
        NULL, FileContentsRef, CF_PROPERTY_LIST_IMMUTABLE, NULL, NULL);
  else
    PListRef = (*CFPropertyListCreateFromXMLDataFunc)(
        NULL, FileContentsRef, CF_PROPERTY_LIST_IMMUTABLE, NULL);
  if (!PListRef)
    goto Fail;

  CFStringRef ProductVersion = (*CFStringCreateWithCStringNoCopyFunc)(
      NULL, "ProductVersion", CF_STRING_ENCODING_ASCII, AllocatorNull);
  if (!ProductVersion)
    goto Fail;
  CFTypeRef OpaqueValue = (*CFDictionaryGetValueFunc)(PListRef, ProductVersion);
  (*CFReleaseFunc)(ProductVersion);
  if (!OpaqueValue ||
      (*CFGetTypeIDFunc)(OpaqueValue) != (*CFStringGetTypeIDFunc)())
    goto Fail;

  char VersionStr[32];
  if (!(*CFStringGetCStringFunc)((CFStringRef)OpaqueValue, VersionStr,
                                 sizeof(VersionStr), CF_STRING_ENCODING_UTF8))
    goto Fail;
  sscanf(VersionStr, "%d.%d.%d", &GlobalMajor, &GlobalMinor, &GlobalSubminor);

Fail:
  if (PListRef)
    (*CFReleaseFunc)(PListRef);
  if (FileContentsRef)
    (*CFReleaseFunc)(FileContentsRef);
  free(PListBuf);
  fclose(PropertyList);
}

// Find and parse the SystemVersion.plist file.
static void compatibilityInitializeAvailabilityCheck(void *Unused) {
  (void)Unused;
  _initializeAvailabilityCheck(/*LoadPlist=*/true);
}

static void initializeAvailabilityCheck(void *Unused) {
  (void)Unused;
  _initializeAvailabilityCheck(/*LoadPlist=*/false);
}

// This old API entry point is no longer used by Clang for Darwin. We still need
// to keep it around to ensure that object files that reference it are still
// usable when linked with new compiler-rt.
int32_t __isOSVersionAtLeast(int32_t Major, int32_t Minor, int32_t Subminor) {
  // Populate the global version variables, if they haven't already.
  dispatch_once_f(&CompatibilityDispatchOnceCounter, NULL,
                  compatibilityInitializeAvailabilityCheck);

  if (Major < GlobalMajor)
    return 1;
  if (Major > GlobalMajor)
    return 0;
  if (Minor < GlobalMinor)
    return 1;
  if (Minor > GlobalMinor)
    return 0;
  return Subminor <= GlobalSubminor;
}

static inline uint32_t ConstructVersion(uint32_t Major, uint32_t Minor,
                                        uint32_t Subminor) {
  return ((Major & 0xffff) << 16) | ((Minor & 0xff) << 8) | (Subminor & 0xff);
}

#define PLATFORM_MACOS 1

int32_t __isPlatformVersionAtLeast(uint32_t Platform, uint32_t Major,
                                   uint32_t Minor, uint32_t Subminor) {
  dispatch_once_f(&DispatchOnceCounter, NULL, initializeAvailabilityCheck);

  if (!AvailabilityVersionCheck) {
    return __isOSVersionAtLeast(Major, Minor, Subminor);
  }
  dyld_build_version_t Versions[] = {
      {Platform, ConstructVersion(Major, Minor, Subminor)}};
  return AvailabilityVersionCheck(1, Versions);
}

#if TARGET_OS_OSX

int32_t __isPlatformOrVariantPlatformVersionAtLeast(
    uint32_t Platform, uint32_t Major, uint32_t Minor, uint32_t Subminor,
    uint32_t Platform2, uint32_t Major2, uint32_t Minor2, uint32_t Subminor2) {
  dispatch_once_f(&DispatchOnceCounter, NULL, initializeAvailabilityCheck);

  if (!AvailabilityVersionCheck) {
    // Handle case of back-deployment for older macOS.
    if (Platform == PLATFORM_MACOS) {
      return __isOSVersionAtLeast(Major, Minor, Subminor);
    }
    assert(Platform2 == PLATFORM_MACOS && "unexpected platform");
    return __isOSVersionAtLeast(Major2, Minor2, Subminor2);
  }
  dyld_build_version_t Versions[] = {
      {Platform, ConstructVersion(Major, Minor, Subminor)},
      {Platform2, ConstructVersion(Major2, Minor2, Subminor2)}};
  return AvailabilityVersionCheck(2, Versions);
}

#endif

#endif
)OPENFRUIT_C";

bool WriteTextIfDifferent(const fs::path& path, const std::string& content) {
    std::ifstream input(path, std::ios::binary);
    if (input) {
        const std::string existing(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>()
        );
        if (existing == content) {
            return true;
        }
    }

    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        return false;
    }

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.flush();
    return static_cast<bool>(output);
}

} // namespace


namespace {
bool Active() {
    const auto operation = CurrentOperationContext();
    return !operation || (!operation->CancellationRequested() && !operation->DeadlineExceeded());
}
std::string ReadBytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

// Native process-wide and cross-process lease for the same cache destination.
class RuntimeLease {
    HANDLE mutex_ = nullptr;
    bool held_ = false;
public:
    explicit RuntimeLease(const std::string& key) {
        const auto name = L"Local\\OPENFRUIT-compiler-rt-" + Win32Process::ToWide(key);
        mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
        while (mutex_ && Active() && std::chrono::steady_clock::now() < deadline) {
            const auto result = WaitForSingleObject(mutex_, 100);
            if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) { held_ = true; break; }
            if (result != WAIT_TIMEOUT) break;
        }
    }
    ~RuntimeLease() { if (held_) ReleaseMutex(mutex_); if (mutex_) CloseHandle(mutex_); }
    explicit operator bool() const { return held_; }
};

bool ValidIosObject(const fs::path& path) {
    std::error_code ec;
    const auto length = fs::file_size(path, ec);
    if (ec || length > 32 * 1024 * 1024) return false;
    const auto bytes = ReadBytes(path);
    auto u32 = [&](std::size_t offset) {
        const auto* p = reinterpret_cast<const unsigned char*>(bytes.data() + offset);
        return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
            (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
    };
    if (bytes.size() < 32 || u32(0) != 0xfeedfacf || u32(4) != 0x0100000c ||
        u32(12) != 1 || !u32(16) || u32(20) > bytes.size() - 32) return false;
    std::size_t offset = 32;
    const std::size_t end = offset + u32(20);
    bool ios = false;
    for (std::uint32_t i = 0; i < u32(16); ++i) {
        if (offset + 8 > end) return false;
        const auto command = u32(offset), size = u32(offset + 4);
        if (size < 8 || size % 4 || size > end - offset) return false;
        if (command == 0x32) { // LC_BUILD_VERSION
            if (size < 24 || u32(offset + 8) != 2 || u32(offset + 20) > (size - 24) / 8) return false;
            ios = true;
        } else if (command == 0x25) { // LC_VERSION_MIN_IPHONEOS
            if (size < 16) return false;
            ios = true;
        }
        offset += size;
    }
    return offset == end && ios;
}

// Clang -MD includes system SDK headers. Parse Make escaping, including Windows
// drive colons, escaped spaces/backslashes, and continued lines.
std::vector<fs::path> DependencyPaths(const std::string& contents, const fs::path& cwd) {
    const auto separator = contents.find(": ");
    if (separator == std::string::npos) return {};
    std::vector<fs::path> result;
    std::string token;
    auto emit = [&] {
        if (!token.empty()) {
            fs::path path = fs::u8path(token);
            if (path.is_relative()) path = cwd / path;
            result.push_back(path.lexically_normal());
            token.clear();
        }
    };
    for (std::size_t i = separator + 2; i < contents.size(); ++i) {
        const char c = contents[i];
        if (c == '$' && i + 1 < contents.size() && contents[i + 1] == '$') { token += '$'; ++i; continue; }
        if (c == '\\' && i + 1 < contents.size()) {
            const char next = contents[i + 1];
            if (next == '\n') { ++i; continue; }
            if (next == '\r' && i + 2 < contents.size() && contents[i + 2] == '\n') { i += 2; continue; }
            if (next == ' ' || next == '\t' || next == '#' || next == ':' || next == '\\') {
                token += next; ++i; continue;
            }
        }
        if (std::isspace(static_cast<unsigned char>(c))) emit();
        else token += c;
    }
    emit();
    return result;
}

bool CacheValid(const fs::path& object, const fs::path& stamp, const std::string& identity) {
    const auto metadata = JsonValue::Parse(ReadBytes(stamp));
    if (!metadata || metadata->GetString("identity") != identity || !ValidIosObject(object)) return false;
    const auto digest = Sha256File(object);
    if (!digest || metadata->GetString("object_sha256") != *digest) return false;
    const auto* dependencies = metadata->Get("dependencies");
    if (!dependencies || !dependencies->IsArray() || dependencies->ArrayItems().empty()) return false;
    for (const auto& dependency : dependencies->ArrayItems()) {
        if (!Active()) return false;
        const auto actual = Sha256File(fs::u8path(dependency.GetString("path")));
        if (!actual || *actual != dependency.GetString("sha256")) return false;
    }
    return true;
}
} // namespace

fs::path EnsureIosAvailabilityRuntimeObject(
    const fs::path& repo_root,
    const fs::path& clang_executable,
    const SDKInfo& sdk_info
) {
    if (!Active() || clang_executable.empty() || sdk_info.sdk_path.empty() ||
        !sdk_info.target_triple.starts_with(L"arm64-apple-ios") ||
        sdk_info.target_triple.find(L"simulator") != std::wstring::npos) return {};
    std::error_code ec;
    const auto compiler = fs::canonical(clang_executable, ec);
    if (ec) return {};
    const auto sdk = fs::canonical(sdk_info.sdk_path, ec);
    if (ec) return {};
    const auto compiler_hash = Sha256FileStatCached(compiler, ToolPaths::FileDigestCache());
    if (!compiler_hash) return {};
    JsonValue inputs = JsonValue::ObjectValue();
    inputs.Set("schema", JsonValue::String("ios-availability-v2"));
    inputs.Set("compile_options", JsonValue::String("-fPIC -O2 -fvisibility=hidden -Wno-unused-command-line-argument -MD"));
    inputs.Set("compiler", JsonValue::String(compiler.generic_string()));
    inputs.Set("compiler_sha256", JsonValue::String(*compiler_hash));
    inputs.Set("sdk", JsonValue::String(sdk.generic_string()));
    inputs.Set("target", JsonValue::String(Win32Process::ToNarrow(sdk_info.target_triple)));
    const auto source_hash = Sha256(kLlvmOsVersionCheckSource);
    if (!source_hash) return {};
    inputs.Set("source_sha256", JsonValue::String(*source_hash));
    for (const auto* name : {"SDKSettings.json", "SDKSettings.plist"}) {
        const auto file = sdk / name;
        if (fs::exists(file, ec)) {
            const auto hash = Sha256File(file);
            if (!hash) return {};
            inputs.Set(name, JsonValue::String(*hash));
        }
    }
    if (!sdk_info.vfs_overlay_path.empty()) {
        const auto hash = Sha256File(fs::path(sdk_info.vfs_overlay_path));
        if (!hash) return {};
        inputs.Set("overlay", JsonValue::String(Win32Process::ToNarrow(sdk_info.vfs_overlay_path)));
        inputs.Set("overlay_sha256", JsonValue::String(*hash));
    }
    const auto identity = Sha256(inputs.Serialize());
    if (!identity) return {};
    // The fingerprint already binds the target; avoid redundant path depth on Windows.
    const auto directory = ToolPaths::CacheRoot() / "compiler-rt" / "v2" / *identity;
    fs::create_directories(directory, ec);
    if (ec) return {};
    const auto lease_key = Sha256(directory.generic_string());
    if (!lease_key) return {};
    RuntimeLease lease(*lease_key);
    if (!lease) return {};
    const auto object = directory / "os_version_check.o";
    const auto stamp = directory / "artifact.json";
    if (CacheValid(object, stamp, *identity)) return object;

    const auto staging = directory / (".stage-" + NewOperationId());
    fs::create_directory(staging, ec);
    if (ec) return {};
    struct StageCleanup {
        fs::path path;
        ~StageCleanup() { std::error_code ignored; fs::remove_all(path, ignored); }
    } cleanup{staging};
    const auto source = staging / "os_version_check.c";
    const auto output = staging / "os_version_check.o";
    const auto depfile = staging / "dependencies.d";
    if (!WriteTextIfDifferent(source, kLlvmOsVersionCheckSource)) return {};
    std::vector<std::wstring> args = { compiler.wstring(), L"-target", sdk_info.target_triple,
        L"-isysroot", sdk.wstring(), L"-fPIC", L"-O2", L"-fvisibility=hidden",
        L"-Wno-unused-command-line-argument", L"-MD", L"-MF", depfile.wstring(),
        L"-c", source.wstring(), L"-o", output.wstring() };
    if (!sdk_info.vfs_overlay_path.empty()) {
        args.push_back(L"-ivfsoverlay"); args.push_back(sdk_info.vfs_overlay_path);
    }
    if (!Active()) return {};
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    const auto build = Win32Process::Run(compiler.wstring(), args, repo_root.wstring(), {}, nullptr, nullptr, options);
    if (!build.success || !ValidIosObject(output)) {
        std::cerr << "OPENFRUIT: authentic LLVM iOS availability provider failed: " << build.std_err << std::endl;
        return {};
    }
    JsonValue::Array dependencies;
    std::set<fs::path> seen;
    for (const auto& dependency : DependencyPaths(ReadBytes(depfile), repo_root)) {
        if (!Active()) return {};
        if (dependency == source || !seen.insert(dependency).second) continue;
        const auto hash = Sha256File(dependency);
        if (!hash) return {};
        auto entry = JsonValue::ObjectValue();
        entry.Set("path", JsonValue::String(dependency.generic_string()));
        entry.Set("sha256", JsonValue::String(*hash));
        dependencies.push_back(std::move(entry));
    }
    // Real os_version_check.c includes SDK headers: absent dependency evidence
    // must never produce a reusable cache entry.
    if (dependencies.empty()) return {};
    const auto digest = Sha256File(output);
    if (!digest) return {};
    auto metadata = JsonValue::ObjectValue();
    metadata.Set("identity", JsonValue::String(*identity));
    metadata.Set("inputs", std::move(inputs));
    metadata.Set("object_sha256", JsonValue::String(*digest));
    metadata.Set("dependencies", JsonValue::ArrayValue(std::move(dependencies)));
    // Under the lease, publish object first and matching metadata last. A crash
    // between publications leaves a mismatched digest, which forces a rebuild.
    if (!MoveFileExW(output.c_str(), object.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ||
        !AtomicFile::Publish(stamp, metadata.Serialize()) || !CacheValid(object, stamp, *identity)) return {};
    std::cout << "OPENFRUIT: authentic LLVM iOS availability provider built: " << object.string() << std::endl;
    return object;
}

} // namespace OpenFruit
