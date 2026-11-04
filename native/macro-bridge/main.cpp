#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr std::uint64_t kMaxMessageSize = 256ull * 1024ull * 1024ull;

void report(const wchar_t* message) {
  const int size = WideCharToMultiByte(CP_UTF8, 0, message, -1, nullptr, 0,
                                       nullptr, nullptr);
  if (size <= 1) {
    return;
  }
  std::vector<char> utf8(static_cast<std::size_t>(size));
  WideCharToMultiByte(CP_UTF8, 0, message, -1, utf8.data(), size, nullptr,
                      nullptr);
  DWORD written = 0;
  WriteFile(GetStdHandle(STD_ERROR_HANDLE), utf8.data(),
            static_cast<DWORD>(utf8.size() - 1), &written, nullptr);
}

bool read_exact(HANDLE handle, void* buffer, std::size_t size) {
  auto* bytes = static_cast<unsigned char*>(buffer);
  while (size != 0) {
    DWORD received = 0;
    const DWORD chunk = static_cast<DWORD>(
        std::min<std::size_t>(size, static_cast<std::size_t>(UINT32_MAX)));
    if (!ReadFile(handle, bytes, chunk, &received, nullptr) || received == 0) {
      return false;
    }
    bytes += received;
    size -= received;
  }
  return true;
}

bool read_exact_until(HANDLE handle, HANDLE process, void* buffer,
                      std::size_t size, ULONGLONG deadline) {
  auto* bytes = static_cast<unsigned char*>(buffer);
  while (size != 0) {
    DWORD available = 0;
    if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr)) {
      return false;
    }
    if (available != 0) {
      DWORD received = 0;
      const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(
          size, static_cast<std::size_t>(available)));
      if (!ReadFile(handle, bytes, chunk, &received, nullptr) ||
          received == 0) {
        return false;
      }
      bytes += received;
      size -= received;
      continue;
    }
    if (process != nullptr &&
        WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
      return false;
    }
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) {
      return false;
    }
    Sleep(static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, 10)));
  }
  return true;
}

bool write_exact(HANDLE handle, const void* buffer, std::size_t size) {
  const auto* bytes = static_cast<const unsigned char*>(buffer);
  while (size != 0) {
    DWORD sent = 0;
    const DWORD chunk = static_cast<DWORD>(
        std::min<std::size_t>(size, static_cast<std::size_t>(UINT32_MAX)));
    if (!WriteFile(handle, bytes, chunk, &sent, nullptr) || sent == 0) {
      return false;
    }
    bytes += sent;
    size -= sent;
  }
  return true;
}

bool read_frame(HANDLE handle, std::string& message) {
  std::uint64_t size = 0;
  if (!read_exact(handle, &size, sizeof(size))) {
    return false;
  }
  if (size > kMaxMessageSize || size == 0) {
    unsigned char window[8];
    std::memcpy(window, &size, 8);
    for (std::size_t i = 0; i < 65536; ++i) {
      std::memmove(window, window + 1, 7);
      if (!read_exact(handle, window + 7, 1)) {
        return false;
      }
      std::memcpy(&size, window, 8);
      if (size > 0 && size <= kMaxMessageSize) {
        char first_char = 0;
        if (read_exact(handle, &first_char, 1)) {
          if (first_char == '{') {
            message.resize(static_cast<std::size_t>(size));
            message[0] = '{';
            return read_exact(handle, message.data() + 1, message.size() - 1);
          }
        }
      }
    }
    return false;
  }
  message.resize(static_cast<std::size_t>(size));
  return read_exact(handle, message.data(), message.size());
}

bool read_frame_until(HANDLE handle, HANDLE process, std::string& message,
                      DWORD timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  std::uint64_t size = 0;
  if (!read_exact_until(handle, process, &size, sizeof(size), deadline)) {
    return false;
  }
  if (size > kMaxMessageSize || size == 0) {
    unsigned char window[8];
    std::memcpy(window, &size, 8);
    for (std::size_t i = 0; i < 65536; ++i) {
      std::memmove(window, window + 1, 7);
      if (!read_exact_until(handle, process, window + 7, 1, deadline)) {
        return false;
      }
      std::memcpy(&size, window, 8);
      if (size > 0 && size <= kMaxMessageSize) {
        char first_char = 0;
        if (read_exact_until(handle, process, &first_char, 1, deadline) &&
            first_char == '{') {
          message.resize(static_cast<std::size_t>(size));
          message[0] = '{';
          return read_exact_until(handle, process, message.data() + 1,
                                  message.size() - 1, deadline);
        }
      }
    }
    return false;
  }
  message.resize(static_cast<std::size_t>(size));
  return read_exact_until(handle, process, message.data(), message.size(),
                          deadline);
}

bool write_frame(HANDLE handle, const std::string& message) {
  const auto size = static_cast<std::uint64_t>(message.size());
  return write_exact(handle, &size, sizeof(size)) &&
         write_exact(handle, message.data(), message.size());
}

std::string windows_json_path_to_darling(std::string value) {
  if (value.size() < 4 || !std::isalpha(static_cast<unsigned char>(value[0])) ||
      value[1] != ':' || value[2] != '\\' || value[3] != '\\') {
    return value;
  }
  std::string result = "/Volumes/SystemRoot/mnt/";
  result.push_back(static_cast<char>(
      std::tolower(static_cast<unsigned char>(value[0]))));
  result.push_back('/');
  for (std::size_t index = 4; index < value.size();) {
    if (index + 1 < value.size() && value[index] == '\\' &&
        value[index + 1] == '\\') {
      result.push_back('/');
      index += 2;
    } else {
      result.push_back(value[index++]);
    }
  }
  return result;
}

void rewrite_library_path(std::string& json,
                          const std::string& darling_plugin_directory,
                          bool native_dylib_names = false) {
  constexpr char key[] = "\"libraryPath\"";
  const auto key_position = json.find(key);
  if (key_position == std::string::npos) {
    return;
  }
  const auto colon = json.find(':', key_position + sizeof(key) - 1);
  if (colon == std::string::npos) {
    return;
  }
  const auto opening = json.find('"', colon + 1);
  if (opening == std::string::npos) {
    return;
  }
  std::size_t closing = opening + 1;
  bool escaped = false;
  for (; closing < json.size(); ++closing) {
    const char character = json[closing];
    if (character == '"' && !escaped) {
      break;
    }
    if (character == '\\') {
      escaped = !escaped;
    } else {
      escaped = false;
    }
  }
  if (closing == json.size()) {
    return;
  }
  const auto original = json.substr(opening + 1, closing - opening - 1);
  auto rewritten = windows_json_path_to_darling(original);
  if (!darling_plugin_directory.empty()) {
    const auto separator = rewritten.find_last_of('/');
    auto filename = separator == std::string::npos
        ? rewritten
        : rewritten.substr(separator + 1);
    if (native_dylib_names) {
      if (filename.size() > 4 && filename.substr(filename.size() - 4) == ".dll") {
        filename = filename.substr(0, filename.size() - 4) + ".dylib";
      }
      if (filename.rfind("lib", 0) != 0) {
        filename = "lib" + filename;
      }
    }
    rewritten = darling_plugin_directory + "/" + filename;
  }
  if (rewritten != original) {
    json.replace(opening + 1, closing - opening - 1, rewritten);
  }
}

std::wstring quote(const std::wstring& value) {
  return L"\"" + value + L"\"";
}

std::filesystem::path executable_path() {
  std::vector<wchar_t> buffer(32768);
  const DWORD size = GetModuleFileNameW(nullptr, buffer.data(),
                                       static_cast<DWORD>(buffer.size()));
  return std::filesystem::path(std::wstring(buffer.data(), size));
}

std::filesystem::path environment_path(const wchar_t* name) {
  const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
  if (size == 0) {
    return {};
  }
  std::vector<wchar_t> buffer(size);
  if (GetEnvironmentVariableW(name, buffer.data(), size) == 0) {
    return {};
  }
  return std::filesystem::path(buffer.data());
}

void trace_payload(const std::filesystem::path& directory,
                   const wchar_t* kind, std::uint64_t index,
                   const std::string& payload) {
  if (directory.empty()) {
    return;
  }
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  const auto name = std::to_wstring(GetCurrentProcessId()) + L"-" + kind +
      L"-" + std::to_wstring(index) + L".json";
  std::ofstream output(directory / name, std::ios::binary | std::ios::trunc);
  output.write(payload.data(), static_cast<std::streamsize>(payload.size()));
}

std::wstring environment_value(const wchar_t* name) {
  const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
  if (size == 0) {
    return {};
  }
  std::vector<wchar_t> buffer(size);
  if (GetEnvironmentVariableW(name, buffer.data(), size) == 0) {
    return {};
  }
  return std::wstring(buffer.data());
}

DWORD environment_dword(const wchar_t* name, DWORD fallback,
                        DWORD minimum, DWORD maximum) {
  const std::wstring value = environment_value(name);
  if (value.empty()) return fallback;
  wchar_t* end = nullptr;
  const unsigned long parsed = std::wcstoul(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != L'\0' ||
      parsed < minimum || parsed > maximum) {
    return fallback;
  }
  return static_cast<DWORD>(parsed);
}

std::wstring darling_command(const std::wstring& action,
                             const std::wstring& prefix) {
  auto distro = environment_value(L"OPENFRUIT_WSL_DISTRO");
  if (distro.empty()) distro = L"Ubuntu";
  std::wstring command = L"wsl.exe -d " + quote(distro) + L" -- ";
  if (!prefix.empty()) {
    command += L"env " + quote(L"DPREFIX=" + prefix) + L" ";
  }
  return command + L"darling " + action;
}

std::string narrow_ascii(const std::wstring& value) {
  return std::string(value.begin(), value.end());
}

bool is_apple_plugin_module(const std::string& req) {
  static const std::vector<std::string> apple_plugins = {
      "AppIntentsMacros", "FinanceMacros", "FoundationMacros",
      "FoundationModelsMacros", "MMIOMacros", "ObservationMacros",
      "PreviewsMacros", "SwiftDataMacros", "SwiftMacros",
      "SwiftUIMacros", "TipKitMacros"
  };
  for (const auto& name : apple_plugins) {
    if (req.find(name) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace

int wmain() {
  const auto bridge = executable_path();
  const auto provider_root = bridge.parent_path().parent_path();

  auto darling_bundle = environment_value(L"OPENFRUIT_DARLING_BUNDLE");
  const auto darling_prefix = environment_value(L"OPENFRUIT_DARLING_PREFIX");
  const bool force_darling = !darling_bundle.empty() || !darling_prefix.empty() ||
      !environment_value(L"OPENFRUIT_OWNED_PROVIDER_LOG").empty() ||
      std::filesystem::exists(bridge.parent_path() / L"wsl.exe");

  std::filesystem::path native_cli = bridge.parent_path() / L"openfruit.exe";
  if (!std::filesystem::exists(native_cli)) {
    native_cli = environment_path(L"LOCALAPPDATA") / L"OPENFRUIT" / L"bin" / L"OPENFRUIT.exe";
  }
  const auto diag_root = environment_path(L"USERPROFILE") / L".OPENFRUIT" / L"diagnostics" / L"architecture-completion";
  const auto closure_dir = diag_root / L"runtime-closure";
  const auto xcode_tree = closure_dir / L"apple-macos-disk-dyld-tree";
  const auto system_tree = diag_root / L"state-macro-native-20261015" / L"sdk27-original-host";
  const bool use_native_darwin_runtime = !force_darling &&
      std::filesystem::exists(native_cli) &&
      std::filesystem::is_directory(closure_dir) &&
      std::filesystem::is_directory(xcode_tree) &&
      std::filesystem::is_directory(system_tree);

  if (darling_bundle.empty()) {
    darling_bundle = L"/Volumes/SystemRoot/opt/OPENFRUIT/bundles/cfc8997ec87d5ba2673d8432f04ba8150e29e084d8992f632010faa41969218c";
  }
  std::wstring server_path = darling_bundle + L"/toolchain/usr/bin/swift-plugin-server";
  std::string plugin_directory = use_native_darwin_runtime
      ? "/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/lib/swift/host/plugins"
      : narrow_ascii(darling_bundle + L"/plugins");

  const std::wstring fallback_command = darling_command(L"shell " + quote(server_path), darling_prefix);
  std::filesystem::path active_report_path;

  HANDLE child_input_write = nullptr;
  HANDLE child_output_read = nullptr;
  PROCESS_INFORMATION process{};
  bool apple_server_started = false;
  bool apple_server_needs_replay = false;
  std::string apple_capability_response;
  HANDLE apple_pool_slot = nullptr;
  std::vector<std::string> apple_setup_requests;

  const DWORD pool_size = environment_dword(
      L"OPENFRUIT_APPLE_PLUGIN_SERVER_POOL_SIZE", 2, 1, 8);
  const DWORD queue_timeout_ms = environment_dword(
      L"OPENFRUIT_APPLE_PLUGIN_SERVER_QUEUE_TIMEOUT_MS", 600000, 1000,
      3600000);
  const DWORD response_timeout_ms = environment_dword(
      L"OPENFRUIT_APPLE_PLUGIN_SERVER_RESPONSE_TIMEOUT_MS", 120000, 1000,
      600000);
  const DWORD retry_count = environment_dword(
      L"OPENFRUIT_APPLE_PLUGIN_SERVER_RETRIES", 3, 1, 8);

  auto stop_apple_server = [&]() {
    if (child_input_write != nullptr) {
      CloseHandle(child_input_write);
      child_input_write = nullptr;
    }
    if (child_output_read != nullptr) {
      CloseHandle(child_output_read);
      child_output_read = nullptr;
    }
    if (process.hProcess != nullptr) {
      if (WaitForSingleObject(process.hProcess, use_native_darwin_runtime ? 1500 : 0) == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 72);
        WaitForSingleObject(process.hProcess, 5000);
      }
      CloseHandle(process.hThread);
      CloseHandle(process.hProcess);
      process = {};
    }
    if (!active_report_path.empty()) {
      std::error_code ec;
      std::filesystem::remove(active_report_path, ec);
      active_report_path.clear();
    }
    if (apple_pool_slot != nullptr) {
      ReleaseSemaphore(apple_pool_slot, 1, nullptr);
      CloseHandle(apple_pool_slot);
      apple_pool_slot = nullptr;
    }
    apple_server_started = false;
    apple_server_needs_replay = false;
  };

  auto ensure_apple_server = [&]() -> bool {
    if (apple_server_started) return child_input_write != nullptr;
    apple_server_started = true;

    // A named semaphore provides a bounded cross-process queue (N = 2):
    // ordinary compilation remains parallel while Apple plugin sessions wait
    // for one of N slots.
    const std::wstring pool_name =
        L"Local\\OPENFRUITDarlingPluginServerPool-v1-" +
        std::to_wstring(pool_size);
    HANDLE pool_slot = CreateSemaphoreW(
        nullptr, static_cast<LONG>(pool_size),
        static_cast<LONG>(pool_size), pool_name.c_str());
    const DWORD slot_wait = pool_slot == nullptr
        ? WAIT_FAILED
        : WaitForSingleObject(pool_slot, queue_timeout_ms);
    if (pool_slot == nullptr || slot_wait != WAIT_OBJECT_0) {
      if (pool_slot != nullptr) CloseHandle(pool_slot);
      apple_server_started = false;
      return false;
    }
    apple_pool_slot = pool_slot;

    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE child_input_read = nullptr;
    HANDLE child_output_write = nullptr;
    if (!CreatePipe(&child_input_read, &child_input_write, &security, 0) ||
        !CreatePipe(&child_output_read, &child_output_write, &security, 0)) {
      if (child_input_read != nullptr) CloseHandle(child_input_read);
      if (child_output_write != nullptr) CloseHandle(child_output_write);
      stop_apple_server();
      return false;
    }
    SetHandleInformation(child_input_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(child_output_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = child_input_read;
    startup.hStdOutput = child_output_write;
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    std::wstring launch_command = fallback_command;
    if (use_native_darwin_runtime) {
      active_report_path = std::filesystem::temp_directory_path() /
          (L"openfruit-macro-report-" + std::to_wstring(GetCurrentProcessId()) +
           L"-" + std::to_wstring(GetTickCount64()) + L".json");
      std::error_code ec;
      std::filesystem::remove(active_report_path, ec);
      const auto preview_tree = closure_dir / L"xcode-original-preview-plugins-c4c76f54aa3b413b912b3b776fad2fc9";
      launch_command = quote(native_cli.wstring()) +
          L" runtime probe-cache-arm64 /Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-plugin-server"
          L" /Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/lib/swift/host/plugins/libSwiftUIMacros.dylib,/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/lib/swift/host/plugins/libPreviewsMacros.dylib " +
          quote((closure_dir / L"apple-macos-systemos-installed-apfs-file.json").wstring()) + L" " +
          quote((closure_dir / L"apple-macos-systemos-installed-apfs-first-child.json").wstring());
      for (int idx = 2; idx <= 78; ++idx) {
        wchar_t num[8]{};
        swprintf(num, 8, L"%02d", idx);
        launch_command += L" " + quote((closure_dir / (std::wstring(L"apple-macos-systemos-apfs-child-") + num + L".json")).wstring());
      }
      launch_command += L" " + quote((closure_dir / L"apple-macos-systemos-installed-apfs-large-file.json").wstring());
      launch_command += L" --protocol-stdio " + quote(active_report_path.wstring()) +
          L" --trees " + quote(xcode_tree.wstring()) + L" " + quote(system_tree.wstring());
      if (std::filesystem::is_directory(preview_tree)) {
        launch_command += L" " + quote(preview_tree.wstring());
      }
    }

    std::vector<wchar_t> command_buffer(launch_command.begin(), launch_command.end());
    command_buffer.push_back(L'\0');
    if (!CreateProcessW(nullptr, command_buffer.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, provider_root.c_str(), &startup,
                        &process)) {
      CloseHandle(child_input_read);
      CloseHandle(child_output_write);
      CloseHandle(child_input_write);
      CloseHandle(child_output_read);
      child_input_write = nullptr;
      child_output_read = nullptr;
      stop_apple_server();
      return false;
    }
    CloseHandle(child_input_read);
    CloseHandle(child_output_write);

    std::string handshake_req = "{\"getCapability\":{}}";
    if (write_frame(child_input_write, handshake_req) &&
        read_frame_until(child_output_read, process.hProcess,
                         apple_capability_response, use_native_darwin_runtime ? 90000 : 30000)) {
      report(L"OPENFRUIT macro bridge: Apple server handshake OK.\r\n");
      apple_server_needs_replay = true;
      return true;
    }
    report(L"OPENFRUIT macro bridge: Apple server handshake timed out or failed.\r\n");
    stop_apple_server();
    return false;
  };

  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  std::string request;
  std::string response;
  const auto trace_directory = environment_path(L"OPENFRUIT_MACRO_TRACE_DIR");
  const bool use_apple_plugin_server = (environment_value(L"OPENFRUIT_DISABLE_APPLE_PLUGIN_SERVER") != L"1");

  std::uint64_t trace_index = 0;
  bool ok = true;
  while (read_frame(input, request)) {
    trace_payload(trace_directory, L"request", trace_index, request);

    if (request.find("\"getCapability\"") != std::string::npos) {
      response = "{\"getCapabilityResult\":{\"capability\":{\"protocolVersion\":8,\"features\":[\"load-plugin-library\"]}}}";
      trace_payload(trace_directory, L"response", trace_index, response);
      if (!write_frame(output, response)) {
        ok = false;
        break;
      }
      ++trace_index;
      continue;
    }

    const bool is_apple_official = is_apple_plugin_module(request);

    bool apple_request_completed = false;
    if (is_apple_official && use_apple_plugin_server) {
      std::string child_request = request;
      rewrite_library_path(child_request, plugin_directory, use_native_darwin_runtime);

      for (DWORD attempt = 0; attempt < retry_count; ++attempt) {
        if (!ensure_apple_server()) {
          if (attempt + 1 < retry_count) {
            // Only retry this bridge's server connection. A shared provider
            // is never ours to shut down or restart.
            Sleep(250 * (attempt + 1));
          }
          continue;
        }

        bool replay_ok = true;
        if (apple_server_needs_replay) {
          std::string replay_response;
          for (const auto& setup_request : apple_setup_requests) {
            if (!write_frame(child_input_write, setup_request) ||
                !read_frame_until(child_output_read, process.hProcess,
                                  replay_response, response_timeout_ms)) {
              replay_ok = false;
              break;
            }
          }
          apple_server_needs_replay = false;
        }

        trace_payload(trace_directory, L"apple-request", trace_index,
                      child_request);
        const bool child_ok = replay_ok &&
            write_frame(child_input_write, child_request) &&
            read_frame_until(child_output_read, process.hProcess,
                             response, response_timeout_ms);
        if (child_ok) {
          if (child_request.find("\"loadPluginLibrary\"") !=
                  std::string::npos &&
              std::find(apple_setup_requests.begin(),
                        apple_setup_requests.end(), child_request) ==
                  apple_setup_requests.end()) {
            apple_setup_requests.push_back(child_request);
          }
          trace_payload(trace_directory, L"apple-response", trace_index,
                        response);
          if (!write_frame(output, response)) {
            ok = false;
            break;
          }
          ++trace_index;
          apple_request_completed = true;
          break;
        }

        report(L"OPENFRUIT macro bridge: Apple plugin server protocol communication failed; requeueing request.\r\n");
        stop_apple_server();
        if (attempt + 1 < retry_count) {
          Sleep(250 * (attempt + 1));
        }
      }
    }
    if (!ok) break;
    if (apple_request_completed) {
      continue;
    }

    if (request.find("\"loadPluginLibrary\"") != std::string::npos) {
      // Non-Apple macros or unhandled Apple macros fall back to -load-plugin-executable
      response = is_apple_official && use_apple_plugin_server
          ? "{\"loadPluginLibraryResult\":{\"diagnostics\":[{\"message\":\"Original plugin server unavailable; shared provider was not restarted\",\"position\":{\"fileName\":\"\",\"offset\":0},\"severity\":\"error\",\"highlights\":[],\"notes\":[],\"fixIts\":[]}],\"loaded\":false}}"
          : "{\"loadPluginLibraryResult\":{\"diagnostics\":[],\"loaded\":false}}";
      trace_payload(trace_directory, L"response", trace_index, response);
      if (!write_frame(output, response)) {
        ok = false;
        break;
      }
      ++trace_index;
      continue;
    }

    if (request.find("\"expandAttachedMacro\"") != std::string::npos) {
      response = "{\"expandAttachedMacroResult\":{\"diagnostics\":[{\"message\":\"Macro not handled by OPENFRUIT external bridge\",\"position\":{\"fileName\":\"\",\"offset\":0},\"severity\":\"error\",\"highlights\":[],\"notes\":[],\"fixIts\":[]}],\"expandedSources\":[]}}";
      trace_payload(trace_directory, L"response", trace_index, response);
      if (!write_frame(output, response)) {
        ok = false;
        break;
      }
      ++trace_index;
      continue;
    }
    if (request.find("\"expandFreestandingMacro\"") != std::string::npos) {
      response = "{\"expandFreestandingMacroResult\":{\"diagnostics\":[{\"message\":\"Macro not handled by OPENFRUIT external bridge\",\"position\":{\"fileName\":\"\",\"offset\":0},\"severity\":\"error\",\"highlights\":[],\"notes\":[],\"fixIts\":[]}],\"expandedSource\":\"\"}}";
      trace_payload(trace_directory, L"response", trace_index, response);
      if (!write_frame(output, response)) {
        ok = false;
        break;
      }
      ++trace_index;
      continue;
    }
  }
  stop_apple_server();
  return ok ? 0 : 72;
}
