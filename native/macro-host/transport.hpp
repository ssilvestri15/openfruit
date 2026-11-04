#pragma once
#include "cancellation.hpp"
#include "json_value.hpp"
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <exception>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace OpenFruit::MacroHost {
inline constexpr std::uint64_t MaxMessageSize = 16ull * 1024ull * 1024ull;
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE handle = nullptr) : value(handle) {}
    ~Handle() { Reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void Reset() noexcept { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
};
inline bool ReadExact(HANDLE handle, void* buffer, std::size_t size, std::size_t& total, bool& ended) {
    auto* bytes = static_cast<unsigned char*>(buffer); total = 0; ended = false;
    while (size) {
        DWORD received = 0;
        if (!ReadFile(handle, bytes, static_cast<DWORD>(std::min<std::size_t>(size, MAXDWORD)), &received, nullptr)) {
            const auto error = GetLastError(); ended = error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF; return false;
        }
        if (!received) { ended = true; return false; }
        bytes += received; size -= received; total += received;
    }
    return true;
}
inline bool WriteExact(HANDLE handle, const void* buffer, std::size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(buffer);
    while (size) {
        DWORD sent = 0;
        if (!WriteFile(handle, bytes, static_cast<DWORD>(std::min<std::size_t>(size, MAXDWORD)), &sent, nullptr) || !sent) return false;
        bytes += sent; size -= sent;
    }
    return true;
}
enum class FrameStatus { Ok, End, Error };
inline FrameStatus ReadFrame(HANDLE input, std::string& message) {
    std::uint64_t size = 0; std::size_t total = 0; bool ended = false;
    if (!ReadExact(input, &size, sizeof(size), total, ended)) return !total && ended ? FrameStatus::End : FrameStatus::Error;
    if (!size) return FrameStatus::End;
    if (size > MaxMessageSize) return FrameStatus::Error;
    message.resize(static_cast<std::size_t>(size));
    return ReadExact(input, message.data(), message.size(), total, ended) ? FrameStatus::Ok : FrameStatus::Error;
}
inline bool WriteFrame(HANDLE output, const std::string& message) {
    const auto size = static_cast<std::uint64_t>(message.size());
    return WriteExact(output, &size, sizeof(size)) && WriteExact(output, message.data(), message.size());
}
// Only this payload field is a host namespace boundary. Other message bytes and
// all original server replies pass through unchanged, including future variants.
using PathTranslator = std::function<bool(const std::string&, std::string&)>;
inline bool ProjectRequest(const std::string& message, const std::map<std::string, std::string>& modules,
                           const PathTranslator& translate, std::string& output, std::string& error) {
    output.clear(); error.clear(); auto request = JsonValue::Parse(message);
    if (!request || !request->IsObject() || request->ObjectItems().size() != 1 ||
        !request->ObjectItems().begin()->second.IsObject()) { error = "Invalid macro protocol request."; return false; }
    output = message;
    auto* load = request->Get("loadPluginLibrary");
    if (!load) return true;
    const auto* path = load->Get("libraryPath"); const auto* module = load->Get("moduleName");
    if (!path || !path->IsString() || !module || !module->IsString()) { error = "Invalid plugin library request."; return false; }
    const auto selected = modules.find(module->StringValue()); std::string mapped;
    if (selected == modules.end() || !translate(path->StringValue(), mapped) || mapped != selected->second) {
        error = "Plugin library is not admitted by the selected managed provider."; return false;
    }
    if (path->StringValue() != mapped) {
        load->Set("libraryPath", JsonValue::String(mapped)); output = request->Serialize();
    }
    return true;
}
inline bool SelectModules(const std::string& selection, const std::map<std::string, std::string>& catalog,
                          std::map<std::string, std::string>& modules, std::vector<std::string>& plugins) {
    modules.clear(); plugins.clear();
    if (selection.empty()) return false;
    for (std::size_t begin = 0; begin <= selection.size();) {
        const auto end = selection.find(',', begin);
        const auto name = selection.substr(begin, end == std::string::npos ? end : end - begin);
        const auto found = catalog.find(name);
        if (name.empty() || found == catalog.end() || !modules.emplace(name, found->second).second) {
            modules.clear(); plugins.clear(); return false;
        }
        plugins.push_back(found->second);
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    return true;
}
struct SessionResult {
    int runtime_exit = 1; bool broker_failed = false; bool cancelled = false; std::string diagnostic;
    // Broker observations for diagnostics: frames forwarded and the last command.
    std::size_t frames = 0; std::string last_command;
};
// Backend runs on its existing runtime thread; this helper only owns native pipe
// transport and shutdown. Tests may use an owned byte consumer, never a plugin.
using Backend = std::function<int(HANDLE, CancellationToken)>;
using Control = std::function<bool()>;
inline SessionResult RunSession(HANDLE compiler_input, const std::map<std::string, std::string>& modules,
                                const PathTranslator& translate, const Backend& backend, const Control& control = {}) {
    SessionResult result;
    HANDLE reader = nullptr, writer = nullptr;
    if (!CreatePipe(&reader, &writer, nullptr, 0)) { result.diagnostic = "Cannot create guest protocol input pipe."; return result; }
    Handle read_end(reader), write_end(writer);
    CancellationSource cancellation;
    std::atomic<bool> runtime_done{false}, broker_done{false}, stopping{false};
    std::mutex mutex; std::condition_variable changed;
    std::thread runtime, broker;
    // Repeated cancellation below closes the check-before-block race: cancelling
    // once could precede a worker's next synchronous ReadFile/WriteFile call.
    try {
        runtime = std::thread([&] {
            try { result.runtime_exit = backend(reader, cancellation.Token()); }
            catch (const std::exception& failure) { std::lock_guard lock(mutex); result.diagnostic = failure.what(); }
            catch (...) { std::lock_guard lock(mutex); result.diagnostic = "Original macro runtime failed."; }
            runtime_done.store(true, std::memory_order_release); changed.notify_all();
        });
        broker = std::thread([&] {
            bool failed = false; std::string diagnostic;
            try {
                while (!stopping.load(std::memory_order_acquire)) {
                    std::string message, projected;
                    const auto frame = ReadFrame(compiler_input, message);
                    if (stopping.load(std::memory_order_acquire)) break;
                    if (frame == FrameStatus::End) break;
                    if (frame == FrameStatus::Error) { failed = true; diagnostic = "Invalid or truncated macro protocol frame."; break; }
                    {
                        std::lock_guard lock(mutex); ++result.frames;
                        const auto quote = message.find('"');
                        const auto end = quote == std::string::npos ? quote : message.find('"', quote + 1);
                        result.last_command = end == std::string::npos ? std::string{} : message.substr(quote + 1, end - quote - 1);
                    }
                    if (!ProjectRequest(message, modules, translate, projected, diagnostic) ||
                        !WriteFrame(writer, projected)) { failed = true; if (diagnostic.empty()) diagnostic = "Guest macro protocol input write failed."; break; }
                }
            } catch (const std::exception& failure) { failed = true; diagnostic = failure.what(); }
            catch (...) { failed = true; diagnostic = "Macro protocol input failed."; }
            // Sole writer closes on physical EOF or the protocol termination
            // header. Original StandardIOMessageConnection observes real EOF.
            write_end.Reset();
            { std::lock_guard lock(mutex); result.broker_failed = failed; if (!diagnostic.empty()) result.diagnostic = diagnostic; }
            if (failed) cancellation.Cancel();
            broker_done.store(true, std::memory_order_release); changed.notify_all();
        });
    } catch (const std::exception& failure) {
        { std::lock_guard lock(mutex); result.diagnostic = failure.what(); }
        cancellation.Cancel(); stopping.store(true);
        if (!runtime.joinable()) runtime_done.store(true);
        write_end.Reset(); broker_done.store(!broker.joinable());
    }
    while (!runtime_done.load(std::memory_order_acquire) || !broker_done.load(std::memory_order_acquire)) {
        const bool externally_cancelled = control && control();
        if (externally_cancelled) { cancellation.Cancel(); result.cancelled = true; }
        if (runtime_done.load(std::memory_order_acquire) || cancellation.Token().Requested()) {
            stopping.store(true, std::memory_order_release);
            if (broker.joinable() && !broker_done.load(std::memory_order_acquire)) CancelSynchronousIo(broker.native_handle());
        }
        if (cancellation.Token().Requested() && runtime.joinable() && !runtime_done.load(std::memory_order_acquire))
            CancelSynchronousIo(runtime.native_handle());
        std::unique_lock lock(mutex); changed.wait_for(lock, std::chrono::milliseconds(20));
    }
    if (broker.joinable()) broker.join();
    if (runtime.joinable()) runtime.join();
    return result;
}
}
