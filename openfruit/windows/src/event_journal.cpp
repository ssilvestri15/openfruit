#include "event_journal.hpp"
#include "process_diagnostics.hpp"
#include "win32_process.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

namespace OpenFruit {
namespace {
std::wstring EnvironmentValue(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    value.resize(written);
    return value;
}

bool ValidId(const std::string& id) {
    return id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

struct FileHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~FileHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
}

class EventJournal::Sink final : public EventSink {
public:
    explicit Sink(std::filesystem::path directory)
        : directory_(std::move(directory)), worker_([this] { WriteLoop(); }) {}
    ~Sink() override {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        available_.notify_one();
        worker_.join();
    }

    void Emit(OperationEvent event) noexcept override {
        try {
            std::lock_guard lock(mutex_);
            auto envelope = envelope_.Build(std::move(event));
            const std::size_t bytes = envelope.Serialize().size();
            if (stopping_ || bytes > kMaximumRecord || queued_bytes_ + bytes > kQueueBudget) {
                ++dropped_;
                errors_ = true;
                return;
            }
            queue_.push_back({std::move(envelope), bytes});
            queued_bytes_ += bytes;
            available_.notify_one();
        } catch (...) { errors_ = true; }
    }

    void Flush() {
        std::unique_lock lock(mutex_);
        drained_.wait(lock, [this] { return queue_.empty() && !writing_; });
        const auto dropped = dropped_;
        dropped_ = 0;
        lock.unlock();
        if (dropped) {
            auto data = JsonValue::ObjectValue();
            data.Set("dropped_events", JsonValue::Number(std::to_string(dropped)));
            Emit({"observability.gap", "warning", directory_.filename().string(), {}, {}, std::move(data)});
            lock.lock();
            drained_.wait(lock, [this] { return queue_.empty() && !writing_; });
        }
    }
    bool HasErrors() const noexcept { return errors_.load(); }
private:
    static constexpr std::size_t kMaximumRecord = 1024 * 1024;
    static constexpr std::size_t kQueueBudget = 8 * 1024 * 1024;
    std::filesystem::path directory_;
    EventEnvelopeBuilder envelope_;
    std::mutex mutex_;
    std::condition_variable available_, drained_;
    std::deque<std::pair<JsonValue, std::size_t>> queue_;
    std::size_t queued_bytes_ = 0;
    std::uint64_t dropped_ = 0;
    bool stopping_ = false, writing_ = false;
    std::atomic<bool> errors_{false};
    std::thread worker_;

    bool Append(JsonValue record) {
        FileHandle counter{CreateFileW((directory_ / "sequence.bin").c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (counter.value == INVALID_HANDLE_VALUE) return false;
        OVERLAPPED offset{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!LockFileEx(counter.value, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset)) {
            if (GetLastError() != ERROR_LOCK_VIOLATION || std::chrono::steady_clock::now() >= deadline) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::uint64_t sequence = 0;
        DWORD count = 0;
        const bool readable = ReadFile(counter.value, &sequence, sizeof(sequence), &count, nullptr) &&
                              (count == 0 || count == sizeof(sequence));
        bool success = false;
        if (readable) {
            ++sequence;
            LARGE_INTEGER beginning{};
            const bool updated = SetFilePointerEx(counter.value, beginning, nullptr, FILE_BEGIN) &&
                WriteFile(counter.value, &sequence, sizeof(sequence), &count, nullptr) && count == sizeof(sequence);
            if (updated) {
                record.Set("sequence", JsonValue::Number(std::to_string(sequence)));
                const std::string line = record.Serialize() + "\n";
                FileHandle journal{CreateFileW((directory_ / "events.jsonl").c_str(), FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
                success = journal.value != INVALID_HANDLE_VALUE &&
                    WriteFile(journal.value, line.data(), static_cast<DWORD>(line.size()), &count, nullptr) && count == line.size();
            }
        }
        UnlockFileEx(counter.value, 0, 1, 0, &offset);
        return success;
    }

    void WriteLoop() noexcept {
        for (;;) {
            JsonValue record;
            {
                std::unique_lock lock(mutex_);
                available_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty() && stopping_) break;
                record = std::move(queue_.front().first);
                queued_bytes_ -= queue_.front().second;
                queue_.pop_front();
                writing_ = true;
                if (dropped_) {
                    record.Set("dropped_events_before_record", JsonValue::Number(std::to_string(dropped_)));
                    dropped_ = 0;
                }
            }
            try { if (!Append(std::move(record))) errors_ = true; }
            catch (...) { errors_ = true; }
            {
                std::lock_guard lock(mutex_);
                writing_ = false;
                drained_.notify_all();
            }
        }
    }
};

EventJournal::EventJournal(const std::filesystem::path& directory, std::string build_id, std::string parent) {
    sink_ = std::make_shared<Sink>(directory);
    context_ = std::make_shared<OperationContext>(OperationContext{sink_, std::move(build_id), std::move(parent), directory});
}
EventJournal::~EventJournal() { Flush(); }

std::shared_ptr<EventJournal> EventJournal::Create(const std::filesystem::path& root) {
    const std::string id = NewOperationId();
    const auto directory = std::filesystem::absolute(root / id).lexically_normal();
    std::filesystem::create_directories(directory);
    return std::shared_ptr<EventJournal>(new EventJournal(directory, id, id));
}

namespace {
std::uint64_t CreationTime(HANDLE process) {
    FILETIME created{}, ended{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &ended, &kernel, &user)) return 0;
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}
// The nearest process in this process's ancestry (itself included) that an
// OPENFRUIT Run started carries the event context, as an inherited variable
// would. A parent PID is trusted only if it was created before its child.
bool InheritedEventContext(std::wstring& directory, std::string& id, std::string& parent) {
    std::map<DWORD, DWORD> parents;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry))
        parents[entry.th32ProcessID] = entry.th32ParentProcessID;
    CloseHandle(snapshot);
    DWORD process = GetCurrentProcessId();
    std::uint64_t created = CreationTime(GetCurrentProcess());
    for (int depth = 0; depth < 32 && process && created; ++depth) {
        std::ifstream record(Win32Process::EventContextRecord(process, created), std::ios::binary);
        std::string directory_text;
        if (record && std::getline(record, directory_text) && std::getline(record, id) && std::getline(record, parent)) {
            directory = Win32Process::ToWide(directory_text);
            return true;
        }
        const auto found = parents.find(process);
        if (found == parents.end() || !found->second || found->second == process) return false;
        const HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, found->second);
        if (!handle) return false;
        const auto parent_created = CreationTime(handle);
        CloseHandle(handle);
        if (!parent_created || parent_created > created) return false;
        process = found->second; created = parent_created;
    }
    return false;
}
}

std::shared_ptr<EventJournal> EventJournal::AttachFromEnvironment() {
    auto directory = EnvironmentValue(L"OPENFRUIT_EVENT_DIRECTORY");
    auto id = Win32Process::ToNarrow(EnvironmentValue(L"OPENFRUIT_EVENT_BUILD_ID"));
    auto parent = Win32Process::ToNarrow(EnvironmentValue(L"OPENFRUIT_EVENT_PARENT_SPAN"));
    // A defined variable (even empty) is explicit; only an absent one defers to ancestry.
    const bool defined = GetEnvironmentVariableW(L"OPENFRUIT_EVENT_DIRECTORY", nullptr, 0) != 0 ||
                         GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    if (directory.empty() && (defined || !InheritedEventContext(directory, id, parent))) return {};
    if (directory.empty() || !ValidId(id) || !ValidId(parent) || !std::filesystem::is_directory(directory)) return {};
    return std::shared_ptr<EventJournal>(new EventJournal(directory, id, parent));
}

void EventJournal::Flush() { if (sink_) sink_->Flush(); }
bool EventJournal::HasErrors() const noexcept { return sink_ && sink_->HasErrors(); }

bool EventJournal::Replay(const std::filesystem::path& directory, std::uint64_t after,
                          std::size_t limit, std::ostream& output, std::string& error) {
    std::ifstream input(directory / "events.jsonl", std::ios::binary);
    if (!input) { error = "Unable to open event journal"; return false; }
    std::size_t emitted = 0;
    std::string line;
    while (emitted < limit && std::getline(input, line)) {
        // A live writer may still be appending its final record.
        if (input.eof()) break;
        auto event = JsonValue::Parse(line, &error);
        if (!event) return false;
        const auto sequence = event->Get("sequence");
        if (!sequence || !sequence->IsNumber()) { error = "Event sequence is missing"; return false; }
        if (std::stoull(sequence->Serialize()) <= after) continue;
        output << line << '\n';
        ++emitted;
    }
    return true;
}

} // namespace OpenFruit
