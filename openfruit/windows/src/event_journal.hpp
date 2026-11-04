#pragma once

#include "operation_events.hpp"

#include <iosfwd>
#include <cstdint>

namespace OpenFruit {

class EventJournal {
public:
    static std::shared_ptr<EventJournal> Create(const std::filesystem::path& diagnostic_root);
    static std::shared_ptr<EventJournal> AttachFromEnvironment();
    static bool Replay(const std::filesystem::path& directory, std::uint64_t after,
                       std::size_t limit, std::ostream& output, std::string& error);
    ~EventJournal();
    OperationContextPtr Context() const noexcept { return context_; }
    const std::filesystem::path& Directory() const noexcept { return context_->journal_directory; }
    void Flush();
    bool HasErrors() const noexcept;
private:
    class Sink;
    std::shared_ptr<Sink> sink_;
    OperationContextPtr context_;
    EventJournal(const std::filesystem::path& directory, std::string build_id, std::string parent);
};

} // namespace OpenFruit
