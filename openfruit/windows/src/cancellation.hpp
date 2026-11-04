#pragma once
#include <atomic>
#include <memory>
namespace OpenFruit {
class CancellationToken {
public:
    bool Requested() const noexcept { return state_ && state_->load(std::memory_order_relaxed); }
private:
    friend class CancellationSource;
    std::shared_ptr<std::atomic<bool>> state_;
};
class CancellationSource {
public:
    CancellationSource() : state_(std::make_shared<std::atomic<bool>>(false)) {}
    CancellationToken Token() const noexcept { CancellationToken token; token.state_ = state_; return token; }
    void Cancel() noexcept { state_->store(true, std::memory_order_relaxed); }
private:
    std::shared_ptr<std::atomic<bool>> state_;
};
}
