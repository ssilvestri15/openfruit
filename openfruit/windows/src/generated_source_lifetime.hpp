#pragma once
#include <memory>
#include <vector>
#include <utility>
namespace OpenFruit {
// Retain existing source-output guards through all consumers. Release in reverse
// production order so overlapping generated outputs restore their before-images.
class GeneratedSourceLifetime {
public:
    GeneratedSourceLifetime() = default;
    GeneratedSourceLifetime(const GeneratedSourceLifetime&) = delete;
    GeneratedSourceLifetime& operator=(const GeneratedSourceLifetime&) = delete;
    void Retain(std::shared_ptr<void> owner) { owners_.push_back(std::move(owner)); }
    ~GeneratedSourceLifetime() { while (!owners_.empty()) owners_.pop_back(); }
private:
    std::vector<std::shared_ptr<void>> owners_;
};
} // namespace OpenFruit
