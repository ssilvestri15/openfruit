#pragma once
#include <filesystem>
#include <string>
namespace OpenFruit {
class AtomicFile {
public:
    // Publish a complete snapshot beside its destination before atomic replacement.
    // False preserves the previous destination; concurrent writers are last-writer-wins.
    static bool Publish(const std::filesystem::path&, const std::string&);
};
}
