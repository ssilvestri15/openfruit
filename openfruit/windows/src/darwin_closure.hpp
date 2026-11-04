#pragma once
#include "darwin_image.hpp"
#include "operation_events.hpp"
#include "cancellation.hpp"
#include <memory>
#include <map>
#include <set>
namespace OpenFruit {
std::string NormalizeDarwinVirtualPath(const std::string& path);
class DyldCacheView;
struct DarwinClosureOptions {
    std::size_t max_files = 100000, max_images = 4096, max_edges = 65536, max_depth = 64;
    std::shared_ptr<DyldCacheView> shared_cache;
    CancellationToken cancellation;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    std::size_t instruction_limit = 5000000;
};
struct DarwinClosureImage { std::string virtual_path; std::filesystem::path source; DarwinImage metadata; bool shared_cache=false; };
struct DarwinClosureEdge {
    std::string owner, install_name, resolved_path, diagnostic;
    std::vector<std::string> candidates;
    bool weak = false, interpreter = false;
};
struct DarwinClosure {
    bool analyzed = false;
    std::string diagnostic;
    std::uint32_t cpu = 0;
    std::shared_ptr<DyldCacheView> original_cache;
    std::vector<DarwinClosureImage> images;
    std::map<std::string,std::filesystem::path> original_files;
    // Directories in the mounted original namespace, including empty entries
    // and its composite virtual root. Directory symlinks are not admitted.
    std::set<std::string> original_directories;
    std::map<std::string,std::string> original_real_paths;
    std::vector<DarwinClosureEdge> edges;
    bool StrongImagesResolved() const noexcept;
    JsonValue ToJson() const;
    // Schedule the initially eager dependency graph only; no code execution,
    // Objective-C notification or dynamic/delayed initialization policy.
    bool EagerInitializationOrder(const std::string& executable,
        const std::vector<std::string>& plugins, std::vector<std::string>& order,
        std::string& error, const DarwinClosureOptions& = {}) const;
    // Explicit original-tree mounts at virtual /. Metadata only, no runtime
    // registration, symbol/ABI validation, mapping, CPU translation or execution.
    static DarwinClosure Inspect(const std::string& executable, const std::vector<std::string>& plugins,
        const std::vector<std::filesystem::path>& original_trees, const DarwinClosureOptions& = {});
};
}
