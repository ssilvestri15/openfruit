#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace OpenFruit {

/*
 * Directed build graph used by v4 for dependency validation and scheduling.
 *
 * - adjacency lists keep memory O(V + E);
 * - Kahn topological ordering supports dependency-ready scheduling;
 * - Tarjan SCC detects cycles in O(V + E);
 * - node IDs are dense integers, allowing cache-friendly vector storage.
 */

using BuildNodeId = std::uint32_t;

struct BuildNode {
    BuildNodeId id = 0;
    std::string name;

    std::vector<BuildNodeId> dependencies;
    std::vector<BuildNodeId> dependents;

    std::function<bool()> action;
};

class BuildGraph {
public:
    BuildNodeId AddNode(
        std::string name,
        std::function<bool()> action = {}
    );

    bool AddDependency(
        BuildNodeId node,
        BuildNodeId depends_on
    );

    std::optional<
        std::vector<BuildNodeId>
    > TopologicalOrder() const;

    std::vector<
        std::vector<BuildNodeId>
    > StronglyConnectedComponents() const;

    bool IsAcyclic() const;

    const BuildNode* Get(
        BuildNodeId id
    ) const;

    std::size_t Size() const noexcept {
        return nodes_.size();
    }

private:
    std::vector<BuildNode> nodes_;
};

} // namespace OpenFruit
