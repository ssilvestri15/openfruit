#include "build_graph.hpp"

#include <algorithm>
#include <queue>
#include <unordered_set>

namespace OpenFruit {

BuildNodeId BuildGraph::AddNode(
    std::string name,
    std::function<bool()> action
) {
    const BuildNodeId id =
        static_cast<BuildNodeId>(
            nodes_.size()
        );

    BuildNode node;
    node.id = id;
    node.name = std::move(name);
    node.action = std::move(action);

    nodes_.push_back(
        std::move(node)
    );

    return id;
}

bool BuildGraph::AddDependency(
    BuildNodeId node,
    BuildNodeId depends_on
) {
    if (node >= nodes_.size() ||
        depends_on >= nodes_.size() ||
        node == depends_on) {
        return false;
    }

    auto& deps =
        nodes_[node].dependencies;

    if (std::find(
            deps.begin(),
            deps.end(),
            depends_on) ==
        deps.end()) {

        deps.push_back(
            depends_on
        );

        nodes_[depends_on]
            .dependents
            .push_back(node);
    }

    return true;
}

std::optional<
    std::vector<BuildNodeId>
>
BuildGraph::TopologicalOrder() const {
    std::vector<std::uint32_t>
        indegree(
            nodes_.size(),
            0
        );

    for (const auto& node :
         nodes_) {
        indegree[node.id] =
            static_cast<std::uint32_t>(
                node.dependencies.size()
            );
    }

    std::queue<BuildNodeId>
        ready;

    for (BuildNodeId id = 0;
         id < nodes_.size();
         ++id) {

        if (indegree[id] == 0) {
            ready.push(id);
        }
    }

    std::vector<BuildNodeId>
        order;

    order.reserve(
        nodes_.size()
    );

    while (!ready.empty()) {
        const BuildNodeId id =
            ready.front();

        ready.pop();

        order.push_back(id);

        for (const auto dependent :
             nodes_[id].dependents) {

            if (--indegree[dependent] ==
                0) {
                ready.push(
                    dependent
                );
            }
        }
    }

    if (order.size() !=
        nodes_.size()) {
        return std::nullopt;
    }

    return order;
}

std::vector<
    std::vector<BuildNodeId>
>
BuildGraph::StronglyConnectedComponents() const {
    const std::size_t count =
        nodes_.size();

    std::vector<int>
        index(count, -1);

    std::vector<int>
        lowlink(count, -1);

    std::vector<bool>
        on_stack(count, false);

    std::vector<BuildNodeId>
        stack;

    std::vector<
        std::vector<BuildNodeId>
    > components;

    int next_index = 0;

    std::function<void(BuildNodeId)>
        visit =
            [&](BuildNodeId id) {
                index[id] =
                    next_index;

                lowlink[id] =
                    next_index;

                ++next_index;

                stack.push_back(id);
                on_stack[id] = true;

                for (const auto dependency :
                     nodes_[id].dependencies) {

                    if (index[dependency] <
                        0) {

                        visit(dependency);

                        lowlink[id] =
                            lowlink[id] <
                                    lowlink[dependency]
                                ? lowlink[id]
                                : lowlink[dependency];

                    } else if (
                        on_stack[dependency]) {

                        lowlink[id] =
                            lowlink[id] <
                                    index[dependency]
                                ? lowlink[id]
                                : index[dependency];
                    }
                }

                if (lowlink[id] !=
                    index[id]) {
                    return;
                }

                std::vector<BuildNodeId>
                    component;

                for (;;) {
                    const BuildNodeId top =
                        stack.back();

                    stack.pop_back();
                    on_stack[top] = false;

                    component.push_back(
                        top
                    );

                    if (top == id) {
                        break;
                    }
                }

                components.push_back(
                    std::move(component)
                );
            };

    for (BuildNodeId id = 0;
         id < count;
         ++id) {

        if (index[id] < 0) {
            visit(id);
        }
    }

    return components;
}

bool BuildGraph::IsAcyclic() const {
    return TopologicalOrder()
        .has_value();
}

const BuildNode* BuildGraph::Get(
    BuildNodeId id
) const {
    return id < nodes_.size()
        ? &nodes_[id]
        : nullptr;
}

} // namespace OpenFruit
