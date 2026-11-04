#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

struct GitSymlinkHeaderMapping {
    std::string include_key;
    std::filesystem::path target_path;
};

class GitSymlinkGuard {
public:
    explicit GitSymlinkGuard(std::filesystem::path root);
    ~GitSymlinkGuard();

    GitSymlinkGuard(const GitSymlinkGuard&) = delete;
    GitSymlinkGuard& operator=(const GitSymlinkGuard&) = delete;

    bool Materialize();
    bool RestoreNow();
    void Disarm();

private:
    std::filesystem::path root_;
    std::vector<std::filesystem::path> modified_repos_;
    bool active_ = false;
};

bool MaterializeGitSymlinksInRepo(const std::filesystem::path& repo_dir);
bool RestoreGitSymlinkPlaceholdersInRepo(const std::filesystem::path& repo_dir);
bool InitializeMissingGitSubmodules(const std::filesystem::path& repo_dir);
std::vector<std::filesystem::path> DiscoverGitRepositories(const std::filesystem::path& root);
std::vector<GitSymlinkHeaderMapping> DiscoverGitSymlinkHeaderMappings(const std::filesystem::path& repo_dir);
std::filesystem::path ResolveGitSymlinkPlaceholderTarget(const std::filesystem::path& path);

} // namespace OpenFruit
