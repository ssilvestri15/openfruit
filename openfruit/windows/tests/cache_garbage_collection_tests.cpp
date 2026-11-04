#include "cache_compression_manager.hpp"

#include <windows.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    stream << text;
    Require(static_cast<bool>(stream), "fixture write failed");
}
void Age(const fs::path& path, int days) {
    fs::last_write_time(path, fs::file_time_type::clock::now() - std::chrono::hours(24 * days));
}
}

int main() {
    fs::path root;
    try {
        root = fs::temp_directory_path() / ("openfruit-cache-gc-" + std::to_string(GetTickCount64()));
        const auto state = root / "state";
        const auto cache = root / "cache";
        fs::create_directories(state);

        // Content-addressed caches: the entry time is its last use.
        const auto used_catalog = cache / "asset-catalogs" / "used";
        const auto unused_catalog = cache / "asset-catalogs" / "unused";
        Write(used_catalog / "Assets.car", "car");
        Write(unused_catalog / "Assets.car", "car");
        Age(used_catalog, 10);
        Age(unused_catalog, 40);
        const auto used_frame = cache / "macro-expansions" / "v2" / "ab" / "ab01.frame";
        const auto unused_frame = cache / "macro-expansions" / "v2" / "cd" / "cd01.frame";
        const auto foreign = cache / "macro-expansions" / "v2" / "cd" / "notes.txt";
        Write(used_frame, "frame");
        Write(unused_frame, "frame");
        Write(foreign, "kept");
        Age(used_frame, 10);
        Age(unused_frame, 40);
        Age(foreign, 40);
        // Other cache categories hold installed inputs and are never pruned here.
        const auto installed = cache / "sdk-archives" / "Xcode.xip";
        Write(installed, "xip");
        Age(installed, 400);

        const auto report = CacheCompressionManager::CollectGarbage(state, cache, 3);
        Require(report.success, "garbage collection failed");
        Require(fs::exists(used_catalog), "recently used asset catalog entry was pruned");
        Require(!fs::exists(unused_catalog), "unused asset catalog entry was kept");
        Require(fs::exists(used_frame), "recently used macro expansion was pruned");
        Require(!fs::exists(unused_frame), "unused macro expansion was kept");
        Require(fs::exists(foreign), "a non-cache file in the expansion cache was pruned");
        Require(fs::exists(installed), "an installed cache category was pruned");
        Require(report.entries_removed == 2, "unexpected number of pruned entries");

        // A missing cache root is not an error.
        Require(CacheCompressionManager::CollectGarbage(state, root / "absent", 3).success,
                "missing cache root failed");

        fs::remove_all(root);
        std::cout << "cache garbage collection PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::error_code ec;
        if (!root.empty()) fs::remove_all(root, ec);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
