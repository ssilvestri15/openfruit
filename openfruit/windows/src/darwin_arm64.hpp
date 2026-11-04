#pragma once
#include "darwin_mapping.hpp"
namespace OpenFruit {
struct DarwinArm64Result { bool returned = false; std::uint64_t value = 0; std::string diagnostic; };
// Borrowed native launch handles, duplicated into task-owned descriptors.
// A non-null input must be a readable byte pipe with exclusive guest reader
// ownership: callers must not consume through another retained handle alias.
// Null input/output leave fd0/fd1 absent. Null error preserves inherited stderr.
struct DarwinProcessStreams {
    void* input=nullptr;
    void* output=nullptr;
    void* error=nullptr;
};
struct DarwinArm64MappingResult {
    bool mapped = false;
    std::size_t images = 0, ranges = 0, applied_fixups = 0;
    std::vector<DarwinWeakBinding> weak_bindings;
    std::vector<DarwinInitializer> initializers;
    std::vector<std::string> initialization_order;
    JsonValue process_arguments;
    JsonValue process_stack;
    JsonValue process_thread;
    JsonValue bootstrap;
    std::string diagnostic;
};
// Uses the same engine, keys, loader and guest mappings as function execution.
// Optional bounded bootstrap probe stops at the first missing service; it does
// not initialize a Darwin process or validate original plugin execution.
DarwinArm64MappingResult MapDarwinArm64Images(const std::string& executable,
    const std::vector<std::filesystem::path>& original_trees, const DarwinClosureOptions& = {},
    const std::vector<std::string>& original_plugins = {}, bool prepare_arguments = false,
    bool probe_bootstrap = false, const DarwinProcessStreams& streams = {});
// CPU execution boundary only. No fake syscall success, macro substitution,
// Darwin process initialization or plugin-service capability.
DarwinArm64Result RunDarwinArm64Function(const std::string& executable,
    const std::vector<std::filesystem::path>& original_trees, const std::string& symbol,
    const std::vector<std::uint64_t>& arguments = {}, const DarwinClosureOptions& = {},
    const std::vector<std::string>& original_plugins = {});
}
