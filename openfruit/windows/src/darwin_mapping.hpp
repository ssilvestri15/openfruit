#pragma once
#include "darwin_closure.hpp"
#include "dyld_cache.hpp"
#include <memory>

namespace OpenFruit {
enum class DarwinMappingMode { NativeCpu, Arm64Guest };
struct DarwinMappedRange { std::uint64_t address = 0, size = 0; std::uint32_t protection = 0; void* host_bytes = nullptr; };
struct DarwinWeakBinding { std::string owner, symbol; std::uint64_t target = 0; };
struct DarwinProcessThread {
    std::string owner;
    std::uint32_t cpu = 0;
    DarwinUnixThread original;
    std::uint64_t pc = 0, sp = 0;
    JsonValue ToJson() const;
};
struct DarwinInitializer {
    std::string owner, section;
    std::uint64_t original_slot = 0, slot = 0, original_target = 0, target = 0;
    bool offset_encoding = false;
    JsonValue ToJson() const;
};
// Windows-owned argument block for 64-bit Darwin startup. The image mapping
// must outlive this block; these are guest/native addresses, not host services.
class DarwinProcessArguments {
public:
    ~DarwinProcessArguments();
    DarwinProcessArguments(const DarwinProcessArguments&) = delete;
    DarwinProcessArguments& operator=(const DarwinProcessArguments&) = delete;
    std::uint64_t kernel_args = 0, program_vars = 0, argv = 0, envp = 0, apple = 0;
    std::uint64_t main_header = 0, main_entry = 0, stack_size_hint = 0;
    std::uint32_t cpu = 0, platform = 0;
    std::size_t argc = 0, environment_count = 0, apple_count = 0;
    DarwinMappedRange Range() const noexcept;
    JsonValue ToJson() const;
private:
    friend class DarwinMappedImages;
    friend class DarwinProcessStack;
    DarwinProcessArguments() = default;
    void* allocation_ = nullptr;
    std::size_t allocation_size_ = 0;
    bool owns_allocation_ = true;
};
class DarwinProcessStack {
public:
    ~DarwinProcessStack();
    DarwinProcessStack(const DarwinProcessStack&) = delete;
    DarwinProcessStack& operator=(const DarwinProcessStack&) = delete;
    static std::unique_ptr<DarwinProcessStack> Create(const DarwinProcessArguments&,
        std::string& error, std::uint64_t inherited_soft_limit = 0);
    DarwinMappedRange Range() const noexcept;
    const DarwinProcessArguments& Arguments() const noexcept { return *arguments_; }
    std::uint64_t PageSize() const noexcept { return page_size_; }
    JsonValue ToJson() const;
private:
    friend class DarwinMappedImages;
    DarwinProcessStack() = default;
    void* reservation_ = nullptr;
    std::uint64_t usable_address_ = 0, usable_size_ = 0, reservation_size_ = 0, page_size_ = 0;
    std::uint64_t stack_top_ = 0, requested_size_ = 0, effective_limit_ = 0;
    std::unique_ptr<DarwinProcessArguments> arguments_;
    bool startup_parameters_prepared_ = false;
};
// Native mapping/fixup primitive, not a Darwin execution environment. No
// constructors, TLS, unwind registration, syscall translation or plugin launch.
class DarwinMappedImages {
public:
    ~DarwinMappedImages();
    DarwinMappedImages(const DarwinMappedImages&) = delete;
    DarwinMappedImages& operator=(const DarwinMappedImages&) = delete;
    static std::unique_ptr<DarwinMappedImages> Load(const std::string& executable,
        const std::vector<std::filesystem::path>& original_trees, std::string& error,
        const DarwinClosureOptions& = {}, DarwinMappingMode = DarwinMappingMode::NativeCpu,
        const std::function<std::uint64_t(const DyldCacheSlideFixup&)>& cache_signer = {},
        const std::vector<std::string>& original_plugins = {},
        const std::function<void(const DarwinClosure&)>& prepare_task = {});
    const void* Symbol(const std::string& image, const std::string& name, std::string& error) const;
    std::size_t ImageCount() const noexcept { return images_.size(); }
    std::size_t AppliedFixups() const noexcept { return applied_; }
    std::uint64_t SharedRegionStart() const noexcept;
    int FilePathByIdentity(std::uint32_t filesystem,std::uint64_t object,std::string& path) const;
    std::vector<DarwinMappedRange> Ranges() const;
    const DarwinClosure& OriginalClosure() const noexcept {return closure_;}
    const std::vector<DarwinWeakBinding>& WeakBindings() const noexcept { return weak_bindings_; }
    // Section order within each image only; not dependency initialization order.
    const std::vector<DarwinInitializer>& Initializers() const noexcept { return initializers_; }
    const std::vector<std::string>& EagerInitializationOrder() const noexcept { return initialization_order_; }
    std::unique_ptr<DarwinProcessArguments> ProcessArguments(const std::string& executable,
        const std::vector<std::string>& argv, const std::vector<std::string>& envp,
        const std::vector<std::string>& apple, std::string& error) const;
    // Adds process-owned Apple stack/entropy keys, derived from this allocation.
    std::unique_ptr<DarwinProcessStack> ProcessStack(const std::string& executable,
        const std::vector<std::string>& argv, const std::vector<std::string>& envp,
        const std::vector<std::string>& apple, std::string& error,
        std::uint64_t inherited_soft_limit = 0) const;
    bool ProcessThread(const std::string& executable,const DarwinProcessStack&,
        DarwinProcessThread&,std::string& error) const;
    bool PrepareForDynamicLinkerBootstrap(const std::string& executable, std::string& error);
private:
    DarwinMappedImages() = default;
    struct RawFixup { std::uint64_t offset = 0, raw = 0; };
    struct Image { DarwinClosureImage original; void* allocation = nullptr; std::uint64_t base = 0, size = 0; std::vector<RawFixup> raw_fixups; };
    struct Resolved { std::uint64_t address = 0; bool found = false, weak_definition = false, cached = false; };
    Resolved Resolve(const std::string&, const std::string&, std::vector<std::string>& stack, bool shallow = false) const;
    Resolved ResolveWeak(const std::string&) const;
    std::string Dependency(const Image&, std::uint32_t ordinal) const;
    const Image& Find(const std::string&) const;
    DarwinClosure closure_;
    std::unique_ptr<DyldCacheMemory> cache_memory_;
    std::vector<Image> images_;
    std::size_t applied_ = 0;
    std::vector<DarwinWeakBinding> weak_bindings_;
    std::vector<DarwinInitializer> initializers_;
    std::vector<std::string> initialization_order_;
};
}
