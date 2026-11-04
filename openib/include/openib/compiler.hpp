#pragma once

#include "openib/diagnostics.hpp"
#include "openib/model.hpp"
#include "openib/nib.hpp"

#include <filesystem>
#include <string>

namespace openib {

struct CompileOptions {
    std::uint32_t nib_coder_version{10};
    bool strict{false};
    bool overwrite{true};
    // Swift module of the target that owns the resource; Interface Builder's
    // customModuleProvider="target" names this module instead of customModule.
    std::string target_module;
};

struct CompileResult {
    bool success{false};
    std::size_t files_written{0};
};

class Compiler {
public:
    CompileResult compile(const std::filesystem::path& input,
                          const std::filesystem::path& output,
                          const CompileOptions& options,
                          Diagnostics& diagnostics) const;
};

} // namespace openib
