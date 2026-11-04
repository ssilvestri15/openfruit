#include "openib/c_api.h"
#include "openib/compiler.hpp"
#include "openib/version.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <string>

namespace {
void copy_message(const std::string& message, char* buffer, size_t size) {
    if (!buffer || size == 0) return;
    const auto n = std::min(size - 1, message.size());
    std::memcpy(buffer, message.data(), n);
    buffer[n] = '\0';
}
}

extern "C" int openib_compile_file(const char* input_path,
                                   const char* output_path,
                                   const openib_compile_options* options,
                                   char* error_buffer,
                                   size_t error_buffer_size) {
    try {
        if (!input_path || !output_path) {
            copy_message("input_path and output_path are required", error_buffer, error_buffer_size);
            return 2;
        }
        openib::CompileOptions cpp_options;
        if (options) {
            cpp_options.nib_coder_version = options->nib_coder_version ? options->nib_coder_version : 10;
            cpp_options.strict = options->strict != 0;
        }
        openib::Diagnostics diagnostics;
        openib::Compiler compiler;
        const auto result = compiler.compile(input_path, output_path, cpp_options, diagnostics);
        std::ostringstream text;
        for (const auto& d : diagnostics.items()) {
            if (d.severity == openib::Severity::Error) text << "error ";
            else if (d.severity == openib::Severity::Warning) text << "warning ";
            else text << "info ";
            text << d.code << ": " << d.message << '\n';
        }
        copy_message(text.str(), error_buffer, error_buffer_size);
        return result.success ? 0 : 1;
    } catch (const std::exception& e) {
        copy_message(e.what(), error_buffer, error_buffer_size);
        return 1;
    }
}

extern "C" const char* openib_version_c(void) {
    static const std::string version = openib::version_string();
    return version.c_str();
}
