#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
  #ifdef OPENIB_BUILD_DLL
    #define OPENIB_API __declspec(dllexport)
  #else
    #define OPENIB_API
  #endif
#else
  #define OPENIB_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct openib_compile_options {
    uint32_t nib_coder_version;
    int strict;
} openib_compile_options;

// Returns 0 on success, non-zero on failure. Diagnostics are copied to error_buffer when provided.
OPENIB_API int openib_compile_file(const char* input_path,
                                   const char* output_path,
                                   const openib_compile_options* options,
                                   char* error_buffer,
                                   size_t error_buffer_size);

OPENIB_API const char* openib_version_c(void);

#ifdef __cplusplus
}
#endif
