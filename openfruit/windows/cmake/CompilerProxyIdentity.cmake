# Build-time identity of the conservative compiler/proxy implementation closure.
# This script hashes build inputs, never installed SDKs or mutable application caches.
if(DEFINED OPENFRUIT_PROXY_INPUTS)
    include("${OPENFRUIT_PROXY_INPUTS}")
    set(identity "")
    set(complete TRUE)
    set(material "openfruit.compiler-proxy-inputs.v1\n${OPENFRUIT_PROXY_OPTIONS_HEX}\n")
    # MSVC/clang-cl also consume these environment inputs outside Ninja's
    # command lines. Bind their current values, not only configure-time state.
    foreach(variable IN ITEMS INCLUDE LIB LIBPATH CL _CL_ LINK)
        string(APPEND material "environment.${variable}=$ENV{${variable}}\n")
    endforeach()
    list(APPEND OPENFRUIT_PROXY_INCLUDE_ROOTS "$ENV{INCLUDE}")
    list(APPEND OPENFRUIT_PROXY_LINK_ROOTS "$ENV{LIB}" "$ENV{LIBPATH}")
    list(FILTER OPENFRUIT_PROXY_INCLUDE_ROOTS EXCLUDE REGEX "^$")
    list(FILTER OPENFRUIT_PROXY_LINK_ROOTS EXCLUDE REGEX "^$")
    list(REMOVE_DUPLICATES OPENFRUIT_PROXY_INCLUDE_ROOTS)
    list(REMOVE_DUPLICATES OPENFRUIT_PROXY_LINK_ROOTS)
    foreach(root IN LISTS OPENFRUIT_PROXY_INCLUDE_ROOTS)
        if(NOT IS_DIRECTORY "${root}")
            set(complete FALSE)
        else()
            # The C++ standard library includes extensionless headers.
            file(GLOB_RECURSE headers LIST_DIRECTORIES FALSE "${root}/*")
            list(APPEND OPENFRUIT_PROXY_FILES ${headers})
        endif()
    endforeach()
    foreach(root IN LISTS OPENFRUIT_PROXY_LINK_ROOTS)
        if(NOT IS_DIRECTORY "${root}")
            set(complete FALSE)
        else()
            file(GLOB_RECURSE libraries LIST_DIRECTORIES FALSE "${root}/*.lib")
            list(APPEND OPENFRUIT_PROXY_FILES ${libraries})
        endif()
    endforeach()
    if(DEFINED OPENFRUIT_PROXY_BINARY_ROOT)
        file(GLOB_RECURSE generated_headers LIST_DIRECTORIES FALSE
            "${OPENFRUIT_PROXY_BINARY_ROOT}/*.h" "${OPENFRUIT_PROXY_BINARY_ROOT}/*.hpp"
            "${OPENFRUIT_PROXY_BINARY_ROOT}/*.inc" "${OPENFRUIT_PROXY_BINARY_ROOT}/*.def"
            "${OPENFRUIT_PROXY_BINARY_ROOT}/*.c" "${OPENFRUIT_PROXY_BINARY_ROOT}/*.cpp")
        foreach(header IN LISTS generated_headers)
            string(FIND "${header}" "${OPENFRUIT_PROXY_BINARY_ROOT}/generated/compiler-proxy-identity/" identity_prefix)
            string(FIND "${header}" "${OPENFRUIT_PROXY_BINARY_ROOT}/Testing/" testing_prefix)
            if(NOT identity_prefix EQUAL 0 AND NOT testing_prefix EQUAL 0)
                list(APPEND OPENFRUIT_PROXY_FILES "${header}")
            endif()
        endforeach()
    endif()
    list(REMOVE_DUPLICATES OPENFRUIT_PROXY_FILES)
    list(SORT OPENFRUIT_PROXY_FILES)
    foreach(input IN LISTS OPENFRUIT_PROXY_FILES)
        if(NOT EXISTS "${input}" OR IS_DIRECTORY "${input}")
            set(complete FALSE)
            break()
        endif()
        file(SHA256 "${input}" digest)
        string(APPEND material "${input}\n${digest}\n")
    endforeach()
    if(complete AND OPENFRUIT_PROXY_FILES AND OPENFRUIT_PROXY_OPTIONS_HEX)
        string(SHA256 identity "${material}")
    endif()
    set(content "#pragma once\n#define OPENFRUIT_COMPILER_PROXY_IDENTITY \"${identity}\"\n")
    set(previous "")
    if(EXISTS "${OPENFRUIT_PROXY_OUTPUT}")
        file(READ "${OPENFRUIT_PROXY_OUTPUT}" previous)
    endif()
    if(NOT content STREQUAL previous)
        get_filename_component(parent "${OPENFRUIT_PROXY_OUTPUT}" DIRECTORY)
        file(MAKE_DIRECTORY "${parent}")
        file(WRITE "${OPENFRUIT_PROXY_OUTPUT}.tmp" "${content}")
        file(RENAME "${OPENFRUIT_PROXY_OUTPUT}.tmp" "${OPENFRUIT_PROXY_OUTPUT}")
    endif()
    return()
endif()

# Targets whose code can run while a package is compiled: the compiler proxy
# and the package engine with everything they link, and the helper
# executables the compiler starts. Other modules (application assembly,
# packaging, signing, devices, the CLI's own commands) never run inside a
# compile, so editing them keeps every package build context valid.
set(OPENFRUIT_PROXY_ROOT_TARGETS openfruit_compiler openfruit_dependencies
    openfruit-macro-host openfruit-macro-bridge openfruit-manifest-runner)

function(openfruit_proxy_link_closure output)
    set(pending ${ARGN})
    set(seen)
    while(pending)
        list(POP_FRONT pending item)
        string(REGEX REPLACE "^[$]<LINK_ONLY:(.*)>$" "\\1" item "${item}")
        if(item MATCHES "^[$]<" OR NOT TARGET "${item}")
            continue()
        endif()
        get_target_property(aliased "${item}" ALIASED_TARGET)
        if(aliased)
            set(item "${aliased}")
        endif()
        if(item IN_LIST seen)
            continue()
        endif()
        list(APPEND seen "${item}")
        foreach(property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(libraries "${item}" ${property})
            if(libraries)
                list(APPEND pending ${libraries})
            endif()
        endforeach()
    endwhile()
    set(${output} ${seen} PARENT_SCOPE)
endfunction()

function(openfruit_enable_compiler_proxy_identity target)
    openfruit_proxy_link_closure(closure ${OPENFRUIT_PROXY_ROOT_TARGETS})
    foreach(item IN LISTS closure)
        get_target_property(imported "${item}" IMPORTED)
        get_target_property(kind "${item}" TYPE)
        if(imported OR kind STREQUAL "INTERFACE_LIBRARY")
            continue()
        endif()
        get_target_property(sources "${item}" SOURCES)
        get_target_property(source_dir "${item}" SOURCE_DIR)
        foreach(source IN LISTS sources)
            if(source MATCHES "^[$]<")
                # A generator-expression source cannot be listed at configure time.
                list(APPEND files "${CMAKE_CURRENT_BINARY_DIR}/unlisted-${item}-identity-input")
                continue()
            endif()
            if(NOT IS_ABSOLUTE "${source}")
                set(source "${source_dir}/${source}")
            endif()
            list(APPEND files "${source}")
        endforeach()
    endforeach()
    # The proxy is dispatched from main(); headers stay broad because every
    # module shares them.
    list(APPEND files "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
    set(roots "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/vendor"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../native" "${CMAKE_CURRENT_SOURCE_DIR}/../../openib")
    foreach(root IN LISTS roots)
        file(GLOB_RECURSE headers CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE
            "${root}/*.h" "${root}/*.hpp" "${root}/*.inc" "${root}/*.def")
        list(APPEND files ${headers})
    endforeach()
    foreach(dependency IN ITEMS openfruit_zlib openfruit_xz openfruit_unicorn
            openfruit_lzfse openfruit_apfs_reference openfruit_bzip2)
        if(DEFINED ${dependency}_SOURCE_DIR AND IS_DIRECTORY "${${dependency}_SOURCE_DIR}")
            file(GLOB_RECURSE inputs CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE
                "${${dependency}_SOURCE_DIR}/*.c" "${${dependency}_SOURCE_DIR}/*.cc" "${${dependency}_SOURCE_DIR}/*.cpp"
                "${${dependency}_SOURCE_DIR}/*.cxx" "${${dependency}_SOURCE_DIR}/*.h" "${${dependency}_SOURCE_DIR}/*.hpp"
                "${${dependency}_SOURCE_DIR}/*.inc" "${${dependency}_SOURCE_DIR}/*.def" "${${dependency}_SOURCE_DIR}/*.s"
                "${${dependency}_SOURCE_DIR}/*.S" "${${dependency}_SOURCE_DIR}/*.asm" "${${dependency}_SOURCE_DIR}/*.cmake"
                "${${dependency}_SOURCE_DIR}/CMakeLists.txt" "${${dependency}_SOURCE_DIR}/*.in"
                "${${dependency}_SOURCE_DIR}/*.py" "${${dependency}_SOURCE_DIR}/*.pl" "${${dependency}_SOURCE_DIR}/*.sh")
            list(APPEND files ${inputs})
        else()
            # Missing dependency input disables component reuse, rather than
            # presenting a partially collected closure as a complete identity.
            list(APPEND files "${CMAKE_CURRENT_BINARY_DIR}/missing-${dependency}-identity-input")
        endif()
    endforeach()
    list(APPEND files "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
        "${CMAKE_CURRENT_SOURCE_DIR}/build.ps1" "${CMAKE_CURRENT_SOURCE_DIR}/src/openfruit.manifest"
        "${CMAKE_CURRENT_FUNCTION_LIST_FILE}" "${CMAKE_C_COMPILER}" "${CMAKE_CXX_COMPILER}")
    foreach(tool IN ITEMS CMAKE_LINKER CMAKE_AR CMAKE_RC_COMPILER CMAKE_MT)
        if(DEFINED ${tool} AND NOT "${${tool}}" STREQUAL "")
            list(APPEND files "${${tool}}")
        else()
            list(APPEND files "${CMAKE_CURRENT_BINARY_DIR}/missing-${tool}-identity-input")
        endif()
    endforeach()
    set(include_roots ${CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES} ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES} "$ENV{INCLUDE}")
    set(link_roots ${CMAKE_C_IMPLICIT_LINK_DIRECTORIES} ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES} "$ENV{LIB}" "$ENV{LIBPATH}")
    foreach(compiler IN ITEMS "${CMAKE_C_COMPILER}" "${CMAKE_CXX_COMPILER}")
        get_filename_component(bin "${compiler}" DIRECTORY)
        # MSVC's cl.exe delegates compilation to adjacent c1/c1xx DLLs.
        file(GLOB compiler_runtime LIST_DIRECTORIES FALSE "${bin}/*.dll")
        list(APPEND files ${compiler_runtime})
        file(GLOB resources LIST_DIRECTORIES TRUE "${bin}/../lib/clang/*/include")
        list(APPEND include_roots ${resources})
        file(GLOB compiler_libs LIST_DIRECTORIES TRUE "${bin}/../lib")
        list(APPEND link_roots ${compiler_libs})
    endforeach()
    list(FILTER include_roots EXCLUDE REGEX "^$")
    list(REMOVE_DUPLICATES include_roots)
    if(NOT include_roots)
        list(APPEND files "${CMAKE_CURRENT_BINARY_DIR}/missing-native-include-identity-input")
    endif()
    list(FILTER link_roots EXCLUDE REGEX "^$")
    list(REMOVE_DUPLICATES link_roots)
    if(NOT link_roots)
        list(APPEND files "${CMAKE_CURRENT_BINARY_DIR}/missing-native-link-identity-input")
    endif()
    # Include additional project-owned build generators automatically.
    file(GLOB_RECURSE generators CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/*.cmake")
    list(APPEND files ${generators})
    list(REMOVE_DUPLICATES files)
    list(SORT files)

    set(options "cmake=${CMAKE_VERSION}\ngenerator=${CMAKE_GENERATOR}\nplatform=${CMAKE_GENERATOR_PLATFORM}\ntoolset=${CMAKE_GENERATOR_TOOLSET}\n")
    get_cmake_property(variables VARIABLES)
    foreach(variable IN LISTS variables)
        if(variable MATCHES "^CMAKE_((C|CXX|RC)_(COMPILER|FLAGS|STANDARD)|BUILD_TYPE|SYSTEM|MSVC_RUNTIME_LIBRARY|INTERPROCEDURAL_OPTIMIZATION|LINKER|EXE_LINKER_FLAGS|STATIC_LINKER_FLAGS|VS_WINDOWS_TARGET_PLATFORM_VERSION)")
            string(APPEND options "${variable}=${${variable}}\n")
        endif()
    endforeach()
    get_property(targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(owner IN LISTS targets)
        foreach(property IN ITEMS COMPILE_OPTIONS COMPILE_DEFINITIONS INCLUDE_DIRECTORIES
                INTERFACE_COMPILE_OPTIONS INTERFACE_COMPILE_DEFINITIONS INTERFACE_INCLUDE_DIRECTORIES
                LINK_OPTIONS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES MSVC_RUNTIME_LIBRARY
                INTERPROCEDURAL_OPTIMIZATION)
            get_target_property(value "${owner}" "${property}")
            if(NOT value STREQUAL "value-NOTFOUND")
                string(APPEND options "${owner}.${property}=${value}\n")
            endif()
        endforeach()
    endforeach()
    # FetchContent options also affect the compiled dependency closure.
    get_cmake_property(cache_variables CACHE_VARIABLES)
    list(SORT cache_variables)
    # CMAKE_WARN/ERROR_DEPRECATED only control CMake's own diagnostics, and
    # reading them is itself deprecated (policy CMP0218).
    list(REMOVE_ITEM cache_variables CMAKE_WARN_DEPRECATED CMAKE_ERROR_DEPRECATED)
    foreach(variable IN LISTS cache_variables)
        string(APPEND options "cache.${variable}=${${variable}}\n")
    endforeach()
    # Hex avoids evaluation of nested generator expressions inside collected
    # build options; their exact recipes are part of the identity.
    string(HEX "${options}" options_hex)
    set(directory "${CMAKE_CURRENT_BINARY_DIR}/generated/compiler-proxy-identity/$<CONFIG>")
    file(GENERATE OUTPUT "${directory}/inputs.cmake" CONTENT
        "set(OPENFRUIT_PROXY_FILES [====[${files}]====])\nset(OPENFRUIT_PROXY_OPTIONS_HEX \"${options_hex}\")\nset(OPENFRUIT_PROXY_INCLUDE_ROOTS [====[${include_roots}]====])\nset(OPENFRUIT_PROXY_LINK_ROOTS [====[${link_roots}]====])\nset(OPENFRUIT_PROXY_BINARY_ROOT [====[${CMAKE_CURRENT_BINARY_DIR}]====])\n")
    add_custom_target(openfruit_compiler_proxy_identity
        COMMAND "${CMAKE_COMMAND}" "-DOPENFRUIT_PROXY_INPUTS=${directory}/inputs.cmake"
            "-DOPENFRUIT_PROXY_OUTPUT=${directory}/openfruit_compiler_proxy_identity.hpp"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_FILE}"
        BYPRODUCTS "${directory}/openfruit_compiler_proxy_identity.hpp"
        VERBATIM)
    # Generated dependency headers/sources must exist before collecting their
    # identity. These codec/backend targets do not depend on package_engine.
    foreach(dependency IN ITEMS ZLIB::ZLIBSTATIC liblzma unicorn lzfse
            openfruit_apfs_reference_codec openfruit_bzip2_codec)
        if(TARGET "${dependency}")
            add_dependencies(openfruit_compiler_proxy_identity "${dependency}")
        endif()
    endforeach()
    add_dependencies("${target}" openfruit_compiler_proxy_identity)
    target_include_directories("${target}" PRIVATE "${directory}")
endfunction()
