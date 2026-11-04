cmake_minimum_required(VERSION 3.28)
project(OpenFruit LANGUAGES C CXX)

# A release build passes its tag as the version (X.Y.Z, or X.Y.Z-dev for a
# prerelease); every target sees the same OPENFRUIT_VERSION.
set(OPENFRUIT_RELEASE_VERSION "" CACHE STRING "Release version from the tag (X.Y.Z or X.Y.Z-dev); empty for the default")
if(OPENFRUIT_RELEASE_VERSION)
    if(NOT OPENFRUIT_RELEASE_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+(-dev)?$")
        message(FATAL_ERROR "OPENFRUIT_RELEASE_VERSION must be X.Y.Z or X.Y.Z-dev, got '${OPENFRUIT_RELEASE_VERSION}'")
    endif()
    add_compile_definitions("OPENFRUIT_VERSION=\"${OPENFRUIT_RELEASE_VERSION}\"")
endif()

if(NOT WIN32)
    message(FATAL_ERROR "The OpenFruit orchestration engine requires Windows")
endif()

include(CTest)
include(FetchContent)
# Native XAR/PBZX decompression, built from verified immutable upstream sources.
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(openfruit_zlib
    URL https://zlib.net/zlib-1.3.2.tar.gz
    URL_HASH SHA256=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
    TLS_VERIFY ON
    EXCLUDE_FROM_ALL)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
foreach(xz_option XZ_TOOL_XZ XZ_TOOL_XZDEC XZ_TOOL_LZMADEC XZ_TOOL_LZMAINFO XZ_DOC XZ_NLS)
    set(${xz_option} OFF CACHE BOOL "" FORCE)
endforeach()
FetchContent_Declare(openfruit_xz
    URL https://github.com/tukaani-project/xz/releases/download/v5.8.4/xz-5.8.4.tar.gz
    URL_HASH SHA256=0014c7886930454fe8bd4228665b51af55eeae560ea135c9c4cd33f55b2591d9
    TLS_VERIFY ON
    EXCLUDE_FROM_ALL)
function(openfruit_load_archive_codecs)
    set(BUILD_TESTING OFF)
    FetchContent_MakeAvailable(openfruit_zlib openfruit_xz)
endfunction()
openfruit_load_archive_codecs()
set(UNICORN_ARCH "aarch64" CACHE STRING "" FORCE)
set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
set(UNICORN_LEGACY_STATIC_ARCHIVE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(openfruit_unicorn
    URL https://codeload.github.com/unicorn-engine/unicorn/tar.gz/refs/tags/2.1.4
    URL_HASH SHA256=ea8863f095a0136388694e5a6063afd9bb7650e30243dd6251af59c5ce5601f4
    TLS_VERIFY ON EXCLUDE_FROM_ALL)
function(openfruit_load_cpu_backend)
    # Keep the original CPU implementation in its own native Windows module;
    # private QEMU utility symbols must not collide with archive codecs.
    set(BUILD_SHARED_LIBS ON)
    FetchContent_MakeAvailable(openfruit_unicorn)
endfunction()
openfruit_load_cpu_backend()
FetchContent_GetProperties(openfruit_unicorn)
install(TARGETS unicorn RUNTIME DESTINATION bin)
install(FILES "${openfruit_unicorn_SOURCE_DIR}/COPYING" DESTINATION share/licenses/openfruit RENAME unicorn-COPYING)
install(FILES "${openfruit_unicorn_SOURCE_DIR}/COPYING.LGPL2" DESTINATION share/licenses/openfruit RENAME unicorn-COPYING.LGPL2)
FetchContent_GetProperties(openfruit_xz)
FetchContent_GetProperties(openfruit_zlib)
# The pinned liblzma build target keeps its API includes private. Expose the
# unchanged upstream API through an OPENFRUIT-owned dependency adapter.
add_library(openfruit_archive_codecs INTERFACE)
target_link_libraries(openfruit_archive_codecs INTERFACE ZLIB::ZLIBSTATIC liblzma)
target_include_directories(openfruit_archive_codecs INTERFACE "${openfruit_xz_SOURCE_DIR}/src/liblzma/api")
install(FILES "${openfruit_zlib_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/openfruit RENAME zlib-LICENSE)
install(FILES "${openfruit_xz_SOURCE_DIR}/COPYING.0BSD" DESTINATION share/licenses/openfruit RENAME liblzma-LICENSE)
# Unmodified Apple reference LZFSE implementation, pinned independently of inputs.
set(LZFSE_BUNDLE_MODE ON)
set(LZFSE_DISABLE_TESTS ON)
FetchContent_Declare(openfruit_lzfse
    URL https://codeload.github.com/lzfse/lzfse/tar.gz/e634ca58b4821d9f3d560cdc6df5dec02ffc93fd
    URL_HASH SHA256=ca98aa6644d44500e3315858daa747ce15bd06d49e3edb12a5458e5525e8ebdb
    TLS_VERIFY ON EXCLUDE_FROM_ALL)
function(openfruit_load_lzfse)
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    FetchContent_MakeAvailable(openfruit_lzfse)
endfunction()
openfruit_load_lzfse()
FetchContent_GetProperties(openfruit_lzfse)
set_target_properties(lzfse PROPERTIES INTERPROCEDURAL_OPTIMIZATION FALSE)
install(FILES "${openfruit_lzfse_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/openfruit RENAME lzfse-LICENSE)
# Unchanged utility codec sources; do not configure the upstream Linux/FUSE driver.
FetchContent_Declare(openfruit_apfs_reference
    URL https://codeload.github.com/sgan81/apfs-fuse/tar.gz/66b86bd525e8cb90f9012543be89b1f092b75cf3
    URL_HASH SHA256=e78e71e87d8ba182822ec34233189141b8816c9a3f700c9a22f6dc1480afee51
    TLS_VERIFY ON SOURCE_SUBDIR openfruit-unused-build)
FetchContent_Declare(openfruit_bzip2
    URL https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
    URL_HASH SHA256=ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269
    TLS_VERIFY ON SOURCE_SUBDIR openfruit-unused-build)
FetchContent_MakeAvailable(openfruit_apfs_reference openfruit_bzip2)
add_library(openfruit_bzip2_codec STATIC
    "${openfruit_bzip2_SOURCE_DIR}/blocksort.c" "${openfruit_bzip2_SOURCE_DIR}/huffman.c"
    "${openfruit_bzip2_SOURCE_DIR}/crctable.c" "${openfruit_bzip2_SOURCE_DIR}/randtable.c"
    "${openfruit_bzip2_SOURCE_DIR}/compress.c" "${openfruit_bzip2_SOURCE_DIR}/decompress.c"
    "${openfruit_bzip2_SOURCE_DIR}/bzlib.c")
target_include_directories(openfruit_bzip2_codec PUBLIC "${openfruit_bzip2_SOURCE_DIR}")
add_library(openfruit_apfs_reference_codec STATIC
    "${openfruit_apfs_reference_SOURCE_DIR}/ApfsLib/Util.cpp"
    "${openfruit_apfs_reference_SOURCE_DIR}/ApfsLib/Unicode.cpp"
    "${openfruit_apfs_reference_SOURCE_DIR}/ApfsLib/Crc32.cpp")
target_include_directories(openfruit_apfs_reference_codec PUBLIC "${openfruit_apfs_reference_SOURCE_DIR}/ApfsLib")
target_include_directories(openfruit_apfs_reference_codec PRIVATE "${openfruit_lzfse_SOURCE_DIR}/src")
target_link_libraries(openfruit_apfs_reference_codec PRIVATE openfruit_bzip2_codec ZLIB::ZLIBSTATIC lzfse)
install(FILES "${openfruit_apfs_reference_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/openfruit RENAME apfs-fuse-LICENSE)
install(FILES "${openfruit_bzip2_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/openfruit RENAME bzip2-LICENSE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(openfruit_options INTERFACE)
target_compile_definitions(openfruit_options INTERFACE
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
if(MSVC)
    target_compile_options(openfruit_options INTERFACE /W3 /EHsc /Zi)
    target_link_options(openfruit_options INTERFACE /DEBUG)
endif()

# Each translation unit has one explicit owner; probes reuse the libraries.
function(openfruit_module name)
    add_library(${name} STATIC ${ARGN})
    target_include_directories(${name} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(${name} PUBLIC openfruit_options)
endfunction()

openfruit_module(openfruit_foundation
    src/json_value.cpp src/native_zip.cpp src/zip_inventory.cpp src/win32_process.cpp
    src/tool_paths.cpp src/system_info.cpp src/header_map.cpp
    src/operation_events.cpp src/console_cancellation.cpp src/process_diagnostics.cpp src/swift_telemetry.cpp src/atomic_file.cpp
    src/content_hash.cpp src/http_transfer.cpp)
target_link_libraries(openfruit_foundation PUBLIC bcrypt shell32 ole32 winhttp shlwapi)
openfruit_module(openfruit_zip src/zip_member.cpp src/zip_stage.cpp)
target_link_libraries(openfruit_zip PUBLIC openfruit_foundation PRIVATE openfruit_archive_codecs)

openfruit_module(openfruit_observability src/event_journal.cpp)
target_link_libraries(openfruit_observability PUBLIC openfruit_foundation)

openfruit_module(openfruit_secure_storage src/protected_credential_store.cpp)
target_link_libraries(openfruit_secure_storage PUBLIC openfruit_foundation crypt32)
openfruit_module(openfruit_configuration src/config.cpp)
target_link_libraries(openfruit_configuration PUBLIC openfruit_secure_storage)

openfruit_module(openfruit_credentials src/apple_auth.cpp src/apple_cookies.cpp)
target_link_libraries(openfruit_credentials PUBLIC openfruit_configuration)

openfruit_module(openfruit_host
    src/wsl_bridge.cpp src/macro_engine.cpp src/archive_shim.cpp
    src/compiler_rt_support.cpp src/preview_agent.cpp)
target_link_libraries(openfruit_host PUBLIC openfruit_foundation)
# The iOS preview agent ships as source and is compiled per SDK by preview
# builds; embed it unchanged as a raw string.
set(OPENFRUIT_PREVIEW_AGENT_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../native/preview-agent/OpenFruitPreviewAgent.m")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${OPENFRUIT_PREVIEW_AGENT_SOURCE}")
file(READ "${OPENFRUIT_PREVIEW_AGENT_SOURCE}" OPENFRUIT_PREVIEW_AGENT_TEXT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/generated/preview_agent_source.hpp.in"
    "#pragma once\n// Generated from native/preview-agent/OpenFruitPreviewAgent.m.\nnamespace OpenFruit {\ninline constexpr const char kPreviewAgentSource[] = R\"OFPREVIEW(${OPENFRUIT_PREVIEW_AGENT_TEXT})OFPREVIEW\";\n}\n")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/generated/preview_agent_source.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/preview_agent_source.hpp" COPYONLY)
target_include_directories(openfruit_host PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")

openfruit_module(openfruit_darwin src/darwin_image.cpp src/darwin_closure.cpp src/darwin_mapping.cpp src/darwin_arm64.cpp src/darwin_files.cpp src/darwin_file_metadata.cpp src/darwin_file_mapping.cpp src/darwin_sysctl.cpp src/darwin_process_identity.cpp src/darwin_pthread_registration.cpp src/darwin_thread_context.cpp src/darwin_thread_run_queue.cpp src/dyld_cache.cpp src/dyld_cache_images.cpp src/darwin_progress.cpp src/darwin_clock_epoch.cpp src/darwin_vm_backing.cpp)
target_link_libraries(openfruit_darwin PUBLIC openfruit_foundation PRIVATE unicorn mincore advapi32 authz)
target_sources(openfruit_darwin PRIVATE src/darwin_macro_provider.cpp)
target_link_libraries(openfruit_host PUBLIC openfruit_darwin)
target_sources(openfruit_darwin PRIVATE src/darwin_pthread_creation.cpp src/darwin_kevent.cpp)
target_sources(openfruit_darwin PRIVATE src/darwin_pointer_auth.cpp)
target_sources(openfruit_darwin PRIVATE src/darwin_pthread_policy.cpp)

openfruit_module(openfruit_sdk src/sdk_manager.cpp src/sdk_acquisition.cpp src/sdk_catalog.cpp src/sdk_usage.cpp
    src/sdk_target_runtime.cpp src/sdk_runtime_abi.cpp
    src/xcode_compatibility.cpp
    src/xip_archive.cpp src/xip_inventory.cpp src/archive_tree_extraction.cpp src/sdk_archive_extraction.cpp src/apple_software_update_trust.cpp
    src/apple_download_catalog.cpp src/browser_apple_auth.cpp)
target_link_libraries(openfruit_sdk PUBLIC openfruit_foundation PRIVATE openfruit_credentials openfruit_archive_codecs xmllite crypt32)
openfruit_module(openfruit_artifacts src/artifact_store.cpp src/cache_compression_manager.cpp)
target_link_libraries(openfruit_artifacts PUBLIC openfruit_foundation)
target_link_libraries(openfruit_configuration PRIVATE openfruit_artifacts)
target_link_libraries(openfruit_sdk PRIVATE openfruit_artifacts)

openfruit_module(openfruit_environment src/environment_manager.cpp src/dependency_updater.cpp src/svg_runtime_provider.cpp
    src/darwin_macro_provider_import.cpp)
target_link_libraries(openfruit_environment PUBLIC
    openfruit_configuration openfruit_sdk openfruit_host openfruit_artifacts)


add_library(openfruit_libplist STATIC
    vendor/libplist/src/base64.c
    vendor/libplist/src/bplist.c
    vendor/libplist/src/bytearray.c
    vendor/libplist/src/common.c
    vendor/libplist/src/hashtable.c
    vendor/libplist/src/jplist.c
    vendor/libplist/src/jsmn.c
    vendor/libplist/src/oplist.c
    vendor/libplist/src/out-default.c
    vendor/libplist/src/out-limd.c
    vendor/libplist/src/out-plutil.c
    vendor/libplist/src/plist.c
    vendor/libplist/src/ptrarray.c
    vendor/libplist/src/time64.c
    vendor/libplist/src/xplist.c
    vendor/libplist/libcnary/node.c
    vendor/libplist/libcnary/node_list.c
)
target_include_directories(openfruit_libplist PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/libplist/include"
)
target_include_directories(openfruit_libplist PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/libplist/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/libplist/libcnary/include"
)
target_compile_definitions(openfruit_libplist PUBLIC
    LIBPLIST_STATIC
)
target_compile_definitions(openfruit_libplist PRIVATE
    PACKAGE_VERSION="2.6.0"
    _CRT_SECURE_NO_WARNINGS
)

openfruit_module(openfruit_restore src/restore_manifest.cpp)
target_link_libraries(openfruit_restore PUBLIC openfruit_zip PRIVATE openfruit_libplist)
openfruit_module(openfruit_aea src/aea_input.cpp src/aea_fcs_key.cpp src/hpke_native.cpp src/aea_root.cpp src/aea_lzfse.c)
openfruit_module(openfruit_apfs src/apfs_metadata.cpp src/apfs_compression.cpp src/apfs_lzvn.c)
target_include_directories(openfruit_apfs PRIVATE "${openfruit_lzfse_SOURCE_DIR}/src")
target_link_libraries(openfruit_apfs PUBLIC openfruit_foundation PRIVATE openfruit_apfs_reference_codec)
target_link_libraries(openfruit_aea PUBLIC openfruit_foundation PRIVATE crypt32 ncrypt bcrypt lzfse openfruit_archive_codecs)
target_include_directories(openfruit_aea PRIVATE "${openfruit_lzfse_SOURCE_DIR}/src")
# Automatic original macro provider: chains the native restore/AEA/APFS/dyld
# cache/XIP stages into the validated provider import.
openfruit_module(openfruit_provider_acquisition src/darwin_provider_acquisition.cpp)
target_link_libraries(openfruit_provider_acquisition PUBLIC openfruit_foundation
    PRIVATE openfruit_restore openfruit_aea openfruit_apfs openfruit_darwin openfruit_sdk openfruit_environment openfruit_libplist)

openfruit_module(openfruit_project
    src/xcode_project.cpp src/xcode_scheme.cpp src/universal_project.cpp src/xcframework_resolver.cpp)
target_link_libraries(openfruit_project PUBLIC openfruit_foundation openfruit_libplist)
target_link_libraries(openfruit_project PRIVATE xmllite)

openfruit_module(openfruit_dependencies
    src/package_engine.cpp src/manifest_projection.cpp
    src/swiftpm_resolve_observation.cpp
    src/carthage_resolver.cpp src/git_symlinks.cpp src/git_source_view.cpp src/swiftpm_source_workspace.cpp)
target_link_libraries(openfruit_dependencies PUBLIC
    openfruit_project openfruit_sdk openfruit_host openfruit_artifacts urlmon)
target_link_libraries(openfruit_dependencies PRIVATE openfruit_environment)

openfruit_module(openfruit_recovery src/import_recovery.cpp)
target_link_libraries(openfruit_recovery PUBLIC openfruit_foundation)

openfruit_module(openfruit_compiler src/compiler_proxy.cpp)
target_link_libraries(openfruit_compiler PUBLIC openfruit_recovery)
target_link_libraries(openfruit_compiler PUBLIC openfruit_dependencies)
target_link_libraries(openfruit_compiler PRIVATE openfruit_resources)

option(openfruit_BUILD_OPENIB "Build the independent OpenIB compiler" ON)
if(openfruit_BUILD_OPENIB)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../openib" openib)
endif()

openfruit_module(openfruit_resources
    src/asset_catalog_compiler.cpp src/core_data_compiler.cpp src/string_catalog_compiler.cpp
    src/intent_definition_compiler.cpp src/interface_builder_compiler.cpp)
target_link_libraries(openfruit_resources PRIVATE openfruit_environment openfruit_libplist)
if(TARGET openib_core)
    target_link_libraries(openfruit_resources PUBLIC openfruit_foundation openib_core)
    target_compile_definitions(openfruit_resources PRIVATE OPENFRUIT_HAS_OPENIB_INPROCESS=1)
else()
    target_link_libraries(openfruit_resources PUBLIC openfruit_foundation)
endif()

openfruit_module(openfruit_build src/app_builder.cpp src/build_graph.cpp src/compiler_module_cache.cpp)
target_link_libraries(openfruit_build PUBLIC
    openfruit_dependencies openfruit_resources openfruit_host)
target_link_libraries(openfruit_build PRIVATE openfruit_environment)

openfruit_module(openfruit_signing src/provisioning_identity.cpp src/signing_credential.cpp src/code_directory_cms.cpp src/macho_code_directory.cpp src/macho_signature.cpp src/entitlement_blobs.cpp src/bundle_resources.cpp)
target_sources(openfruit_signing PRIVATE src/ipa_verification.cpp)
target_link_libraries(openfruit_signing PUBLIC openfruit_foundation PRIVATE openfruit_libplist crypt32)
target_link_libraries(openfruit_signing PRIVATE openfruit_zip)
target_sources(openfruit_darwin PRIVATE src/darwin_file_signature.cpp)
target_link_libraries(openfruit_darwin PRIVATE openfruit_signing crypt32)
openfruit_module(openfruit_packaging src/packager_signer.cpp)
target_link_libraries(openfruit_packaging PUBLIC openfruit_resources openfruit_secure_storage PRIVATE openfruit_signing openfruit_artifacts)

openfruit_module(openfruit_devices src/device_deployer.cpp src/device_session.cpp src/device_tls.cpp)
target_link_libraries(openfruit_devices PUBLIC openfruit_foundation)
target_sources(openfruit_devices PRIVATE src/device_usbmux.cpp)
target_link_libraries(openfruit_devices PRIVATE openfruit_libplist ws2_32)

openfruit_module(openfruit_application src/sdk_selection.cpp src/sdk_read_operations.cpp src/cache_read_operations.cpp src/sdk_auto_selection.cpp src/capabilities.cpp src/project_inspection.cpp src/project_selection_metadata.cpp src/build_workspace.cpp
    src/cocoapods_installer.cpp)
target_sources(openfruit_application PRIVATE src/application_service.cpp src/operation_adapter.cpp)
if(TARGET openib_core)
    target_compile_definitions(openfruit_application PRIVATE OPENFRUIT_HAS_OPENIB_INPROCESS=1)
endif()
target_link_libraries(openfruit_application PUBLIC openfruit_configuration openfruit_sdk openfruit_project openfruit_host openfruit_dependencies)
target_link_libraries(openfruit_application PRIVATE openfruit_artifacts openfruit_darwin openfruit_observability)
target_link_libraries(openfruit_application PRIVATE openfruit_build openfruit_packaging openfruit_devices openfruit_environment openfruit_provider_acquisition)


# Transitional facade: keeps current consumers stable during service extraction.
add_library(openfruit_core INTERFACE)
target_link_libraries(openfruit_core INTERFACE
    openfruit_environment openfruit_credentials openfruit_compiler openfruit_build
    openfruit_packaging openfruit_devices openfruit_application)
add_executable(openfruit src/main.cpp src/cli_commands.cpp src/openfruit.manifest src/openfruit.rc)
add_custom_command(TARGET openfruit POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:unicorn> $<TARGET_FILE_DIR:openfruit>)
target_link_libraries(openfruit PRIVATE openfruit_core openfruit_observability openfruit_darwin openfruit_zip openfruit_restore openfruit_aea openfruit_apfs openfruit_signing openfruit_provider_acquisition)
install(TARGETS openfruit RUNTIME DESTINATION bin)
install(FILES "$<TARGET_FILE:unicorn>" DESTINATION bin)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/WINDOWS_STANDALONE.md"
    DESTINATION share/doc/openfruit)
add_executable(openfruit-macro-bridge "${CMAKE_CURRENT_SOURCE_DIR}/../../native/macro-bridge/main.cpp")
target_link_libraries(openfruit-macro-bridge PRIVATE openfruit_options)
install(TARGETS openfruit-macro-bridge RUNTIME DESTINATION toolchains/darling/bin)
add_executable(openfruit-macro-host "${CMAKE_CURRENT_SOURCE_DIR}/../../native/macro-host/main.cpp" src/openfruit.manifest)
target_link_libraries(openfruit-macro-host PRIVATE openfruit_darwin)
install(TARGETS openfruit-macro-host RUNTIME DESTINATION bin)
# Xcode developer tools that build phases invoke by name.
add_executable(genstrings src/genstrings_main.cpp src/genstrings.cpp src/openfruit.manifest)
target_link_libraries(genstrings PRIVATE openfruit_options)
install(TARGETS genstrings RUNTIME DESTINATION bin)
if(MSVC)
    install(FILES "$<TARGET_PDB_FILE:openfruit>" DESTINATION bin OPTIONAL)
endif()

function(openfruit_probe name option_name description)
    option(${option_name} "${description}" OFF)
    if(${option_name})
        add_executable(${name} "tests/${name}.cpp")
        target_link_libraries(${name} PRIVATE openfruit_core)
    endif()
endfunction()

openfruit_probe(carthage_binary_probe openfruit_BUILD_CARTHAGE_BINARY_PROBE
    "Build the isolated Carthage binary-cache regression probe")
openfruit_probe(carthage_xcode_contract_probe openfruit_BUILD_CARTHAGE_XCODE_CONTRACT_PROBE
    "Build the Xcode-to-Carthage XCFramework contract probe")
openfruit_probe(carthage_propagation_probe openfruit_BUILD_CARTHAGE_PROPAGATION_PROBE
    "Build the Carthage-to-compiler framework-path propagation probe")
openfruit_probe(swiftpm_host_sdk_probe openfruit_BUILD_SWIFTPM_HOST_SDK_PROBE
    "Build the SwiftPM legacy-manifest host SDK projection probe")
if(openfruit_BUILD_SWIFTPM_HOST_SDK_PROBE)
    target_sources(swiftpm_host_sdk_probe PRIVATE src/openfruit.manifest)
endif()
openfruit_probe(swiftpm_submodule_probe openfruit_BUILD_SWIFTPM_SUBMODULE_PROBE
    "Build the SwiftPM Git submodule long-path checkout probe")
openfruit_probe(swiftpm_binary_artifact_probe openfruit_BUILD_SWIFTPM_BINARY_ARTIFACT_PROBE
    "Build the SwiftPM binary-artifact path-budget probe")
openfruit_probe(swift_fallback_modulemap_probe openfruit_BUILD_SWIFT_FALLBACK_MODULEMAP_PROBE
    "Build the Swift fallback generated-modulemap projection probe")
openfruit_probe(swiftpm_windows_host_macro_probe openfruit_BUILD_SWIFTPM_WINDOWS_HOST_MACRO_PROBE
    "Build the SwiftPM Windows-host macro end-to-end probe")
openfruit_probe(xcode_xcconfig_anchor_probe openfruit_BUILD_XCCONFIG_ANCHOR_PROBE
    "Build the isolated Xcode xcconfig anchor regression probe")
openfruit_probe(config_active_sdk_probe openfruit_BUILD_CONFIG_ACTIVE_SDK_PROBE
    "Build the active-version SDK config update regression probe")
openfruit_probe(swift_import_recovery_probe openfruit_BUILD_SWIFT_IMPORT_RECOVERY_PROBE
    "Build the production SwiftPM import-recovery ambiguity probe")
if(openfruit_BUILD_SWIFT_IMPORT_RECOVERY_PROBE)
    target_link_libraries(swift_import_recovery_probe PRIVATE openfruit_observability)
endif()


if(BUILD_TESTING)
    add_executable(application_service_tests tests/application_service_tests.cpp)
    target_link_libraries(application_service_tests PRIVATE openfruit_application openfruit_observability)
    add_test(NAME application_service_tests COMMAND application_service_tests)
    set_tests_properties(application_service_tests PROPERTIES TIMEOUT 30)
    add_executable(operation_adapter_tests tests/operation_adapter_tests.cpp)
    target_link_libraries(operation_adapter_tests PRIVATE openfruit_application openfruit_observability)
    add_test(NAME operation_adapter_tests COMMAND operation_adapter_tests)
    set_tests_properties(operation_adapter_tests PROPERTIES TIMEOUT 30)
    add_executable(device_usbmux_tests tests/device_usbmux_tests.cpp)
    target_link_libraries(device_usbmux_tests PRIVATE openfruit_devices openfruit_libplist ws2_32)
    add_test(NAME device_usbmux_tests COMMAND device_usbmux_tests)
    set_tests_properties(device_usbmux_tests PROPERTIES TIMEOUT 30)
    add_executable(device_session_tests tests/device_session_tests.cpp)
    target_link_libraries(device_session_tests PRIVATE openfruit_devices openfruit_libplist ws2_32)
    add_test(NAME device_session_tests COMMAND device_session_tests)
    set_tests_properties(device_session_tests PROPERTIES TIMEOUT 30)
    add_executable(ipa_verification_tests tests/ipa_verification_tests.cpp)
    target_link_libraries(ipa_verification_tests PRIVATE openfruit_signing openfruit_zip crypt32 ncrypt)
    add_test(NAME ipa_verification_tests COMMAND ipa_verification_tests)
    set_tests_properties(ipa_verification_tests PROPERTIES TIMEOUT 60)
    add_executable(svg_runtime_provider_tests tests/svg_runtime_provider_tests.cpp)
    target_link_libraries(svg_runtime_provider_tests PRIVATE openfruit_environment)
    add_test(NAME svg_runtime_provider_tests COMMAND svg_runtime_provider_tests)
    set_tests_properties(svg_runtime_provider_tests PROPERTIES TIMEOUT 60)
    add_executable(asset_catalog_compiler_tests tests/asset_catalog_compiler_tests.cpp)
    target_link_libraries(asset_catalog_compiler_tests PRIVATE openfruit_resources openfruit_observability)
    add_test(NAME asset_catalog_compiler_tests COMMAND asset_catalog_compiler_tests)
    set_tests_properties(asset_catalog_compiler_tests PROPERTIES TIMEOUT 60)

    add_executable(string_catalog_compiler_tests tests/string_catalog_compiler_tests.cpp)
    target_link_libraries(string_catalog_compiler_tests PRIVATE openfruit_resources openfruit_observability)
    add_test(NAME string_catalog_compiler_tests COMMAND string_catalog_compiler_tests)
    set_tests_properties(string_catalog_compiler_tests PROPERTIES TIMEOUT 60)

    add_executable(cache_garbage_collection_tests tests/cache_garbage_collection_tests.cpp)
    target_link_libraries(cache_garbage_collection_tests PRIVATE openfruit_artifacts)
    add_test(NAME cache_garbage_collection_tests COMMAND cache_garbage_collection_tests)
    set_tests_properties(cache_garbage_collection_tests PROPERTIES TIMEOUT 60)
    add_executable(unsigned_packaging_tests tests/unsigned_packaging_tests.cpp)
    target_link_libraries(unsigned_packaging_tests PRIVATE openfruit_packaging openfruit_project)
    add_test(NAME unsigned_packaging_tests COMMAND unsigned_packaging_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/signing-identity" $<TARGET_FILE:openfruit>)
    set_tests_properties(unsigned_packaging_tests PROPERTIES TIMEOUT 30)
    add_executable(macro_bridge_lifecycle_tests tests/macro_bridge_lifecycle_tests.cpp)
    target_link_libraries(macro_bridge_lifecycle_tests PRIVATE openfruit_foundation)
    add_test(NAME macro_bridge_lifecycle_tests COMMAND macro_bridge_lifecycle_tests $<TARGET_FILE:openfruit-macro-bridge>)
    set_tests_properties(macro_bridge_lifecycle_tests PROPERTIES TIMEOUT 30)
    add_executable(swiftpm_source_workspace_tests tests/swiftpm_source_workspace_tests.cpp)
    add_executable(binary_artifact_recovery_tests tests/binary_artifact_recovery_tests.cpp)
    add_executable(swiftpm_resolve_observation_tests tests/swiftpm_resolve_observation_tests.cpp)
    target_link_libraries(swiftpm_resolve_observation_tests PRIVATE openfruit_dependencies)
    add_test(NAME swiftpm_resolve_observation_tests COMMAND swiftpm_resolve_observation_tests)
    set_tests_properties(swiftpm_resolve_observation_tests PROPERTIES TIMEOUT 30)
    add_executable(compiler_module_cache_tests tests/compiler_module_cache_tests.cpp)
    target_link_libraries(compiler_module_cache_tests PRIVATE openfruit_build)
    add_test(NAME compiler_module_cache_tests COMMAND compiler_module_cache_tests)
    set_tests_properties(compiler_module_cache_tests PROPERTIES TIMEOUT 45)
    add_executable(compiler_proxy_identity_tests tests/compiler_proxy_identity_tests.cpp src/openfruit.manifest)
    target_link_libraries(compiler_proxy_identity_tests PRIVATE openfruit_dependencies)
    add_dependencies(compiler_proxy_identity_tests openfruit)
    add_test(NAME compiler_proxy_identity_tests COMMAND compiler_proxy_identity_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(compiler_proxy_identity_tests PROPERTIES TIMEOUT 60)
    add_test(NAME compiler_proxy_build_identity_tests
        COMMAND "${CMAKE_COMMAND}"
            "-DOPENFRUIT_IDENTITY_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/Testing/CompilerProxyIdentity"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/compiler_proxy_build_identity_tests.cmake")
    set_tests_properties(compiler_proxy_build_identity_tests PROPERTIES TIMEOUT 60)
    add_executable(swiftpm_manifest_integrity_tests tests/swiftpm_manifest_integrity_tests.cpp)
    target_link_libraries(swiftpm_manifest_integrity_tests PRIVATE openfruit_dependencies openfruit_observability)
    add_dependencies(swiftpm_manifest_integrity_tests openfruit)
    add_test(NAME swiftpm_manifest_integrity_tests COMMAND swiftpm_manifest_integrity_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(swiftpm_manifest_integrity_tests PROPERTIES TIMEOUT 720 SKIP_RETURN_CODE 77)
    target_link_libraries(binary_artifact_recovery_tests PRIVATE openfruit_dependencies)
    add_test(NAME binary_artifact_recovery_tests COMMAND binary_artifact_recovery_tests)
    set_tests_properties(binary_artifact_recovery_tests PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
    target_link_libraries(swiftpm_source_workspace_tests PRIVATE openfruit_dependencies)
    add_test(NAME swiftpm_source_workspace_tests COMMAND swiftpm_source_workspace_tests)
    # Includes real cold/warm builds, source deltas and a resolved revision update.
    set_tests_properties(swiftpm_source_workspace_tests PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77)
    add_executable(build_workspace_tests tests/build_workspace_tests.cpp)
    target_link_libraries(build_workspace_tests PRIVATE openfruit_application)
    add_test(NAME build_workspace_tests COMMAND build_workspace_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/signing-identity")
    set_tests_properties(build_workspace_tests PROPERTIES TIMEOUT 90)
    add_executable(genstrings_tests tests/genstrings_tests.cpp src/genstrings.cpp)
    target_link_libraries(genstrings_tests PRIVATE openfruit_options)
    target_include_directories(genstrings_tests PRIVATE src)
    add_test(NAME genstrings_tests COMMAND genstrings_tests)
    set_tests_properties(genstrings_tests PROPERTIES TIMEOUT 30)
    add_executable(cocoapods_installer_tests tests/cocoapods_installer_tests.cpp)
    target_link_libraries(cocoapods_installer_tests PRIVATE openfruit_application)
    add_test(NAME cocoapods_installer_tests COMMAND cocoapods_installer_tests)
    set_tests_properties(cocoapods_installer_tests PROPERTIES TIMEOUT 30)
    add_executable(git_source_view_tests tests/git_source_view_tests.cpp)
    add_executable(swift_host_environment_tests tests/swift_host_environment_tests.cpp src/openfruit.manifest)
    target_link_libraries(swift_host_environment_tests PRIVATE openfruit_environment)
    add_test(NAME swift_host_environment_tests COMMAND swift_host_environment_tests)
    set_tests_properties(swift_host_environment_tests PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
    add_executable(environment_probe_retention_tests tests/environment_probe_retention_tests.cpp src/openfruit.manifest)
    target_link_libraries(environment_probe_retention_tests PRIVATE openfruit_environment)
    add_test(NAME environment_probe_retention_tests COMMAND environment_probe_retention_tests)
    set_tests_properties(environment_probe_retention_tests PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
    add_executable(compiler_rt_support_tests tests/compiler_rt_support_tests.cpp)
    add_executable(sdk_runtime_abi_tests tests/sdk_runtime_abi_tests.cpp)
    target_link_libraries(sdk_runtime_abi_tests PRIVATE openfruit_sdk)
    add_test(NAME sdk_runtime_abi_tests COMMAND sdk_runtime_abi_tests)
    set_tests_properties(sdk_runtime_abi_tests PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
    add_executable(sdk_target_runtime_tests tests/sdk_target_runtime_tests.cpp src/openfruit.manifest)
    target_link_libraries(sdk_target_runtime_tests PRIVATE openfruit_sdk)
    add_test(NAME sdk_target_runtime_tests COMMAND sdk_target_runtime_tests)
    set_tests_properties(sdk_target_runtime_tests PROPERTIES TIMEOUT 60)
    target_link_libraries(compiler_rt_support_tests PRIVATE openfruit_host)
    add_test(NAME compiler_rt_support_tests COMMAND compiler_rt_support_tests)
    set_tests_properties(compiler_rt_support_tests PROPERTIES TIMEOUT 60)
    target_link_libraries(git_source_view_tests PRIVATE openfruit_dependencies)
    add_test(NAME git_source_view_tests COMMAND git_source_view_tests)
    set_tests_properties(git_source_view_tests PROPERTIES TIMEOUT 30)
    add_executable(console_cancellation_tests tests/console_cancellation_tests.cpp)
    target_link_libraries(console_cancellation_tests PRIVATE openfruit_foundation)
    add_test(NAME console_cancellation_tests COMMAND console_cancellation_tests $<TARGET_FILE:openfruit>)
    add_executable(bundle_resource_tests tests/bundle_resource_tests.cpp)
    target_link_libraries(bundle_resource_tests PRIVATE openfruit_signing openfruit_libplist crypt32)
    add_test(NAME bundle_resource_tests COMMAND bundle_resource_tests)
    if(TARGET openib_core)
        add_executable(interface_builder_diagnostics_tests tests/interface_builder_diagnostics_tests.cpp)
        target_link_libraries(interface_builder_diagnostics_tests PRIVATE openfruit_resources openfruit_observability)
        add_test(NAME interface_builder_diagnostics_tests COMMAND interface_builder_diagnostics_tests)
        set_tests_properties(interface_builder_diagnostics_tests PROPERTIES TIMEOUT 60)
        add_executable(interface_builder_failure_diagnostics_tests tests/interface_builder_failure_diagnostics_tests.cpp)
        target_link_libraries(interface_builder_failure_diagnostics_tests PRIVATE openfruit_resources openfruit_observability)
        add_test(NAME interface_builder_failure_diagnostics_tests COMMAND interface_builder_failure_diagnostics_tests)
        set_tests_properties(interface_builder_failure_diagnostics_tests PROPERTIES TIMEOUT 60)
    endif()
    add_executable(xcode_target_dependency_graph_tests tests/xcode_target_dependency_graph_tests.cpp src/openfruit.manifest)
    target_link_libraries(xcode_target_dependency_graph_tests PRIVATE openfruit_build openfruit_application)
    add_test(NAME xcode_target_dependency_graph_tests COMMAND xcode_target_dependency_graph_tests)
    set_tests_properties(xcode_target_dependency_graph_tests PROPERTIES TIMEOUT 60)
    add_executable(xcode_dependency_inventory_tests tests/xcode_dependency_inventory_tests.cpp)
    add_executable(xcode_package_selection_tests tests/xcode_package_selection_tests.cpp)
    target_link_libraries(xcode_package_selection_tests PRIVATE openfruit_dependencies)
    add_test(NAME xcode_package_selection_tests COMMAND xcode_package_selection_tests)
    set_tests_properties(xcode_package_selection_tests PROPERTIES TIMEOUT 30)
    target_link_libraries(xcode_dependency_inventory_tests PRIVATE openfruit_project)
    add_test(NAME xcode_dependency_inventory_tests COMMAND xcode_dependency_inventory_tests)
    set_tests_properties(xcode_dependency_inventory_tests PROPERTIES TIMEOUT 60)
    add_executable(entitlement_der_tests tests/entitlement_der_tests.cpp)
    target_link_libraries(entitlement_der_tests PRIVATE openfruit_signing)
    add_test(NAME entitlement_der_tests COMMAND entitlement_der_tests)
    add_executable(provisioning_identity_tests tests/provisioning_identity_tests.cpp)
    target_link_libraries(provisioning_identity_tests PRIVATE openfruit_signing openfruit_packaging openfruit_project crypt32 ncrypt)
    target_compile_definitions(provisioning_identity_tests PRIVATE OPENFRUIT_SIGNING_PROJECT_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/signing-identity")
    add_test(NAME provisioning_identity_tests COMMAND provisioning_identity_tests)
    set_tests_properties(provisioning_identity_tests PROPERTIES SKIP_RETURN_CODE 77)
    add_executable(macro_host_protocol_tests tests/macro_host_protocol_tests.cpp)
    add_executable(macro_engine_tests tests/macro_engine_tests.cpp)
    target_link_libraries(macro_engine_tests PRIVATE openfruit_host)
    add_test(NAME macro_engine_tests COMMAND macro_engine_tests)
    set_tests_properties(macro_engine_tests PROPERTIES TIMEOUT 30)
    add_executable(darwin_macro_provider_import_tests tests/darwin_macro_provider_import_tests.cpp)
    target_link_libraries(darwin_macro_provider_import_tests PRIVATE openfruit_environment)
    add_test(NAME darwin_macro_provider_import_tests COMMAND darwin_macro_provider_import_tests)
    set_tests_properties(darwin_macro_provider_import_tests PROPERTIES TIMEOUT 60)
    add_executable(darwin_macro_provider_tests tests/darwin_macro_provider_tests.cpp)
    target_link_libraries(darwin_macro_provider_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_macro_provider_tests COMMAND darwin_macro_provider_tests)
    set_tests_properties(darwin_macro_provider_tests PROPERTIES TIMEOUT 60)
    add_executable(darwin_image_tests tests/darwin_image_tests.cpp)
    add_executable(darwin_workqueue_tests tests/darwin_workqueue_tests.cpp)
    target_link_libraries(darwin_workqueue_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_workqueue_tests COMMAND darwin_workqueue_tests)
    set_tests_properties(darwin_workqueue_tests PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
    add_executable(darwin_task_info_tests tests/darwin_task_info_tests.cpp)
    target_link_libraries(darwin_task_info_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_task_info_tests COMMAND darwin_task_info_tests)
    set_tests_properties(darwin_task_info_tests PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
    add_executable(darwin_nocancel_tests tests/darwin_nocancel_tests.cpp)
    target_link_libraries(darwin_nocancel_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_nocancel_tests COMMAND darwin_nocancel_tests)
    set_tests_properties(darwin_nocancel_tests PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
    add_executable(darwin_tagged_rebase_tests tests/darwin_tagged_rebase_tests.cpp)
    target_link_libraries(darwin_tagged_rebase_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_tagged_rebase_tests COMMAND darwin_tagged_rebase_tests)
    set_tests_properties(darwin_tagged_rebase_tests PROPERTIES TIMEOUT 30)
    add_executable(darwin_sysctl_tests tests/darwin_sysctl_tests.cpp)
    add_executable(darwin_file_metadata_tests tests/darwin_file_metadata_tests.cpp)
    add_executable(darwin_file_mapping_tests tests/darwin_file_mapping_tests.cpp)
    add_executable(darwin_output_tests tests/darwin_output_tests.cpp)
    add_executable(darwin_loader_policy_tests tests/darwin_loader_policy_tests.cpp)
    add_executable(darwin_file_signature_tests tests/darwin_file_signature_tests.cpp)
    add_executable(darwin_progress_tests tests/darwin_progress_tests.cpp)
    add_executable(darwin_vm_backing_tests tests/darwin_vm_backing_tests.cpp)
    target_link_libraries(darwin_vm_backing_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_vm_backing_tests COMMAND darwin_vm_backing_tests)
    add_executable(darwin_clock_epoch_tests tests/darwin_clock_epoch_tests.cpp)
    target_link_libraries(darwin_clock_epoch_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_clock_epoch_tests COMMAND darwin_clock_epoch_tests)
    target_link_libraries(darwin_progress_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_progress_tests COMMAND darwin_progress_tests)
    target_link_libraries(darwin_file_signature_tests PRIVATE openfruit_darwin openfruit_signing)
    add_test(NAME darwin_file_signature_tests COMMAND darwin_file_signature_tests)
    target_link_libraries(darwin_loader_policy_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_loader_policy_tests COMMAND darwin_loader_policy_tests)
    target_link_libraries(darwin_output_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_output_tests COMMAND darwin_output_tests)
    target_link_libraries(darwin_file_mapping_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_file_mapping_tests COMMAND darwin_file_mapping_tests)
    target_link_libraries(darwin_file_metadata_tests PRIVATE openfruit_darwin advapi32)
    add_test(NAME darwin_file_metadata_tests COMMAND darwin_file_metadata_tests)
    add_executable(darwin_process_identity_tests tests/darwin_process_identity_tests.cpp)
    target_link_libraries(darwin_process_identity_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_process_identity_tests COMMAND darwin_process_identity_tests)
    add_executable(darwin_pthread_registration_tests tests/darwin_pthread_registration_tests.cpp)
    target_link_libraries(darwin_pthread_registration_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_pthread_registration_tests COMMAND darwin_pthread_registration_tests)
    add_executable(darwin_pthread_creation_tests tests/darwin_pthread_creation_tests.cpp)
    target_link_libraries(darwin_pthread_creation_tests PRIVATE openfruit_darwin unicorn)
    add_test(NAME darwin_pthread_creation_tests COMMAND darwin_pthread_creation_tests)
    add_executable(darwin_kevent_tests tests/darwin_kevent_tests.cpp)
    target_link_libraries(darwin_kevent_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_kevent_tests COMMAND darwin_kevent_tests)
    add_executable(darwin_pointer_auth_tests tests/darwin_pointer_auth_tests.cpp)
    target_link_libraries(darwin_pointer_auth_tests PRIVATE openfruit_darwin unicorn)
    add_test(NAME darwin_pointer_auth_tests COMMAND darwin_pointer_auth_tests)
    add_executable(darwin_pthread_policy_tests tests/darwin_pthread_policy_tests.cpp)
    target_link_libraries(darwin_pthread_policy_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_pthread_policy_tests COMMAND darwin_pthread_policy_tests)
    add_executable(darwin_files_tests tests/darwin_files_tests.cpp)
    target_link_libraries(darwin_files_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_files_tests COMMAND darwin_files_tests)
    add_executable(darwin_thread_context_tests tests/darwin_thread_context_tests.cpp)
    target_link_libraries(darwin_thread_context_tests PRIVATE openfruit_darwin unicorn)
    add_test(NAME darwin_thread_context_tests COMMAND darwin_thread_context_tests)
    add_executable(darwin_thread_run_queue_tests tests/darwin_thread_run_queue_tests.cpp)
    target_link_libraries(darwin_thread_run_queue_tests PRIVATE openfruit_darwin unicorn)
    add_test(NAME darwin_thread_run_queue_tests COMMAND darwin_thread_run_queue_tests)
    target_link_libraries(darwin_sysctl_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_sysctl_tests COMMAND darwin_sysctl_tests)
    add_executable(dyld_cache_tests tests/dyld_cache_tests.cpp)
    target_link_libraries(dyld_cache_tests PRIVATE openfruit_darwin)
    add_test(NAME dyld_cache_tests COMMAND dyld_cache_tests $<TARGET_FILE:openfruit>)
    target_link_libraries(darwin_image_tests PRIVATE openfruit_darwin)
    add_test(NAME darwin_image_tests COMMAND darwin_image_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(darwin_image_tests PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
    target_link_libraries(macro_host_protocol_tests PRIVATE openfruit_foundation)
    add_test(NAME macro_host_protocol_tests COMMAND macro_host_protocol_tests $<TARGET_FILE:openfruit-macro-host>)
    set_tests_properties(macro_host_protocol_tests PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
    add_executable(capabilities_tests tests/capabilities_tests.cpp)
    target_link_libraries(capabilities_tests PRIVATE openfruit_observability)
    add_test(NAME capabilities_tests COMMAND capabilities_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(capabilities_tests PROPERTIES TIMEOUT 30)
    add_executable(process_supervisor_tests tests/process_supervisor_tests.cpp)
    target_link_libraries(process_supervisor_tests PRIVATE openfruit_observability)
    add_test(NAME process_supervisor_tests COMMAND process_supervisor_tests)
    set_tests_properties(process_supervisor_tests PROPERTIES TIMEOUT 30)
    add_executable(swift_telemetry_tests tests/swift_telemetry_tests.cpp)
    target_link_libraries(swift_telemetry_tests PRIVATE openfruit_foundation)
    add_test(NAME swift_telemetry_tests COMMAND swift_telemetry_tests)
    set_tests_properties(swift_telemetry_tests PROPERTIES TIMEOUT 30)
    add_executable(compiler_diagnostics_tests tests/compiler_diagnostics_tests.cpp)
    target_link_libraries(compiler_diagnostics_tests PRIVATE openfruit_foundation openfruit_environment)
    add_test(NAME compiler_diagnostics_tests COMMAND compiler_diagnostics_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(compiler_diagnostics_tests PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
    add_executable(sdk_auto_selection_tests tests/sdk_auto_selection_tests.cpp)
    target_link_libraries(sdk_auto_selection_tests PRIVATE openfruit_application)
    add_test(NAME sdk_auto_selection_tests COMMAND sdk_auto_selection_tests)
    add_executable(sdk_archive_extraction_tests tests/sdk_archive_extraction_tests.cpp)
    target_link_libraries(sdk_archive_extraction_tests PRIVATE openfruit_sdk openfruit_archive_codecs)
    add_test(NAME sdk_archive_extraction_tests COMMAND sdk_archive_extraction_tests $<TARGET_FILE:openfruit>)
    add_executable(apple_download_catalog_tests tests/apple_download_catalog_tests.cpp)
    target_link_libraries(apple_download_catalog_tests PRIVATE openfruit_sdk)
    add_test(NAME apple_download_catalog_tests COMMAND apple_download_catalog_tests)
    add_executable(xip_archive_tests tests/xip_archive_tests.cpp)
    target_link_libraries(xip_archive_tests PRIVATE openfruit_sdk openfruit_archive_codecs)
    add_test(NAME xip_archive_tests COMMAND xip_archive_tests $<TARGET_FILE:openfruit>)
    add_executable(http_transfer_tests tests/http_transfer_tests.cpp)
    add_executable(zip_inventory_tests tests/zip_inventory_tests.cpp)
    add_executable(zip_member_tests tests/zip_member_tests.cpp)
    add_executable(restore_manifest_tests tests/restore_manifest_tests.cpp)
    add_executable(aea_decode_tests tests/aea_decode_tests.cpp)
    add_executable(apfs_metadata_tests tests/apfs_metadata_tests.cpp)
    add_executable(apfs_compression_tests tests/apfs_compression_tests.cpp)
    target_link_libraries(apfs_compression_tests PRIVATE openfruit_apfs)
    add_test(NAME apfs_compression_tests COMMAND apfs_compression_tests)
    target_link_libraries(apfs_metadata_tests PRIVATE openfruit_apfs)
    add_test(NAME apfs_metadata_tests COMMAND apfs_metadata_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(apfs_metadata_tests PROPERTIES TIMEOUT 60)
    target_link_libraries(aea_decode_tests PRIVATE openfruit_aea)
    add_test(NAME aea_decode_tests COMMAND aea_decode_tests)
    add_executable(aea_input_tests tests/aea_input_tests.cpp)
    target_link_libraries(aea_input_tests PRIVATE openfruit_aea)
    add_test(NAME aea_input_tests COMMAND aea_input_tests)
    target_link_libraries(restore_manifest_tests PRIVATE openfruit_restore)
    add_test(NAME restore_manifest_tests COMMAND restore_manifest_tests)
    target_link_libraries(zip_member_tests PRIVATE openfruit_zip openfruit_archive_codecs)
    add_test(NAME zip_member_tests COMMAND zip_member_tests)
    target_link_libraries(zip_inventory_tests PRIVATE openfruit_foundation)
    add_test(NAME zip_inventory_tests COMMAND zip_inventory_tests)
    target_link_libraries(http_transfer_tests PRIVATE openfruit_foundation ws2_32)
    add_test(NAME http_transfer_tests COMMAND http_transfer_tests)
    set_tests_properties(http_transfer_tests PROPERTIES TIMEOUT 40)
    add_executable(http_transfer_reuse_tests tests/http_transfer_reuse_tests.cpp)
    target_link_libraries(http_transfer_reuse_tests PRIVATE openfruit_foundation ws2_32)
    add_test(NAME http_transfer_reuse_tests COMMAND http_transfer_reuse_tests)
    set_tests_properties(http_transfer_reuse_tests PROPERTIES TIMEOUT 30)
    add_executable(apple_cookies_tests tests/apple_cookies_tests.cpp)
    target_link_libraries(apple_cookies_tests PRIVATE openfruit_credentials)
    add_test(NAME apple_cookies_tests COMMAND apple_cookies_tests $<TARGET_FILE:openfruit>)
    add_executable(sdk_usage_tests tests/sdk_usage_tests.cpp)
    target_link_libraries(sdk_usage_tests PRIVATE openfruit_sdk openfruit_artifacts)
    add_test(NAME sdk_usage_tests COMMAND sdk_usage_tests)
    add_executable(sdk_selection_tests tests/sdk_selection_tests.cpp)
    target_link_libraries(sdk_selection_tests PRIVATE openfruit_application)
    add_test(NAME sdk_selection_tests COMMAND sdk_selection_tests $<TARGET_FILE:openfruit>)
    add_executable(sdk_removal_safety_tests tests/sdk_removal_safety_tests.cpp src/openfruit.manifest)
    target_link_libraries(sdk_removal_safety_tests PRIVATE openfruit_application)
    add_test(NAME sdk_removal_safety_tests COMMAND sdk_removal_safety_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(sdk_removal_safety_tests PROPERTIES TIMEOUT 60)
    add_executable(sdk_removal_cleanup_tests tests/sdk_removal_cleanup_tests.cpp src/openfruit.manifest)
    target_link_libraries(sdk_removal_cleanup_tests PRIVATE openfruit_application)
    add_dependencies(sdk_removal_cleanup_tests openfruit)
    add_test(NAME sdk_removal_cleanup_tests COMMAND sdk_removal_cleanup_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(sdk_removal_cleanup_tests PROPERTIES TIMEOUT 90)
    add_executable(sdk_catalog_tests tests/sdk_catalog_tests.cpp)
    target_link_libraries(sdk_catalog_tests PRIVATE openfruit_sdk)
    add_test(NAME sdk_catalog_tests COMMAND sdk_catalog_tests)
    add_executable(sdk_selected_inspection_tests tests/sdk_selected_inspection_tests.cpp)
    target_link_libraries(sdk_selected_inspection_tests PRIVATE openfruit_sdk)
    add_test(NAME sdk_selected_inspection_tests COMMAND sdk_selected_inspection_tests)
    set_tests_properties(sdk_selected_inspection_tests PROPERTIES TIMEOUT 45)
    add_executable(cache_read_operations_tests tests/cache_read_operations_tests.cpp src/openfruit.manifest)
    target_link_libraries(cache_read_operations_tests PRIVATE openfruit_application)
    add_test(NAME cache_read_operations_tests COMMAND cache_read_operations_tests)
    set_tests_properties(cache_read_operations_tests PROPERTIES TIMEOUT 60)
    add_executable(sdk_read_operations_tests tests/sdk_read_operations_tests.cpp src/openfruit.manifest)
    target_link_libraries(sdk_read_operations_tests PRIVATE openfruit_application)
    add_dependencies(sdk_read_operations_tests openfruit)
    add_test(NAME sdk_read_operations_tests COMMAND sdk_read_operations_tests $<TARGET_FILE:openfruit>)
    set_tests_properties(sdk_read_operations_tests PROPERTIES TIMEOUT 90)
    add_executable(config_publication_tests tests/config_publication_tests.cpp)
    target_link_libraries(config_publication_tests PRIVATE openfruit_configuration)
    add_test(NAME config_publication_tests COMMAND config_publication_tests)
    add_executable(sdk_acquisition_tests tests/sdk_acquisition_tests.cpp)
    target_link_libraries(sdk_acquisition_tests PRIVATE openfruit_sdk)
    add_test(NAME sdk_acquisition_tests COMMAND sdk_acquisition_tests $<TARGET_FILE:openfruit>)
    add_executable(artifact_transactions_tests tests/artifact_transactions_tests.cpp src/openfruit.manifest)
    target_link_libraries(artifact_transactions_tests PRIVATE openfruit_artifacts)
    add_dependencies(artifact_transactions_tests openfruit)
    add_test(NAME artifact_transactions_tests COMMAND artifact_transactions_tests $<TARGET_FILE:openfruit>)
    add_executable(managed_layout_tests tests/managed_layout_tests.cpp)
    target_link_libraries(managed_layout_tests PRIVATE openfruit_sdk)
    add_test(NAME managed_layout_tests COMMAND managed_layout_tests)
    add_executable(credential_boundaries_tests tests/credential_boundaries_tests.cpp)
    target_link_libraries(credential_boundaries_tests PRIVATE openfruit_credentials)
    add_test(NAME credential_boundaries_tests COMMAND credential_boundaries_tests)
    add_executable(operation_events_tests tests/operation_events_tests.cpp)
    target_link_libraries(operation_events_tests PRIVATE openfruit_observability)
    add_test(NAME operation_events_tests COMMAND operation_events_tests)
    set_tests_properties(operation_events_tests PROPERTIES TIMEOUT 60)
    add_executable(project_inspection_tests tests/project_inspection_tests.cpp)
    target_link_libraries(project_inspection_tests PRIVATE openfruit_application)
    target_compile_definitions(project_inspection_tests PRIVATE
        OPENFRUIT_SHELL_PHASE_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/xcode-shell-phase")
    add_test(NAME project_inspection_tests COMMAND project_inspection_tests)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/CompilerProxyIdentity.cmake")
openfruit_enable_compiler_proxy_identity(openfruit_dependencies)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/StandalonePackaging.cmake")
