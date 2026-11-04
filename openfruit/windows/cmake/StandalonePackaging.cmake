# Binary distribution uses the same install rules as the native build. No SDKs,
# credentials, workspaces or application caches enter this archive.
set(OPENFRUIT_PACKAGE_VERSION "0.1.0" CACHE STRING "Standalone package version")
set(CPACK_PACKAGE_NAME "OPENFRUIT")
set(CPACK_PACKAGE_VENDOR "OPENFRUIT")
set(CPACK_PACKAGE_VERSION "${OPENFRUIT_PACKAGE_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Windows-native iOS build tools")
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_FILE_NAME "OPENFRUIT-${OPENFRUIT_PACKAGE_VERSION}-windows-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
set(CPACK_SOURCE_GENERATOR "")
include(CPack)
