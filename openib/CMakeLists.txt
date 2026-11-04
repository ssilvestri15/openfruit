cmake_minimum_required(VERSION 3.20)
project(OpenIB VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(OPENIB_BUILD_TESTS "Build OpenIB tests" ON)

add_library(openib_core
    src/xml.cpp
    src/model.cpp
    src/nib.cpp
    src/compiler.cpp
    src/text_layout.cpp
    src/diff.cpp
    src/c_api.cpp
)

target_include_directories(openib_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_definitions(openib_core PUBLIC
    OPENIB_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    OPENIB_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    OPENIB_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

if(MSVC)
    target_compile_options(openib_core PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(openib_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(openib src/main.cpp)
target_link_libraries(openib PRIVATE openib_core)

install(TARGETS openib RUNTIME DESTINATION bin)

if(OPENIB_BUILD_TESTS)
    enable_testing()
    add_executable(openib_tests tests/test_main.cpp)
    target_link_libraries(openib_tests PRIVATE openib_core)
    target_compile_definitions(openib_tests PRIVATE OPENIB_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    add_test(NAME openib_tests COMMAND openib_tests)
endif()
