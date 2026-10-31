cmake_minimum_required(VERSION 3.16)
project(sarif-writer VERSION 0.1.0 DESCRIPTION "Streaming SARIF 2.1.0 writer" LANGUAGES C)

option(SARIF_WRITER_BUILD_EXAMPLES "Build examples" OFF)

include(GNUInstallDirs)

add_library(sarif-writer src/sarif-writer.c src/sarw_json.c src/sarw_uri.c)
add_library(sarif-writer::sarif-writer ALIAS sarif-writer)
target_include_directories(sarif-writer PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(sarif-writer PROPERTIES
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

if(BUILD_SHARED_LIBS)
    target_compile_definitions(sarif-writer PRIVATE SARW_BUILD_SHARED INTERFACE SARW_SHARED)
endif()

if(SARIF_WRITER_BUILD_EXAMPLES)
    add_executable(sarif_hello examples/sarif-hello.c)
    target_link_libraries(sarif_hello PRIVATE sarif-writer)
endif()
