cmake_minimum_required(VERSION 3.16)
project(sarif-writer VERSION 0.1.0 DESCRIPTION "Streaming SARIF 2.1.0 writer" LANGUAGES C)

option(SARIF_WRITER_BUILD_TESTS "Build tests" OFF)
option(SARIF_WRITER_BUILD_EXAMPLES "Build examples" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

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

set(PC_CFLAGS "")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(sarif-writer PRIVATE SARW_BUILD_SHARED INTERFACE SARW_SHARED)
    set(PC_CFLAGS "-DSARW_SHARED")
endif()

install(TARGETS sarif-writer EXPORT sarif-writerTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT sarif-writerTargets
    NAMESPACE sarif-writer::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sarif-writer)

configure_package_config_file(cmake/sarif-writerConfig.cmake.in
    ${PROJECT_BINARY_DIR}/sarif-writerConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sarif-writer)
write_basic_package_version_file(${PROJECT_BINARY_DIR}/sarif-writerConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${PROJECT_BINARY_DIR}/sarif-writerConfig.cmake
    ${PROJECT_BINARY_DIR}/sarif-writerConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sarif-writer)

configure_file(sarif-writer.pc.in ${PROJECT_BINARY_DIR}/sarif-writer.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/sarif-writer.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(SARIF_WRITER_BUILD_TESTS)
    enable_testing()
    add_executable(test_sarif-writer tests/test_sarif-writer.c)
    target_link_libraries(test_sarif-writer PRIVATE sarif-writer)
    add_test(NAME sarif-writer COMMAND test_sarif-writer)
    add_executable(sarw_lines tests/sarw_lines.c)
    target_link_libraries(sarw_lines PRIVATE sarif-writer)
    set_target_properties(test_sarif-writer sarw_lines PROPERTIES C_STANDARD 99)
    add_library(sarif-writer_header_check OBJECT tests/header_check.c)
    target_include_directories(sarif-writer_header_check PRIVATE include)
endif()

if(SARIF_WRITER_BUILD_EXAMPLES)
    add_executable(sarif_hello examples/sarif-hello.c)
    target_link_libraries(sarif_hello PRIVATE sarif-writer)
endif()
