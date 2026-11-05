cmake_minimum_required(VERSION 3.16)
project(sarif-writer_consumer LANGUAGES C)

find_package(sarif-writer REQUIRED)

add_executable(consumer ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/sarif-hello.c)
target_link_libraries(consumer PRIVATE sarif-writer::sarif-writer)
