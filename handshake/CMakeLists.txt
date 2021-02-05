cmake_minimum_required(VERSION 3.10)

project(tcpTest VERSION 1.0 DESCRIPTION "")

set(CMAKE_C_FLAGS "-std=gnu99")
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(tcpTest tcp_handshake.c)

target_link_libraries(tcpTest net pcap)
