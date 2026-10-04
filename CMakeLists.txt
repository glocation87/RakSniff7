cmake_minimum_required(VERSION 3.15)
project(omp_packet_viewer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Npcap SDK path (set via -DNPCAP_SDK_DIR=... or environment)
if(NOT NPCAP_SDK_DIR)
    if(DEFINED ENV{NPCAP_SDK_DIR})
        set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
    else()
        set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk")
    endif()
endif()

add_executable(omp_packet_viewer
    src/main.c
    src/bitstream.c
    src/pcap_reader.c
    src/query.c
    src/decrypt.c
    src/omp_encrypt.c
    src/handshake.c
    src/raknet.c
    src/split.c
    src/dedup.c
    src/identify.c
    src/connection.c
    src/pipeline.c
)

target_include_directories(omp_packet_viewer PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

if(WIN32)
    target_include_directories(omp_packet_viewer PRIVATE
        "${NPCAP_SDK_DIR}/Include"
    )
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_directories(omp_packet_viewer PRIVATE "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        target_link_directories(omp_packet_viewer PRIVATE "${NPCAP_SDK_DIR}/Lib")
    endif()
    target_link_libraries(omp_packet_viewer wpcap ws2_32)
else()
    target_link_libraries(omp_packet_viewer pcap)
endif()
