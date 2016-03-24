cmake_minimum_required(VERSION 2.7)
project(xdccget)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wfatal-errors -Os  -std=gnu11")

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

find_package (Threads)

add_definitions(-DENABLE_SSL)
add_definitions(-DDEBUG)
add_definitions(-DFILE_API)
add_definitions(-DENABLE_IPV6)
add_definitions(-D_FILE_OFFSET_BITS=64)
include_directories(libircclient-include)

set(SOURCE_FILES
    libircclient-src/libircclient.c
    argument_parser.c
    argument_parser.h
    config.c
    config.h
    dirs.c
    dirs.h
    file.c
    file.h
    helper.c
    helper.h
    sds.c
    sds.h
    xdccget.c
    xdccget.h
    hashing_algo.c
    sph_md5.c)

add_executable(xdccget ${SOURCE_FILES} libircclient-src/portable_endian.h)
target_link_libraries(xdccget ${OPENSSL_LIBRARIES})
target_link_libraries (xdccget ${CMAKE_THREAD_LIBS_INIT})
