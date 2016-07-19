cmake_minimum_required(VERSION 2.7)
project(xdccget)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wfatal-errors -Os -std=gnu11 -fstack-protector")

find_package(OpenSSL REQUIRED)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL is required for building xdccget!")
endif()

find_package (Threads)

add_definitions(-DENABLE_SSL)
add_definitions(-DDEBUG)
add_definitions(-DFILE_API)
add_definitions(-DENABLE_IPV6)
add_definitions(-D_FILE_OFFSET_BITS=64)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
   add_definitions(-DHAVE_POLL)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
   add_definitions(-DHAVE_POLL)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "CYGWIN")
   add_definitions(-DHAVE_POLL)
endif()


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
