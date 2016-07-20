cmake_minimum_required(VERSION 2.7)
project(xdccget)

include(FindPackageHandleStandardArgs)
include(CheckFunctionExists)

set(CMAKE_REQUIRED_QUIET_SAVE ${CMAKE_REQUIRED_QUIET})
set(CMAKE_REQUIRED_QUIET TRUE)

check_function_exists("argp_parse" ARGP_IN_LIBC)
if (ARGP_IN_LIBC)
	set(ARGP_LIBRARIES "c" CACHE STRING "ARGP libraries.")
	
elseif (NOT ARGP_IN_LIBC)
	unset(ARGP_IN_LIBC CACHE)

	find_library(ARGP_LIB "argp")
	mark_as_advanced(ARGP_LIB)
	if (ARGP_LIB)
		set(CMAKE_REQUIRED_LIBRARIES "${ARGP_LIB}")
		check_function_exists("argp_parse" ARGP_EXTERNAL)
		if (ARGP_EXTERNAL)
			set(ARGP_LIBRARIES "${ARGP_LIB}" CACHE STRING "ARGP libraries.")
		endif ()
	endif ()
endif ()

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
#add_definitions(-DDEBUG)
add_definitions(-DFILE_API)
add_definitions(-DENABLE_IPV6)
add_definitions(-D_FILE_OFFSET_BITS=64)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
   add_definitions(-DHAVE_POLL)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
   add_definitions(-DHAVE_POLL)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "CYGWIN")
   add_definitions(-DHAVE_POLL)
   
endif()

include_directories(libircclient-include)

set(SOURCE_FILES
    libircclient-src/libircclient.c
    argument_parser.c
    config.c
    dirs.c
    dirs.h
    file.c
    helper.c
    sds.c
    xdccget.c
    hashing_algo.c
    sph_md5.c)

add_executable(xdccget ${SOURCE_FILES})
target_link_libraries(xdccget ${OPENSSL_LIBRARIES})
target_link_libraries (xdccget ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (xdccget ${ARGP_LIBRARIES})
