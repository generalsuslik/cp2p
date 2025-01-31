cmake_minimum_required(VERSION 3.10)
project(cp2p VERSION 0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if (CLANG_TIDY_EXE)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
        message(STATUS "clang-tidy set")
    else ()
        message(WARNING "Could not find clang-tidy")
    endif ()
endif ()

#-----BOOST-----#
find_package(Boost REQUIRED COMPONENTS system)

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    message(STATUS "Boost include directories: ${Boost_INCLUDE_DIRS}")
else ()
    message(FATAL_ERROR "Boost not found")
endif ()

#-----OpenSSL-----#
find_package(OpenSSL REQUIRED)

if (OpenSSL_FOUND)
    include_directories(${OpenSSL_INCLUDE_DIRS})
    message(STATUS "OpenSSL include directories: ${OpenSSL_INCLUDE_DIRS}")
else ()
    message(FATAL_ERROR "OpenSSL not found")
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -O2 -fsanitize=address -Wsign-compare")

add_executable(${PROJECT_NAME} main.cpp
        src/peer.cpp
        inc/peer.hpp
        src/crypto.cpp
        inc/crypto.hpp
)

target_link_libraries(${PROJECT_NAME} Boost::system)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)


