cmake_minimum_required(VERSION 3.10)
project(anonet VERSION 0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system)

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    message(STATUS "Boost include directories: ${Boost_INCLUDE_DIRS}")
else ()
    message(FATAL_ERROR "Boost not found")
endif ()

add_executable(${PROJECT_NAME} main.cpp
        src/Peer.cpp
        inc/Peer.hpp)
target_link_libraries(${PROJECT_NAME} Boost::system)
