cmake_minimum_required(VERSION 3.28)
project(cp2p_build VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O2 -pipe")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -fsanitize=address")

#-----Clang-tidy-----#
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
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

#-----nlohmann JSON-----#
find_package(nlohmann_json 3.11.3 REQUIRED)

if (nlohmann_json_FOUND)
    include_directories(${nlohmann_json_INCLUDE_DIRS})
    message(STATUS "nlohmann JSON include directories: ${nlohmann_json_INCLUDE_DIRS}")
else ()
    message(FATAL_ERROR "nlohmann JSON not found")
endif ()

#----Logger----#
find_package(spdlog REQUIRED)

if (spdlog_FOUND)
    include_directories(${spdlog_INCLUDE_DIRS})
    message(STATUS "spdlog include directories: ${spdlog_INCLUDE_DIRS}")
else ()
    message(FATAL_ERROR "spdlog not found")
endif ()

set(SOURCES
        ${CMAKE_SOURCE_DIR}/crypto/src/aes.cpp
        ${CMAKE_SOURCE_DIR}/crypto/inc/aes.hpp
        ${CMAKE_SOURCE_DIR}/crypto/src/rsa.cpp
        ${CMAKE_SOURCE_DIR}/crypto/inc/rsa.hpp
        ${CMAKE_SOURCE_DIR}/crypto/src/util.cpp
        ${CMAKE_SOURCE_DIR}/crypto/inc/util.hpp

        ${CMAKE_SOURCE_DIR}/network/src/node.cpp
        ${CMAKE_SOURCE_DIR}/network/inc/node.hpp

        ${CMAKE_SOURCE_DIR}/network/src/connection.cpp
        ${CMAKE_SOURCE_DIR}/network/inc/connection.hpp

        ${CMAKE_SOURCE_DIR}/network/src/message.cpp
        ${CMAKE_SOURCE_DIR}/network/inc/message.hpp

        ${CMAKE_SOURCE_DIR}/network/inc/message_queue.hpp

        ${CMAKE_SOURCE_DIR}/util/inc/util.hpp

        ${CMAKE_SOURCE_DIR}/include/cp2p.hpp

    CACHE INTERNAL ""
)

set(INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/crypto/inc
        ${CMAKE_SOURCE_DIR}/network/inc

    CACHE INTERNAL ""
)

add_executable(${PROJECT_NAME}
        ${CMAKE_SOURCE_DIR}/main.cpp

        ${SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only
)

add_subdirectory(include)
add_subdirectory(test)
