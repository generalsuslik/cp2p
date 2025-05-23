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
        crypto/src/aes.cpp
        crypto/inc/aes.hpp
        crypto/src/rsa.cpp
        crypto/inc/rsa.hpp
        crypto/src/util.cpp
        crypto/inc/util.hpp

        network/src/node.cpp
        network/inc/node.hpp

        network/src/connection.cpp
        network/inc/connection.hpp

        network/src/message.cpp
        network/inc/message.hpp

        network/inc/message_queue.hpp

        util/inc/util.hpp

        include/cp2p.hpp
)

add_executable(${PROJECT_NAME}
        main.cpp

        ${SOURCES}
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only
)

find_package(GTest REQUIRED)
include(GoogleTest)

find_package(fmt REQUIRED)

enable_testing()

add_executable(tests
        ${SOURCES}

        test/crypto/test_aes.cpp
        test/crypto/test_aes_rsa_integrity.cpp
        test/test_util/test_util.cpp
        test/test_util/test_util.hpp
        test/network/test_message.cpp
        test/crypto/test_rsa.cpp
        test/crypto/test_util.cpp
)
target_link_libraries(tests
    PRIVATE
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt
)

target_compile_options(tests PRIVATE -g)

gtest_discover_tests(tests)

#---Library stuff---#
set(LIBRARY cp2p)
add_library(${LIBRARY}
    SHARED
        ${SOURCES}
)

target_include_directories(${LIBRARY}
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${LIBRARY}
    PRIVATE
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only
)
