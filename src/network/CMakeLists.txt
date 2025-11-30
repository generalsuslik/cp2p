set(TARGET cp2p_network)

set(SOURCES
        ${CMAKE_SOURCE_DIR}/src/network/node.cpp
        ${CMAKE_SOURCE_DIR}/src/network/connection.cpp
        ${CMAKE_SOURCE_DIR}/src/network/message.cpp
)

add_subdirectory(proto)

add_library(cp2p_network
        ${SOURCES}
)

target_include_directories(${TARGET}
    PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(${TARGET}
    PRIVATE
        Boost::system
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only

        cp2p_crypto
        network_proto
        util
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)