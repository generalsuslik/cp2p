set(TARGET cp2p_network_core)

set(SOURCES
        ${CMAKE_SOURCE_DIR}/network/core/connection.cpp
        ${CMAKE_SOURCE_DIR}/network/core/message.cpp
)

add_subdirectory(proto)

add_library(cp2p_network_core
        ${SOURCES}
)

target_include_directories(${TARGET}
    PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(${TARGET}
    PUBLIC
        Boost::system
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only

        cp2p_crypto
        network_proto
        util
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)