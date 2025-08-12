set(TARGET cp2p_network)

set(SOURCES
        ${CMAKE_SOURCE_DIR}/network/node.cpp
        ${CMAKE_SOURCE_DIR}/network/node.hpp

        ${CMAKE_SOURCE_DIR}/network/connection.cpp
        ${CMAKE_SOURCE_DIR}/network/connection.hpp

        ${CMAKE_SOURCE_DIR}/network/message.cpp
        ${CMAKE_SOURCE_DIR}/network/message.hpp

        ${CMAKE_SOURCE_DIR}/network/message_queue.hpp
)

add_subdirectory(proto)

add_library(cp2p_network
        ${SOURCES}
)

target_include_directories(${TARGET}
    PUBLIC
        ${CMAKE_SOURCE_DIR}
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