set(TARGET cp2p_network)

set(SOURCES
        ${CMAKE_SOURCE_DIR}/network/src/node.cpp
        ${CMAKE_SOURCE_DIR}/network/inc/node.hpp

        ${CMAKE_SOURCE_DIR}/network/src/connection.cpp
        ${CMAKE_SOURCE_DIR}/network/inc/connection.hpp

        ${CMAKE_SOURCE_DIR}/network/src/message.cpp
        ${CMAKE_SOURCE_DIR}/network/inc/message.hpp

        ${CMAKE_SOURCE_DIR}/network/inc/message_queue.hpp
)

add_library(${TARGET}
        ${SOURCES}
)

target_include_directories(${TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/network/inc
        ${CMAKE_SOURCE_DIR}/crypro/inc
)

target_link_libraries(${TARGET}
    PRIVATE
        Boost::system
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only

        cp2p_crypto
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)