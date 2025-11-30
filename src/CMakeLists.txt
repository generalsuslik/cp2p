set(TARGET cp2p)

add_library(cp2p INTERFACE)

add_subdirectory(crypto)
add_subdirectory(network)
add_subdirectory(util)

target_include_directories(cp2p INTERFACE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/network
    ${CMAKE_SOURCE_DIR}/util
)

target_link_libraries(cp2p INTERFACE
    cp2p_application
    cp2p_crypto
    cp2p_network
    ${Protobuf_LIBRARIES}
)

