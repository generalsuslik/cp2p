set(TARGET cp2p_graph)

set(SOURCES
        graph.cpp
)

add_library(cp2p_graph
        ${SOURCES}
)

target_include_directories(${TARGET}
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(${TARGET}
    PRIVATE
        util
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)
