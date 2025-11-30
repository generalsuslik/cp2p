set(TARGET cp2p_build)

add_executable(${TARGET}
        ${CMAKE_SOURCE_DIR}/example/main.cpp
)

add_subdirectory(application)

target_link_libraries(${TARGET}
    PRIVATE
        cp2p_application
        cp2p
        ${Protobuf_LIBRARIES}
)