# CMakeLists.txt for shared library

set(LIBRARY cp2p)

add_library(${LIBRARY}
    SHARED
        ${SOURCES}
)

target_link_libraries(${LIBRARY}
        PRIVATE
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        spdlog::spdlog_header_only

        cp2p_crypto
        сp2p_network
        util
)
