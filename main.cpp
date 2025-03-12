//
// Created by generalsuslik on 22.01.25.
//

#include "network/inc/connection.hpp"
#include "network/inc/message.hpp"
#include "network/inc/peer.hpp"

#include <iostream>
#include <cstdint>

// -------------------------------------------------------------
// Main function
// Usage: p2p_chat <local_port> [remote_host remote_port]
// -------------------------------------------------------------
int main(const int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: p2p_chat <local_port> [remote_host remote_port]" << std::endl;
            return 1;
        }

        boost::asio::io_context io_context;

        cp2p::Peer peer(io_context, std::strtol(argv[1], nullptr, 10));

        if (argc == 4) {
            const std::string remote_host = argv[2];
            const uint16_t remote_port = std::strtol(argv[3], nullptr, 10);
            peer.connect_to(remote_host, remote_port);
        }

        std::thread io_thread([&io_context] {
            io_context.run();
        });

        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            cp2p::Message msg;
            if (line.starts_with("send ")) {
                std::istringstream iss(line);
                std::string command, host, port, message;
                iss >> command >> host >> port >> message;

                iss.clear();

                std::cout << "Entered: " << host << ":" << port << " " << message << std::endl;

                msg.set_body_length(message.size());
                std::memcpy(msg.body(), message.c_str(), msg.body_length());
                msg.encode_header();
                peer.send_message(host + ":" + port, msg);
            } else if (line == "exit") {
                break;
            } else {
                msg.set_body_length(line.size());
                std::memcpy(msg.body(), line.c_str(), msg.body_length());
                msg.encode_header();
                peer.broadcast(msg);
            }
        }

        io_context.stop();
        io_thread.join();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}


