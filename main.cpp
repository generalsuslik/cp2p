//
// Created by generalsuslik on 22.01.25.
//

#include "network/inc/connection.hpp"
#include "network/inc/message.hpp"
#include "network/inc/node.hpp"

#include <iostream>
#include <cstdint>

int main(const int argc, char* argv[]) {
    try {
        std::string host_;
        std::string port_;
        if (argc < 2) {
            host_ = "127.0.0.1";
            port_ = "9000";
        } else {
            host_ = "127.0.0.1";
            port_ = argv[1];
        }

        boost::asio::io_context io_context;

        if (argc >= 3) {
            host_ = argv[1];
            port_ = argv[2];
        }

        cp2p::Node peer(io_context, host_, std::atoi(port_.c_str()));

        std::thread io_thread([&io_context] {
            io_context.run();
        });

        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            if (line.starts_with("send ")) {
                std::istringstream iss(line);
                std::string command, id, message;
                iss >> command >> id;

                std::getline(iss >> std::ws, message);

                iss.clear();

                cp2p::Message msg(message);
                peer.send_message(id, msg);
            } else if (line.starts_with("connect ")) {
                std::istringstream iss(line);
                std::string command, host;
                uint16_t port;
                iss >> command >> host >> port;

                peer.connect_to(host, port);

            } else if (line == "exit") {
                break;
            } else if (line == "lc") {
                auto conns = peer.get_connections();
                for (const auto& conn : conns) {
                    std::cout << conn->get_remote_id() << std::endl;
                }
            } else {
                cp2p::Message msg(line);
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


