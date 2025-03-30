//
// Created by generalsuslik on 22.01.25.
//

#include "network/inc/connection.hpp"
#include "network/inc/message.hpp"
#include "network/inc/node.hpp"

#include <iostream>
#include <cstdint>
#include <spdlog/spdlog.h>

int main(const int argc, char* argv[]) {
    try {
        std::string host_;
        std::uint16_t port_;
        if (argc < 2) {
            host_ = "127.0.0.1";
            port_ = 9000;
        } else {
            host_ = "127.0.0.1";
            port_ = std::atoi(argv[1]);
        }

        boost::asio::io_context io_context;

        if (argc >= 3) {
            host_ = argv[1];
            port_ = std::atoi(argv[2]);
        }

        cp2p::Node node(io_context, host_, port_);
        std::cout << "Do you want to be a hub? (y/N) ";
        std::string ans;
        std::cin >> ans;
        if (ans == "y") {
            node.set_hub(true);
        }
        std::cout.flush();

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
                node.send_message(id, msg);
            } else if (line.starts_with("connect ")) {
                std::istringstream iss(line);

                std::string command, option; // options: -h # via hub, -ip # via ip address
                iss >> command >> option;
                if (option == "-h") {
                    spdlog::debug("-h");
                    std::string id, host;
                    std::uint16_t port;
                    iss >> id >> host >> port;

                    node.connect_to(id, host, port);
                } else if (option == "-ip") {
                    std::string host;
                    std::uint16_t port;
                    iss >> host >> port;

                    node.connect_to(host, port);
                }
            } else if (line == "exit") {
                // node.disconnect_from_all();
                break;
            } else if (line == "lc") {
                auto conns = node.get_connections();
                for (const auto& conn : conns) {
                    std::cout << conn->get_remote_id() << std::endl;
                }
            } else {
                cp2p::Message msg(line);
                node.broadcast(msg);
            }
        }

        io_context.stop();
        io_thread.join();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}


