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
        std::uint16_t port_;
        if (argc < 2) {
            host_ = "127.0.0.1";
            port_ = 9000;
        } else {
            host_ = "127.0.0.1";
            port_ = std::atoi(argv[1]);
        }

        if (argc >= 3) {
            host_ = argv[1];
            port_ = std::atoi(argv[2]);
        }

        cp2p::Node node(host_, port_);
        std::cout << "Do you want to be a hub?" << std::endl;
        std::string ans;
        std::cin >> ans;
        if (ans == "y") {
            node.set_hub(true);
        }

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
                std::string command, mode;
                iss >> command >> mode;

                if (mode == "-h") { // hub
                    std::string id;
                    std::string hub_host;
                    std::uint16_t hub_port;

                    iss >> id >> hub_host >> hub_port;
                    node.connect_to(id, hub_host, hub_port);
                } else if (mode == "-ip") { // directly via target's ip
                    std::string target_host;
                    std::uint16_t target_port;
                    iss >> target_host >> target_port;

                    node.connect_to(target_host, target_port);
                } else {
                    std::cout << "Usage: " << argv[0] << "[-h|-ip] [<host>] <port>" << std::endl;
                }
            } else if (line == "exit") {
                node.stop();
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
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}


