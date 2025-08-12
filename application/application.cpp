//
// Created by generalsuslik on 27.07.25.
//

#include "application.hpp"

#include "network/node.hpp"

#include <iostream>

Application::Application() = default;

void Application::run(int argc, char* argv[]) {
    std::string host_;
    std::uint16_t port_;
    if (argc < 2) {
        host_ = "127.0.0.1";
        port_ = 9000;
    } else {
        host_ = "127.0.0.1";
        port_ = std::stoi(argv[1]);
    }

    if (argc >= 3) {
        host_ = argv[1];
        port_ = std::stoi(argv[2]);
    }

    auto node = std::make_shared<cp2p::Node>(host_, port_);
    node->run();
    // std::cout << "Do you want to be a hub?" << std::endl;
    // std::string ans;
    // std::cin >> ans;
    // if (ans == "y") {
    //     node->set_hub(true);
    // }

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

            node->send_message(id, message);
        } else if (line.starts_with("connect ")) {
            std::istringstream iss(line);
            std::string command;
            std::string mode;
            iss >> command >> mode;

            if (mode == "-h") { // hub
                std::string id;
                std::string hub_host;
                std::uint16_t hub_port;

                iss >> id >> hub_host >> hub_port;
                node->connect_to(id, hub_host, hub_port);
            } else if (mode == "-ip") { // directly via target's ip
                std::string target_host;
                std::uint16_t target_port;
                iss >> target_host >> target_port;

                node->connect_to(target_host, target_port);
            } else {
                std::cout << "Usage: " << argv[0] << "[-h|-ip] [<host>] <port>" << std::endl;
            }
        } else if (line == "exit") {
            node->stop();
            break;
        } else if (line == "lc") {
            const auto& conns = node->get_connections();
            for (const auto& conn : conns) {
                std::cout << conn->get_remote_id() << std::endl;
            }
        } else {
            cp2p::VecMessage msg(cp2p::get_container_from_string(line));
            node->broadcast(msg);
        }
    }
}
