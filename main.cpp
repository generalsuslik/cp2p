//
// Created by generalsuslik on 22.01.25.
//

#include "network/inc/peer.hpp"

#include <boost/asio.hpp>

#include <iostream>

namespace asio = boost::asio;

int main(const int argc, char* argv[]) {
    uint16_t listening_port = 9000; // default params
    uint16_t target_port = 9001;

    if (argc == 3) {
        listening_port = std::stoi(argv[1]);
        target_port = std::stoi(argv[2]);
    }

    cp2p::Peer peer(listening_port);

    std::thread receive_thread([&peer, target_port] {
        peer.start();

        peer.set_message_callback([target_port](const std::string& message) {
           std::cout << "Received [127.0.0.1:" << target_port << "]: " << message << std::endl;
        });
    });

    std::thread send_thread([&peer, target_port]{
        peer.connect("localhost", target_port);

        for (;;) {
            std::string message;
            std::getline(std::cin, message);
            if (message == "exit") {
                break;
            }
            peer.send_message(message);
        }
    });

    receive_thread.join();
    send_thread.join();

    return 0;
}



