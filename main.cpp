//
// Created by generalsuslik on 22.01.25.
//

#include "inc/peer.hpp"

#include <boost/asio.hpp>

#include <iostream>

namespace asio = boost::asio;

void cli_send(cp2p::Peer& peer) {
    for (;;) {
        std::string message;
        std::getline(std::cin, message);
        if (message == "exit") {
            return;
        }
        peer.send_message(message);
    }
}

int main(const int argc, char* argv[]) {
    using tcp = asio::ip::tcp;

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <listening_port> <target_port>" << std::endl;
        return 1;
    }

    const uint16_t listening_port = std::stoi(argv[1]);
    const uint16_t target_port = std::stoi(argv[2]);
    const tcp::endpoint endpoint(asio::ip::address::from_string("127.0.0.1"), target_port);

    cp2p::Peer peer(listening_port);
    peer.start();
    peer.connect(endpoint);

    peer.set_message_callback([](const std::string& message) {
       std::cout << "Received: " << message << std::endl;
    });

    // std::thread send_thread(cli_send, std::ref(peer));
    std::thread send_thread([&peer]{
        for (;;) {
            std::string message;
            std::getline(std::cin, message);
            if (message == "exit") {
                break;
            }
            peer.send_message(message);
        }
    });

    send_thread.join();

    return 0;
}
