//
// Created by generalsuslik on 22.01.25.
//

#include "inc/peer.hpp"

#include <iostream>

void cli_send(Peer& peer) {
    for (;;) {
        std::string message;
        std::getline(std::cin, message);
        if (message == "exit") {
            return;
        }
        peer.send_message(message);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <listening_port> [<target_port>]" << std::endl;
        return 1;
    }

    const uint16_t listening_port = std::stoi(argv[1]);
    const uint16_t target_port = std::stoi(argv[2]);
    const tcp::endpoint endpoint(asio::ip::address::from_string("127.0.0.1"), target_port);

    Peer peer(listening_port);
    peer.start();
    peer.connect(endpoint);

    std::thread send_thread(cli_send, std::ref(peer));

    send_thread.join();

    return 0;
}
