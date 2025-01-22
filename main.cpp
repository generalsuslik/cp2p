//
// Created by generalsuslik on 22.01.25.
//

#include <iostream>

#include "inc/Peer.hpp"

int main() {
    try {
        asio::io_context io_context;

        Peer peer(io_context, 12345);

        std::thread sender_thread([&io_context]() {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            const udp::endpoint target(asio::ip::address::from_string("127.0.0.1"), 12345);

            Peer sender(io_context, 12346);
            sender.send_message("asdasd, 52", target);
        });

        io_context.run();
        sender_thread.join();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
