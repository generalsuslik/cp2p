//
// Created by generalsuslik on 22.01.25.
//

#include <iostream>

#include "yahanet/inc/Peer.hpp"

int main(int argc, char* argv[]) { // my_port, send_port
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <your port> <receiver port>" << std::endl;
    }

    const unsigned short listening_port = static_cast<unsigned short>(std::stoi(argv[1]));
    const unsigned short target_port = static_cast<unsigned short>(std::stoi(argv[2]));

    try {
        asio::io_context io_context;

        udp::socket socket(io_context);
        udp::endpoint local_endpoint(udp::v4(), listening_port);
        socket.open(local_endpoint.protocol());
        socket.bind(local_endpoint);

        udp::endpoint target_endpoint(asio::ip::address::from_string("127.0.0.1"), target_port);

        std::array<char, 1024> recv_buffer{};
        udp::endpoint sender_endpoint;

        std::thread receiver_thread([&sender_endpoint, &socket, &recv_buffer] -> void {
            while (true) {
                boost::system::error_code ec;
                const std::size_t bytes_received = socket.receive_from(
                    asio::buffer(recv_buffer), sender_endpoint, 0, ec
                    );

                if (ec) {
                    std::cerr << "Receive failed: " << ec.message() << std::endl;
                } else {
                    std::string message(recv_buffer.data(), bytes_received);
                    std::cout << "Received from: " << sender_endpoint << ": " << message << std::endl;
                }
            }
        });

        while (true) {
            std::cout << "Enter message to send or type exit: ";
            std::string message;
            getline(std::cin, message);

            if (message == "exit") {
                break;
            }

            boost::system::error_code ec;
            socket.send_to(asio::buffer(message), target_endpoint, 0, ec);
            if (ec) {
                std::cerr << "Send failed: " << ec.message() << std::endl;
            } else {
                std::cout << "Sent to: " << target_endpoint << ": " << message << std::endl;
            }
        }

        receiver_thread.join();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
