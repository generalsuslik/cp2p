//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/Peer.hpp"

#include <iostream>
#include <string>

Peer::Peer(asio::io_context& io_context, const unsigned short port)
        : socket_(io_context, udp::endpoint(asio::ip::udp::v4(), port)) {
    receive();
}

void Peer::send_message(const std::string& message, const udp::endpoint& target) {
    socket_.async_send_to(
        asio::buffer(message), target,
        [](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                std::cerr << "Send failed: " << ec.message() << std::endl;
            }
        });
}

void Peer::receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](const boost::system::error_code& ec, const std::size_t length) {
            if (!ec) {
                const std::string message(recv_buffer_.begin(), length);
                std::cout << "Received from " << remote_endpoint_ << ": " << message << std::endl;

                receive();
            }
        });
}


