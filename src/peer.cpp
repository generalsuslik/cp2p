//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/peer.hpp"

#include <iostream>
#include <string>

Peer::Peer(const uint16_t port)
    : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {}

void Peer::start() {
    accept();
    std::thread([this] {
        io_context_.run();
    }).detach();
}

void Peer::connect(const tcp::endpoint& endpoint) {
    auto socket = std::make_shared<tcp::socket>(io_context_);

    socket->async_connect(endpoint,
        [this, endpoint, socket](const boost::system::error_code& ec) {
            if (!ec) {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_.push_back(socket);
                read(socket);
                std::cout << "Connected to peer: " << endpoint.address().to_string() << ":" << endpoint.port() << std::endl;
            } else {
                std::cerr << "[Peer::connect] Connection failed: " << ec.message() << std::endl;
            }
        });
}

void Peer::send_message(const std::string& message) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (auto& socket : connections_) {
        async_write(
            *socket,
            asio::buffer(message + "\n"),
            [](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::send_message] Failed to send message: " << ec.message() << std::endl;
                }
            });
    }
}

void Peer::accept() {
    auto socket = std::make_shared<tcp::socket>(io_context_);
    acceptor_.async_accept(*socket,
        [this, socket](const boost::system::error_code& ec) {
            if (!ec) {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_.push_back(socket);
                read(socket);
            }
            accept();
        });
}

void Peer::read(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<asio::streambuf>();
    async_read_until(
        *socket, *buffer, '\n',
        [this, buffer, socket](const boost::system::error_code& error, std::size_t) {
            if (!error) {
                std::istream stream(buffer.get());
                std::string message;
                std::getline(stream, message);
                if (!message.empty()) {
                    std::cout << "[" << socket->local_endpoint().address().to_string() << ":"
                            << socket->local_endpoint().port() << "]: "
                                << message << std::endl;
                }
                read(socket);
            } else {
                std::cerr << "Read error: " << error.message() << "\n";
            }
        });
}


