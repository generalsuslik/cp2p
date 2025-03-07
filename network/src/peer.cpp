//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/peer.hpp"

#include <iostream>

namespace cp2p {

    Peer::Peer(asio::io_context& io_context, const uint16_t port)
            : io_context_(io_context)
            , acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {
        accept();
    }

    void Peer::connect_to(const std::string& host, const uint16_t port) {
        tcp::resolver resolver(io_context_);
        auto endpoints = resolver.resolve(host, std::to_string(port));

        auto new_conn = std::make_shared<Connection>(io_context_);
        async_connect(new_conn->socket(), endpoints,
            [this, new_conn](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) {
                    std::cerr << "[Peer::connect_to] " << ec.message() << "\n";
                    return;
                }

                {
                    std::lock_guard lock(mutex_);
                    connections_.push_back(new_conn);
                }

                new_conn->start();
            });
    }

    void Peer::broadcast(const Message& message) {
        std::lock_guard lock(mutex_);

        for (const auto& conn : connections_) {
            conn->deliver(message);
        }
    }

    void Peer::accept() {
        auto new_conn = std::make_shared<Connection>(io_context_);

        acceptor_.async_accept(new_conn->socket(),
            [this, new_conn](const boost::system::error_code& ec) {
                if (!ec) {
                    {
                        std::lock_guard lock(mutex_);
                        connections_.push_back(new_conn);
                    }
                    new_conn->start();
                }

                accept();
            });
    }


} // cp2p


