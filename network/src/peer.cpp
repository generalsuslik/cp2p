//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/peer.hpp"

#include "../../crypto/inc/rsa.hpp"
#include "../../util/inc/util.hpp"

#include <iostream>

namespace cp2p {


    Peer::Peer(asio::io_context& io_context, const uint16_t port)
            : io_context_(io_context)
            , acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {
        std::tie(rsa_public_key_, rsa_private_key_) = rsa::generate_rsa_keys();
        id_ = to_hex(rsa_public_key_.begin(), rsa_public_key_.end());

        accept();
    }

    void Peer::connect_to(const std::string& host, const uint16_t port) {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        auto new_conn = std::make_shared<Connection>(io_context_);
        if (!new_conn->socket().is_open()) {
            std::cerr << "[Peer::connect_to] Error: Socket not open" << std::endl;
            new_conn->socket().open(tcp::v4());
            std::cout << "Opened socket" << std::endl;
        }

        async_connect(new_conn->socket(), endpoints,
            [this, new_conn, host, port](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) {
                    std::cerr << "[Peer::connect_to] " << ec.message() << std::endl;
                    return;
                }

                const std::string id = host + ":" + std::to_string(port);

                {
                    std::lock_guard lock(mutex_);
                    connections_[id] = new_conn;
                }

                std::cout << "[Peer::accept] Connected to: " << id << std::endl;
                new_conn->start();
            });
    }

    void Peer::broadcast(const Message& message) {
        std::lock_guard lock(mutex_);

        for (const auto& [_, conn] : connections_) {
            conn->deliver(message);
        }
    }

    void Peer::send_message(const std::string& id, const Message& message) {
        std::lock_guard lock(mutex_);
        const auto it = connections_.find(id);
        if (it == connections_.end()) {
            std::cerr << "[Peer::send_message] id: " << id << " not found" << std::endl;
            return;
        }

        it->second->deliver(message);
    }

    void Peer::accept() {
        auto new_conn = std::make_shared<Connection>(io_context_);

        acceptor_.async_accept(new_conn->socket(),
            [this, new_conn](const boost::system::error_code& ec) {
                if (!ec) {
                    const std::string id = new_conn->socket().remote_endpoint().address().to_string() + ":" + std::to_string(new_conn->socket().remote_endpoint().port());

                    {
                        std::lock_guard lock(mutex_);
                        connections_[id] = new_conn;
                    }

                    std::cout << "[Peer::accept] Accepted from: " << id << std::endl;
                    new_conn->start();
                }

                accept();
            });
    }


} // cp2p


