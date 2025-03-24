//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/peer.hpp"

#include "../../crypto/inc/rsa.hpp"

#include <iostream>

#include "../../util/inc/util.hpp"

namespace cp2p {


    Peer::Peer(asio::io_context& io_context, const std::string& host, const uint16_t port)
            : io_context_(io_context)
            , acceptor_(io_context_) {
        std::tie(rsa_public_key_, rsa_private_key_) = rsa::generate_rsa_keys();

        const tcp::endpoint ep(asio::ip::make_address(host), port);
        acceptor_.open(ep.protocol());

        boost::system::error_code ec;
        ec = acceptor_.bind(ep, ec);
        if (ec) {
            std::cerr << ec.message() << std::endl;
        }
        acceptor_.listen();

        id_ = std::to_string(std::hash<std::string>{}(to_hex(rsa_public_key_.begin(), rsa_public_key_.end())));

        std::cout << "id_: " << id_ << std::endl;

        accept();
    }

    void Peer::connect_to(const std::string& host, const uint16_t port) {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        auto new_conn = std::make_shared<Connection>(io_context_);
        if (!new_conn->socket().is_open()) {
            new_conn->socket().open(tcp::v4());
            std::cout << "[Peer::connect_to] Opened socket" << std::endl;
        }

        async_connect(new_conn->socket(), endpoints,
            [this, new_conn](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) {
                    std::cerr << "[Peer::connect_to] error: " << ec.message() << std::endl;
                    return;
                }

                const Message handshake(id_, MessageType::HANDSHAKE);

                new_conn->connect(handshake, [this, new_conn](const std::shared_ptr<Message>& msg) {
                    const std::string id = msg->body();
                    std::cout << "id: " << id << std::endl;

                    new_conn->set_remote_id(id);

                    {
                        std::unique_lock lock(mutex_);
                        connections_[id] = new_conn;
                    }

                    new_conn->start();
                    std::cout << "Started" << std::endl;
                });
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

    std::vector<std::shared_ptr<Connection>> Peer::get_connections() {
        std::vector<std::shared_ptr<Connection>> res;
        for (const auto& [_, conn] : connections_) {
            res.push_back(conn);
        }

        return res;
    }

    void Peer::accept() {
        auto new_conn = std::make_shared<Connection>(io_context_);

        acceptor_.async_accept(new_conn->socket(),
            [this, new_conn](const boost::system::error_code& ec) {
                if (!ec) {
                    new_conn->accept([this, new_conn](const std::shared_ptr<Message>& msg){
                        new_conn->set_remote_id(msg->body());

                        {
                            std::lock_guard lock(mutex_);
                            connections_[new_conn->get_remote_id()] = new_conn;
                        }

                        std::cout << "[Peer::accept] Accepted from: " << new_conn->get_remote_id() << std::endl;
                        new_conn->start();

                        const Message approve(id_, MessageType::APPROVE);
                        new_conn->deliver(approve);
                    });
                }

                accept();
            });
    }

    std::string Peer::get_ip() const {
        try {
            tcp::resolver resolver(io_context_);
            const tcp::resolver::results_type endpoints = resolver.resolve(asio::ip::host_name(), "");

            for (const auto& ep : endpoints) {
                const auto addr = ep.endpoint().address();
                if (addr.is_v4() && addr.to_string().find("127.") != 0 && addr.to_string() != "0.0.0.0") {
                    return addr.to_string();
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[Peer::get_ip] " << e.what() << std::endl;
        }

        return "0.0.0.0";
    }



} // cp2p


