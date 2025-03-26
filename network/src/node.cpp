//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/node.hpp"

#include "../../crypto/inc/common.hpp"
#include "../../crypto/inc/rsa.hpp"

#include <spdlog/spdlog.h>

#include <iostream>

namespace cp2p {


    Node::Node(asio::io_context& io_context, const std::string& host, const uint16_t port, const bool is_hub)
            : io_context_(io_context)
            , acceptor_(io_context_)
            , is_hub_(is_hub)
            , host_(host)
            , port_(port) {
        std::tie(rsa_public_key_, rsa_private_key_) = rsa::generate_rsa_keys();

        const tcp::endpoint ep(asio::ip::make_address(host), port);
        acceptor_.open(ep.protocol());

        boost::system::error_code ec;
        ec = acceptor_.bind(ep, ec);
        if (ec) {
            std::cerr << ec.message() << std::endl;
        }
        acceptor_.listen();

        id_ = host + ":" + std::to_string(port);
        
        spdlog::info("Initialized with id: {}", id_);

        if (is_hub_) {
            inform_server("127.0.0.1", 8080);
            spdlog::info("Hub initialized; Sent id to remote server");
        }

        accept();
    }

    void Node::connect_to(const std::string& host, const uint16_t port) {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        auto new_conn = std::make_shared<Connection>(io_context_);
        if (!new_conn->socket().is_open()) {
            new_conn->socket().open(tcp::v4());
            spdlog::info("[Node::connect_to] Opened socket");
        }

        async_connect(new_conn->socket(), endpoints,
            [this, new_conn](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) {
                    spdlog::error("[Node::connect_to] Error {}", ec.message());
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

    void Node::broadcast(const Message& message) {
        std::lock_guard lock(mutex_);

        for (const auto& [_, conn] : connections_) {
            conn->deliver(message);
        }
    }

    void Node::send_message(const std::string& id, const Message& message) {
        std::lock_guard lock(mutex_);
        const auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Node::send_message] id: {} not found", id);
            return;
        }

        it->second->deliver(message);
    }

    std::string Node::get_id() const {
        return id_;
    }

    std::vector<std::shared_ptr<Connection>> Node::get_connections() {
        std::vector<std::shared_ptr<Connection>> res;
        for (const auto& [_, conn] : connections_) {
            res.push_back(conn);
        }

        return res;
    }

    void Node::accept() {
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

                        spdlog::info("[Node::accept] Accepted from {}", new_conn->get_remote_id());
                        new_conn->start();

                        const Message approve(id_, MessageType::APPROVE);
                        new_conn->deliver(approve);
                    });
                }

                accept();
            });
    }

    void Node::inform_server(const std::string& host, const std::uint16_t port) const {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        tcp::socket socket(io_context_);
        asio::connect(socket, endpoints);
        {
            write(socket, asio::buffer(id_));
            socket.close();
        }
    }

    std::string Node::get_ip() const {
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
            spdlog::error("[Node::get_ip] {}", e.what());
        }

        return "0.0.0.0";
    }


} // cp2p


