//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/node.hpp"

#include "../../crypto/inc/rsa.hpp"
#include "../../util/inc/util.hpp"

#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <iostream>
#include <utility>

namespace cp2p {

    namespace beast = boost::beast;
    namespace http = beast::http;

    using json = nlohmann::json;

    Node::Node() : Node("0.0.0.0", 9000) {}

    Node::Node(std::string host, const std::uint16_t port, const bool is_hub)
            : acceptor_(io_context_)
            , is_hub_(is_hub)
            , is_active_(true)
            , host_(std::move(host))
            , port_(port) {
        std::tie(rsa_public_key_, rsa_private_key_) = rsa::generate_rsa_keys();

        const tcp::endpoint ep(asio::ip::make_address(host_), port_);
        acceptor_.open(ep.protocol());

        boost::system::error_code ec;
        ec = acceptor_.bind(ep, ec);
        if (ec) {
            std::cerr << ec.message() << std::endl;
        }
        acceptor_.listen();

        id_ = std::to_string(std::hash<std::string>{}(to_hex(rsa_public_key_.begin(), rsa_public_key_.end())));

        spdlog::info("Initialized with id: {}", id_);

        accept();
        run();
    }

    Node::~Node() {
        stop();
    }

    void Node::run() {
        if (io_thread_.joinable()) {
            return;
        }

        io_thread_ = std::thread([this] {
            io_context_.run();
        });
    }

    void Node::stop() {
        is_active_ = false;

        disconnect_from_all([this] {
            acceptor_.close();
            io_context_.stop();

            if (io_thread_.joinable()) {
                io_thread_.join();
            }
        });
    }

    void Node::connect_to(const std::string&, const std::string& hub_host, const std::uint16_t hub_port) {
        json hub = get_hub_data(hub_host, hub_port);

        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(
            hub["host"].get<std::string>(),
            hub["port"].get<std::string>()
        );

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

                    new_conn->set_remote_id(id);

                    {
                        std::lock_guard lock(mutex_);
                        connections_[id] = new_conn;
                    }

                    receive(new_conn);
                    spdlog::info("[Node::connect_to] Connected to {}", id);
                });
            });
    }

    void Node::connect_to(const std::string& host, const std::uint16_t port) {
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
                    // processing ACCEPT msg
                    const std::string id = msg->body();

                    new_conn->set_remote_id(id);

                    {
                        std::lock_guard lock(mutex_);
                        connections_[id] = new_conn;
                    }

                    receive(new_conn);
                    spdlog::info("[Node::connect_to] Connected to {}", id);
                });
            });
    }

    void Node::broadcast(const Message& message) {
        std::lock_guard lock(mutex_);

        for (const auto& conn : connections_ | std::views::values) {
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

    void Node::disconnect_from_all(const std::function<void()>& on_success) {
        if (connections_.empty()) {
            return;
        }

        for (const auto& id : connections_ | std::views::keys) {
            disconnect(id);
        }

        spdlog::info("Disconnected from all connected nodes");
        on_success();
    }

    void Node::disconnect(const std::string& id) {
        if (!connections_.contains(id)) {
            spdlog::error("[Node::disconnect] id: {} not found", id);
            return;
        }

        const Message disconnect_message(id_, MessageType::DISCONNECT);

        spdlog::info("[Node::disconnect] Disconnecting...");
        connections_[id]->disconnect(disconnect_message, [this, &id] {
            connections_[id]->close();
            connections_.erase(id);
        });
    }

    void Node::remove_connection(const std::string& id) {
        std::lock_guard lock(mutex_);
        const auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Node::remove_connection] id: {} not found", id);
        }

        connections_.erase(it);
    }

    std::string Node::get_id() const {
        return id_;
    }

    std::vector<std::shared_ptr<Connection>> Node::get_connections() {
        std::vector<std::shared_ptr<Connection>> res;
        for (const auto& conn : connections_ | std::views::values) {
            res.push_back(conn);
        }

        return res;
    }

    void Node::set_hub(const bool val) {
        is_hub_ = val;
        if (is_hub_) {
            inform_server("127.0.0.1", 8080);
        }
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

                        const Message approve(id_, MessageType::ACCEPT);
                        new_conn->deliver(approve);

                        spdlog::info("[Node::accept] Accepted from {}", new_conn->get_remote_id());
                        receive(new_conn);
                   });
                }

                accept();
           });
    }

    void Node::receive(const std::shared_ptr<Connection>& conn) {
        conn->start([this, conn](const std::shared_ptr<Message>& msg) {
            if (msg->type() == MessageType::DISCONNECT) {
                spdlog::info("[Node::receive] Disconnecting...");
                std::cout << "ASD: " << msg->body() << std::endl;
                connections_.erase(msg->body());
            } else if (msg->type() == MessageType::TEXT) {
                spdlog::info("Received [{}]: {}", conn->get_remote_id(), std::string(msg->body(), msg->body_length()));
            }
        });
    }

    void Node::inform_server(const std::string& host, const std::uint16_t port) {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        beast::tcp_stream stream(io_context_);
        stream.connect(endpoints);

        const json payload = {
            { "id", id_ },
            { "host", host_ },
            { "port", port_ },
        };
        spdlog::info("Payload dump: {}", payload.dump());

        http::request<http::string_body> req(http::verb::post, "/", 11);
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/json");
        req.body() = payload.dump();
        req.prepare_payload();

        http::write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        if (res.result() == http::status::temporary_redirect || res.result() == http::status::found) {
            auto location = res[http::field::location];
            spdlog::info("[Redirecting to] {}", location);

            // Extract new path from the location header
            std::string new_path = location.substr(location.find("/", 7));  // Remove "http://127.0.0.1:8080"

            req.target(new_path);
            buffer.consume(buffer.size());  // Clear buffer
            http::read(stream, buffer, res);
        }

        beast::error_code ec;
        ec = stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        if (ec && ec != beast::errc::not_connected) {
            spdlog::error("[Node::inform_server] socket shutdown failed {}", ec.message());
        }
    }

    json Node::get_hub_data(const std::string& host, const std::uint16_t port) {
        tcp::resolver resolver(io_context_);
        beast::tcp_stream stream(io_context_);

        const auto endpoints = resolver.resolve(host, std::to_string(port));
        stream.connect(endpoints);

        http::request<http::string_body> req(http::verb::get, "/connect/", 11);\
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        if (res.result() == http::status::temporary_redirect || res.result() == http::status::found) {
            auto location = res[http::field::location];
            spdlog::info("[Redirecting to] {}", location);

            // Extract new path from the location header
            std::string new_path = location.substr(location.find("/", 7));  // Remove "http://127.0.0.1:8080"

            req.target(new_path);
            buffer.consume(buffer.size());  // Clear buffer
            http::write(stream, req);
            http::read(stream, buffer, res);
        }

        json response_json = json::parse(res.body());
        if (response_json.contains("id")) {
            return response_json;
        }

        beast::error_code ec;
        ec = stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        if (ec && ec != beast::errc::not_connected) {
            spdlog::error("[Node::get_hub_data] Error {}", ec.message());
        }

        return {};
    }

    std::string Node::get_ip() {
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
            spdlog::error("[Node::get_ip] Error {}", e.what());
        }

        return "0.0.0.0";
    }


} // cp2p


