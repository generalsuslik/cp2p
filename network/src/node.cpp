//
// Created by generalsuslik on 22.01.25.
//

#include "node.hpp"

#include "crypto/inc/aes.hpp"
#include "crypto/inc/util.hpp"
#include "util/inc/util.hpp"

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

    Node::Node(const std::string& host, const std::uint16_t port, const bool is_hub)
            : acceptor_(io_context_)
            , is_hub_(is_hub)
            , is_active_(false)
            , identity_(std::make_shared<NodeIdentity>()) {
        identity_->id = std::move(generate_id(identity_->rsa.to_public_string()));
        std::tie(identity_->host, identity_->port) = std::tie(host, port);

        const tcp::endpoint ep(asio::ip::make_address(identity_->host), identity_->port);
        acceptor_.open(ep.protocol());

        boost::system::error_code ec;
        ec = acceptor_.bind(ep, ec);
        if (ec) {
            std::cerr << ec.message() << std::endl;
        }
        acceptor_.listen();

        spdlog::info("Initialized with id: {}", get_id());
    }

    Node::~Node() {
        stop();
    }

    /**
     * @brief Runs the node by creating a thread and running io_context in it
     */
    void Node::run() {
        if (io_thread_.joinable() && is_active_) {
            return;
        }

        is_active_ = true;

        io_thread_ = std::thread([this] {
            io_context_.run();
        });

        accept();
    }

    /**
     * @brief Stops the node by stopping the io_context and joining the thread
     *
     * Also, it sends a disconnect request to the hub's server if is_hub is set to true
     */
    void Node::stop() {
        if (!is_active_) {
            return;
        }

        is_active_ = false;
        if (is_hub_) {
            disconnect_from_server("127.0.0.1", 8080);
            is_hub_ = false;
        }

        disconnect_from_all([this] {
            acceptor_.close();
            io_context_.stop();

            if (io_thread_.joinable()) {
                io_thread_.join();
            }
        });
    }

    /**
     * @brief Connects to target_id via hub's hub_host & hub's hub_port
     *
     * @param target_id id to connect to
     * @param server_host host of the node that will be an intermediate
     * @param server_port port of the node that will be an intermediate
     */
    void Node::connect_to(const std::string& target_id, const std::string& server_host, const std::uint16_t server_port) {
        json hub = get_hub_data(server_host, server_port);

        const std::string hub_id = hub["node_id"].get<std::string>();
        const std::string hub_host = hub["host"].get<std::string>();
        const std::uint16_t hub_port = hub["port"].get<std::uint16_t>();

        connect_to(hub_host, hub_port, [this, hub_id, target_id] {
            const Message search_node_message(target_id, MessageType::SEARCH);
            do_send_message(hub_id, search_node_message);
        });
    }

    /**
     * @brief Connects directly to node host:port
     *
     * @param host node-to-connect-to's host
     * @param port node-to-connect-to's port
     * @param on_success just a callback to be executed right after connection (maybe nullptr)
     */
    void Node::connect_to(const std::string& host, const std::uint16_t port, const std::function<void()>& on_success) {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        auto new_conn = std::make_shared<Connection>(io_context_);
        if (!new_conn->socket().is_open()) {
            new_conn->socket().open(tcp::v4());
            spdlog::info("[Node::connect_to] Opened socket");
        }

        async_connect(new_conn->socket(), endpoints,
            [this, new_conn, on_success](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (ec) {
                    spdlog::error("[Node::connect_to] Error {}", ec.message());
                    return;
                }

                const Message handshake(get_id(), MessageType::HANDSHAKE);

                new_conn->connect(handshake,
                        [this, new_conn, on_success](const std::shared_ptr<Message>& msg) {
                    // processing ACCEPT msg
                    const std::string id = msg->body();

                    new_conn->set_remote_id(id);

                    {
                        std::lock_guard lock(mutex_);
                        connections_[id] = new_conn;
                    }

                    receive(new_conn);
                    spdlog::info("[Node::connect_to] Connected to {}", id);

                    if (on_success) {
                        on_success();
                    }
                });
            });
    }

    /**
     * @brief Sends a message to all connected nodes
     *
     * @param message message to send
     */
    void Node::broadcast(const Message& message) {
        std::lock_guard lock(mutex_);

        for (const auto& conn : connections_ | std::views::values) {
            conn->deliver(message);
        }
    }

    void Node::send_message(const std::string& id, const std::string& message) {
        const Message msg(message);
        do_send_message(id, msg);
    }

    // void Node::send_message(const std::string& id, const Message& message) {
    //     // now we have to encrypt the message before sending it
    //
    //     if (message.type() != MessageType::TEXT) {
    //         spdlog::error("[Node::send_message] message type is not TEXT");
    //         return;
    //     }
    //
    //     const std::string& message_body = message.body();
    //     const auto& [aes_key, aes_iv] = aes::generate_aes_key_iv();
    //     const auto& encrypted_body = aes::aes_encrypt(message_body, aes_key, aes_iv);
    //
    //     const auto& encrypted_aes_key = rsa::RSAKeyPair::encrypt(aes_key.begin(), aes_key.end());
    //     const auto& encrypted_aes_iv = rsa::RSAKeyPair::encrypt(aes_iv.begin(), aes_iv.end());
    // }

    /**
     * @brief Sends message to node {id}
     *
     * @param id node-to-send-a-message's id
     * @param message message to send
     */
    void Node::do_send_message(const std::string& id, const Message& message) {
        std::lock_guard lock(mutex_);

        const auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Node::send_message] id: {} not found", id);
            return;
        }

        it->second->deliver(message);
    }

    /**
     * @brief Sends message to node {id}
     *
     * @param id node-to-send-message's id
     * @param message message to send
     * @param on_success callback called after a message is sent
     */
    void Node::do_send_message(const std::string& id, const Message& message, const std::function<void()>& on_success) {
        std::lock_guard lock(mutex_);

        const auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Node::send_message] id: {} not found", id);
            return;
        }

        it->second->deliver(message);
        on_success();
    }

    /**
     * @brief Disconnects from all connected nodes
     */
    void Node::disconnect_from_all(const std::function<void()>& on_success) {
        std::lock_guard lock(mutex_);

        if (!connections_.empty()) {
            for (const auto& id : connections_ | std::views::keys) {
                disconnect(id);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            connections_.clear();

            spdlog::info("Disconnected from all connected nodes");
        }

        on_success();
    }

    /**
     * @brief Disconnects from the node with id_ == id
     *
     * @param id node to disconnect 's id
     */
    void Node::disconnect(const std::string& id) {
        if (!connections_.contains(id)) {
            spdlog::error("[Node::disconnect] id: {} not found", id);
            return;
        }

        const Message disconnect_message(get_id(), MessageType::DISCONNECT);

        spdlog::info("[Node::disconnect] Disconnecting...");
        connections_[id]->disconnect(disconnect_message, [this, &id] {
            connections_[id]->close();
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

    /**
     * @brief Returns self id
     */
    Node::ID Node::get_id() const {
        return identity_->id;
    }

    /**
     * @brief Returns vector of all the node's connections
     */
    std::vector<std::shared_ptr<Connection>> Node::get_connections() {
        std::vector<std::shared_ptr<Connection>> res;
        for (const auto& conn : connections_ | std::views::values) {
            res.push_back(conn);
        }

        return res;
    }

    /**
     * @brief sets is_hub value to val
     *
     * @param val boolean to set for is_hub
     */
    void Node::set_hub(const bool val) {
        is_hub_ = val;

        if (is_hub_) {
            connect_to_server("127.0.0.1", 8080);
        } else {
            disconnect_from_server("127.0.0.1", 8080);
        }
    }

    Node::ID Node::generate_id(const std::string& public_key) {
        return crypto::md5_hash(public_key);
    }

    /**
     * @brief Accepts incoming connections \n
     * method is called from the constructor \n\n
     *
     * Creates a new Connection object
     */
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

                        const Message approve(get_id(), MessageType::ACCEPT);
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
                const std::string id = msg->body();

                connections_[id]->close();
                remove_connection(id);

                spdlog::info("[Node::receive] Disconnected from {}", id);
            } else if (msg->type() == MessageType::TEXT) {
                spdlog::info("Received [{}]: {}", conn->get_remote_id(), std::string(msg->body(), msg->body_length()));
            } else if (msg->type() == MessageType::SEARCH) {
                const json node = search_node(msg->body());
                std::cout << node << std::endl;
            }
        });
    }

    json Node::search_node(const std::string& target_id) {
        // tcp::resolver resolver(io_context_);

        // json res;

        // for (const auto& conn : connections_ | std::views::values) {
        //     if (conn->get_remote_id() == target_id) {
        //         res = conn->get_remote_no
        //     }
        // }
        return nullptr;
    }

    json Node::request_connection(const std::string& target_id) {
        return nullptr;
    }

    void Node::connect_to_server(const std::string& host, const std::uint16_t port) {
        inform_server(host, port, http::verb::post);
    }

    void Node::disconnect_from_server(const std::string& host, const std::uint16_t port) {
        inform_server(host, port, http::verb::delete_);
    }

    /**
     * @brief CALLED ONLY IF is_hub SET TO TRUE \n
     * Sends to server JSON: { "id": ..., "host": ..., "port": ... }
     *
     * @param host server's host
     * @param port server's port
     * @param verb post/delete self info from remote server (http::verb::post / http::verb::delete_)
     */
    void Node::inform_server(const std::string& host, const std::uint16_t port, http::verb verb) {
        tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host, std::to_string(port));

        beast::tcp_stream stream(io_context_);
        stream.connect(endpoints);

        const json payload = {
            { "id", get_id() },
            { "host", identity_->host },
            { "port", identity_->port },
        };

        http::request<http::string_body> req(verb, "/", 11);
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

            // Extract a new path from the location header
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

        ec = stream.socket().close(ec);
        if (ec && ec != beast::errc::not_connected) {
            spdlog::error("[Node::get_hub_data] Error {}", ec.message());
        }
    }

    /**
     * @brief When the method Node::connect_to is called, it tries to receive one of the hub's info,
     * so it could connect to target_id via that hub
     *
     * @param host - server's host
     * @param port - server's port
     * @return hub's info JSON: { "id": ..., "host": ..., "port": ... }
     */
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

            // Extract a new path from the location header
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

        ec = stream.socket().close(ec);
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


