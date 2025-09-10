//
// Created by generalsuslik on 22.01.25.
//

#include "node.hpp"

#include "crypto/util.hpp"
#include "util/util.hpp"

#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <iostream>
#include <utility>

namespace {

    using IDPair = std::pair<cp2p::Node::ID, cp2p::rsa::EVP_PKEY_ptr>;

    template <cp2p::CMessageContainer MessageContainer>
    IDPair parse_handshake_string(const MessageContainer& handshake_data) {
        auto separator_it = std::ranges::find(handshake_data, cp2p::DELIMITER);
        assert(separator_it != handshake_data.end());
        assert(*separator_it == cp2p::DELIMITER);

        std::string id;
        for (auto it = handshake_data.begin(); it != separator_it; ++it) {
            id.push_back(*it);
        }

        const std::vector<std::uint8_t> public_key_data(separator_it + 1, handshake_data.end());

        assert(handshake_data.size() == public_key_data.size() + id.size() + 1);

        return { id, cp2p::rsa::to_public_key(public_key_data) };
    }

} // namespace

namespace cp2p {

    namespace beast = boost::beast;
    namespace http = beast::http;

    using json = nlohmann::json;

    Node::Node() : Node("0.0.0.0", 9000) {}

    Node::Node(const std::string& host, const std::uint16_t port, const bool is_hub)
        : acceptor_(io_context_)
        , is_hub_(is_hub)
        , is_active_(false)
        , identity_(std::make_shared<NodeIdentity>())
    {
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
        if (is_active_) {
            return;
        }

        is_active_ = true;

        for (std::uint32_t i = 0; i < num_workers; ++i) {
            io_workers_.emplace_back([this] {
                io_context_.run();
            });
        }

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

            for (auto& th : io_workers_) {
                if (th.joinable()) {
                    th.join();
                }
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
            auto search_node_message = std::make_shared<VecMessage>(get_container_from_string(target_id), MessageType::SEARCH);
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

                const VecMessage handshake = generate_handshake();

                new_conn->connect(
                    handshake,
                    [this, new_conn, on_success](const MessagePtr& msg) {
                        // processing ACCEPT msg
                        auto [id, pubkey_ptr] = parse_handshake_string(msg->get_message());

                        new_conn->set_remote_id(id);

                        {
                            std::lock_guard lock(mutex_);
                            connections_[id] = new_conn;
                            public_keys_.emplace(id, std::move(pubkey_ptr));
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
    void Node::broadcast(const std::string& message) {
        std::lock_guard lock(mutex_);

        for (const auto& conn : connections_ | std::views::values) {
            send_message(conn->get_remote_id(), message);
        }
    }

    void Node::send_message(const std::string& id, const std::string& message) {
        auto mes = std::make_shared<VecMessage>(get_container_from_string(message));
        encrypt(id, mes);
        do_send_message(id, mes);
    }

    void Node::send_message(const std::string& id, const MessagePtr& message) {
        encrypt(id, message);
        do_send_message(id, message);
    }

    void Node::send_message(const std::string& id, const VecMessage& message, const std::function<void()>& on_success) {
        do_send_message(id, message, on_success);
    }

    /**
     * @brief Sends message to node {id}
     *
     * @param id node-to-send-a-message's id
     * @param message message to send
     */
    void Node::do_send_message(const std::string& id, const MessagePtr& message) {
        const auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Node::send_message] id: {} not found", id);
            return;
        }

        assert(message->is_encrypted());
        it->second->deliver(*message);
    }

    /**
     * @brief Sends message to node {id}
     *
     * @param id node-to-send-message's id
     * @param message message to send
     * @param on_success callback called after a message is sent
     */
    void Node::do_send_message(const std::string& id, const VecMessage& message, const std::function<void()>& on_success) {
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
            connections_.clear();

            spdlog::info("Disconnected from all connected nodes");
        }

        on_success();
    }

    void Node::disconnect_from(const ID& id) {
        std::lock_guard lock(mutex_);

        auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Node::disconnect_from] id: {} not found", id);
            return;
        }

        spdlog::info("[Node::disconnect] Disconnecting from {}...", id);
        it->second->close();
        remove_connection(id, lock);
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
        connections_[id]->close();
    }

    void Node::remove_connection(const std::string& id, const std::lock_guard<std::mutex>& lock) {
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
                    new_conn->accept([this, new_conn](const MessagePtr& msg){

                        auto [id, pubkey_ptr] = parse_handshake_string(msg->get_message());

                        new_conn->set_remote_id(id);

                        {
                            std::lock_guard lock(mutex_);
                            connections_[new_conn->get_remote_id()] = new_conn;
                            public_keys_.emplace(new_conn->get_remote_id(), std::move(pubkey_ptr));
                        }

                        const VecMessage approve(get_container_from_string(generate_handshake_string()), MessageType::ACCEPT);
                        new_conn->deliver(approve);

                        spdlog::info("[Node::accept] Accepted from {}", new_conn->get_remote_id());
                        receive(new_conn);
                   });
                }

                accept();
           });
    }

    void Node::receive(const std::shared_ptr<Connection>& conn) {
        conn->start([this, conn](const MessagePtr& msg) {
            if (msg->get_type() == MessageType::DISCONNECT) {
                const std::string id = get_string_from_container(msg->get_message());

                {
                    std::lock_guard lock(mutex_);
                    connections_[id]->close();
                    remove_connection(id, lock);
                }

                spdlog::info("[Node::receive] Disconnected from {}", id);
            } else if (msg->get_type() == MessageType::TEXT) {
                if (msg->is_broadcasting()) {
                    try {
                        decrypt(msg);
                        spdlog::info("Received [{}]: {}", conn->get_remote_id(), get_string_from_container(msg->get_message()));
                    } catch (const aes::aes_exception&) {
                        // do nothing
                        // because the message has arrived not to target id
                    }
                } else {
                    decrypt(msg);
                    spdlog::info("Received [{}]: {}", conn->get_remote_id(), get_string_from_container(msg->get_message()));
                }
            } else if (msg->get_type() == MessageType::SEARCH) {
                const json node = search_node(get_string_from_container(msg->get_message()));
                std::cout << node << std::endl;
            }
        });
    }

    void Node::encrypt(const ID& target_id, const MessagePtr& message) {
        auto it = public_keys_.find(target_id);
        if (it == public_keys_.end()) {
            spdlog::error("[Node::encrypt] id: {} not found", target_id);
            return;
        }

        message->encrypt();
        assert(message->is_encrypted());

        const auto& aes_key = message->get_aes_key();
        const auto& aes_iv = message->get_aes_iv();

        auto* target_rsa_key = it->second.get();
        const auto& aes_key_encrypted = rsa::RSAKeyPair::encrypt(aes_key.begin(), aes_key.end(), target_rsa_key);
        const auto& aes_iv_encrypted = rsa::RSAKeyPair::encrypt(aes_iv.begin(), aes_iv.end(), target_rsa_key);

        message->set_aes(aes_key_encrypted, aes_iv_encrypted);
    }

    void Node::decrypt(const MessagePtr& message) const {
        const auto& aes_key_encrypted = message->get_aes_key();
        const auto& aes_iv_encrypted = message->get_aes_iv();

        const auto& decrypted_aes_key = identity_->rsa.decrypt(aes_key_encrypted.begin(), aes_key_encrypted.end());
        const auto& decrypted_aes_iv = identity_->rsa.decrypt(aes_iv_encrypted.begin(), aes_iv_encrypted.end());

        message->set_aes(decrypted_aes_key, decrypted_aes_iv);

        message->decrypt();
        assert(!message->is_encrypted());
    }

    json Node::search_node(const std::string& target_id) {
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

    std::string Node::generate_handshake_string() const {
        std::stringstream message_stream;
        message_stream << get_id() << DELIMITER << identity_->rsa.to_public_string();
        return message_stream.str();
    }

    VecMessage Node::generate_handshake() const {
        const std::string handshake_string = generate_handshake_string();
        const auto& handshake_vec = get_container_from_string(handshake_string);

        VecMessage message(handshake_vec, MessageType::HANDSHAKE);
        return message;
    }


} // cp2p


