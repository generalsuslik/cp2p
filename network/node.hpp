//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include "connection.hpp"

#include "crypto/rsa.hpp"
#include "network/message.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>

namespace cp2p {

    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    namespace beast = boost::beast;
    namespace http = beast::http;

    using json = nlohmann::json;

    using StrMessage = Message<std::string>;
    using VecMessage = Message<std::vector<std::uint8_t>>;
    using MessagePtr = std::shared_ptr<VecMessage>;

    /**
     * @brief Represents a node in the network \n
     * It can be either a hub or general node.
     *
     * Hubs allow other nodes to connect to their `passions` via themselves
     * losing the anonymity.
     */
    class Node : public std::enable_shared_from_this<Node> {
    public:
        using ID = std::string;
        using PublicKeyPtr = rsa::EVP_PKEY_ptr;

    public:
        struct NodeIdentity {
            ID id;
            rsa::RSAKeyPair rsa;

            std::string host;
            std::uint16_t port;

            std::uint64_t created_at;
        };

    public:
        Node();

        Node(const std::string& host, uint16_t port, bool is_hub = false);

        ~Node();

        /**
         * @brief Runs the node by creating a thread and running io_context in it
         */
        void run();

        /**
         * @brief Stops the node by stopping the io_context and joining the thread
         *
         * Also, it sends a disconnect request to the hub's server if is_hub is set to true
         */
        void stop();

        /**
         * @brief Connects to target_id via hub's hub_cost & hub's hub_port
         *
         * @param target_id id to connect to
         * @param server_host host of the node that will be an intermediate
         * @param server_port port of the node that will be an intermediate
         */
        void connect_to(const std::string& target_id, const std::string& server_host, std::uint16_t server_port);

        /**
         * @brief Connects directly to node host:port
         *
         * @param host node-to-connect-to's host
         * @param port node-to-connect-to's port
         * @param on_success
         */
        void connect_to(const std::string& host, std::uint16_t port, const std::function<void()>& on_success = nullptr);

        /**
         * @brief Sends a message to all connected nodes
         *
         * @param message message to send
         */
        void broadcast(VecMessage& message);

        void send_message(const std::string& id, const std::string& message);

        void send_message(const std::string& id, VecMessage message);

        void send_message(const std::string& id, const VecMessage& message, const std::function<void()>& on_success);

        /**
         * @brief Sends message to node {id}
         *
         * @param id node-to-send-message's id
         * @param message message to send
         */
        void do_send_message(const std::string& id, const VecMessage& message);

        /**
         * @brief Sends message to node {id}
         *
         * @param id node-to-send-message's id
         * @param message message to send
         * @param on_success callback called after a message is sent
         */
        void do_send_message(const std::string& id, const VecMessage& message, const std::function<void()>& on_success);

        /**
         * @brief Disconnects from all connected nodes
         */
        void disconnect_from_all(const std::function<void()>& on_success);

        /**
         * @brief Disconnects from the node with id_ == id
         *
         * @param id node to disconnect 's id
         */
        void disconnect(const std::string& id);

        void remove_connection(const std::string& id);

        /**
         * @brief Returns self id
         */
        ID get_id() const;

        /**
         * @brief Returns vector of all the node's connections
         */
        std::vector<std::shared_ptr<Connection>> get_connections();

        /**
         * @brief sets is_hub value to val
         *
         * @param val boolean to set for is_hub
         */
        void set_hub(bool val);

    private:
        /**
         * @brief Accepts incoming connections \n
         * method is called from the constructor \n\n
         *
         * Creates a new Connection object
         */
        void accept();

        void receive(const std::shared_ptr<Connection>& conn);

        void encrypt(const ID& target_id, const MessagePtr& message);

        static void decrypt(const MessagePtr& message);

        json search_node(const std::string& target_id);

        json request_connection(const std::string& target_id);

        void connect_to_server(const std::string& host, std::uint16_t port);

        void disconnect_from_server(const std::string& host, std::uint16_t port);

        /**
         * @brief CALLED ONLY IF is_hub SET TO TRUE \n
         * Sends to server JSON: { "id": ..., "host": ..., "port": ... }
         *
         * @param host server's host
         * @param port server's port
         * @param verb
         */
        void inform_server(const std::string& host, std::uint16_t port, http::verb verb);

        /**
         * @brief When the method Node::connect_to is called, it tries to receive one of the hub's info,
         * so it could connect to target_id via that hub
         *
         * @param host server's host
         * @param port server's port
         * @return hub's info JSON: { "id": ..., "host": ..., "port": ... }
         */
        json get_hub_data(const std::string& host, std::uint16_t port);

        std::string get_ip();

        static ID generate_id(const std::string& public_key);

        std::string generate_handshake_string() const;

        VecMessage generate_handshake() const;

    private:
        asio::io_context io_context_;
        std::vector<std::thread> io_workers_;
        inline static std::uint32_t num_workers = 1;

        tcp::acceptor acceptor_;

        std::unordered_map<ID, std::shared_ptr<Connection>> connections_; // "public key hash": conn
        std::unordered_map<ID, PublicKeyPtr> public_keys_; // "public key hash": public key

        std::mutex mutex_;

        std::atomic_bool is_hub_;
        std::atomic_bool is_active_;

        std::shared_ptr<NodeIdentity> identity_;
    };


} // cp2p

#endif //PEER_H